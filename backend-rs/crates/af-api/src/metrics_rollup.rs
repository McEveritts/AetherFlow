//! Calendar-day transfer totals and bounded capacity trend data.
use rusqlite::{params, Connection};
use serde_json::{json, Value};

// Collapse simultaneous measurements before taking differences. A corrupt or
// conflicting measurement breaks the interval on either side of it.
const COUNTERS: &str = r#"
WITH observations AS (
    SELECT unixepoch(timestamp, 'subsec') AS t,
           MIN(net_rx_bytes) AS rx, MIN(net_tx_bytes) AS tx,
           AVG(cpu_avg) AS cpu, AVG(mem_used_gb) AS mem, AVG(mem_total_gb) AS ram,
           AVG(disk_read_bps) AS disk_read, AVG(disk_write_bps) AS disk_write,
           COUNT(*) AS n,
           SUM(CASE WHEN typeof(net_rx_bytes) != 'integer' OR net_rx_bytes < 0
                      OR typeof(net_tx_bytes) != 'integer' OR net_tx_bytes < 0 THEN 1 ELSE 0 END) AS invalid,
           MIN(net_rx_bytes) != MAX(net_rx_bytes) OR MIN(net_tx_bytes) != MAX(net_tx_bytes) AS conflict
      FROM metrics_history
     WHERE timestamp >= date(?1, 'unixepoch', '-1 day')
       AND unixepoch(timestamp, 'subsec') BETWEEN ?1 AND ?2 GROUP BY t
), samples AS (
    SELECT *, CASE WHEN invalid=0 AND conflict=0 THEN rx END AS valid_rx,
              CASE WHEN invalid=0 AND conflict=0 THEN tx END AS valid_tx
      FROM observations
), intervals AS (
    SELECT *, LAG(valid_rx) OVER w AS prev_rx, LAG(valid_tx) OVER w AS prev_tx,
              t - LAG(t) OVER w AS duration FROM samples WINDOW w AS (ORDER BY t)
), deltas AS (
    SELECT *, CASE WHEN prev_rx IS NULL THEN NULL WHEN valid_rx < prev_rx THEN valid_rx
                   ELSE valid_rx - prev_rx END AS received,
              CASE WHEN prev_tx IS NULL THEN NULL WHEN valid_tx < prev_tx THEN valid_tx
                   ELSE valid_tx - prev_tx END AS sent FROM intervals
)
"#;

pub(super) fn daily_transfer(conn: &Connection, start: i64, end: i64) -> rusqlite::Result<Value> {
    let sql = format!(
        "{COUNTERS}
        SELECT date(t, 'unixepoch'), SUM(1.0 * received), SUM(1.0 * sent), COUNT(valid_rx),
               SUM(CASE WHEN invalid=0 AND conflict=0 THEN n-1 ELSE 0 END),
               SUM(CASE WHEN invalid=0 AND conflict THEN 1 ELSE 0 END),
               SUM(invalid), SUM(COALESCE(valid_rx < prev_rx,0) + COALESCE(valid_tx < prev_tx,0))
        FROM deltas GROUP BY 1 ORDER BY 1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params![start, end])?;
    let (mut duplicates, mut conflicts, mut invalid, mut resets) = (0i64, 0i64, 0i64, 0i64);
    let mut days = Vec::new();
    while let Some(row) = rows.next()? {
        if row.get::<_, i64>(3)? > 0 {
            days.push(json!({"date":row.get::<_,String>(0)?, "downloaded_bytes":row.get::<_,Option<f64>>(1)?,
                "uploaded_bytes":row.get::<_,Option<f64>>(2)?}));
        }
        duplicates += row.get::<_, i64>(4)?;
        conflicts += row.get::<_, i64>(5)?;
        invalid += row.get::<_, i64>(6)?;
        resets += row.get::<_, i64>(7)?;
    }
    Ok(
        json!({"days":days,"duplicate_samples":duplicates,"conflicting_samples":conflicts,
        "invalid_samples":invalid,"counter_resets":resets}),
    )
}

pub(super) fn capacity(conn: &Connection, start: i64, end: i64) -> rusqlite::Result<Value> {
    // Three-hour UTC buckets preserve calendar boundaries across the 30-day view.
    let sql = format!(
        "{COUNTERS}
        SELECT strftime('%Y-%m-%dT%H:%M:%fZ', MAX(t), 'unixepoch'),
               AVG(cpu), AVG(mem), AVG(ram), AVG(disk_read), AVG(disk_write),
               TOTAL(received) / SUM(CASE WHEN received IS NOT NULL THEN duration END),
               TOTAL(sent) / SUM(CASE WHEN sent IS NOT NULL THEN duration END)
          FROM deltas GROUP BY CAST(t / 10800 AS INTEGER) ORDER BY MAX(t)"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![start, end], |r| {
        Ok(json!({
            "timestamp":r.get::<_,String>(0)?, "cpu_avg":r.get::<_,Option<f64>>(1)?,
            "mem_used_gb":r.get::<_,Option<f64>>(2)?, "mem_total_gb":r.get::<_,Option<f64>>(3)?,
            "disk_read_bps":r.get::<_,Option<f64>>(4)?, "disk_write_bps":r.get::<_,Option<f64>>(5)?,
            "net_rx_bps":r.get::<_,Option<f64>>(6)?, "net_tx_bps":r.get::<_,Option<f64>>(7)?
        }))
    })?;
    Ok(Value::Array(rows.collect::<rusqlite::Result<_>>()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn includes_history_before_latest_ten_thousand_and_preserves_missing_intervals() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE metrics_history(timestamp TEXT,net_rx_bytes INTEGER,net_tx_bytes INTEGER,
            cpu_avg REAL,mem_used_gb REAL,mem_total_gb REAL,disk_read_bps REAL,disk_write_bps REAL);
            INSERT INTO metrics_history VALUES ('2026-01-01 01:00:00',100,5,12,4,8,0,0);
            WITH RECURSIVE seq(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM seq WHERE i<10000)
            INSERT INTO metrics_history SELECT datetime('2026-01-03','+'||i||' seconds'), i, 5, 20, 6, 8, 1, 0 FROM seq;
            INSERT INTO metrics_history SELECT * FROM metrics_history WHERE timestamp='2026-01-03 00:01:00';
            INSERT INTO metrics_history VALUES ('2026-01-06 01:00:00',10000,5,12,4,8,0,0);
            ").unwrap();
        let result = daily_transfer(&db, 1767225600, 1768003200).unwrap();
        assert_eq!(result["days"].as_array().unwrap().len(), 3);
        assert_eq!(result["days"][0]["downloaded_bytes"], Value::Null);
        assert_eq!(result["days"][1]["downloaded_bytes"], 10000.0);
        assert_eq!(result["days"][2]["downloaded_bytes"], 0.0);
        assert_eq!(result["duplicate_samples"], 1);
        assert_eq!(result["counter_resets"], 1);
        let trends = capacity(&db, 1767225600, 1768003200).unwrap();
        assert_eq!(trends[0]["cpu_avg"], 12.0);
        assert_eq!(trends[0]["net_rx_bps"], Value::Null);
    }
}
