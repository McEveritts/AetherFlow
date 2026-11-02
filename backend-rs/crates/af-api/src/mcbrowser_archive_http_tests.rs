use super::*;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::os::unix::fs::symlink;

fn decode_archive_files(
    format: operations::ArchiveFormat,
    bytes: &[u8],
) -> BTreeMap<String, Vec<u8>> {
    if format != operations::ArchiveFormat::Zip {
        return operations::decode_tar_archive_entries(format, Cursor::new(bytes)).unwrap();
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut files = BTreeMap::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        if entry.is_file() {
            let name = entry.name().unwrap().to_string();
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents).unwrap();
            files.insert(name, contents);
        }
    }
    files
}

#[tokio::test]
async fn mounted_alias_archives_preserve_names_all_codecs_and_reauthorize_tickets_and_actions() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    assert_eq!(
        request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/directory",
            serde_json::json!({"path":"target"})
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute(
                "INSERT INTO mcbrowser_policies (user_id, perm_execute) VALUES (1, 1)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE user_quotas SET quota_bytes = 1000000 WHERE user_id = 1",
                [],
            )
            .unwrap();
    }
    fs::write(fixture.user_root().join("target/a.txt"), b"approved bytes").unwrap();
    symlink("target", fixture.user_root().join("hop")).unwrap();
    symlink("hop", fixture.user_root().join("links")).unwrap();
    symlink("links/a.txt", fixture.user_root().join("leaf.txt")).unwrap();
    let selection = serde_json::json!(["links", "leaf.txt"]);
    for format in operations::ArchiveFormat::ALL {
        let response = request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/archive",
            serde_json::json!({"paths":selection,"format":format.extension()}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{format:?}");
        let bytes = tokio::time::timeout(Duration::from_secs(5), response.into_body().collect())
            .await
            .unwrap()
            .unwrap()
            .to_bytes();
        let files = decode_archive_files(format, &bytes);
        assert_eq!(files.len(), 2);
        assert_eq!(files["links/a.txt"], b"approved bytes");
        assert_eq!(files["leaf.txt"], b"approved bytes");
    }

    let response = request_json(fixture.router(), "POST", "/mcbrowser/actions",
        serde_json::json!({"action":"CreateArchive","source_paths":selection,"destination_path":"saved.zip","format":"zip"})).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let files = decode_archive_files(
        operations::ArchiveFormat::Zip,
        &fs::read(fixture.user_root().join("saved.zip")).unwrap(),
    );
    assert_eq!(files["links/a.txt"], b"approved bytes");
    assert_eq!(files["leaf.txt"], b"approved bytes");

    let response = request_json(fixture.router(), "POST", "/mcbrowser/actions",
        serde_json::json!({"action":"CreateArchive","source_paths":["links"],"destination_path":"target/overlap.zip","format":"zip"})).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!fixture.user_root().join("target/overlap.zip").exists());

    for denied in [
        "links",
        "hop",
        "target",
        "links/a.txt",
        "hop/a.txt",
        "target/a.txt",
        "leaf.txt",
    ] {
        let ticket_response = request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/archive-ticket",
            serde_json::json!({"paths":selection,"format":"zip"}),
        )
        .await;
        assert_eq!(ticket_response.status(), StatusCode::OK);
        let body = ticket_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let ticket: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ticket_endpoint = ticket["url"]
            .as_str()
            .unwrap()
            .strip_prefix("/api/v1/auth")
            .unwrap();
        {
            let connection = af_db::get_conn().unwrap();
            connection.execute("INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow) VALUES (1, 0, ?1, 0)", [denied]).unwrap();
        }
        let response = request_json(
            fixture.router(),
            "GET",
            ticket_endpoint,
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "ticket {denied}");
        let response = request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/archive",
            serde_json::json!({"paths":selection,"format":"zip"}),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "download {denied}"
        );
        let response = request_json(fixture.router(), "POST", "/mcbrowser/actions",
            serde_json::json!({"action":"CreateArchive","source_paths":selection,"destination_path":"denied.zip","format":"zip"})).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "action {denied}");
        assert!(!fixture.user_root().join("denied.zip").exists());
        af_db::get_conn()
            .unwrap()
            .execute("DELETE FROM mcbrowser_policy_rules WHERE user_id = 1", [])
            .unwrap();
    }
}
