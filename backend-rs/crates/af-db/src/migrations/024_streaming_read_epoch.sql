CREATE TABLE IF NOT EXISTS streaming_history_read_revision (
    id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO streaming_history_read_revision(id,revision) VALUES(1,0);
CREATE TRIGGER IF NOT EXISTS streaming_read_changed AFTER UPDATE ON streaming_history
WHEN OLD.provider IS NOT NEW.provider OR OLD.server_id IS NOT NEW.server_id
 OR OLD.user_id IS NOT NEW.user_id OR OLD.user_name IS NOT NEW.user_name
 OR OLD.item_id IS NOT NEW.item_id OR OLD.item_name IS NOT NEW.item_name
 OR OLD.item_type IS NOT NEW.item_type OR OLD.series_name IS NOT NEW.series_name
 OR OLD.client_name IS NOT NEW.client_name OR OLD.device_name IS NOT NEW.device_name
 OR OLD.play_method IS NOT NEW.play_method OR OLD.started_at IS NOT NEW.started_at
 OR OLD.provenance IS NOT NEW.provenance OR OLD.policy_status IS NOT NEW.policy_status
 OR OLD.timestamp_certainty IS NOT NEW.timestamp_certainty OR OLD.byte_accuracy IS NOT NEW.byte_accuracy
 OR OLD.source_event_id IS NOT NEW.source_event_id
 OR ((OLD.watched_secs >= (SELECT minimum_watch_secs FROM streaming_tracking_policies WHERE id=1))
     IS NOT (NEW.watched_secs >= (SELECT minimum_watch_secs FROM streaming_tracking_policies WHERE id=1)))
BEGIN UPDATE streaming_history_read_revision SET revision=revision+1 WHERE id=1; END;
CREATE TRIGGER IF NOT EXISTS streaming_read_deleted AFTER DELETE ON streaming_history
BEGIN UPDATE streaming_history_read_revision SET revision=revision+1 WHERE id=1; END;
CREATE TRIGGER IF NOT EXISTS streaming_read_policy AFTER UPDATE ON streaming_tracking_policies
BEGIN UPDATE streaming_history_read_revision SET revision=revision+1 WHERE id=1; END;
