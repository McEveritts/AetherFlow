ALTER TABLE streaming_history ADD COLUMN provenance TEXT NOT NULL DEFAULT 'legacy_unverified'
    CHECK(provenance IN ('legacy_unverified', 'observed_session', 'imported_event', 'item_summary'));
ALTER TABLE streaming_history ADD COLUMN server_id TEXT NOT NULL DEFAULT '';
ALTER TABLE streaming_history ADD COLUMN source_event_id TEXT;
ALTER TABLE streaming_history ADD COLUMN timestamp_certainty TEXT NOT NULL DEFAULT 'legacy_unverified'
    CHECK(timestamp_certainty IN ('legacy_unverified', 'observed', 'source_event', 'last_played', 'unrecorded'));
ALTER TABLE streaming_history ADD COLUMN byte_accuracy TEXT NOT NULL DEFAULT 'legacy_unverified'
    CHECK(byte_accuracy IN ('legacy_unverified', 'estimated', 'unrecorded'));
ALTER TABLE streaming_history ADD COLUMN policy_status TEXT NOT NULL DEFAULT 'included'
    CHECK(policy_status IN ('included', 'excluded', 'duplicate', 'ambiguous'));
ALTER TABLE streaming_history ADD COLUMN event_unix INTEGER
    GENERATED ALWAYS AS (CAST(strftime('%s', NULLIF(started_at, '')) AS INTEGER)) VIRTUAL;
ALTER TABLE streaming_history ADD COLUMN event_missing INTEGER
    GENERATED ALWAYS AS (CASE WHEN event_unix IS NULL THEN 1 ELSE 0 END) VIRTUAL;
CREATE INDEX idx_streaming_archive_desc ON streaming_history(event_missing ASC, event_unix DESC, id DESC);
CREATE INDEX idx_streaming_archive_asc ON streaming_history(event_missing ASC, event_unix ASC, id ASC);
CREATE INDEX idx_streaming_archive_user ON streaming_history(provider, server_id, user_id, event_unix DESC, id DESC);
CREATE INDEX idx_streaming_archive_item ON streaming_history(provider, item_id, event_unix DESC, id DESC);
CREATE UNIQUE INDEX idx_streaming_source_event ON streaming_history(provider, server_id, source_event_id)
    WHERE source_event_id IS NOT NULL AND source_event_id != '';
CREATE TABLE streaming_history_revision (
    id INTEGER PRIMARY KEY CHECK(id = 1), revision INTEGER NOT NULL DEFAULT 0
);
INSERT INTO streaming_history_revision(id, revision) VALUES(1, 0);
CREATE TRIGGER streaming_history_changed AFTER UPDATE ON streaming_history BEGIN
    UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER streaming_history_deleted AFTER DELETE ON streaming_history BEGIN
    UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1;
END;
CREATE TABLE streaming_history_labels (
    history_id INTEGER NOT NULL REFERENCES streaming_history(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('library', 'genre')),
    value TEXT NOT NULL, name TEXT NOT NULL,
    PRIMARY KEY(history_id, kind, value)
);
CREATE INDEX idx_streaming_history_labels ON streaming_history_labels(kind, value, history_id);
CREATE TABLE streaming_user_links (
    af_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL, server_id TEXT NOT NULL DEFAULT '', provider_user_id TEXT NOT NULL,
    PRIMARY KEY(af_user_id, provider, server_id, provider_user_id)
);
CREATE TABLE streaming_tracking_policies (
    id INTEGER PRIMARY KEY CHECK(id = 1), minimum_watch_secs INTEGER NOT NULL DEFAULT 0 CHECK(minimum_watch_secs BETWEEN 0 AND 86400),
    excluded_users TEXT NOT NULL DEFAULT '[]', excluded_libraries TEXT NOT NULL DEFAULT '[]',
    reconnect_window_secs INTEGER NOT NULL DEFAULT 0 CHECK(reconnect_window_secs BETWEEN 0 AND 300),
    revision INTEGER NOT NULL DEFAULT 0
);
INSERT INTO streaming_tracking_policies(id) VALUES(1);
CREATE TRIGGER streaming_policies_changed AFTER UPDATE ON streaming_tracking_policies BEGIN
    UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER streaming_links_inserted AFTER INSERT ON streaming_user_links BEGIN
    UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER streaming_links_updated AFTER UPDATE ON streaming_user_links BEGIN
    UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER streaming_links_deleted AFTER DELETE ON streaming_user_links BEGIN
    UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER streaming_labels_inserted AFTER INSERT ON streaming_history_labels BEGIN
    UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER streaming_labels_updated AFTER UPDATE ON streaming_history_labels BEGIN
    UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1;
END;
CREATE TRIGGER streaming_labels_deleted AFTER DELETE ON streaming_history_labels BEGIN
    UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1;
END;
CREATE TABLE streaming_import_checkpoints (
    provider TEXT NOT NULL, server_id TEXT NOT NULL, source TEXT NOT NULL,
    checkpoint TEXT NOT NULL DEFAULT '', imported INTEGER NOT NULL DEFAULT 0,
    last_error TEXT, updated_at TEXT NOT NULL,
    PRIMARY KEY(provider, server_id, source)
);
CREATE TABLE streaming_history_audit (
    id INTEGER PRIMARY KEY, actor_id INTEGER NOT NULL, operation TEXT NOT NULL,
    preview_hash TEXT NOT NULL, before_json TEXT NOT NULL, after_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE streaming_session_samples (
    history_id INTEGER NOT NULL REFERENCES streaming_history(id) ON DELETE CASCADE,
    sampled_at INTEGER NOT NULL, observed_secs INTEGER NOT NULL CHECK(observed_secs BETWEEN 0 AND 60),
    playing INTEGER NOT NULL CHECK(playing IN (0, 1)), bitrate_bps INTEGER NOT NULL CHECK(bitrate_bps >= 0),
    PRIMARY KEY(history_id, sampled_at)
);
CREATE INDEX idx_streaming_session_samples_time ON streaming_session_samples(sampled_at, history_id);
