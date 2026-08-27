CREATE TABLE network_observations (
    observation_id TEXT PRIMARY KEY NOT NULL,
    flow_id TEXT,
    observed_at_unix_ms BIGINT NOT NULL,
    ingress_source TEXT NOT NULL,
    destination_host TEXT,
    source_pid BIGINT,
    source_process_name TEXT,
    source_executable_path TEXT,
    source_bundle_id TEXT,
    hop TEXT NOT NULL,
    direction TEXT,
    operation TEXT,
    stage TEXT NOT NULL,
    outcome TEXT NOT NULL,
    failure_class TEXT,
    technical_error_code TEXT,
    started_at_unix_ms BIGINT NOT NULL,
    ended_at_unix_ms BIGINT NOT NULL,
    elapsed_ms BIGINT NOT NULL,
    http_status INTEGER,
    request_method TEXT,
    request_path TEXT,
    bytes_up BIGINT NOT NULL,
    bytes_down BIGINT NOT NULL,
    error TEXT
);

CREATE INDEX network_observations_observed_at_idx
    ON network_observations (observed_at_unix_ms DESC);
