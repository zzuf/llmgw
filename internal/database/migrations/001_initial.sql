CREATE TABLE admins (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY NOT NULL,
    admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE engines (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    base_url TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'auto',
    detected_type TEXT NOT NULL DEFAULT '',
    auth_type TEXT NOT NULL DEFAULT 'none',
    secret_cipher BLOB,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    status TEXT NOT NULL DEFAULT 'Unknown',
    last_check TEXT NOT NULL DEFAULT '',
    last_success TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    latency_ms REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE upstream_models (
    engine_id TEXT NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    upstream_id TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    available INTEGER NOT NULL DEFAULT 1 CHECK(available IN (0,1)),
    capabilities TEXT NOT NULL DEFAULT '{}',
    last_seen TEXT NOT NULL,
    PRIMARY KEY(engine_id, upstream_id)
);
CREATE TABLE models (
    id TEXT PRIMARY KEY NOT NULL,
    alias TEXT NOT NULL UNIQUE,
    engine_id TEXT NOT NULL REFERENCES engines(id) ON DELETE RESTRICT,
    upstream_model_id TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    published INTEGER NOT NULL DEFAULT 0 CHECK(published IN (0,1)),
    available INTEGER NOT NULL DEFAULT 0 CHECK(available IN (0,1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(engine_id, upstream_model_id) REFERENCES upstream_models(engine_id, upstream_id) ON DELETE RESTRICT
);
CREATE INDEX models_upstream ON models(engine_id, upstream_model_id);
CREATE TABLE model_allowed_ips (
    model_id TEXT NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL,
    PRIMARY KEY(model_id, cidr)
);
CREATE TABLE api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    secret_cipher BLOB NOT NULL,
    secret_hash TEXT NOT NULL UNIQUE,
    suffix TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    last_used_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE api_key_tags (
    api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY(api_key_id, tag)
);
CREATE TABLE model_allowed_api_keys (
    model_id TEXT NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE RESTRICT,
    PRIMARY KEY(model_id, api_key_id)
);
CREATE INDEX model_allowed_api_keys_key ON model_allowed_api_keys(api_key_id);
CREATE TABLE model_capabilities (
    model_id TEXT NOT NULL REFERENCES models(id) ON DELETE CASCADE,
    capability TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    PRIMARY KEY(model_id, capability)
);
CREATE TABLE request_stats (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL UNIQUE,
    api_key_id TEXT NOT NULL DEFAULT '',
    api_key_name TEXT NOT NULL DEFAULT '',
    api_key_tags TEXT NOT NULL DEFAULT '[]',
    model_id TEXT NOT NULL DEFAULT '',
    model_alias TEXT NOT NULL DEFAULT '',
    engine_id TEXT NOT NULL DEFAULT '',
    engine_name TEXT NOT NULL DEFAULT '',
    upstream_model TEXT NOT NULL DEFAULT '',
    endpoint TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 0,
    streaming INTEGER NOT NULL DEFAULT 0,
    duration_ms REAL NOT NULL DEFAULT 0,
    ttft_ms REAL NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    error_code TEXT NOT NULL DEFAULT ''
);
CREATE INDEX request_stats_timestamp ON request_stats(timestamp);
CREATE INDEX request_stats_model ON request_stats(model_id, timestamp);
CREATE INDEX request_stats_engine ON request_stats(engine_id, timestamp);
CREATE INDEX request_stats_key ON request_stats(api_key_id, timestamp);
CREATE INDEX request_stats_source ON request_stats(source_ip, timestamp);
CREATE TABLE daily_stats (
    day TEXT NOT NULL,
    model_id TEXT NOT NULL DEFAULT '',
    engine_id TEXT NOT NULL DEFAULT '',
    api_key_id TEXT NOT NULL DEFAULT '',
    model_alias TEXT NOT NULL DEFAULT '',
    engine_name TEXT NOT NULL DEFAULT '',
    api_key_name TEXT NOT NULL DEFAULT '',
    api_key_tags TEXT NOT NULL DEFAULT '[]',
    requests INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    streaming INTEGER NOT NULL DEFAULT 0,
    duration_ms REAL NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(day, model_id, engine_id, api_key_id)
);
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    actor_id TEXT NOT NULL DEFAULT '',
    actor_name TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_logs_timestamp ON audit_logs(timestamp);
CREATE TABLE settings (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);
CREATE TABLE backups (
    id TEXT PRIMARY KEY NOT NULL,
    filename TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
