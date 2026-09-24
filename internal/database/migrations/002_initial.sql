CREATE TABLE safeguards (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    engine_id TEXT NOT NULL REFERENCES engines(id) ON DELETE RESTRICT,
    upstream_model_id TEXT NOT NULL,
    adapter TEXT NOT NULL CHECK(adapter IN ('qwen3guard_gen')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    last_check TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(engine_id, upstream_model_id) REFERENCES upstream_models(engine_id, upstream_id) ON DELETE RESTRICT
);
CREATE INDEX safeguards_upstream ON safeguards(engine_id, upstream_model_id);
ALTER TABLE api_keys ADD COLUMN input_safeguard_id TEXT REFERENCES safeguards(id) ON DELETE RESTRICT;
ALTER TABLE api_keys ADD COLUMN output_safeguard_id TEXT REFERENCES safeguards(id) ON DELETE RESTRICT;
ALTER TABLE api_keys ADD COLUMN block_controversial INTEGER NOT NULL DEFAULT 0 CHECK(block_controversial IN (0,1));
CREATE INDEX api_keys_input_safeguard ON api_keys(input_safeguard_id);
CREATE INDEX api_keys_output_safeguard ON api_keys(output_safeguard_id);
ALTER TABLE request_stats ADD COLUMN guard_checks TEXT NOT NULL DEFAULT '[]';
ALTER TABLE request_stats ADD COLUMN upstream_ttft_ms REAL NOT NULL DEFAULT 0;
