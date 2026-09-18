# Database schema and migration plan

All timestamps are UTC RFC3339Nano strings, IDs are random opaque strings, booleans are INTEGER 0/1.
Migration 1 is embedded, applied within a transaction, recorded in `schema_migrations(version, applied_at)`.
Startup refuses a database created by a newer schema. Foreign keys are enabled on every connection.

| Entity | Columns / constraints |
|---|---|
| admins | id PK, username UNIQUE, password_hash, created_at, updated_at |
| sessions | token_hash PK, admin_id FK CASCADE, csrf_token, expires_at, created_at |
| engines | id PK, name, base_url, type, detected_type, auth_type, secret_cipher, enabled, status, last_check, last_success, last_error, latency_ms, created_at, updated_at |
| upstream_models | engine_id + upstream_id composite PK, display_name, available, capabilities JSON, last_seen; engine FK CASCADE |
| models | id PK, alias UNIQUE, engine_id FK RESTRICT, upstream_model_id, display_name, published, available, created_at, updated_at |
| model_allowed_ips | model_id FK CASCADE, cidr; composite PK |
| api_keys | id PK, name, secret_cipher, secret_hash UNIQUE, suffix, enabled, last_used_at, created_at, updated_at |
| api_key_tags | api_key_id FK CASCADE, tag; composite PK |
| model_allowed_api_keys | model_id FK CASCADE, api_key_id FK RESTRICT; composite PK |
| model_capabilities | model_id FK CASCADE, capability, enabled; composite PK; rows represent effective admin-overridable flags |
| request_stats | id PK, timestamp, source_ip, request_id, api_key_id/name/tags snapshots, model alias/id, engine id/name, upstream_model, endpoint, method, status, streaming, duration_ms, ttft_ms, input/output/total_tokens, error_code |
| daily_stats | day + model_id + engine_id + api_key_id composite PK; snapshot names, requests, errors, streaming, duration_ms, input/output/total_tokens |
| audit_logs | id PK, timestamp, actor_id/name, source_ip, action, target, result, detail (sanitized) |
| settings | key PK, value JSON |
| backups | id PK, filename UNIQUE, kind, size, created_at |
| schema_migrations | version PK, applied_at |

Statistics deliberately do not use foreign keys for deleted configuration: historical snapshots survive.
Detailed statistics have timestamp/filter indexes. Daily aggregation uses UPSERT in the same transaction
as insertion of the detail record. Request ID is unique to avoid accidental duplicate counting.
Audit logs never contain prompt or credentials. Request prompts live only in rotating JSONL files.

Deletion policy: engines with gateway models and API keys referenced by model ACLs cannot be deleted.
The UI explains the dependency. Deleting a model removes its ACL/capability children. Deleting an admin
invalidates its sessions; deletion of the last admin is rejected inside a transaction.

Discovery sync is one transaction: mark previous discoveries unavailable, upsert discovered IDs, update
gateway availability by presence, preserve all model aliases/ACL/capability overrides. Probe failures never
execute the absence transaction. Newly discovered IDs remain upstream-only until explicit registration.

Settings include listen_address, health_interval_seconds, request_timeout_seconds, log_rotation_bytes,
log_generations, statistics_retention_days, backup_retention_days, and auto_backup_enabled.
Defaults are 0.0.0.0:8080, 30, 600, 104857600, 10, 90, 14, true respectively.
