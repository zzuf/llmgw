# LLM Gateway implementation plan

Goal: implement the full gateway described in architecture.md, database-schema.md and api-design.md.
Global constraints: no external runtime, no plaintext stored secrets, native macOS Keychain, no inferred
cross-protocol conversions, loopback default ACL, actual RemoteAddr, bounded streaming/log memory.

- [x] Phase 1: inspect workspace, architecture, API design, self-review.
- [x] Phase 2: relational schema, migration and restore invariants.
- [x] Phase 3: module, package contracts, build/check scripts.
- [x] Phase 4: SQLite repository, hot settings, crypto, Keychain.
- [x] Phase 5: setup/login/session/CSRF/password recovery.
- [x] Phase 6: engines and periodic health checks.
- [x] Phase 7: discovery sync, registration and unique aliases.
- [x] Phase 8: model ACL and encrypted API keys.
- [x] Phase 9: public API handlers and controlled errors.
- [x] Phase 10: native engine adapters and capabilities.
- [x] Phase 11: SSE framing, flush, usage and cancellation.
- [x] Phase 12: redacted JSONL, rotation and gzip.
- [x] Phase 13: request/daily stats and dashboard.
- [x] Phase 14: action audit records.
- [x] Phase 15: snapshots, daily retention, portable encryption and restore.
- [x] Phase 16: responsive embedded admin UI, forms/filtering/pagination (DOM integration verified; visual browser verification unavailable).
- [x] Phase 17: launchd CLI and graceful lifecycle.
- [x] Phase 18: integration/security/race tests and Apple Silicon build.
- [x] Phase 19: README and operational/security limitations.

Each implementation boundary runs gofmt, go vet ./..., go test ./... via scripts/check.sh.
Phases 1–2 contain no Go code yet: Go checks become executable with Phase 3; this is recorded rather
than claiming nonexistent tests passed. Independent modules may be developed concurrently after their
contracts are fixed. Integration gates run before marking their phases complete.

Tests are written around security invariants and behavior: ACL matrix, model disappearance/reappearance,
native endpoints, secrets/CSRF/session, usage/SSE/cancellation, snapshots/rewrapping, log rotation/redaction.
Final verification includes go test -race ./..., go vet ./..., native darwin/arm64 binary and CLI smoke tests.

## Review findings resolved

- Model reads and ACL child reads share a database snapshot; key/engine dependency deletion fails closed.
- Password-based session insertion checks that the verified password hash remains current.
- Post-commit audit writes survive request cancellation; restore initiator audit survives DB replacement.
- Graceful shutdown separates signal lifetime from active stream lifetime, drains logs, and bounds forced stop.
- Live listener replacement rolls back bind/DB/log-setting failures and removes retired listeners.
- Request deadlines include body reads and client writes; timed-out unread bodies cannot hang HTTP cleanup.
- Streaming usage uses the adapter's presence-aware cumulative result, including final corrections to zero.
- SSE parsing handles BOM, LF, CRLF and CR across arbitrary read boundaries before alias/error normalization.
- Backups reject missing required credential ciphertext and retain corrupt pre-restore files for recovery.

Operational verification boundaries are recorded in docs/verification.md; native Keychain interaction,
real LLM inference, and installing the user's LaunchAgent were not exercised by automated tests.
