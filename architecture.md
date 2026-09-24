# LLM Gateway architecture

## Scope and decisions

LLMGateway is a modular Go monolith for Apple Silicon macOS. It performs no inference.
One HTTP listener (default `0.0.0.0:8080`) serves `/v1/`, `/admin/`, `/setup`, and `/health`.
The deliverable embeds vanilla HTML/CSS/JavaScript and requires no Node or Python runtime.
SQLite uses WAL, foreign keys, bounded busy waits, parameterized SQL, and numbered migrations.
The pure-Go modernc SQLite driver avoids a separate SQLite installation. Darwin Security.framework
is linked through cgo for Keychain; building on macOS needs Apple's command line tools, but running
the binary needs only macOS system frameworks.

## Modules and request flow

`cmd/llmgw` provides serve, version, administrator recovery, backup/restore, and LaunchAgent commands.
`internal/app` owns lifecycle, listener replacement, background jobs, and shutdown.
`internal/database` owns migrations and transactional repositories. `internal/domain` shares types.
`internal/auth`, `acl`, `cryptoutil`, and `keychain` own identity, authorization, and secrets.
`internal/engine` provides typed endpoint requests and per-engine adapters. `internal/gateway` routes
requests and serves the embedded administrative UI/API. `internal/logging` owns JSONL and statistics.
`internal/safeguard` implements safety-classifier adapters, strict text extraction, and held-response validation.
`internal/backup` owns consistent snapshots, encrypted portable archives, and validated restore.

Requests receive a random request ID, a normalized TCP peer IP, and an optional bearer candidate.
Alias resolution precedes publication/availability/ACL/capability checks and adapter selection.
The gateway reserializes a parsed endpoint-specific representation with the upstream model ID.
It constructs upstream headers from engine credentials, never from client Authorization.
Unknown fields are retained to preserve protocol extensions; invalid protocol shape is rejected.
There is no chat-to-responses or messages-to-chat emulation. Unsupported native endpoints return
explicit errors. Responses rewrite protocol-level model fields to the public alias, including SSE.
Engine type is a profile, not proof of every capability. Model metadata contributes conservative
capability defaults; administrators can override every flag. Auto detection is best effort and falls
back to generic OpenAI. The configured type and detected type remain separate.

## Optional API-key safeguards

Safeguard profiles reference an engine and a synchronized upstream model independently of public aliases.
API keys may select separate input/output profiles and optionally reject Controversial as well as Unsafe.
Both profile references default to NULL, preserving existing keys, anonymous access, and realtime SSE.
A supplied enabled key's policy applies even on models without key ACLs. Mandatory moderation requires
the model's API-key ACL: neither an IP-only rule nor CORS requires the caller to supply a guarded key.

After ACL and capability checks, the gateway snapshots key, safeguard, engine, and settings data without
holding a DB transaction during inference. It runs input inspection before generation and output
inspection before delivery. Guard calls use engine credentials directly, never recursive Gateway HTTP
requests or client generation parameters. Disabled/missing guards and failed classifications stop the
request. References survive model disappearance; referenced safeguards and engines cannot be deleted.

The initial adapter is Qwen3Guard-Gen, using native nonstreaming Chat Completions and the model's official
chat template on the upstream engine. Quantized variants must preserve that template. Classification
parsing rejects missing, unknown, duplicate, or truncated labels. Request history and text content are
represented with role labels, including system/developer, tools, reasoning, and all output choices/items.
Unsupported media, token IDs, unseen stored context, and unrecognized content fields fail explicitly.
Embeddings and rerank scores are numerical outputs; rerank document text still receives output inspection.

An output-guarded SSE response is held in a private 0600 temporary file under a 0700 directory, unlinked
immediately after opening. No headers/content are committed before a complete, structurally valid stream
passes inspection. Events are then replayed in normalized order. Input-only safeguards retain incremental
delivery after the input passes. Cancellation closes upstream work and the file descriptor. Defaults are
256 KiB inspection text, 64 MiB held response, 64 KiB guard reply, and 60 seconds per guard call. The first,
second, and fourth limits are live settings. Over-limit content is rejected without truncation, and these
limits do not constrain unguarded requests.

Access records contain per-stage classifier metadata and separate classifier token usage, with immutable
queued snapshots. No extra client request is counted for internal guard calls, and generation aggregates
exclude guard tokens. Client TTFT includes output-check delay; upstream TTFT is retained separately.
Raw classifier output and rejected response text are not logged. Admin profile changes/checks and key
policy changes are audited. Settings contains profile CRUD/checks; API keys assigns the policies.

## Authorization and administration

IP lists and API-key lists are independent allow lists combined with AND. An empty list imposes no
restriction. Unknown bearer tokens are ignored when a model has no key ACL. IPs use `net/netip`,
unmap IPv4-mapped IPv6, and never consult forwarding headers. New models receive `127.0.0.1/32`
and `::1/128`; an explicitly empty edited list removes IP restriction. Key deletion must not turn a
restricted model public: deletion of referenced keys is rejected until its ACL references are removed.
`GET /v1/models` filters published, available, enabled-engine models by both ACLs.

The public API (`/v1` and `/v1/*`) permits every browser Origin via wildcard CORS, without cookie
credentials. Preflight OPTIONS is logged and answered locally before authentication or database access;
actual API calls still evaluate both model ACLs. IP-only ACLs do not distinguish websites running in
an allowed client's browser. Public CORS is not applied to administration, setup, or health routes.

First setup is local TCP loopback only, with a transaction preventing concurrent first-admin creation.
Administrators use Argon2id hashes, opaque freshly generated sessions (24 hours), HttpOnly/SameSite
cookies, same-origin checks, and session-bound CSRF tokens. Password changes revoke sessions.
The final administrator cannot be deleted. The login/setup pages also use a pre-auth CSRF challenge.
All administrators have equal rights. API keys are a separate principal class with no admin access.
The UI uses textContent rather than unsafe HTML for untrusted data, a strict CSP, and no CDN scripts.

## Secrets and backup

256-bit master keys live exclusively in the user's macOS Keychain, scoped to canonical data-directory
identity. AES-256-GCM ciphertexts bind a purpose/record identity via authenticated additional data.
API keys use 32 random bytes; only a SHA-256 lookup digest, a masked suffix, and encrypted secret are
stored. Upstream credentials are encrypted independently. Secret reveal is an audited POST operation.
Keychain access failures fail closed: there is no plaintext-file or environment-key fallback in production.

SQLite online snapshots use `VACUUM INTO` to include committed WAL contents. A local backup contains
encrypted DB secrets and requires the original Keychain key. Portable backups wrap a database snapshot
and its master key together inside an Argon2id-derived AES-GCM envelope; no plaintext secret is written
to the archive. Import decrypts in memory, validates schema/integrity, and re-encrypts every database
secret with the destination Mac's master key before installation. Known older schema versions are
validated against their original schema and authenticated before migration, then validated again against
the current schema; guard assignments remain disabled for pre-safeguard keys. Sessions are discarded on restore.
Restore is staged and applied on next start under the exclusive process lock; it never replaces an open
database. A pre-restore snapshot provides rollback. CLI restore refuses to run against an active service.
Automatic backups run daily, with default 14-day retention. Directory and secret-containing files use
0700/0600 permissions. Backup names are server-generated and paths cannot traverse directories.

## Streaming, health, and observability

Each request has its own context and timeout (default 10 minutes, configurable). Unguarded SSE is forwarded and
flushed per event, buffering only the current event, never the full generation. A bounded event size
protects against malformed unbounded SSE frames, not client request sizes. Client cancellation closes
the upstream request. TTFT measures first nonempty data event; usage comes from the final available
usage event, including nested responses/messages formats. Already-started streams cannot change HTTP
status; failures terminate with a sanitized SSE error and record failure in stats.

Health checks run every 30 seconds, using models discovery. Transport failures are Offline; HTTP/API
failures are Degraded; valid discovery is Online. A failed probe does not delete discoveries or mark all
models missing. Only successful model sync marks absent upstream IDs unavailable and restores returning
models. No discovery automatically publishes a gateway model. Cached Offline does not gate inference:
one actual attempt is made, with a 503 on connection failure.

Detailed JSONL logs contain redacted prompts. SQLite request_stats never contains prompt text.
Binary data URLs, base64 payloads, image/audio/document blocks become byte-count markers. Access logs
rotate at 100 MiB, retain 10 generations, and gzip old files. A bounded writer queue drains at shutdown;
when full it applies backpressure only after response forwarding, never accumulating unbounded memory.
Daily aggregates are updated transactionally with each request and outlive 90-day detail retention.
Audit events record actor, TCP source, action, target, result, and time without secrets.

## Live configuration and process ownership

Database-backed settings take effect for new operations immediately. Listener changes first bind the new
address, persist only on success, then gracefully retire the old listener. Existing streams can drain.
CLI flags/environment supply initial defaults and data-directory selection; persisted settings win after
first start. Changing data directory requires restart; restore explicitly requires restart.
The user LaunchAgent uses an absolute executable/data path and the same login user's Keychain.
It does not install a root daemon or change the user's shell profile. The app holds an exclusive data-dir
lock to exclude multiple writers/services and unsafe concurrent CLI restoration.

## Design review

- Requirements: administration, all seven protocol routes, health/discovery, ACL, observability, backup,
  CLI, embedded UI, tests, and docs have explicit owners; no inference/load balancing/failover is added.
- Database: unique alias, FK enforcement, explicit deletion policy, transactional ACL and aggregate writes.
- ACL: key removal cannot silently make a restricted model anonymous; IPv4 mapping is canonicalized.
- Streaming: bounded per-event memory, context cancellation, alias normalization, no global DB lock.
- Keychain: native API avoids command-line secret leakage, separate directory identity, no fallback.
- Restore: online snapshots include WAL; portability rewraps secrets; integrity and schema checks precede
  staged installation; current DB remains intact on wrong passphrase/key or failed validation.
- Compatibility limits: capability detection cannot prove support without inference; admin override is
  explicit. Real engine/version combinations require validation beyond the mock integration suite.

Primary protocol references: [LM Studio API](https://lmstudio.ai/docs/developer/rest),
[MLX LM server](https://github.com/ml-explore/mlx-lm/blob/main/mlx_lm/SERVER.md).
