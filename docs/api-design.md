# API design

## Public API

`GET /health` returns process liveness without credentials/configuration. `GET /v1/models` returns
`{"object":"list","data":[{"id":"public-alias","object":"model","owned_by":"llmgw"}]}`
filtered by availability, publication, engine enabled state and both model ACL lists.

All generation calls require a nonempty string `model` (public alias). Supported native protocol routes:

| Route | Capability | Input for detailed log |
|---|---|---|
| POST /v1/chat/completions | chat_completions | messages |
| POST /v1/responses | responses | input, instructions |
| POST /v1/completions | completions | prompt |
| POST /v1/embeddings | embeddings | input |
| POST /v1/rerank | rerank | query, documents |
| POST /v1/messages | messages | messages, system |

Gateway request parsing preserves extension fields as JSON RawMessage while validating envelope and
endpoint input shape. Streaming, tools and vision are independently capability-checked. There is no
cross-protocol synthesis: unsupported native features return 400/501 and clear unsupported codes.
Adapters construct absolute endpoint URLs relative to the configured API base (`.../v1`), authenticate
with engine secrets, disable redirects (credential isolation), and map native model metadata.
Upstream HTTP failures become controlled gateway errors; response bodies are not blindly forwarded.
Response JSON and SSE protocol model fields expose the public alias. Numeric usage is normalized for
statistics but original valid API fields remain intact for compatibility.

All API responses have `X-Request-ID`. Errors are JSON:
`{"error":{"message":"safe description","type":"gateway_error","code":"model_not_found"}}`.
Codes: unauthorized (401), forbidden (403), model_not_found (404), model_unavailable (503),
engine_unavailable (503), unsupported_endpoint (501), unsupported_capability (400), upstream_error (502),
timeout (504), invalid_request (400), internal_error (500). Unauthorized only applies when a key ACL
exists. A valid but unlisted key is forbidden. Unsupported method returns 405.

### API-key safeguards

An enabled supplied key may select an input and/or output safeguard. After normal ACL/capability checks,
the gateway snapshots its policy, calls the input guard before inference, and withholds output until its
output guard allows it. No new client request fields or routes are required. Guard policy is server-owned;
clients cannot override it with generation settings. GET models and OPTIONS do not invoke classifiers.
Keys with no safeguards, anonymous requests, and unknown Bearer tokens retain their existing behavior.
Configure a model's API-key ACL when every successful request must use a guarded key.

Text inspection includes all messages, role-labelled context, system/developer instructions, tool schemas,
tool arguments/results, reasoning, and every generated choice/item. Images/audio/files, token ID inputs,
unseen stored history, and unknown content fields return `unsupported_guard_content`, including on
output-only guarded requests where the input is needed as context. Embeddings and rerank text inputs can
be inspected. Numeric vectors/scores have no output text; returned rerank documents are output-inspected.

The initial format is `qwen3guard_gen`: native Chat Completions with the upstream's dedicated Qwen template,
strict Safety/Categories parsing, and Refusal on output classification. Classification labels are Safe,
Unsafe, and Controversial; Unsafe is always rejected, Controversial only when the key requests it. Broken,
truncated, duplicate, or unrecognized classifications never pass. Classification calls use only engine
credentials and fixed guard generation settings. They do not inherit public API keys or client headers.

Output-guarded SSE sends no events or response headers before the full response passes. Normalized events
are held in an immediately unlinked private temporary file, validated through the terminal event, then
replayed in order. Input-only guards permit normal realtime delivery after approval. Guard timeouts and
inspection/held-response limits apply only to guarded work and never silently truncate content.
Output-guarded SSE explicitly rejects logprobs, nonempty annotations, unknown content-bearing events,
and incomplete finish states rather than forwarding uninspected data. Unguarded SSE is unchanged.

| HTTP | Error code | Meaning |
|---|---|---|
| 403 | guard_rejected | Unsafe, or Controversial when enabled |
| 503 | guard_unavailable | Disabled/missing guard, upstream failure, or invalid classification |
| 504 | guard_timeout | Classifier deadline exceeded |
| 400 | unsupported_guard_content | Content cannot be fully represented for inspection |
| 503 | guard_limit_exceeded | Inspection text or held-response bound exceeded |

### Browser access / CORS

Only `/v1` and `/v1/*` allow all origins with `Access-Control-Allow-Origin: *`, including
successes, errors, and streaming responses. `X-Request-ID` is exposed to browser JavaScript.
`OPTIONS` returns 204 before database access, credential lookup, model ACL evaluation, or upstream
requests. Preflight permits GET, POST, and OPTIONS and explicitly echoes requested header names,
including Authorization and SDK extension headers; absent a requested list, it permits Authorization
and Content-Type. Responses vary on Access-Control-Request-Headers. Preflights are included in access
logs and request statistics, with no model, engine, or API-key attribution.

Cookie credentials are not enabled: browser clients should use `credentials: 'omit'` and provide
any required Gateway API key via Authorization: Bearer. All model ACLs still apply to actual calls.
Source-IP rules identify the browser's TCP peer, not the initiating website, so IP-only models are
callable by any origin on an allowed client. Administrative routes never inherit this CORS policy.
Browser mixed-content and local-network permission policies remain independent of CORS.

## Administrative API and UI

Embedded `/setup`, `/admin/login`, and `/admin/` pages use same-origin requests and cookie sessions.
JSON resources below `/admin/api/`: session, dashboard, engines, upstream-models, models, keys, safeguards, admins,
access-logs, audit-logs, statistics, backups, settings. Resource updates use POST/PUT/DELETE; lists use
GET with pagination/filter query parameters where appropriate. Login/logout/setup are explicit POSTs.
All state changes validate Origin/Host and a CSRF token; session responses expose the CSRF token only
to authenticated same-origin callers. Secret reveal is POST `/admin/api/keys/{id}/reveal` and audited.
Engine `/check` and `/sync` actions use the same validated discovery path, with status recorded.

Models contain alias, engine_id, upstream_model_id, display_name, published, available,
capabilities map[string]bool, allowed_ips string[], allowed_api_keys string[]. Creation defaults the IP
ACL to loopback if omitted; editing accepts empty arrays to intentionally remove a restriction.
API key creation returns a generated key only within an authenticated no-store response; lists return
masked secrets. Engine APIs never return decrypted credentials; blank credential edits preserve them.

### Safeguard administration

`GET/POST /admin/api/safeguards` lists/creates profiles. `PUT/DELETE /admin/api/safeguards/{id}` edits/deletes.
Writable fields are `name`, `engine_id`, `upstream_model_id`, `adapter` (`qwen3guard_gen`), and `enabled`.
The model must be a synchronized upstream entry; a public alias is not required. Read responses also
contain `id`, `available`, `last_check`, `last_error`, `created_at`, and `updated_at`. Model-name suggestions
in the UI do not activate a profile. Referenced profiles and their engines cannot be deleted.

`POST /admin/api/safeguards/{id}/check` tests both input/output classification formats and returns
`{"ok":true,"input":{...},"output":{...}}`. Each stage uses the same GuardCheck metadata as access logs;
last check/error is persisted, and checks and CRUD operations use the existing session/CSRF/audit controls.

API-key POST/PUT accepts nullable `input_safeguard_id`, nullable `output_safeguard_id`, and boolean
`block_controversial`. New keys default to null/null/false. On update, omitted fields preserve the current
value; explicit null clears an assignment. Enable/disable changes do not remove guard policy. Any active
request keeps its initial snapshot; later requests use updated profiles, engine configuration, and settings.

Settings adds `guard_timeout_seconds` (60, range 1–86400), `guard_max_text_bytes` (262144, range 1–16777216),
and `guard_max_spool_bytes` (67108864, range 1–1073741824). Classifier responses have a fixed 65536-byte cap.

Access logs include `guard_checks`: stage, safeguard ID/name, engine ID/name, upstream model, result
(`allowed`, `rejected`, `error`, or `not_applicable`), classification label/categories/refusal, duration,
error code, and separate `usage` input/output/total tokens. Admin tests use the result `checked`.
`guard:` filters this metadata. `ttft_ms` measures client first data after approval; `upstream_ttft_ms`
retains the generation engine's first-event time. Classifier calls add neither client requests nor tokens
to generation aggregates. Raw rejected output/classifier text is not included in records.

Backup create accepts kind local/portable; portable requires a passphrase. Download is authenticated
and audited; restoration accepts a stored backup or uploaded archive and a passphrase. Restore stages
the validated DB and tells the administrator to restart. Deletion is confirmed in the UI. All archive
names are generated by the server and downloads use attachment disposition.

Safeguard profiles and key policies are included in local and portable backups. Known older snapshots
are authenticated and validated before migration, then revalidated against the current schema.

## Compatibility policy

The gateway supports protocol-native routes and retains unknown JSON extensions without dropping
semantics. A successful HTTP connection is not evidence of full engine capabilities. Discovery uses
model metadata and known engine profiles conservatively; the administrator can correct capabilities.
Version-specific endpoints must be validated against the target engine. `/v1/messages` speaks the native
Anthropic-compatible messages protocol; it is not misrepresented as OpenAI chat completions.
