# Verification record

Environment: macOS Apple Silicon (`darwin/arm64`), Go 1.27.1, Apple Command Line Tools.
The Go toolchain was installed from an official archive after SHA-256 verification.
The commands below assume `go` is available in PATH.

## Commands verified

```sh
sh scripts/check.sh             # gofmt, go vet ./..., go test ./...
go test -race ./...
go test -cover ./...
go build -trimpath -o bin/llmgw ./cmd/llmgw
file bin/llmgw                  # Mach-O 64-bit executable arm64
bin/llmgw version               # llmgw 0.1.0
node --check web/static/app.js  # development-only syntax validation
go run golang.org/x/vuln/cmd/govulncheck@latest -show verbose ./...
```

The standard test suite and race detector pass. Vet reports no issues. The binary is approximately
18 MiB and `otool -L` shows only macOS libSystem, libresolv, CoreFoundation and Security.framework.
Node is not a build or runtime dependency of the gateway.

The initial implementation and CORS verification listed 120 top-level tests, including one opt-in browser
preview that skips normally. Safeguard coverage was subsequently added as described below. Table-driven
subtests exercise additional cases.

Govulncheck found no affected symbols or imported packages. It noted GO-2026-5932 in the unused
`golang.org/x/crypto/openpgp` package at module level; the gateway imports Argon2, not OpenPGP.

## Behavioral coverage

| Area | Verified behavior |
|---|---|
| ACL | no ACL, IP-only, key-only, AND, invalid IP, CIDR, IPv6, mapped IPv4, unknown Bearer, disabled key, forwarding-header spoofing |
| Models | aliases, duplicate rejection, hidden/unavailable rejection, restricted listing, discovery absence/reappearance, preserved policy |
| Protocols | all six POST routes with Mock Engine, model/credential rewrite isolation, malformed JSON, unsupported endpoints/capabilities, upstream 500 and timeouts |
| CORS | any Origin including null, preflight without DB/auth, requested SDK headers, readable errors/request ID, unchanged model ACL/filtering, early SSE headers, no CORS on admin/setup/health |
| Streaming | early flush, cancellation, usage/TTFT, truncation, started-stream failures, nested Responses/Messages usage, final zero corrections, BOM/CR/LF/CRLF framing |
| Admin | localhost setup, concurrent first setup, login/logout/session rotation, stale password check, password revocation, CSRF/origin, CRUD, secret reveal audit |
| Crypto | Argon2id, random API keys, AES-GCM round trip, tampering, wrong master/AAD, Keychain backend failures/canonical path isolation |
| Logs | JSONL, 0600 permissions, gzip rotation, generation changes, binary redaction, bounded queue/flush/shutdown, usage/daily aggregation, retained history |
| Backups | WAL snapshot, retention, passphrase/tampering rejection, destination-key rewrap, session removal, schema validation, path traversal/symlinks, rollback, corrupt DB preservation, durable restore audit |
| Lifecycle | graceful and forced stream shutdown, live listener replacement, failure rollback, retired-listener cleanup, immediate health-interval updates |
| CLI / service | command validation, stdin secrets, renamed portable archives, damaged-DB restoration, exclusive lock, XML escaping and macOS plutil validation |

Package-local statement coverage ranges with the scope of their own tests. Integration tests additionally
exercise dependency packages; `go test -cover` without `-coverpkg` does not attribute that coverage to
the dependency's own package line.

## Administrator UI DOM integration

An isolated development-only happy-dom 20.14.5 harness exercised the actual JavaScript and a disposable
Go Gateway/Mock Engine, without production credentials or Keychain access. All 18 checks passed across
82 administrative HTTP requests, with zero JavaScript runtime/console errors and six confirmation
dialogs exercised. The only HTTP errors were the expected unauthenticated-session 401 and an intentional
incorrect-password 401.

Covered: setup/login/dashboard, all 11 navigation sections, Engine/Model/API Key CRUD, secret reveal,
copy and clearing, reveal audit, key ACL and authorized inference, ACL cancellation/confirmation,
settings, local backup creation, deletion, logout and re-login. No production UI fixes were needed.
The local harness/report are in the ignored `.tools/ui-qa/` directory. This test dependency is not part of
go.mod, the build, or the delivered binary. Temporary test services were stopped afterward.

## Explicit verification limits

- Native Keychain code compiles and links on this Mac. Automated tests use injected backends and do
  not create, read, or change the user's real Keychain credentials.
- LaunchAgent XML passes `/usr/bin/plutil -lint`. No LaunchAgent was installed into the user's account.
- Real LM Studio/oMLX/MLX inference was not run. Protocol and health behavior is verified with local
  httptest servers, and engine capability detection remains conservative and overrideable.
- The supplied Browser connection failed before page navigation with a request-header-policy loading
  error on three attempts. Visual layout and real-browser interaction are therefore not claimed verified.
- Optional `TestBrowserPreview` provides a disposable loopback UI server with a mock engine and an
  injected test key. It skips by default and exits on SIGINT/SIGTERM or after 15 minutes:

  ```sh
  LLMGW_BROWSER_PREVIEW=1 go test ./internal/gateway -run '^TestBrowserPreview$' -v -timeout=16m
  ```

No inference, root service, remote account integration, or production credentials are installed by the tests.

## Safeguards UI and logging verification (2026-09-24)

The safeguard UI/logging changes passed `go test ./internal/logging`, `go test -race ./internal/logging`,
`go vet ./internal/logging`, and `node --check web/static/app.js`. The logging regression test first failed
with missing SQLite guard metadata, then passed after persistence/query support was implemented. It
checks JSONL/SQLite metadata equality, copied nested slices despite caller mutation, separate upstream
and client TTFT, guard-name/verdict/category search, and unchanged normal request/token aggregates.
After all feature changes and security-review fixes were integrated, `sh scripts/check.sh` (gofmt,
`go vet ./...`, `go test ./...`), `go test -race ./...`, the native Apple Silicon build, and JavaScript
syntax validation all passed. The suite lists 170 top-level tests, with the browser preview opt-in.
`file bin/llmgw` reports a Mach-O arm64 executable; the binary reports `llmgw 0.1.0`.

Gateway tests cover all four text-generation protocols, input/output/both/unguarded policies,
input rejection without generation, full output suppression on rejection, Controversial policy,
in-flight configuration snapshots, unavailable/disabled/reappearing guards, timeouts, and CORS.
Network-level SSE tests verify no response starts while output classification is pending, safe replay,
client TTFT including moderation, and realtime delivery with input-only checks. Guard tests include
all choices, history, tools, reasoning, malformed/duplicate labels and JSON, lifecycle-field collisions,
large integer preservation, incomplete/post-terminal events, cancellation, private unlinked spools,
and bounds on text, buffered responses, and classifier replies. Valid usage survives invalid verdicts.
Migration/restore tests cover v1 originals and v2 safeguards for local, portable, and pending restoration,
including rejection of wrong keys and tampered schemas before migration.

Actual embedded JavaScript was run with development-only happy-dom 20.14.5 against a disposable Go
Gateway and Mock Engine. All 14 checks passed across 72 administrative HTTP requests, with zero
JavaScript runtime/console errors. Expected administrative errors were the initial unauthenticated 401
and rejection of deleting a referenced safeguard (409). Two confirmation dialogs were exercised.

The flow covered initial setup, engine discovery, safeguard model suggestion with disabled-by-default
registration, input/output connection tests, live guard-limit settings, creation of a guarded API key,
enable/disable policy preservation, alias/ACL setup, safe inference (200), unsafe input rejection (403),
stored `guard:Unsafe` filtering and detailed classification/token display, referenced-deletion protection,
explicit None assignment clearing, normal inference after clearing, and unreferenced profile deletion.
A separate mocked-HTTP DOM test also verified that a safeguard name containing HTML is displayed as text.

The test used an injected ephemeral master key and temporary database, without real Keychain access or
production credentials. The opt-in preview fixture includes `Qwen3Guard-Gen-mock` to reproduce official
classification shapes. The preview process was stopped with SIGTERM and its Go test exited successfully.
The development-only harness and result are under ignored `.tools/ui-qa/`; Node and happy-dom remain
absent from the production build/runtime dependencies. This DOM exercise does not claim real-browser
visual verification or accuracy of a real safeguard model's classifications.
