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
17 MiB and `otool -L` shows only macOS libSystem, libresolv, CoreFoundation and Security.framework.
Node is not a build or runtime dependency of the gateway.

The macOS test listing contains 120 top-level tests, including one opt-in browser preview that skips
normally. Table-driven subtests exercise additional cases. No TODO/stub implementation was left for a
requested feature.

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
