# Lockwire

E2E-encrypted terminal sharing. `lw share` generates a code; `lw join <code>` gives a read-only live view. The relay is a blind pipe — it forwards opaque AES-256-GCM blobs and never touches key material.

## Working With Me

- **Never assume — verify.** Check the code, search the web, or ask the user. Do not guess at behavior, API surfaces, or library capabilities.
- **Specs are the source of truth.** If asked to implement something not covered by a spec, confirm with the user whether the spec should be updated first. Update the spec, then implement.
- **Challenge directions that seem wrong.** Push back respectfully when something looks incorrect, contradictory, or likely to cause problems. Don't agree just to be agreeable.

## Repository Layout

```
lockwire/
  cmd/
    lw/              # main package — entry point, version var, cobra root cmd
  internal/
    crypto/          # SPAKE2, AES-256-GCM helpers, HKDF epoch key derivation
    session/         # session lifecycle, viewer registry, Stream Key rotation
    relay/           # WebSocket broker — blob forwarding, heartbeat, web viewer
    pty/             # terminal capture (wraps creack/pty)
    protocol/        # wire message types, framing constants, Session ID derivation
    ipc/             # Unix socket control server/client (lw revoke, lw list)
  web/
    src/             # TypeScript source
    index.html
    tsconfig.json
    package.json
  specs/             # behavioral specs (source of truth)
  skills/            # Claude Code skills
  workflows/         # development workflows
  scripts/
    pre-commit       # installed as .git/hooks/pre-commit via make setup
  Makefile
  AGENTS.md
  go.mod
  .golangci.yml
```

Organize by domain, not by layer. No `pkg/utils`, no `internal/helpers`. One concern per package.

## Setup

```bash
make setup     # installs pre-commit hook, downloads tools
make build     # build lw binary for current platform
make test      # full test suite with race detector
make lint      # golangci-lint + tsc --noEmit
make web       # build TypeScript web viewer into web/dist/
make build-all # cross-compile all release targets into dist/
```

## Build and Version Stamping

Version is derived from git at build time — no hand-edited version files:

```bash
# Injected via ldflags in Makefile
VERSION := $(shell git describe --tags --always --dirty)
# e.g. v1.0.0, v1.0.0-5-gabcdef, v1.0.0-dirty

go build -ldflags "-X main.version=$(VERSION) -w -s" -o lw ./cmd/lw
```

- Tag format: `vMAJOR.MINOR.PATCH` (e.g. `v1.2.0`)
- `lw --version` prints `lw v1.2.0` (or `lw v1.2.0-5-gabcdef` on untagged commits)
- Release builds must be tagged and clean (`-dirty` suffix must not appear in a release)
- `CGO_ENABLED=0` on all targets — pure Go, no libc dependency

Release targets: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`.

## Pre-Commit Hook

Installed by `make setup`. Fast gate — runs on every commit:

```bash
go vet ./...               # compiler-level checks
golangci-lint run --fast   # subset of linters (< 10s)
go build ./...             # catches compilation errors across all packages
cd web && tsc --noEmit     # TypeScript type check, no output
```

Full test suite (`go test -race ./...`) runs on pre-push, not pre-commit.

## Architecture

- CLI (`lw`) and relay (`lw relay`) are a single Go binary.
- Web viewer is TypeScript served by the relay over HTTPS.
- **Correctness over cleverness.** Simple, readable code. Remove dead code. No premature abstractions.

## Security Invariants

These must never be violated — no exceptions, no shortcuts:

- **Key material is never logged.** Stream Key, epoch keys, per-viewer SPAKE2 session keys (K_auth_i) must not appear in any log, error message, or panic output — not even truncated.
- **Key material is never written to disk.** No swap, no temp files, no crash dumps knowingly containing keys.
- **Sensitive allocations are mlocked.** Use `golang.org/x/sys/unix.Mlock` for byte slices holding K, K_auth_i, and derived epoch keys where the OS permits. Fail open (log a warning) if mlock is unavailable rather than aborting.
- **Zeroing before release.** All key material byte slices are overwritten with zeros before being released or going out of scope. Use a named `zeroBytes(b []byte)` helper — never rely on GC to handle this.
- **Nonce monotonicity.** The 96-bit nonce counter for AES-256-GCM is global to the session and increments by 1 per frame. It does **not** reset on epoch rotation or Stream Key rotation (K → K'). A new (key, nonce) pair must never repeat.
- **The relay is blind.** Relay code (`internal/relay`) must not import `internal/crypto` or touch any type that carries key material. If a reviewer sees key material flowing into the relay package, that is a bug.
- **AES-256-GCM, not ChaCha20.** This was an explicit decision for WebCrypto API compatibility. Do not switch ciphers without updating the spec and AGENTS.md.
- **HKDF info strings must match the spec exactly.** Use the constants in `internal/protocol`:
  - Session ID: `HMAC-SHA256(K, "lw-session-id")`
  - Epoch key: `HKDF-SHA256(K, info="lw-epoch-{n}")`
  - SPAKE2 associated data: `"lockwire-v1"`
- **Forward secrecy scope.** Lockwire provides inter-session FS (fresh K per session). Within a session, K is the master secret: all epoch keys are derivable from K. This is intentional (simpler architecture, Viewers derive epoch keys independently). Do not implement a ratchet without a spec change.
- **K_auth_i lifetime.** The per-viewer SPAKE2 session key for each Viewer must survive in memory for the full session — it is needed to deliver K' during revocation. Do not discard it after the initial key handshake.

## Testing

- **Fakes, not mocks.** Test doubles must be behavioral fakes. No `gomock`, no `testify/mock`.
- Tests verify behavior, not implementation details.
- If the tests pass but `lw share` crashes, the tests did not do their job.
- Crypto tests must use known-answer vectors where they exist (NIST test vectors for AES-GCM, RFC vectors for HKDF).
- Concurrency: any package that spawns goroutines must have at least one test run under `-race`.

### Running Tests

```bash
go test ./...                    # full suite
go test -race ./...              # with race detector (required before concurrency commits)
go test -run TestFoo ./...       # single test
go test -v ./internal/crypto/... # single package, verbose
```

## Go Standards

- **Error wrapping everywhere.** `fmt.Errorf("context: %w", err)` — never discard errors, never return bare strings as errors.
- **No magic strings.** All protocol constants (message type bytes, HKDF info strings, domain separators, socket paths) live in `internal/protocol/constants.go`. Never inline them.
- **Explicit over implicit.** No `init()` with side effects. No package-level mutable state.
- **`go vet` and `golangci-lint` must pass** before any commit.
- Use `golang.org/x/crypto` for SPAKE2, HKDF — do not implement these primitives.
- Use `github.com/creack/pty` for PTY capture.
- Use `github.com/gorilla/websocket` or `nhooyr.io/websocket` for WebSocket — decide at implementation time, document in go.mod.

## TypeScript Standards (web viewer)

- **Strict mode.** `"strict": true` in `tsconfig.json`. No `any`, no `as unknown`.
- No framework. Vanilla TypeScript + xterm.js + WebCrypto API.
- All crypto operations go through `crypto.subtle` — no third-party crypto libraries.
- SPAKE2 must be interoperable with the Go implementation: same group, same M/N points, same associated data string (`"lockwire-v1"`).

## Specs

- Specs live in `specs/` and define desired state using RFC 2119 language (`SHALL`, `MUST`, `SHOULD`, `MAY`).
- Specs describe observable behavior, not implementation. See `specs/index.spec.md` for format and domain vocabulary.
