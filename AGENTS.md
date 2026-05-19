# Lockwire

E2E-encrypted terminal sharing. `lw share` generates a code; `lw join <code>` gives a read-only live view. The relay is a blind pipe — it forwards opaque AES-256-GCM blobs and never touches key material.

## Working With Me

- **Never assume — verify.** Check the code, search the web, or ask the user. Do not guess at behavior, API surfaces, or library capabilities.
- **Specs are the source of truth.** If asked to implement something not covered by a spec, confirm with the user whether the spec should be updated first. Update the spec, then implement.
- **Challenge directions that seem wrong.** Push back respectfully when something looks incorrect, contradictory, or likely to cause problems. Don't agree just to be agreeable.

## Architecture

- CLI (`lw`) and relay (`lw relay`) are a single Go binary.
- Web viewer is TypeScript served by the relay over HTTPS.
- Organize by domain, not by layer. No `pkg/utils`, no `internal/helpers`.
- **Correctness over cleverness.** Simple, readable code. Remove dead code. No premature abstractions.

## Security Invariants

These must never be violated — no exceptions, no shortcuts:

- Key material (Stream Key, epoch keys, per-viewer SPAKE2 keys) is never written to disk, never logged, never included in error messages.
- All sensitive allocations must be zeroed before release.
- Use `golang.org/x/sys/unix.Mlock` for sensitive byte slices where the OS permits.
- The relay receives no key material. If relay code touches a key, that is a bug.
- Nonces are strictly monotonically increasing and never reset within a (key, session) pair.

## Testing

- **Fakes, not mocks.** Test doubles must be behavioral fakes. No `gomock`, no `testify/mock`.
- Tests verify behavior, not implementation details.
- If the tests pass but `lw share` crashes, the tests did not do their job.
- Crypto tests must use known-answer vectors where they exist.

### Running Tests

```bash
go test ./...              # full suite
go test ./... -run TestFoo # single test
go test -race ./...        # race detector (run before any commit touching concurrency)
```

## Development Workflow

- Invoke the `/develop` skill. This will provide you with a verifiable unit of work tied to a spec that you are to complete.

## Go Standards

- **Error wrapping everywhere.** `fmt.Errorf("context: %w", err)` — never discard errors, never return bare strings.
- **No magic strings.** All protocol constants (message type bytes, HKDF info strings, domain separators) live in a `const` block, never inline.
- **Explicit over implicit.** No `init()` functions with side effects. No global mutable state.
- **`go vet` and `staticcheck` must pass** before any commit.
- Use `golang.org/x/crypto` for SPAKE2, HKDF, and related primitives — do not roll your own.

## TypeScript Standards (web viewer)

- **Strict mode.** `"strict": true` in `tsconfig.json`. No `any`.
- No framework. Vanilla TypeScript + xterm.js + WebCrypto API.
- All crypto operations go through `crypto.subtle` — no third-party crypto libraries.

## Specs

- Specs live in `specs/` and define desired state using RFC 2119 language (`SHALL`, `MUST`, `SHOULD`, `MAY`).
- Specs describe observable behavior, not implementation. See `specs/index.spec.md` for format and domain vocabulary.
