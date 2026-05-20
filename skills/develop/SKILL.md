---
name: develop
description: >
  Retrieve a verifiable unit of work, derived from a spec, to implement.
  Use when the user wants to continue the development of the system.
---

Follow the workflow phases in order.

## Steps

### Phase 1 — Retrieve Unit of Work

Spawn a subagent with instructions found verbatim in <repo_root>/workflows/development/next-unit-of-work.workflow.md.

### Phase 2 — Execute the Unit of Work

Read actual code and existing specs in the affected areas. Confirm your understanding without wasting the user's time.

Proceed with test-driven development. Tests should share reusable components where possible,
use fakes instead of mocks, and test real behavior. If the tests pass but the software crashes,
the tests did not do their job.

Use atomic, conventional commits.

Follow implementation guidelines found in AGENTS.md.

### Phase 4 — Critic Pass

Spawn critics in parallel to review the implementation:

**Standard critics (every unit of work):**

- **Security invariants** — verify each of the invariants in AGENTS.md § Security Invariants:
  - No key material in logs, errors, or panic output
  - zeroBytes() called on all key slices before release
  - Nonce counter never resets within a (key, session) pair
  - Relay package does not import internal/crypto or handle key types
  - HKDF info strings match the constants in internal/protocol exactly
  - K_auth_i is retained for the session lifetime (not discarded post-handshake)
  - AES-256-GCM used — no ChaCha20 or other cipher
- **Protocol correctness** — message framing matches the type-byte table in the relay spec; Session ID derived correctly
- **Consistency and style** — no magic strings (all constants in internal/protocol), error wrapping with %w, no global mutable state
- **Test coverage** — fakes not mocks, known-answer vectors for crypto, race detector exercised for concurrent code
- **Smoke test** — run the actual binary from the command line. Tests verify code correctness; this critic verifies the software works when a user runs it.

**Work-driven critics (add based on scope):**
- If touching crypto: verify SPAKE2 parameters (role A/B, associated data "lockwire-v1"), AES-GCM tag length (128-bit), HKDF output length (32 bytes)
- If touching relay: verify relay package has no access to key material; verify fan-out ordering; verify unicast routing by Viewer ID
- If touching web viewer: verify WebCrypto API usage (crypto.subtle only), strict TypeScript, SPAKE2 interop with Go implementation
- If touching IPC: verify Unix socket path from constants, not hardcoded

### Phase 5–6 — Synthesize and Present

Separate findings into factual errors (fix directly) and design decisions (present to user with 2–3 concrete options each, one at a time).

### Phase 7 — Apply and Verify

Apply all fixes. Run a second critic pass (Phase 8). Stop when only MINORs remain.

### Phase 8 -- Proceed to Next Loop Iteration 

Run `kill $PPID`. You're running in a loop that requires
killing the current process to hand over control back to the loop
orchestrator. This is safe, just a sigterm. 
