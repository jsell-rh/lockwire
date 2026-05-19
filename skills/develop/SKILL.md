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

Proceed with test driven development. Tests should share reusable components where possible,
use fakes instead of mocks, and test real behavior. If the tests pass but the software crashes,
the tests did not do their job.

Use atomic, conventional commits.

Follow implementation guidelines found in AGENTS.md.

### Phase 4 — Critic Pass

Spawn critics in parallel to review the implementation. Standard critics:
- Data shape and wire protocol correctness
- Security review (key material handling, memory zeroing, no secrets in logs)
- Consistency and code style (no magic strings — use constants)
- Test coverage
- Verify actual functionality by running the real binary from the command line, not just via test harnesses. If the work produces a CLI command, run it. Tests verify code correctness — this critic verifies that the software actually works when a user runs it.

Plus work-driven critics based on the scope of the unit of work.

### Phase 5–6 — Synthesize and Present

Separate findings into factual errors (fix directly) and design decisions (present to user with 2–3 concrete options each, one at a time).

### Phase 7 — Apply and Verify

Apply all fixes. Run a second critic pass (Phase 8). Stop when only MINORs remain.
