# CLI Commands Specification

## Purpose

Lockwire is distributed as a single static binary, `lw`. It exposes subcommands: `share`, `join`, `revoke`, `list`, and `help`. The CLI is the primary user-facing surface. All cryptographic operations happen in-process. The UX must require zero configuration for the common case.

`lw revoke` and `lw list` communicate with a running `lw share` process via a Unix domain socket at `$TMPDIR/lw-<pid>.sock`. The Sharer's process creates and listens on this socket at startup; control commands locate it via a PID file at `$TMPDIR/lw.pid`.

## Requirements

### Requirement: Zero Configuration Default

The system SHALL work with no configuration file, environment variable, or flag for the common case of sharing and joining over the public relay.

#### Scenario: First-time user shares
- GIVEN a user has installed `lw` and never configured it
- WHEN they run `lw share`
- THEN a session begins using the default public relay (`wss://relay.lockwire.io`)
- AND a Code and watch link are printed to stdout

---

### Requirement: `lw share`

The system SHALL start a terminal sharing session, print the Code and watch URL, and stream the current terminal to the relay until the process exits.

#### Scenario: Share starts and prints Code
- GIVEN a user runs `lw share`
- WHEN the session is established
- THEN exactly two lines are printed to stdout:
  ```
  code: thunder-eagle-river-moon-stone-fire
  link: https://relay.lockwire.io/join#thunder-eagle-river-moon-stone-fire
  ```
- AND subsequent output is the Sharer's normal terminal (no additional cli output)

#### Scenario: Share with custom relay
- GIVEN a user runs `lw share --relay wss://relay.example.com`
- WHEN the session is established
- THEN the session uses the specified relay
- AND the printed link reflects the custom relay host

#### Scenario: Share fails to connect
- GIVEN the relay is unreachable
- WHEN a user runs `lw share`
- THEN the process exits with status 1
- AND a human-readable error is printed to stderr
- AND nothing is printed to stdout

#### Scenario: Concurrent `lw share` processes
- GIVEN a `lw share` process is already running on this machine (PID file exists and process is alive)
- WHEN a second `lw share` is run
- THEN the second process prints `error: a session is already active (pid <N>). Run 'lw list' to see viewers.` to stderr
- AND exits with status 1

---

### Requirement: `lw join <code>`

The system SHALL connect to an active session identified by the Code, show a connecting indicator, complete the SPAKE2 handshake, and render the Sharer's terminal in the Viewer's terminal in real-time, read-only.

**Code normalization:** `lw join` SHALL accept the Code in any of the following equivalent forms and normalize before lookup:
- `thunder-eagle-river-moon-stone-fire` (canonical)
- `thunder eagle river moon stone fire` (spaces)
- `Thunder-Eagle-River-Moon-Stone-Fire` (mixed case)
- Any combination of the above

#### Scenario: Successful join
- GIVEN a session is active for the Code
- WHEN a user runs `lw join thunder-eagle-river-moon-stone-fire`
- THEN `connecting…` is displayed, then replaced by the Sharer's terminal upon stream start
- AND the user cannot send keystrokes to the Sharer's session

#### Scenario: Session ends while Viewer is watching (clean)
- GIVEN a Viewer is watching an active session
- WHEN the Sharer terminates the session cleanly
- THEN the Viewer's terminal prints `session ended by sharer` on a new line and the process exits with status 0

#### Scenario: Session ends while Viewer is watching (connection lost)
- GIVEN a Viewer is watching an active session
- WHEN the Sharer's connection to the relay drops
- THEN the Viewer's terminal prints `session lost (connection dropped)` and the process exits with status 1

#### Scenario: Join with custom relay
- GIVEN a user runs `lw join <code> --relay wss://relay.example.com`
- WHEN the session is established
- THEN the session connects to the specified relay

---

### Requirement: `lw list`

The system SHALL display currently connected Viewers for the active local session.

#### Scenario: List viewers
- GIVEN a session is active with one CLI viewer and one browser viewer
- WHEN the Sharer runs `lw list`
- THEN stdout contains one row per viewer: `<viewer-id>  <cli|browser>  joined <N>m ago`

#### Scenario: No session active
- GIVEN no `lw share` process is running
- WHEN a user runs `lw list`
- THEN the process exits with status 1
- AND `error: no active session` is printed to stderr

---

### Requirement: `lw revoke <viewer-id>`

The system SHALL revoke a specific Viewer's access from the active local session via the control socket.

#### Scenario: Revoke by Viewer ID
- GIVEN a session is active and Viewer A has ID `a3k9x7`
- WHEN the Sharer runs `lw revoke a3k9x7`
- THEN the command sends a revoke request to the `lw share` process via Unix socket
- AND `revoked a3k9x7` is printed to stdout on success
- AND the `lw share` process initiates Stream Key rotation

#### Scenario: Revoke unknown ID
- GIVEN a session is active
- WHEN the Sharer runs `lw revoke unknown-id`
- THEN the process exits with status 1
- AND `error: viewer not found` is printed to stderr

#### Scenario: No session active
- GIVEN no `lw share` process is running
- WHEN a user runs `lw revoke <id>`
- THEN the process exits with status 1
- AND `error: no active session` is printed to stderr

---

### Requirement: `--relay` Flag

The `--relay` flag SHALL accept a WebSocket URL with the following constraints:
- Scheme MUST be `wss://` (TLS required); `ws://` SHALL be rejected with an error
- A path component is allowed (e.g. `wss://host/lockwire`)
- Self-signed TLS certificates SHALL be rejected by default; `--relay-insecure` MAY be used to override for development

#### Scenario: Non-TLS relay rejected
- GIVEN a user runs `lw share --relay ws://localhost:8080`
- WHEN the flag is parsed
- THEN the process exits with status 1
- AND `error: relay URL must use wss:// (TLS required)` is printed to stderr

---

### Requirement: Global Flags and Help

The binary SHALL support:
- `lw --version` → prints `tv <semver>` to stdout
- `lw --help` or `lw help` → prints usage summary to stdout
- `lw <subcommand> --help` → prints subcommand-specific help

#### Scenario: Version flag
- GIVEN a user runs `lw --version`
- THEN stdout contains `lw 1.0.0` (or current version)
- AND the process exits with status 0

---

### Requirement: Binary Distribution

The `lw` binary SHALL be a single statically linked executable with no runtime dependencies, buildable for Linux (amd64, arm64) and macOS (amd64, arm64).

#### Scenario: Install and run
- GIVEN a user downloads the `lw` binary for their platform
- WHEN they run `lw share`
- THEN the command runs without installing any additional runtime, daemon, or dependency
