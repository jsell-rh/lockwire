# CLI Commands Specification

## Purpose

Lockwire is distributed as a single static binary, `lw`. It exposes subcommands: `share`, `join`, `revoke`, `list`, `relay`, and `help`. The CLI is the primary user-facing surface. All cryptographic operations happen in-process. The UX must require zero configuration for the common case.

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
- AND the Sharer's shell is launched in a PTY occupying the full terminal except the bottom row
- AND a status bar is rendered on the bottom row (see Session Lifecycle § Sharer Status Bar)
- AND the Sharer's terminal experience is otherwise indistinguishable from their normal shell

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
- AND a Warning Amber status bar is rendered on the bottom row (see Session Lifecycle § Viewer Status Bar)
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

### Requirement: `lw stop`

The system SHALL allow the Sharer to terminate the active session by running `lw stop` from any terminal on the same machine. The command communicates with the running `lw share` process via the control socket.

To ensure `lw stop` is always available from within the shared session, `lw share` SHALL prepend the directory containing the `lw` binary to `PATH` in the spawned shell's environment. This way, even if the user installed `lw` in a non-standard location, the command is discoverable inside the shared session.

#### Scenario: Stop active session
- GIVEN a `lw share` process is running
- WHEN the Sharer runs `lw stop`
- THEN the command sends a stop request to the `lw share` process via Unix socket
- AND `session stopped` is printed to stdout
- AND the `lw share` process terminates cleanly (zeroing keys, notifying viewers)

#### Scenario: No session active
- GIVEN no `lw share` process is running
- WHEN a user runs `lw stop`
- THEN the process exits with status 1
- AND `error: no active session` is printed to stderr

---

### Requirement: `--relay` Flag

The `--relay` flag SHALL accept a WebSocket URL with the following constraints:
- Scheme MUST be `wss://` (TLS required); `ws://` SHALL be rejected with an error
- A path component is allowed (e.g. `wss://host/lockwire`)
- Self-signed TLS certificates SHALL be rejected by default; `--relay-insecure` skips TLS certificate chain and hostname verification and MUST be used when connecting to a Relay with a self-signed certificate (the TLS handshake will otherwise fail)

When `--relay-insecure` is active, the binary SHALL print `warning: TLS certificate verification disabled` to stderr before connecting.

#### Scenario: Non-TLS relay rejected
- GIVEN a user runs `lw share --relay ws://localhost:8080`
- WHEN the flag is parsed
- THEN the process exits with status 1
- AND `error: relay URL must use wss:// (TLS required)` is printed to stderr

#### Scenario: `--relay-insecure` warning on share
- GIVEN a user runs `lw share --relay wss://localhost:8443 --relay-insecure`
- WHEN the command starts
- THEN `warning: TLS certificate verification disabled` is printed to stderr before the connection is established
- AND the command proceeds normally

#### Scenario: `--relay-insecure` warning on join
- GIVEN a user runs `lw join <code> --relay wss://localhost:8443 --relay-insecure`
- WHEN the command starts
- THEN `warning: TLS certificate verification disabled` is printed to stderr before the connection is established
- AND the command proceeds normally

---

### Requirement: `lw relay`

When run as `lw relay`, the binary SHALL act as a Relay server, listening on a configurable TCP address over TLS. The Relay SHALL require exactly one TLS certificate configuration: either `--tls-cert` and `--tls-key` together, or `--self-signed`. These two modes are mutually exclusive. The default listen address is `:8443`; this is configurable via `--listen`. The Relay SHALL require TLS 1.2 or later.

When `--self-signed` is specified, the Relay SHALL generate a TLS certificate and private key at startup without requiring any files on disk. The generated certificate SHALL use ECDSA P-256 or RSA-2048, be valid for at least one year, and include SubjectAltNames as follows: if the `--listen` address contains an explicit hostname (e.g., `relay.example.com:8443`), the SAN SHALL cover that hostname; if the listen address has no hostname (e.g., `:8443` or `0.0.0.0:8443`), the SAN SHALL cover `127.0.0.1` and `::1`. This mode is intended for development and self-hosted deployments where a CA-signed certificate is not available. Clients connecting to a Relay using a self-signed certificate MUST use `--relay-insecure`.

#### Scenario: Start Relay with explicit certificate files
- GIVEN a user runs `lw relay --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem`
- WHEN the Relay starts successfully
- THEN the Relay listens on `:8443` (or the address specified by `--listen`)
- AND prints to stderr:
  ```
  relay listening on <addr>
  web viewer at https://<addr>/join
  ```
  where `<addr>` is the resolved bound TCP address as reported by the OS (e.g., `[::]:8443`)
- AND nothing is printed to stdout

#### Scenario: Start Relay with self-signed certificate
- GIVEN a user runs `lw relay --self-signed`
- WHEN the Relay starts successfully
- THEN the Relay generates a TLS certificate and private key at startup
- AND listens on the configured address using that certificate
- AND prints to stderr:
  ```
  relay listening on <addr> (self-signed; use --relay-insecure to connect)
  fingerprint: SHA256:<colon-separated uppercase hex pairs, e.g. AA:BB:CC:...>
  web viewer at https://<addr>/join
  ```
- AND nothing is printed to stdout

#### Scenario: --self-signed conflicts with explicit cert flags
- GIVEN a user runs `lw relay` with `--self-signed` and any of `--tls-cert` or `--tls-key` (any combination)
- WHEN the flags are parsed (conflict detection takes precedence over pair-completeness checking)
- THEN the process exits with status 1
- AND prints `error: --self-signed cannot be used with --tls-cert or --tls-key` to stderr

#### Scenario: No TLS configuration provided
- GIVEN a user runs `lw relay` without any of `--tls-cert`, `--tls-key`, or `--self-signed`
- WHEN the flags are parsed
- THEN the process exits with status 1
- AND prints `error: --tls-cert and --tls-key are required (or use --self-signed)` to stderr

#### Scenario: Only one of --tls-cert / --tls-key provided (without --self-signed)
- GIVEN a user runs `lw relay --tls-cert /path/to/cert.pem` without `--tls-key`, or `--tls-key /path/to/key.pem` without `--tls-cert`, and `--self-signed` is not set
- WHEN the flags are parsed
- THEN the process exits with status 1
- AND prints `error: --tls-cert and --tls-key must be used together` to stderr

#### Scenario: Certificate file unreadable
- GIVEN a user runs `lw relay --tls-cert /nonexistent.pem --tls-key /path/to/key.pem`
- WHEN the Relay attempts to load the certificate
- THEN the process exits with status 1
- AND prints `error: could not load TLS certificate: <os-error>` to stderr
- (where `<os-error>` is the verbatim OS error string, e.g. `open /nonexistent.pem: no such file or directory`)

#### Scenario: Key file unreadable
- GIVEN a user runs `lw relay --tls-cert /path/to/cert.pem --tls-key /nonexistent.key`
- WHEN the Relay attempts to load the key
- THEN the process exits with status 1
- AND prints `error: could not load TLS private key: <os-error>` to stderr

#### Scenario: Listen address unavailable
- GIVEN a user runs `lw relay --self-signed --listen :9000` and port 9000 is already bound, or the operator lacks privilege to bind the requested port
- WHEN the Relay attempts to bind the address
- THEN the process exits with status 1
- AND prints `error: could not listen on <addr>: <os-error>` to stderr

#### Scenario: Graceful shutdown
- GIVEN the Relay is running
- WHEN the process receives SIGTERM or SIGINT
- THEN the Relay stops accepting new connections
- AND waits up to 10 seconds for in-flight connections to close
- AND exits with status 0 without printing any shutdown message

---

### Requirement: Global Flags and Help

The binary SHALL support:
- `lw --version` → prints `lw <semver>` to stdout
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
