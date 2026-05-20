# Session Lifecycle Specification

## Purpose

A Session is the core unit of Lockwire. It represents a live terminal sharing instance initiated by a Sharer and observed by zero or more Viewers. Sessions are ephemeral: they exist only while the Sharer's process is running. All cryptographic material is held in memory and zeroed on termination. Viewers may join via the CLI (`lw join <code>`) or via a browser link (`https://<relay>/join#<code>`); both paths produce an identical read-only live view.

## Requirements

### Requirement: Session Creation

The system SHALL create a new Session when the Sharer runs `lw share`, connecting to the relay and printing the Code and watch URL to stdout before any terminal output is captured or transmitted.

#### Scenario: Successful session creation
- GIVEN a user runs `lw share`
- WHEN the relay connection is established and the Session is registered
- THEN two lines are printed to stdout:
  ```
  code: thunder-eagle-river-moon-stone-fire
  link: https://relay.lockwire.io/join#thunder-eagle-river-moon-stone-fire
  ```
- AND the Sharer's terminal output (pty) is captured and streamed from that point forward

#### Scenario: Relay unavailable
- GIVEN a user runs `lw share`
- WHEN the relay cannot be reached within 5 seconds
- THEN the process exits with status 1
- AND an actionable error is printed to stderr (e.g. `error: could not reach relay at wss://relay.lockwire.io — check your connection`)
- AND nothing is printed to stdout

#### Scenario: Session ID does not reveal the Code
- GIVEN a Session is registered on the relay
- WHEN the relay's session table is inspected
- THEN the Code does not appear in any field
- AND the Session ID is `Argon2id(code_bytes, salt="lockwire-session-id-v1", m=65536, t=1, p=1, len=16)` hex-encoded

---

### Requirement: Session Joining (CLI)

The system SHALL allow a Viewer to join an active Session by running `lw join <code>`, showing a connecting indicator, completing a SPAKE2 handshake with the Sharer, and rendering the Sharer's terminal read-only in the Viewer's terminal.

#### Scenario: Connecting state
- GIVEN a user runs `lw join thunder-eagle-river-moon-stone-fire`
- WHEN the relay connection is being established and SPAKE2 is in progress
- THEN a single line is displayed: `connecting…`
- AND this line is cleared and replaced by the Sharer's terminal once the stream begins

#### Scenario: Successful join
- GIVEN a Session is active for Code `thunder-eagle-river-moon-stone-fire`
- WHEN a Viewer runs `lw join thunder-eagle-river-moon-stone-fire` and the SPAKE2 handshake succeeds
- THEN the Viewer's terminal mirrors the Sharer's terminal in real-time
- AND the Viewer cannot send input to the Sharer's terminal
- AND the Viewer's terminal is resized to match the Sharer's pty dimensions

#### Scenario: Code not found
- GIVEN no active Session exists for the given Code
- WHEN a Viewer runs `lw join <code>`
- THEN the process exits with status 1
- AND `error: session not found` is printed to stderr

#### Scenario: Join times out during handshake
- GIVEN a Session exists but the Sharer's process is unresponsive
- WHEN the SPAKE2 handshake does not complete within 15 seconds
- THEN the process exits with status 1
- AND `error: handshake timed out` is printed to stderr

#### Scenario: Multiple Viewers join simultaneously
- GIVEN a Session is active
- WHEN two Viewers run `lw join <code>` concurrently
- THEN both complete independent SPAKE2 handshakes with the Sharer
- AND both receive the stream independently
- AND neither Viewer's join affects the other's

---

### Requirement: Session Joining (Web Browser)

The system SHALL allow a Viewer to join an active Session via a browser by navigating to `https://<relay-host>/join#<code>`, entering the Code if not pre-filled, and viewing the Sharer's terminal rendered in xterm.js. The cryptographic operations (SPAKE2, AES-256-GCM) SHALL execute in the browser using the WebCrypto API.

#### Scenario: Browser join via URL
- GIVEN a user opens `https://relay.lockwire.io/join#thunder-eagle-river-moon-stone-fire`
- WHEN the page loads
- THEN the Code is pre-populated in the input field
- AND the user clicks "Watch"
- AND SPAKE2 executes in the browser
- AND on success, the terminal renders in an xterm.js instance

#### Scenario: Browser join via manual code entry
- GIVEN a user opens `https://relay.lockwire.io`
- WHEN the user types the Code into the input field and clicks "Watch"
- THEN the behavior is identical to the URL-based flow

#### Scenario: Browser cannot modify Sharer terminal
- GIVEN a browser Viewer is watching a session
- WHEN the Viewer types in the xterm.js window
- THEN no input is transmitted to the Sharer's terminal

---

### Requirement: Terminal Size Propagation

The Sharer's pty dimensions (columns and rows) SHALL be transmitted to all Viewers when they join and whenever the Sharer resizes their terminal. Viewers SHALL resize their display to match. If a Viewer's terminal is physically smaller than the Sharer's, the Viewer's client SHALL display what fits and scroll, rather than refusing to connect.

#### Scenario: Viewer terminal smaller than Sharer's
- GIVEN the Sharer's terminal is 220 columns × 50 rows
- AND a Viewer's terminal is 80 columns × 24 rows
- WHEN the Viewer joins
- THEN the Viewer's client renders the top-left 80×24 portion of the Sharer's output
- AND displays a notice: `[terminal too small — sharer: 220×50, you: 80×24]`

#### Scenario: Sharer resizes terminal mid-session
- GIVEN a Viewer is watching
- WHEN the Sharer resizes their terminal from 200×50 to 120×40
- THEN all Viewers receive the new dimensions and re-render accordingly

---

### Requirement: Session Termination

The system SHALL terminate the Session when the Sharer's process exits, immediately notifying the relay and disconnecting all Viewers. The reason for termination SHALL be communicated to Viewers.

#### Scenario: Sharer exits cleanly
- GIVEN a Session has two active Viewers
- WHEN the Sharer presses Ctrl+C or the shell exits naturally
- THEN all cryptographic material is zeroed before process exit
- AND both Viewers' processes print `session ended by sharer` and exit with status 0 within 2 seconds

#### Scenario: Sharer process killed (SIGKILL)
- GIVEN a Session is active
- WHEN the Sharer's process is killed
- THEN the relay detects the timeout (≤ 10 seconds)
- AND Viewers receive `session lost (connection dropped)` and exit with status 1

---

### Requirement: Viewer Listing

The system SHALL allow the Sharer to list currently connected Viewers at any time by running `lw list`. The list SHALL include each Viewer's ID, join time, and client type (CLI or browser).

#### Scenario: List active viewers
- GIVEN a Session has Viewers A (CLI, ID `a3k9x7`) and B (browser, ID `m2p4n8`)
- WHEN the Sharer runs `lw list`
- THEN stdout contains:
  ```
  a3k9x7  cli      joined 3m ago
  m2p4n8  browser  joined 1m ago
  ```

#### Scenario: No active viewers
- GIVEN a Session has no connected Viewers
- WHEN the Sharer runs `lw list`
- THEN stdout contains `no viewers connected`

---

### Requirement: Viewer Revocation

The system SHALL allow the Sharer to revoke an individual Viewer's access without terminating the Session or interrupting other Viewers. A revoked Viewer SHALL lose the ability to decrypt new frames within one epoch interval (≤ 60 seconds).

#### Scenario: Revoke one Viewer
- GIVEN a Session has Viewers A and B
- WHEN the Sharer runs `lw revoke a3k9x7`
- THEN Viewer A's terminal stops updating within one epoch interval
- AND Viewer B continues receiving the stream uninterrupted
- AND `revoked a3k9x7` is printed to stdout

#### Scenario: Revoked Viewer sees a disconnect message
- GIVEN Viewer A is being revoked
- WHEN the Stream Key rotation completes and Viewer A can no longer decrypt
- THEN Viewer A's client detects sustained decryption failure and prints `access revoked` before exiting

#### Scenario: Revoke unknown Viewer ID
- GIVEN a session is active
- WHEN the Sharer runs `lw revoke unknown-id`
- THEN the process exits with status 1
- AND `error: viewer not found` is printed to stderr

#### Scenario: Revoked Viewer attempts rejoin with same Code
- GIVEN Viewer A has been revoked
- WHEN Viewer A runs `lw join <same-code>` again and completes SPAKE2
- THEN Viewer A receives a new Viewer ID
- AND the Sharer sees the standard `viewer joined: <new-id> (cli)` notification
- AND the system does not distinguish the rejoin from a new Viewer joining; the Code remains valid for all parties who know it
- AND the Sharer must explicitly run `lw revoke <new-id>` again to block them; re-joining is not auto-blocked

> **Design note:** The relay is a blind pipe and cannot correlate connections to previously-revoked Viewers. SPAKE2 produces unique session keys per handshake, so derived auth keys provide no linkage. To permanently block a Viewer, the Sharer must terminate the session and create a new one with a fresh Code.

#### Scenario: Viewer join notification
- GIVEN a session is active
- WHEN Viewer A joins successfully
- THEN a line is printed on the Sharer's terminal: `viewer joined: a3k9x7 (cli)`
- AND when Viewer A disconnects: `viewer left: a3k9x7`
