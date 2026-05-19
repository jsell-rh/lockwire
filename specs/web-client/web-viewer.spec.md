# Web Viewer Specification

## Purpose

The Lockwire web viewer allows a Viewer to watch a shared session in any modern browser without installing the `lw` binary. The web viewer is served by the relay at `https://<relay-host>/join/<code>` and performs all cryptographic operations (SPAKE2, AES-256-GCM) natively in the browser using the WebCrypto API. Terminal output is rendered in an xterm.js instance. The web viewer is read-only and cryptographically equivalent to the CLI Viewer.

## Requirements

### Requirement: No Installation Required

The web viewer SHALL function in any modern browser (Chrome ≥ 111, Firefox ≥ 113, Safari ≥ 16.4) without plugins, extensions, or WASM downloads. All cryptographic primitives SHALL be sourced from the browser's native WebCrypto API.

#### Scenario: First-time browser viewer
- GIVEN a user receives the link `https://relay.lockwire.io/join/thunder-eagle-river-moon-stone-fire`
- WHEN they open it in a supported browser
- THEN the page loads fully (HTML + JS) in under 2 seconds on a typical connection
- AND no plugin prompt, install prompt, or download appears

---

### Requirement: Code Pre-fill from URL

The web viewer SHALL extract the Code from the URL path and pre-populate the code input field. The user SHALL be able to edit the pre-filled code before initiating the session.

#### Scenario: Code in URL
- GIVEN the URL is `https://relay.lockwire.io/join/thunder-eagle-river-moon-stone-fire`
- WHEN the page loads
- THEN the code input field contains `thunder-eagle-river-moon-stone-fire`
- AND a "Watch" button is available

#### Scenario: No code in URL
- GIVEN the URL is `https://relay.lockwire.io`
- WHEN the page loads
- THEN the code input field is empty
- AND the user must type the Code before clicking "Watch"

---

### Requirement: In-Browser SPAKE2 Handshake

The web viewer SHALL perform SPAKE2 key exchange using WebCrypto primitives. The SPAKE2 parameters, role assignment, and associated data SHALL be identical to the CLI implementation so that a browser Viewer and a CLI Sharer are interoperable.

#### Scenario: Browser completes SPAKE2 with CLI Sharer
- GIVEN a `lw share` session is active
- WHEN a browser Viewer clicks "Watch" with the correct Code
- THEN SPAKE2 completes successfully
- AND the browser receives the Stream Key K
- AND the terminal begins rendering

#### Scenario: Wrong Code in browser
- GIVEN a session is active
- WHEN a browser Viewer enters an incorrect Code and clicks "Watch"
- THEN the browser displays `incorrect code — session not found` inline (no page reload)

---

### Requirement: Stream Decryption via WebCrypto

The web viewer SHALL decrypt incoming stream frames using AES-256-GCM via the browser's native `SubtleCrypto` API (`crypto.subtle.decrypt`). Epoch key derivation SHALL use `crypto.subtle.deriveBits` with HKDF-SHA256 with the same parameters as the CLI.

#### Scenario: Frame decrypted in browser
- GIVEN the browser holds Stream Key K and the current epoch is n
- WHEN a stream blob arrives from the relay WebSocket
- THEN the browser derives K_n via HKDF-SHA256(K, info="lw-epoch-n")
- AND decrypts the frame via `crypto.subtle.decrypt({name: "AES-GCM", iv: nonce, tagLength: 128}, K_n, ciphertext)`
- AND feeds the plaintext terminal data to xterm.js

#### Scenario: Tampered frame in browser
- GIVEN an in-transit frame is modified
- WHEN the browser attempts decryption
- THEN WebCrypto throws a DOMException (OperationError) and the frame is silently discarded

---

### Requirement: Terminal Rendering

The web viewer SHALL render the Sharer's terminal using xterm.js, supporting the full VT100/xterm escape sequence set including colors, cursor movement, and Unicode.

#### Scenario: Color and cursor rendering
- GIVEN the Sharer's terminal displays colored output (e.g. `ls --color`)
- WHEN the frame is rendered in the browser
- THEN colors and formatting match what the Sharer sees

#### Scenario: Sharer resizes terminal
- GIVEN a browser Viewer is watching
- WHEN the Sharer resizes their terminal
- THEN the xterm.js instance resizes to match the new dimensions within one frame

#### Scenario: Browser window too small
- GIVEN the Sharer's terminal is 220×50 and the browser viewport can only render 80×24
- WHEN the Viewer loads the page
- THEN the xterm.js instance scrolls/clips and a banner displays the size mismatch
- AND the Viewer can scroll to see clipped content

---

### Requirement: Read-Only Enforcement

The web viewer SHALL not transmit any keyboard input to the Sharer's terminal. The xterm.js instance SHALL be configured in read-only mode.

#### Scenario: Viewer types in browser terminal
- GIVEN a browser Viewer is watching a session
- WHEN the Viewer types in the xterm.js window
- THEN no data is sent to the relay or to the Sharer
- AND the typed characters do not appear in the xterm.js display

---

### Requirement: Connection State Display

The web viewer SHALL display connection state clearly throughout the session lifecycle.

#### Scenario: Connection states
| State | Display |
|-------|---------|
| Pre-join | Code input + "Watch" button |
| Connecting / SPAKE2 in progress | Spinner + "Connecting…" |
| Active session | Full-screen xterm.js |
| Session ended cleanly | Overlay: "Session ended by sharer" |
| Connection lost | Overlay: "Session lost (connection dropped)" |
| Access revoked | Overlay: "Access revoked" |

---

### Requirement: No Persistent State

The web viewer SHALL store no session data, keys, or codes in browser storage (localStorage, sessionStorage, IndexedDB, or cookies). All cryptographic material exists only in JavaScript memory and is garbage-collected when the tab is closed.

#### Scenario: Tab closed and reopened
- GIVEN a Viewer closes the browser tab during an active session
- WHEN they reopen the relay URL
- THEN no previous session state is restored
- AND they must re-enter the Code and rejoin
