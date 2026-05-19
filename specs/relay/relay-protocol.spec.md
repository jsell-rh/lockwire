# Relay Protocol Specification

## Purpose

The Relay is a stateless message broker. Its sole function is to route encrypted blobs between a Sharer and the Viewers in a Session, identified by Session ID. The Relay has no knowledge of the Code, the Stream Key, or any cryptographic material. It cannot read, modify, or replay session content in a way that survives AES-256-GCM authentication on the receiving end.

The relay also serves the web viewer application (static HTML/JS) over HTTPS at the same host, enabling browser-based joining.

## Message Framing

All messages on the relay WebSocket connection are binary frames with a 1-byte type prefix:

| Type byte | Direction | Meaning |
|-----------|-----------|---------|
| `0x01` | Viewer → Relay → Sharer | SPAKE2 handshake message (unicast to Sharer) |
| `0x02` | Sharer → Relay → all Viewers | Stream blob (broadcast) |
| `0x03` | Sharer → Relay → one Viewer | Unicast delivery (key wrap, Viewer ID, K' rotation) |
| `0x04` | Either → Relay | Heartbeat ping |
| `0x05` | Relay → either | Heartbeat pong |
| `0x06` | Relay → Viewer | Session control (join ack, session-not-found, session-ended) |

For types `0x03` and `0x06`, the 6 bytes following the type byte are the Viewer ID (ASCII, zero-padded). The relay routes unicast messages by Viewer ID without inspecting the payload.

## Requirements

### Requirement: Session Registration

The relay SHALL accept a session registration from a Sharer presenting a Session ID. Registration is first-come-first-served: the Session ID space (128 bits) makes collision negligible for independent sessions. The relay MAY require a registration token (implementation-defined) for self-hosted deployments to prevent unauthorized session creation.

#### Scenario: Sharer registers a session
- GIVEN a Sharer connects and sends a registration frame with a Session ID
- WHEN the relay processes the registration
- THEN the relay maps the Session ID to the Sharer's connection
- AND responds with a registration-ack via a `0x06` control frame
- AND the relay stores only: Session ID, Sharer connection handle, viewer connection list

#### Scenario: Duplicate Session ID
- GIVEN a Session ID is already registered with an active Sharer
- WHEN a second registration arrives for the same Session ID
- THEN the relay rejects the second registration with a `session-id-conflict` control frame
- AND the existing session is unaffected

---

### Requirement: Viewer Connection

The relay SHALL allow Viewers to connect to an active session by presenting a Session ID. The relay does not authenticate Viewers — authentication is the Sharer's responsibility via SPAKE2.

The relay SHALL assign each connected Viewer a relay-level connection handle used for unicast routing. This is distinct from the Viewer ID assigned by the Sharer.

#### Scenario: Viewer connects to active session
- GIVEN a Session is registered for Session ID X
- WHEN a Viewer connects with Session ID X
- THEN the relay adds the Viewer to the session's subscriber list
- AND sends an `0x06` join-ack to the Viewer
- AND begins forwarding `0x02` stream blobs to the Viewer

#### Scenario: Viewer connects to nonexistent session
- GIVEN no session is registered for Session ID X
- WHEN a Viewer connects with Session ID X
- THEN the relay sends a `session-not-found` `0x06` control frame
- AND closes the connection

#### Scenario: Max viewers exceeded
- GIVEN a session already has 20 connected Viewers (default limit)
- WHEN a 21st Viewer attempts to connect
- THEN the relay rejects the connection with a `session-full` `0x06` control frame
- AND existing Viewers are unaffected
- NOTE: the Sharer MAY configure a higher or lower limit at session registration time

---

### Requirement: Blob Forwarding

The relay SHALL forward every `0x02` stream blob received from the Sharer to all currently connected Viewers of that session, in the order received. The relay SHALL NOT inspect, buffer beyond in-flight delivery, modify, or log blob payloads.

If a Viewer's connection is too slow to accept blobs at the rate the Sharer produces them, the relay SHALL drop blobs for that Viewer (rather than backpressuring the Sharer or other Viewers). The relay SHALL disconnect a Viewer whose outbound buffer exceeds 512 KB.

#### Scenario: Blob delivered to all Viewers
- GIVEN a Session has Viewers A and B
- WHEN the Sharer sends a `0x02` blob
- THEN the relay forwards the identical blob bytes to both A and B
- AND the relay does not retain the blob after delivery

#### Scenario: Viewer-to-Sharer SPAKE2 messages are unicast
- GIVEN a Viewer sends a `0x01` SPAKE2 handshake message
- WHEN the relay receives the message
- THEN the relay routes it only to the Sharer, not to other Viewers

#### Scenario: Sharer sends unicast key delivery
- GIVEN the Sharer sends a `0x03` frame addressed to Viewer ID `a3k9x7`
- WHEN the relay receives the message
- THEN the relay routes it only to the Viewer whose ID is `a3k9x7`

---

### Requirement: Heartbeat

The relay SHALL send `0x05` pong frames in response to `0x04` ping frames from either party. Both Sharer and Viewer clients SHALL send a ping at least every 5 seconds when idle.

A Sharer connection that produces no traffic (data or ping) for more than 10 seconds SHALL be treated as disconnected, triggering session teardown.

A Viewer connection that produces no traffic for more than 30 seconds SHALL be treated as disconnected and removed from the subscriber list.

#### Scenario: Killed Sharer process
- GIVEN a Sharer's process is killed (SIGKILL)
- WHEN 10 seconds elapse with no traffic from the Sharer
- THEN the relay treats the session as terminated and triggers teardown

---

### Requirement: Session Teardown

The relay SHALL tear down a session when the Sharer disconnects (cleanly or via timeout), sending a `session-ended` `0x06` control frame to all connected Viewers and closing their connections.

#### Scenario: Sharer disconnects cleanly
- GIVEN a Session has two active Viewers
- WHEN the Sharer's WebSocket connection closes with a normal close code
- THEN the relay sends `session-ended` to both Viewers within 1 second
- AND closes both Viewer connections
- AND frees the Session ID

#### Scenario: Viewer disconnects
- GIVEN a Session is active
- WHEN one Viewer's connection closes
- THEN the relay removes that Viewer from the subscriber list
- AND the Sharer and remaining Viewers are unaffected
- AND the relay sends no notification to the Sharer (Viewer departure is handled by the Sharer's SPAKE2 state)

---

### Requirement: Relay Opacity

The relay SHALL be architecturally incapable of reading session content. This is enforced by design: the relay never receives the Code or the Stream Key. All `0x02` blobs it forwards are AES-256-GCM ciphertext; any modification produces an authentication failure on the Viewer side.

#### Scenario: Relay operator captures all traffic
- GIVEN a relay operator records all WebSocket frames
- WHEN they attempt to reconstruct session content
- THEN they observe only: Session IDs (derived tokens), SPAKE2 handshake blobs (opaque without the Code), AES-256-GCM ciphertext frames (opaque without the Stream Key)

---

### Requirement: Web Viewer Hosting

The relay SHALL serve the Lockwire web viewer application over HTTPS at the same host. The web viewer SHALL be accessible at `https://<relay-host>/join/<code>`.

#### Scenario: Browser viewer via URL
- GIVEN a user opens `https://relay.lockwire.io/join/thunder-eagle-river-moon-stone-fire`
- WHEN the page loads
- THEN the browser downloads the web viewer application
- AND the Code is pre-filled from the URL path
- AND the user initiates the SPAKE2 handshake by clicking "Watch"
- AND on success, the terminal is rendered in the browser via xterm.js
