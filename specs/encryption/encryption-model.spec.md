# Encryption Model Specification

## Purpose

Lockwire's cryptographic model enforces a strict separation between authentication and encryption. The Code authenticates Viewers; a random Stream Key encrypts content. The relay is a blind pipe: it forwards opaque blobs and cannot read session content, authenticate participants, or derive any session secret. This separation ensures that Code disclosure — even after a session ends — cannot decrypt captured traffic.

**Forward secrecy scope:** Lockwire provides *inter-session* forward secrecy. Each session generates a fresh Stream Key; compromise of a past session's Stream Key does not affect other sessions. *Within* a session, the Stream Key is the master secret: a party who possesses K can derive all epoch keys for that session's lifetime. See Requirement: Epoch Rotation for tradeoffs.

**Cipher:** AES-256-GCM is used for all authenticated encryption. This choice enables native implementation in both the CLI binary (standard library support on all targets) and the browser-based web viewer (WebCrypto API, no WASM required).

## Requirements

### Requirement: Code Is Never Transmitted

The Code SHALL NOT appear in any message sent to the relay or to any peer. It is consumed locally for two purposes: (1) as the SPAKE2 password in the handshake computation, and (2) as the input to Session ID derivation via Argon2id. In neither case is the Code transmitted.

**Code entropy:** The Code is six words drawn uniformly at random from the BIP39 English wordlist (2048 words). This provides log₂(2048⁶) = 66 bits of entropy. SPAKE2 provides online-only brute-force resistance: each guess requires a live round-trip with the Sharer. The relay SHALL rate-limit connection attempts to a maximum of 10 failed handshakes per Session ID per minute. The Code is also used to derive the Session ID via Argon2id (see Requirement: Session ID Derivation). The memory-hard Argon2id parameters ensure that offline brute-force of the Code from a captured Session ID is computationally infeasible.

#### Scenario: Passive observer sees no Code
- GIVEN a Viewer runs `lw join <code>`
- WHEN the full SPAKE2 exchange completes over the relay
- THEN no message in the exchange contains the Code in any form (plaintext, hash, or derivation)
- AND the SPAKE2 session secret is discarded immediately after Stream Key delivery

---

### Requirement: Stream Key Independence

The Stream Key (K) SHALL be a cryptographically random 256-bit value generated fresh for each session. It SHALL NOT be derived from or computationally related to the Code.

#### Scenario: Post-session Code exposure cannot decrypt traffic
- GIVEN a session has ended and all relay traffic was captured by an attacker
- WHEN the attacker later obtains the Code
- THEN the attacker cannot derive K from the Code
- AND the captured traffic remains undecryptable

---

### Requirement: Session ID Derivation

The relay-facing Session ID SHALL be derived from the Code (not the Stream Key) using Argon2id, enabling both the Sharer and the Viewer to compute it independently before contacting the relay.

**Derivation formula:**

```
Argon2id(password=code_bytes, salt="lockwire-session-id-v1", m=65536, t=1, p=1, len=16) → hex
```

**Parameters (RFC 9106):**
- Variant: Argon2id (hybrid side-channel + GPU resistance)
- Memory (m): 64 MiB (65536 KiB)
- Iterations (t): 1
- Parallelism (p): 1
- Salt: the ASCII bytes of `"lockwire-session-id-v1"` (fixed domain separator; both parties must derive the same output; the `v1` suffix allows future parameter changes without ambiguity)
- Output length: 16 bytes (hex-encoded to 32 characters)

`code_bytes` is the Code in canonical form (lowercase, hyphen-separated, e.g. `thunder-eagle-river-moon-stone-fire`), encoded as UTF-8.

**Security rationale:** The Code has 66 bits of entropy (2048⁶ BIP39 words). Argon2id with 64 MiB memory makes each evaluation take approximately 50–100 ms on modern hardware. Brute-forcing the Session ID to recover the Code requires approximately 2⁶⁶ evaluations, which is computationally infeasible. The relay cannot determine the Code from the Session ID.

**Session ID stability:** Because the Session ID is derived from the Code (not from K), it does not change when the Stream Key is rotated during viewer revocation. The relay routing is stable across key rotations.

#### Scenario: Relay knows only the Session ID
- GIVEN a session is active
- WHEN the relay's internal state is fully inspected
- THEN the relay holds only the Session ID, not K and not the Code
- AND the Session ID cannot be used to determine the Code (Argon2id is a memory-hard one-way function)
- AND all blobs stored or forwarded by the relay are opaque ciphertext

#### Scenario: Sharer and Viewer derive the same Session ID independently
- GIVEN a Sharer runs `lw share` and obtains Code C
- AND a Viewer runs `lw join C`
- WHEN both compute `Argon2id(C, "lockwire-session-id-v1", m=65536, t=1, p=1, len=16)`
- THEN both produce the identical Session ID
- AND both connect to the relay using that Session ID before the SPAKE2 handshake begins

#### Scenario: Session ID is stable across Stream Key rotation
- GIVEN a session is active with Code C and Stream Key K
- WHEN a Viewer is revoked and the Stream Key rotates to K'
- THEN the Session ID does not change (it is derived from C, not K or K')
- AND the relay continues routing messages under the same Session ID

---

### Requirement: SPAKE2 Handshake per Viewer

Each Viewer SHALL complete an independent SPAKE2 handshake with the Sharer's process before receiving the Stream Key. The SPAKE2 instance SHALL use:
- The Code as the shared password
- Sharer as role A, Viewer as role B
- Associated data: the ASCII string `"lockwire-v1"` included in the transcript hash

The Sharer retains the per-viewer SPAKE2-derived session key (K_auth_i) in memory for the duration of the session. This key is used to deliver K and, if revocation occurs, K'.

#### Scenario: Authenticated key delivery
- GIVEN a Session is active with Stream Key K
- WHEN a Viewer completes SPAKE2 using the Code as the password
- THEN the Sharer encrypts K with the SPAKE2-derived per-viewer key K_auth_i using AES-256-GCM
- AND delivers the encrypted K to the Viewer via the relay
- AND the Viewer decrypts and holds K in memory for stream decryption

#### Scenario: Failed handshake is rejected
- GIVEN a Viewer presents an incorrect Code
- WHEN the SPAKE2 handshake is evaluated
- THEN the Sharer does not deliver K
- AND the connection is closed with no indication of whether the Session ID exists

---

### Requirement: Viewer ID Assignment

The Sharer's process SHALL assign each successfully authenticated Viewer a Viewer ID: a 6-character alphanumeric string (case-insensitive, e.g. `a3k9x7`), unique within the session, generated randomly by the Sharer and communicated to the Viewer as part of key delivery. The Viewer ID is bound to the SPAKE2 session; a revoked Viewer who reconnects receives a new Viewer ID and must pass the revocation check again.

#### Scenario: Viewer ID delivered at join
- GIVEN a Viewer completes SPAKE2 and receives K
- WHEN the key delivery message is received
- THEN it also contains the Viewer's assigned Viewer ID
- AND the Sharer logs `viewer joined: <viewer-id>` on its terminal

---

### Requirement: Authenticated Stream Encryption

All terminal output transmitted to the relay SHALL be encrypted with AES-256-GCM using the current Epoch Key and a per-session monotonically increasing 96-bit nonce counter.

The nonce counter is global to the session and does NOT reset on epoch rotation or Stream Key rotation. On Stream Key rotation (K → K'), the nonce counter continues from its current value. This ensures nonce uniqueness across all (key, nonce) pairs within the session.

#### Scenario: Frame encryption
- GIVEN epoch n is active with Epoch Key K_n
- WHEN the Sharer captures a terminal frame
- THEN the frame is encrypted as `AES-256-GCM(K_n, nonce, plaintext_frame)`
- AND the nonce is the current 96-bit counter value, incremented by 1 after each frame
- AND the nonce and epoch number are transmitted in the frame header alongside the ciphertext

#### Scenario: Viewer rejects replayed or out-of-order frames
- GIVEN a Viewer has successfully decrypted a frame with nonce N
- WHEN a frame arrives with nonce ≤ N
- THEN the Viewer discards the frame without attempting decryption

#### Scenario: Tampered frame is rejected
- GIVEN a relay or attacker modifies a ciphertext blob
- WHEN the Viewer attempts decryption
- THEN AES-256-GCM authentication fails and the frame is discarded silently

---

### Requirement: Epoch Key Derivation

The Epoch Key for epoch n SHALL be derived as:

```
K_n = HKDF-SHA256(ikm=K, salt=nil, info="lw-epoch-" || uint64_big_endian(n), length=32)
```

Viewers who possess K derive K_n independently and identically without any additional message from the Sharer. No epoch key is transmitted over the relay.

**Forward secrecy property:** K_n cannot be used to derive K_{n-1} or K_{n-2}. However, K can derive any K_n. The Stream Key K is therefore the session-long master secret; its protection is the primary security invariant.

#### Scenario: Epoch boundary is transparent to active Viewers
- GIVEN an epoch boundary is crossed
- WHEN the epoch increments from n to n+1
- THEN both Sharer and active Viewers independently compute K_{n+1} = HKDF(K, "lw-epoch-" || (n+1))
- AND active Viewers seamlessly decrypt frames under K_{n+1} without reconnecting or receiving any additional message

#### Scenario: Straggler frames at epoch boundary
- GIVEN the epoch transitions from n to n+1
- WHEN a frame encrypted under K_n arrives after the epoch boundary due to relay buffering
- THEN the Viewer SHALL accept the frame if it carries epoch number n in its header and has a valid nonce
- AND the Viewer SHALL maintain the ability to decrypt epoch-n frames for a 5-second grace period after the epoch boundary

---

### Requirement: Stream Key Rotation for Viewer Revocation

When the Sharer revokes a Viewer, the system SHALL generate a new Stream Key K' (fresh random 256-bit value) and deliver it to all non-revoked Viewers using their retained per-viewer SPAKE2 session key (K_auth_i). New frames SHALL be encrypted under epochs derived from K'. The epoch counter resets to the current epoch number; the nonce counter does NOT reset. The Session ID does not change during Stream Key rotation; it is derived from the Code, which remains constant for the session's lifetime.

#### Scenario: K' delivered to non-revoked Viewers
- GIVEN Viewer A is revoked and Viewer B is not
- WHEN the Sharer generates K'
- THEN the Sharer encrypts K' with K_auth_B (Viewer B's retained SPAKE2 session key) and delivers it via the relay
- AND Viewer B decrypts K' and begins using epochs derived from K' for subsequent frames
- AND Viewer B does not need to reconnect

#### Scenario: Revoked Viewer cannot decrypt new frames
- GIVEN Viewer A is revoked and K' has been distributed
- WHEN the next epoch under K' begins
- THEN Viewer A has no path to K' (it was never delivered to K_auth_A)
- AND Viewer A cannot decrypt any frame encrypted under K'

#### Scenario: Revoked Viewer attempts rejoin
- GIVEN Viewer A has been revoked
- WHEN Viewer A runs `lw join <same-code>` again
- THEN Viewer A completes SPAKE2 (Code is unchanged) and receives a new Viewer ID
- AND the Sharer's revocation list is checked against Viewer IDs, not against the Code
- AND the Sharer MAY reject the new join or allow it, at the Sharer's discretion (explicit re-allow required)

---

### Requirement: Memory Security

All cryptographic material (K, K', K_auth_i for all viewers, derived epoch keys) SHALL be:
- Held in process memory only; never written to any file, log, or persistent store
- Allocated in memory regions locked against paging to disk (mlock/VirtualLock or equivalent) where the OS permits
- Zeroed (overwritten with zeros) before the memory is freed and before the process exits

#### Scenario: No key material on disk
- GIVEN a session is active or has ended
- WHEN the filesystem and swap of the Sharer's machine are inspected
- THEN no file or swap page contains K, any K_auth_i, or any derived epoch key
