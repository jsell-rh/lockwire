import { SPAKE2Server } from "./spake2.js";
import {
  deriveSessionID,
  deriveEpochKey,
  deriveAuthKey,
  aesGcmDecrypt,
  aesGcmDecryptRaw,
} from "./crypto.js";
import {
  MSG_TYPE_SPAKE2,
  MSG_TYPE_STREAM,
  MSG_TYPE_HEARTBEAT,
  MSG_TYPE_PONG,
  MSG_TYPE_CONTROL,
  MSG_TYPE_TERM_SIZE,
  CTRL_JOIN_ACK,
  CTRL_SESSION_NOT_FOUND,
  CTRL_SESSION_ENDED,
  CTRL_SESSION_FULL,
  CLIENT_BYTE_BROWSER,
  VIEWER_ID_LEN,
  NONCE_LEN,
  GCM_TAG_LEN,
  KEY_LEN,
  HEARTBEAT_INTERVAL_MS,
  VIEWER_REVOCATION_FAILURE_THRESHOLD,
  SPAKE2_ASSOCIATED_DATA,
  EPOCH_GRACE_PERIOD_MS,
} from "./protocol.js";

export type ConnectionState =
  | "pre-join"
  | "connecting"
  | "active"
  | "ended"
  | "lost"
  | "revoked"
  | "error";

export interface ViewerCallbacks {
  onStateChange(state: ConnectionState, message?: string): void;
  onTerminalData(data: Uint8Array): void;
  onTerminalResize(cols: number, rows: number): void;
}

export class LockwireClient {
  private ws: WebSocket | null = null;
  private streamKey: Uint8Array | null = null;
  private authKey: Uint8Array | null = null;
  private viewerID = "";
  private lastNonce = 0n;
  private consecutiveFailures = 0;
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private state: ConnectionState = "pre-join";
  private readonly callbacks: ViewerCallbacks;
  private currentEpoch = 0n;
  private epochTransitionTime = 0;
  private epochInitialized = false;

  constructor(callbacks: ViewerCallbacks) {
    this.callbacks = callbacks;
  }

  async connect(code: string): Promise<void> {
    this.setState("connecting");

    const codeBytes = new TextEncoder().encode(code);
    const sessionID = deriveSessionID(codeBytes);

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${window.location.host}/api/watch/${sessionID}`;

    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(url);
      this.ws.binaryType = "arraybuffer";

      this.ws.onopen = () => {
        this.runHandshake(codeBytes)
          .then(resolve)
          .catch((err: unknown) => {
            this.handleError(err);
            reject(err);
          });
      };

      this.ws.onerror = () => {
        this.setState("lost", "connection failed");
        reject(new Error("WebSocket connection failed"));
      };

      this.ws.onclose = () => {
        this.stopHeartbeat();
        if (this.state === "active") {
          this.setState("lost", "session lost (connection dropped)");
        }
      };
    });
  }

  disconnect(): void {
    this.stopHeartbeat();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.zeroKeys();
  }

  private async runHandshake(code: Uint8Array): Promise<void> {
    await this.waitForJoinAck();

    const spake = new SPAKE2Server(code, {
      aad: new TextEncoder().encode(SPAKE2_ASSOCIATED_DATA),
    });

    this.send(new Uint8Array([MSG_TYPE_SPAKE2, CLIENT_BYTE_BROWSER]));

    const msgA = await this.recvHandshakeMsg();
    const msgB = spake.exchange(msgA);
    this.sendSPAKE2(msgB);

    const confirmA = await this.recvHandshakeMsg();
    const confirmB = spake.confirm(confirmA);
    this.sendSPAKE2(confirmB);

    const delivery = await this.recvHandshakeMsg();
    await this.processKeyDelivery(spake, delivery);

    this.setState("active");
    this.startHeartbeat();
    this.startStreamLoop();
  }

  private waitForJoinAck(): Promise<void> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("handshake timed out"));
      }, 15000);

      const handler = (ev: MessageEvent) => {
        const data = new Uint8Array(ev.data as ArrayBuffer);
        if (data.length < 2 || data[0] !== MSG_TYPE_CONTROL) return;

        switch (data[1]) {
          case CTRL_JOIN_ACK:
            clearTimeout(timeout);
            this.ws!.removeEventListener("message", handler);
            resolve();
            break;
          case CTRL_SESSION_NOT_FOUND:
            clearTimeout(timeout);
            this.ws!.removeEventListener("message", handler);
            reject(new Error("incorrect code — session not found"));
            break;
          case CTRL_SESSION_FULL:
            clearTimeout(timeout);
            this.ws!.removeEventListener("message", handler);
            reject(new Error("session full — too many viewers"));
            break;
        }
      };

      this.ws!.addEventListener("message", handler);
    });
  }

  private recvHandshakeMsg(): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("handshake timed out"));
      }, 15000);

      const handler = (ev: MessageEvent) => {
        const data = new Uint8Array(ev.data as ArrayBuffer);
        if (data.length === 0) return;

        switch (data[0]) {
          case MSG_TYPE_STREAM:
          case MSG_TYPE_TERM_SIZE:
          case MSG_TYPE_PONG:
            return;
          case MSG_TYPE_CONTROL:
            if (data.length >= 2) {
              if (data[1] === CTRL_SESSION_ENDED) {
                clearTimeout(timeout);
                this.ws!.removeEventListener("message", handler);
                reject(new Error("session ended by sharer"));
                return;
              }
              if (data[1] === CTRL_SESSION_NOT_FOUND) {
                clearTimeout(timeout);
                this.ws!.removeEventListener("message", handler);
                reject(new Error("incorrect code — session not found"));
                return;
              }
            }
            return;
          default:
            clearTimeout(timeout);
            this.ws!.removeEventListener("message", handler);
            resolve(data);
        }
      };

      this.ws!.addEventListener("message", handler);
    });
  }

  private async processKeyDelivery(
    spake: SPAKE2Server,
    delivery: Uint8Array,
  ): Promise<void> {
    const minLen = VIEWER_ID_LEN + NONCE_LEN + 1;
    if (delivery.length < minLen) {
      throw new Error(`key delivery too short: ${delivery.length} bytes`);
    }

    this.viewerID = new TextDecoder().decode(
      delivery.slice(0, VIEWER_ID_LEN),
    );
    const nonce = delivery.slice(VIEWER_ID_LEN, VIEWER_ID_LEN + NONCE_LEN);
    const ciphertext = delivery.slice(VIEWER_ID_LEN + NONCE_LEN);

    const spakeSecret = spake.sessionKey();
    const authKey = await deriveAuthKey(spakeSecret);
    const k = await aesGcmDecryptRaw(authKey, nonce, ciphertext);

    if (k.length !== KEY_LEN) {
      throw new Error(`stream key wrong length: ${k.length}`);
    }

    this.streamKey = k;
    this.authKey = authKey;
  }

  private startStreamLoop(): void {
    this.ws!.onmessage = (ev: MessageEvent) => {
      const data = new Uint8Array(ev.data as ArrayBuffer);
      if (data.length === 0) return;

      switch (data[0]) {
        case MSG_TYPE_STREAM:
          this.handleStreamFrame(data);
          break;
        case MSG_TYPE_TERM_SIZE:
          this.handleTermSizeFrame(data);
          break;
        case MSG_TYPE_CONTROL:
          if (data.length >= 2 && data[1] === CTRL_SESSION_ENDED) {
            this.setState("ended", "session ended by sharer");
            this.disconnect();
          }
          break;
        case MSG_TYPE_PONG:
          break;
        default:
          this.handlePossibleRekey(data);
          break;
      }
    };
  }

  private async handleStreamFrame(frame: Uint8Array): Promise<void> {
    const headerLen = 1 + 8 + NONCE_LEN;
    if (frame.length < headerLen + GCM_TAG_LEN) return;

    const view = new DataView(
      frame.buffer,
      frame.byteOffset,
      frame.byteLength,
    );
    const epoch = view.getBigUint64(1, false);

    if (!this.validateEpoch(epoch)) return;

    const nonce = frame.slice(9, 9 + NONCE_LEN);
    const ciphertext = frame.slice(9 + NONCE_LEN);

    const nonceCounter = extractNonceCounter(nonce);
    if (nonceCounter <= this.lastNonce) return;

    try {
      const epochKey = await deriveEpochKey(this.streamKey!, epoch);
      const plaintext = await aesGcmDecrypt(epochKey, nonce, ciphertext);
      this.lastNonce = nonceCounter;
      this.consecutiveFailures = 0;
      this.callbacks.onTerminalData(plaintext);
    } catch {
      this.consecutiveFailures++;
      if (
        this.consecutiveFailures >= VIEWER_REVOCATION_FAILURE_THRESHOLD
      ) {
        this.setState("revoked", "access revoked");
        this.disconnect();
      }
    }
  }

  private async handleTermSizeFrame(frame: Uint8Array): Promise<void> {
    const headerLen = 1 + 8 + NONCE_LEN;
    if (frame.length < headerLen + GCM_TAG_LEN + 4) return;

    const view = new DataView(
      frame.buffer,
      frame.byteOffset,
      frame.byteLength,
    );
    const epoch = view.getBigUint64(1, false);

    if (!this.validateEpoch(epoch)) return;

    const nonce = frame.slice(9, 9 + NONCE_LEN);
    const ciphertext = frame.slice(9 + NONCE_LEN);

    try {
      const epochKey = await deriveEpochKey(this.streamKey!, epoch);
      const plaintext = await aesGcmDecrypt(epochKey, nonce, ciphertext);
      if (plaintext.length < 4) return;

      const pview = new DataView(
        plaintext.buffer,
        plaintext.byteOffset,
        plaintext.byteLength,
      );
      const cols = pview.getUint16(0, false);
      const rows = pview.getUint16(2, false);
      this.callbacks.onTerminalResize(cols, rows);
    } catch {
      // ignore decode errors on size frames
    }
  }

  private async handlePossibleRekey(data: Uint8Array): Promise<void> {
    const minLen = VIEWER_ID_LEN + NONCE_LEN + GCM_TAG_LEN + 1;
    if (data.length < minLen) return;
    if (!this.authKey) return;

    const id = new TextDecoder().decode(data.slice(0, VIEWER_ID_LEN));
    if (id !== this.viewerID) return;

    const nonce = data.slice(VIEWER_ID_LEN, VIEWER_ID_LEN + NONCE_LEN);
    const ciphertext = data.slice(VIEWER_ID_LEN + NONCE_LEN);

    try {
      const kPrime = await aesGcmDecryptRaw(this.authKey, nonce, ciphertext);
      this.zeroStreamKey();
      this.streamKey = kPrime;
      this.consecutiveFailures = 0;
    } catch {
      // not a valid rekey
    }
  }

  private validateEpoch(epoch: bigint): boolean {
    const now = Date.now();
    if (!this.epochInitialized) {
      this.currentEpoch = epoch;
      this.epochTransitionTime = now;
      this.epochInitialized = true;
      return true;
    }
    if (epoch >= this.currentEpoch) {
      if (epoch > this.currentEpoch) {
        this.currentEpoch = epoch;
        this.epochTransitionTime = now;
      }
      return true;
    }
    if (epoch === this.currentEpoch - 1n) {
      if (now - this.epochTransitionTime <= EPOCH_GRACE_PERIOD_MS) {
        return true;
      }
    }
    return false;
  }

  private sendSPAKE2(payload: Uint8Array): void {
    const msg = new Uint8Array(1 + payload.length);
    msg[0] = MSG_TYPE_SPAKE2;
    msg.set(payload, 1);
    this.send(msg);
  }

  private send(data: Uint8Array): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(data);
    }
  }

  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      this.send(new Uint8Array([MSG_TYPE_HEARTBEAT]));
    }, HEARTBEAT_INTERVAL_MS);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatInterval !== null) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  private setState(state: ConnectionState, message?: string): void {
    this.state = state;
    this.callbacks.onStateChange(state, message);
  }

  private handleError(err: unknown): void {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("session not found")) {
      this.setState("error", "incorrect code — session not found");
    } else if (message.includes("session full")) {
      this.setState("error", "session full — too many viewers");
    } else {
      this.setState("error", message);
    }
    this.disconnect();
  }

  private zeroStreamKey(): void {
    if (this.streamKey) {
      this.streamKey.fill(0);
    }
  }

  private zeroKeys(): void {
    this.zeroStreamKey();
    if (this.authKey) {
      this.authKey.fill(0);
    }
  }
}

function extractNonceCounter(nonce: Uint8Array): bigint {
  let val = 0n;
  for (let i = 4; i < 12; i++) {
    val = (val << 8n) | BigInt(nonce[i] ?? 0);
  }
  return val;
}
