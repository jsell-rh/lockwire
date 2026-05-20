import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { hkdf } from "@noble/hashes/hkdf";
import { SPAKE2_CONFIRMATION_KEYS_INFO } from "./protocol.js";

type Point = ReturnType<typeof p256.ProjectivePoint.fromHex>;
const ProjectivePoint = p256.ProjectivePoint;

const M_HEX = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const N_HEX = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

const M: Point = ProjectivePoint.fromHex(M_HEX);
const N: Point = ProjectivePoint.fromHex(N_HEX);

const IDENTITY_A = new TextEncoder().encode("A");
const IDENTITY_B = new TextEncoder().encode("B");

function derivePassword(password: Uint8Array): bigint {
  const digest = sha256(password);
  let val = 0n;
  for (const b of digest) {
    val = (val << 8n) | BigInt(b);
  }
  return val % p256.CURVE.n;
}

function encodeLength(data: Uint8Array): Uint8Array {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(data.length), true);
  return buf;
}

function buildTranscript(
  identityA: Uint8Array,
  identityB: Uint8Array,
  messageA: Uint8Array,
  messageB: Uint8Array,
  k: Uint8Array,
  password: Uint8Array,
  aad: Uint8Array | null,
): Uint8Array {
  const parts: Uint8Array[] = [];

  for (const field of [identityA, identityB, messageA, messageB, k, password]) {
    parts.push(encodeLength(field));
    parts.push(field);
  }

  if (aad !== null && aad.length > 0) {
    parts.push(encodeLength(aad));
    parts.push(aad);
  }

  let totalLen = 0;
  for (const p of parts) totalLen += p.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    result.set(p, offset);
    offset += p.length;
  }
  return result;
}

function pointToBytes(p: Point): Uint8Array {
  return p.toRawBytes(false);
}

function pointFromBytes(data: Uint8Array): Point {
  return ProjectivePoint.fromHex(data);
}

function scalarToBytes(s: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let val = s;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

function randomScalar(): bigint {
  const buf = new Uint8Array(48);
  crypto.getRandomValues(buf);
  let val = 0n;
  for (const b of buf) {
    val = (val << 8n) | BigInt(b);
  }
  return val % p256.CURVE.n;
}

function hmacSHA256(key: Uint8Array, message: Uint8Array): Uint8Array {
  return hmac(sha256, key, message);
}

function hkdfSHA256(ikm: Uint8Array, salt: Uint8Array | undefined, info: Uint8Array, length: number): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}

export interface SPAKE2Options {
  aad: Uint8Array | null;
}

export class SPAKE2Server {
  private readonly password: bigint;
  private readonly aad: Uint8Array | null;
  private scalar: bigint | null = null;
  private sharedKey: Uint8Array | null = null;
  private confirmKeyA: Uint8Array | null = null;
  private confirmKeyB: Uint8Array | null = null;
  private transcript: Uint8Array | null = null;

  constructor(passwordBytes: Uint8Array, options: SPAKE2Options) {
    this.password = derivePassword(passwordBytes);
    this.aad = options.aad;
  }

  exchange(clientMessage: Uint8Array): Uint8Array {
    const pA = pointFromBytes(clientMessage);
    this.scalar = randomScalar();

    const gen = ProjectivePoint.BASE;
    const y = gen.multiply(this.scalar);
    const pB = N.multiply(this.password).add(y);

    const wm = M.multiply(this.password);
    const pAminusWm = pA.subtract(wm);
    const k = pAminusWm.multiply(this.scalar);

    const pBData = pointToBytes(pB);
    const kData = pointToBytes(k);
    const passData = scalarToBytes(this.password);

    this.transcript = buildTranscript(
      IDENTITY_A,
      IDENTITY_B,
      clientMessage,
      pBData,
      kData,
      passData,
      this.aad,
    );

    this.deriveKeys(this.transcript);
    return pBData;
  }

  confirm(clientConfirmation: Uint8Array): Uint8Array {
    if (!this.confirmKeyA || !this.confirmKeyB || !this.transcript) {
      throw new Error("protocol not started");
    }

    const expected = hmacSHA256(this.confirmKeyA, this.transcript);
    if (!constantTimeEqual(clientConfirmation, expected)) {
      throw new Error("password mismatch");
    }

    const confirmB = hmacSHA256(this.confirmKeyB, this.transcript);
    return confirmB;
  }

  sessionKey(): Uint8Array {
    if (!this.sharedKey) {
      throw new Error("protocol not completed");
    }
    return this.sharedKey;
  }

  private deriveKeys(transcript: Uint8Array): void {
    const h = sha256(transcript);
    const halfLen = h.length / 2;
    this.sharedKey = h.slice(0, halfLen);
    const authKey = h.slice(halfLen);

    const confirmInfo = new Uint8Array([
      ...new TextEncoder().encode(SPAKE2_CONFIRMATION_KEYS_INFO),
      ...(this.aad ?? []),
    ]);
    const kc = hkdfSHA256(authKey, undefined, confirmInfo, 32);
    this.confirmKeyA = kc.slice(0, 16);
    this.confirmKeyB = kc.slice(16);
  }
}

export class SPAKE2Client {
  private readonly password: bigint;
  private readonly aad: Uint8Array | null;
  private scalar: bigint | null = null;
  private sharedKey: Uint8Array | null = null;
  private confirmKeyA: Uint8Array | null = null;
  private confirmKeyB: Uint8Array | null = null;
  private transcript: Uint8Array | null = null;

  constructor(passwordBytes: Uint8Array, options: SPAKE2Options) {
    this.password = derivePassword(passwordBytes);
    this.aad = options.aad;
  }

  start(): Uint8Array {
    this.scalar = randomScalar();
    const gen = ProjectivePoint.BASE;
    const x = gen.multiply(this.scalar);
    const pA = M.multiply(this.password).add(x);
    return pointToBytes(pA);
  }

  finish(serverMessage: Uint8Array): Uint8Array {
    if (this.scalar === null) {
      throw new Error("protocol not started");
    }

    const pB = pointFromBytes(serverMessage);
    const wn = N.multiply(this.password);
    const pBminusWn = pB.subtract(wn);
    const k = pBminusWn.multiply(this.scalar);

    const pAData = this.regenerateInitialMessage();
    const kData = pointToBytes(k);
    const passData = scalarToBytes(this.password);

    this.transcript = buildTranscript(
      IDENTITY_A,
      IDENTITY_B,
      pAData,
      serverMessage,
      kData,
      passData,
      this.aad,
    );

    this.deriveKeys(this.transcript);

    const confirmA = hmacSHA256(this.confirmKeyA!, this.transcript);
    return confirmA;
  }

  verify(serverConfirmation: Uint8Array): void {
    if (!this.confirmKeyB || !this.transcript) {
      throw new Error("protocol not completed");
    }

    const expected = hmacSHA256(this.confirmKeyB, this.transcript);
    if (!constantTimeEqual(serverConfirmation, expected)) {
      throw new Error("password mismatch");
    }
  }

  sessionKey(): Uint8Array {
    if (!this.sharedKey) {
      throw new Error("protocol not completed");
    }
    return this.sharedKey;
  }

  private regenerateInitialMessage(): Uint8Array {
    if (this.scalar === null) throw new Error("no scalar");
    const gen = ProjectivePoint.BASE;
    const x = gen.multiply(this.scalar);
    const pA = M.multiply(this.password).add(x);
    return pointToBytes(pA);
  }

  private deriveKeys(transcript: Uint8Array): void {
    const h = sha256(transcript);
    const halfLen = h.length / 2;
    this.sharedKey = h.slice(0, halfLen);
    const authKey = h.slice(halfLen);

    const confirmInfo = new Uint8Array([
      ...new TextEncoder().encode(SPAKE2_CONFIRMATION_KEYS_INFO),
      ...(this.aad ?? []),
    ]);
    const kc = hkdfSHA256(authKey, undefined, confirmInfo, 32);
    this.confirmKeyA = kc.slice(0, 16);
    this.confirmKeyB = kc.slice(16);
  }
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}
