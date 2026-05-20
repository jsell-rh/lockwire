import { argon2id } from "hash-wasm";
import {
  KEY_LEN,
  NONCE_LEN,
  SESSION_ID_LEN,
  SESSION_ID_ARGON_SALT,
  SESSION_ID_ARGON_TIME,
  SESSION_ID_ARGON_MEMORY,
  SESSION_ID_ARGON_THREADS,
  EPOCH_KEY_INFO_PREFIX,
  AUTH_KEY_INFO,
} from "./protocol.js";

function toBuffer(data: Uint8Array): ArrayBuffer {
  return new Uint8Array(data).buffer as ArrayBuffer;
}

export async function deriveSessionID(code: Uint8Array): Promise<string> {
  return argon2id({
    password: code,
    salt: new TextEncoder().encode(SESSION_ID_ARGON_SALT),
    iterations: SESSION_ID_ARGON_TIME,
    memorySize: SESSION_ID_ARGON_MEMORY,
    parallelism: SESSION_ID_ARGON_THREADS,
    hashLength: SESSION_ID_LEN,
    outputType: "hex",
  });
}

export async function deriveEpochKey(
  streamKey: Uint8Array,
  epoch: bigint,
): Promise<CryptoKey> {
  const info = new Uint8Array(EPOCH_KEY_INFO_PREFIX.length + 8);
  const enc = new TextEncoder();
  info.set(enc.encode(EPOCH_KEY_INFO_PREFIX), 0);
  const view = new DataView(info.buffer, info.byteOffset, info.byteLength);
  view.setBigUint64(EPOCH_KEY_INFO_PREFIX.length, epoch, false);

  const baseKey = await crypto.subtle.importKey(
    "raw",
    toBuffer(streamKey),
    "HKDF",
    false,
    ["deriveBits"],
  );

  const epochKeyBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new ArrayBuffer(0),
      info: toBuffer(info),
    },
    baseKey,
    KEY_LEN * 8,
  );

  return crypto.subtle.importKey(
    "raw",
    epochKeyBits,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
}

export async function deriveEpochKeyRaw(
  streamKey: Uint8Array,
  epoch: bigint,
): Promise<Uint8Array> {
  const info = new Uint8Array(EPOCH_KEY_INFO_PREFIX.length + 8);
  const enc = new TextEncoder();
  info.set(enc.encode(EPOCH_KEY_INFO_PREFIX), 0);
  const view = new DataView(info.buffer, info.byteOffset, info.byteLength);
  view.setBigUint64(EPOCH_KEY_INFO_PREFIX.length, epoch, false);

  const baseKey = await crypto.subtle.importKey(
    "raw",
    toBuffer(streamKey),
    "HKDF",
    false,
    ["deriveBits"],
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new ArrayBuffer(0),
      info: toBuffer(info),
    },
    baseKey,
    KEY_LEN * 8,
  );

  return new Uint8Array(bits);
}

export async function deriveAuthKey(spakeSecret: Uint8Array): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    toBuffer(spakeSecret),
    "HKDF",
    false,
    ["deriveBits"],
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new ArrayBuffer(0),
      info: toBuffer(new TextEncoder().encode(AUTH_KEY_INFO)),
    },
    baseKey,
    KEY_LEN * 8,
  );

  return new Uint8Array(bits);
}

export async function aesGcmDecrypt(
  key: CryptoKey,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  if (nonce.length !== NONCE_LEN) {
    throw new Error(`nonce length ${nonce.length}, want ${NONCE_LEN}`);
  }

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toBuffer(nonce), tagLength: 128 },
    key,
    toBuffer(ciphertext),
  );

  return new Uint8Array(plaintext);
}

export async function aesGcmDecryptRaw(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== KEY_LEN) {
    throw new Error(`key length ${key.length}, want ${KEY_LEN}`);
  }

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    toBuffer(key),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  return aesGcmDecrypt(cryptoKey, nonce, ciphertext);
}
