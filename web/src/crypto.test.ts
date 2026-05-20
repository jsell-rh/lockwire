import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import {
  deriveSessionID,
  deriveEpochKeyRaw,
  deriveAuthKey,
  aesGcmDecryptRaw,
} from "./crypto.js";

const enc = new TextEncoder();

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("Session ID (Argon2id)", () => {
  it("matches Go DeriveSessionID for known code", async () => {
    const code = enc.encode("thunder-eagle-river-moon-stone-fire");
    const sid = await deriveSessionID(code);
    assert.strictEqual(sid.length, 32, "session ID must be 32 hex chars");

    const { execFileSync } = await import("node:child_process");
    const goSid = execFileSync("go", [
      "run", "./web/testdata/sessionid_helper.go",
      "thunder-eagle-river-moon-stone-fire",
    ], {
      cwd: "/home/jsell/code/lockwire",
      encoding: "utf-8",
    }).trim();

    assert.strictEqual(sid, goSid, "session IDs must match");
  });

  it("is deterministic", async () => {
    const code = enc.encode("abandon-abandon-abandon-abandon-abandon-abandon");
    const s1 = await deriveSessionID(code);
    const s2 = await deriveSessionID(code);
    assert.strictEqual(s1, s2);
  });

  it("different codes produce different session IDs", async () => {
    const s1 = await deriveSessionID(enc.encode("code-one"));
    const s2 = await deriveSessionID(enc.encode("code-two"));
    assert.notStrictEqual(s1, s2);
  });
});

describe("Epoch Key (HKDF-SHA256)", () => {
  it("matches Go DeriveEpochKey for known inputs", async () => {
    const k = new Uint8Array(32);
    for (let i = 0; i < 32; i++) k[i] = i;

    const ek = await deriveEpochKeyRaw(k, 42n);

    const { execFileSync } = await import("node:child_process");
    const goEk = execFileSync("go", [
      "run", "./web/testdata/epochkey_helper.go",
      bytesToHex(k),
      "42",
    ], {
      cwd: "/home/jsell/code/lockwire",
      encoding: "utf-8",
    }).trim();

    assert.strictEqual(bytesToHex(ek), goEk, "epoch keys must match");
  });

  it("is deterministic", async () => {
    const k = new Uint8Array(32);
    k[0] = 0x99;
    const e1 = await deriveEpochKeyRaw(k, 5n);
    const e2 = await deriveEpochKeyRaw(k, 5n);
    assert.deepStrictEqual(e1, e2);
  });

  it("different epochs produce different keys", async () => {
    const k = new Uint8Array(32);
    const e1 = await deriveEpochKeyRaw(k, 0n);
    const e2 = await deriveEpochKeyRaw(k, 1n);
    assert.notDeepStrictEqual(e1, e2);
  });
});

describe("Auth Key (HKDF-SHA256)", () => {
  it("matches Go DeriveAuthKey for known inputs", async () => {
    const spakeSecret = new Uint8Array(16);
    for (let i = 0; i < 16; i++) spakeSecret[i] = i + 0x10;

    const ak = await deriveAuthKey(spakeSecret);

    const { execFileSync } = await import("node:child_process");
    const goAk = execFileSync("go", [
      "run", "./web/testdata/authkey_helper.go",
      bytesToHex(spakeSecret),
    ], {
      cwd: "/home/jsell/code/lockwire",
      encoding: "utf-8",
    }).trim();

    assert.strictEqual(bytesToHex(ak), goAk, "auth keys must match");
  });
});

describe("AES-256-GCM", () => {
  it("NIST test vector: all-zero key/nonce/plaintext", async () => {
    const key = new Uint8Array(32);
    const nonce = new Uint8Array(12);

    const wantCT = hexToBytes("cea7403d4d606b6e074ec5d3baf39d18");
    const wantTag = hexToBytes("d0d1c8a799996bf0265b98b5d48ab919");
    const ciphertext = new Uint8Array([...wantCT, ...wantTag]);

    const plaintext = await aesGcmDecryptRaw(key, nonce, ciphertext);
    assert.deepStrictEqual(plaintext, new Uint8Array(16));
  });

  it("round-trip with Go Seal output", async () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i;
    const nonce = new Uint8Array(12);
    nonce[11] = 1;

    const { execFileSync } = await import("node:child_process");
    const goCT = execFileSync("go", [
      "run", "./web/testdata/aead_helper.go",
      bytesToHex(key),
      bytesToHex(nonce),
      "hello, lockwire!",
    ], {
      cwd: "/home/jsell/code/lockwire",
      encoding: "utf-8",
    }).trim();

    const plaintext = await aesGcmDecryptRaw(key, nonce, hexToBytes(goCT));
    assert.strictEqual(
      new TextDecoder().decode(plaintext),
      "hello, lockwire!",
    );
  });

  it("rejects tampered ciphertext", async () => {
    const key = new Uint8Array(32);
    const nonce = new Uint8Array(12);
    nonce[11] = 1;

    const wantCT = hexToBytes("cea7403d4d606b6e074ec5d3baf39d18");
    const wantTag = hexToBytes("d0d1c8a799996bf0265b98b5d48ab919");
    const ciphertext = new Uint8Array([...wantCT, ...wantTag]);
    ciphertext[0] ^= 0xff;

    await assert.rejects(
      () => aesGcmDecryptRaw(key, nonce, ciphertext),
    );
  });
});
