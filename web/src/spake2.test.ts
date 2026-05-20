import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { SPAKE2Client, SPAKE2Server } from "./spake2.js";

const enc = new TextEncoder();

function aad(): Uint8Array {
  return enc.encode("lockwire-v1");
}

describe("SPAKE2", () => {
  it("round-trip produces matching session keys", () => {
    const code = enc.encode("abandon abandon abandon abandon abandon about");

    const client = new SPAKE2Client(code, { aad: aad() });
    const server = new SPAKE2Server(code, { aad: aad() });

    const msgA = client.start();
    const msgB = server.exchange(msgA);
    const confirmA = client.finish(msgB);
    const confirmB = server.confirm(confirmA);
    client.verify(confirmB);

    const clientKey = client.sessionKey();
    const serverKey = server.sessionKey();

    assert.deepStrictEqual(clientKey, serverKey);
    assert.ok(clientKey.length > 0, "session key must not be empty");
  });

  it("wrong code produces different keys or fails confirmation", () => {
    const client = new SPAKE2Client(enc.encode("correct code"), { aad: aad() });
    const server = new SPAKE2Server(enc.encode("wrong code"), { aad: aad() });

    const msgA = client.start();
    const msgB = server.exchange(msgA);
    const confirmA = client.finish(msgB);

    assert.throws(
      () => server.confirm(confirmA),
      { message: "password mismatch" },
    );
  });

  it("different sessions produce different keys", () => {
    const code = enc.encode("same code for both sessions");

    const key1 = completeSPAKE2(code);
    const key2 = completeSPAKE2(code);

    assert.notDeepStrictEqual(key1, key2);
  });

  it("session key length is 16 bytes (half of SHA-256)", () => {
    const code = enc.encode("test code");
    const key = completeSPAKE2(code);
    assert.strictEqual(key.length, 16);
  });
});

function completeSPAKE2(code: Uint8Array): Uint8Array {
  const client = new SPAKE2Client(code, { aad: enc.encode("lockwire-v1") });
  const server = new SPAKE2Server(code, { aad: enc.encode("lockwire-v1") });

  const msgA = client.start();
  const msgB = server.exchange(msgA);
  const confirmA = client.finish(msgB);
  const confirmB = server.confirm(confirmA);
  client.verify(confirmB);

  return client.sessionKey();
}
