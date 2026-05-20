import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { SPAKE2Client, SPAKE2Server } from "./spake2.js";

const enc = new TextEncoder();
const CWD = "/home/jsell/code/lockwire";

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

function spawnGo(entrypoint: string, code: string): {
  write: (hex: string) => void;
  readLine: () => Promise<string>;
  wait: () => Promise<{ exitCode: number; stderr: string }>;
} {
  const proc = spawn("go", ["run", entrypoint, code], {
    cwd: CWD,
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stderrBuf = "";
  proc.stderr!.on("data", (chunk: Buffer) => {
    stderrBuf += chunk.toString();
  });

  let stdoutBuf = "";
  const lineQueue: string[] = [];
  const waiters: Array<(line: string) => void> = [];

  proc.stdout!.on("data", (chunk: Buffer) => {
    stdoutBuf += chunk.toString();
    let idx: number;
    while ((idx = stdoutBuf.indexOf("\n")) !== -1) {
      const line = stdoutBuf.substring(0, idx);
      stdoutBuf = stdoutBuf.substring(idx + 1);
      const waiter = waiters.shift();
      if (waiter) {
        waiter(line);
      } else {
        lineQueue.push(line);
      }
    }
  });

  return {
    write(hex: string) {
      proc.stdin!.write(hex + "\n");
    },
    readLine(): Promise<string> {
      const queued = lineQueue.shift();
      if (queued !== undefined) return Promise.resolve(queued);
      return new Promise((resolve) => waiters.push(resolve));
    },
    wait(): Promise<{ exitCode: number; stderr: string }> {
      return new Promise((resolve) => {
        proc.on("close", (code) => {
          resolve({ exitCode: code ?? 1, stderr: stderrBuf });
        });
      });
    },
  };
}

describe("SPAKE2 Go ↔ TypeScript interop", () => {
  it("TypeScript server completes handshake with Go client", async () => {
    const code = "thunder-eagle-river-moon-stone-fire";
    const go = spawnGo("./web/testdata/spake2_interop.go", code);

    const msgAHex = await go.readLine();
    const server = new SPAKE2Server(enc.encode(code), {
      aad: enc.encode("lockwire-v1"),
    });
    const msgB = server.exchange(hexToBytes(msgAHex));
    go.write(bytesToHex(msgB));

    const confirmAHex = await go.readLine();
    const confirmB = server.confirm(hexToBytes(confirmAHex));
    go.write(bytesToHex(confirmB));

    const goKeyHex = await go.readLine();
    const result = await go.wait();
    assert.strictEqual(result.exitCode, 0, `Go stderr: ${result.stderr}`);

    const tsKeyHex = bytesToHex(server.sessionKey());
    assert.strictEqual(tsKeyHex, goKeyHex, "session keys must match");
  });

  it("TypeScript client completes handshake with Go server", async () => {
    const code = "thunder-eagle-river-moon-stone-fire";
    const go = spawnGo("./web/testdata/spake2_viewer_interop.go", code);

    const client = new SPAKE2Client(enc.encode(code), {
      aad: enc.encode("lockwire-v1"),
    });
    const msgA = client.start();
    go.write(bytesToHex(msgA));

    const msgBHex = await go.readLine();
    const confirmA = client.finish(hexToBytes(msgBHex));
    go.write(bytesToHex(confirmA));

    const confirmBHex = await go.readLine();
    client.verify(hexToBytes(confirmBHex));

    const goKeyHex = await go.readLine();
    const result = await go.wait();
    assert.strictEqual(result.exitCode, 0, `Go stderr: ${result.stderr}`);

    const tsKeyHex = bytesToHex(client.sessionKey());
    assert.strictEqual(tsKeyHex, goKeyHex, "session keys must match");
  });
});
