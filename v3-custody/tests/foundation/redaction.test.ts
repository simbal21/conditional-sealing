// Foundation test — σ redaction discipline (S2-3 §1.2 / §1.4 / §14.1).
//
// Asserts SigmaBuffer never leaks bytes via:
//   - toString()
//   - JSON.stringify
//   - util.inspect
// Asserts zeroize() actually fills the buffer with zeros.
// Asserts sanitizeLog() strips σ-like fields.

import { describe, it, expect } from "vitest";
import { inspect } from "node:util";

import {
  SigmaBuffer,
  sanitizeLog,
  safeStringify,
  zeroize,
  zeroizeAll,
} from "../../src/redaction/index.js";

const SECRET_HEX = "0x" + "deadbeef".repeat(16); // 64 bytes
const SECRET_BYTES = (() => {
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) out[i] = 0xab;
  return out;
})();

describe("SigmaBuffer redaction discipline (Phase A acceptance gate)", () => {
  it("toString() does not leak σ bytes", () => {
    const buf = new SigmaBuffer(SECRET_BYTES);
    const s = buf.toString();
    expect(s).not.toContain("ab");
    expect(s).not.toContain("AB");
    expect(s).toMatch(/^\[SigmaBuffer length=64 sha256=0x[0-9a-f]{16}…\]$/);
  });

  it("JSON.stringify({sigma}) does not leak σ bytes", () => {
    const buf = new SigmaBuffer(SECRET_BYTES);
    const wrapped = { sigma: buf };
    const s = JSON.stringify(wrapped);
    expect(s).not.toContain("171"); // 0xab as decimal
    expect(s).not.toContain("ab".repeat(8));
    expect(s).toContain("SigmaBuffer");
  });

  it("util.inspect(buf) does not leak σ bytes", () => {
    const buf = new SigmaBuffer(SECRET_BYTES);
    const s = inspect(buf);
    expect(s).not.toContain("ab".repeat(8));
    expect(s).toContain("SigmaBuffer");
  });

  it("util.inspect({sigma: buf}) does not leak σ bytes", () => {
    const buf = new SigmaBuffer(SECRET_BYTES);
    const s = inspect({ sigma: buf });
    expect(s).not.toContain("ab".repeat(8));
  });

  it("unwrap() returns the original bytes (defensive copy)", () => {
    const buf = new SigmaBuffer(SECRET_BYTES);
    const out = buf.unwrap();
    expect(out).toEqual(SECRET_BYTES);
    // Mutating the unwrapped copy doesn't affect the buffer.
    out[0] = 0;
    expect(buf.unwrap()[0]).toBe(0xab);
  });

  it("zeroize() fills the wrapped buffer with zeros", () => {
    const buf = new SigmaBuffer(SECRET_BYTES);
    buf.zeroize();
    expect(() => buf.unwrap()).toThrow(/zeroized/);
  });

  it("toString() reflects zeroized state", () => {
    const buf = new SigmaBuffer(SECRET_BYTES);
    buf.zeroize();
    expect(buf.toString()).toContain("ZEROIZED");
  });

  it("zeroize() is idempotent", () => {
    const buf = new SigmaBuffer(SECRET_BYTES);
    buf.zeroize();
    expect(() => buf.zeroize()).not.toThrow();
  });

  it("zeroize() helper actually zeros a Uint8Array", () => {
    const b = new Uint8Array([1, 2, 3, 4]);
    zeroize(b);
    expect(b).toEqual(new Uint8Array([0, 0, 0, 0]));
  });

  it("zeroizeAll() works on multiple buffers", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5, 6]);
    zeroizeAll(a, b);
    expect(a).toEqual(new Uint8Array([0, 0, 0]));
    expect(b).toEqual(new Uint8Array([0, 0, 0]));
  });
});

describe("sanitizeLog() σ-redaction filter", () => {
  it("redacts a Uint8Array with a σ-like field name AND known σ size", () => {
    const r = sanitizeLog({
      sigma_g4: new Uint8Array(64),
      ok: true,
    });
    expect(r).toEqual({
      sigma_g4: "[REDACTED:sigma]",
      ok: true,
    });
  });

  it("redacts a hex string in a σ-named field", () => {
    const r = sanitizeLog({ sigmaLit: SECRET_HEX });
    expect(r).toEqual({ sigmaLit: "[REDACTED:sigma]" });
  });

  it("replaces SigmaBuffer with opaque digest summary", () => {
    const buf = new SigmaBuffer(SECRET_BYTES);
    const r = sanitizeLog({ payload: buf });
    expect(r).toMatchObject({
      payload: { $sigmaBuffer: expect.stringMatching(/[0-9a-f]+…/), length: 64 },
    });
  });

  it("recurses into nested objects + arrays", () => {
    const r = sanitizeLog({
      results: [
        { sigma: SECRET_HEX, ok: true },
        { sigma: new Uint8Array(96), ok: false },
      ],
    });
    expect(r).toEqual({
      results: [
        { sigma: "[REDACTED:sigma]", ok: true },
        { sigma: "[REDACTED:sigma]", ok: false },
      ],
    });
  });

  it("does NOT redact non-σ fields with similar shape", () => {
    const r = sanitizeLog({
      authorizationId: "0x1234567890abcdef".repeat(4),
      block: 100n,
    }) as { authorizationId: string; block: bigint };
    expect(r.authorizationId).toBe("0x1234567890abcdef".repeat(4));
    expect(r.block).toBe(100n);
  });

  it("safeStringify produces JSON with bigint suffix + redaction", () => {
    const s = safeStringify({ sigma: SECRET_HEX, block: 100n });
    expect(s).toContain('"sigma":"[REDACTED:sigma]"');
    expect(s).toContain('"block":"100n"');
  });

  it("non-σ Uint8Array becomes a length summary", () => {
    const r = sanitizeLog({ pubkey: new Uint8Array(32) });
    expect(r).toEqual({ pubkey: { $bytes: "length=32" } });
  });
});
