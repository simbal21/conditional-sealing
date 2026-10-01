import { describe, expect, it } from "vitest";
import {
  bytesEqual,
  bytesToHex,
  bytesToHex32,
  combineAndDecrypt,
  hexToBytes,
  isZero32,
  jcsCanonicalize,
  metadataBigint,
} from "../../src/index.js";
import { makeFixture } from "./combiner-testkit.js";

describe("combiner adversarial redaction", () => {
  it("does not echo sigma-like bytes from hostile metadata into failure results", () => {
    const base = makeFixture();
    const raw = base.sigmas.evidence[0]!.sigmaBytes;
    const hex = bytesToHex(raw);
    const decimal = Array.from(raw).join(",");
    const evidence = base.sigmas.evidence.map((item, index) =>
      index === 0
        ? {
            ...item,
            metadata: {
              ...item.metadata,
              verified: "false",
              verifyCode: `ERR_${hex}_${decimal}`,
            },
          }
        : item,
    );
    const result = combineAndDecrypt({ ...base, sigmas: { ...base.sigmas, evidence } });
    const serialized = JSON.stringify(result);
    expect(result.ok).toBe(false);
    expect(serialized).not.toContain(hex);
    expect(serialized).not.toContain(decimal);
    expect(serialized).not.toContain(Buffer.from(raw).toString("base64"));
  });

  it("keeps combiner utility validation explicit", () => {
    expect(() => bytesToHex32(new Uint8Array([1, 2]))).toThrow("expected 32 bytes");
    expect(() => hexToBytes("0xabc")).toThrow("even number of nibbles");
    expect(bytesEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
    expect(isZero32(new Uint8Array(31))).toBe(false);
    expect(metadataBigint({ n: 1n }, "n")).toBe(1n);
    expect(jcsCanonicalize({ b: 2, a: 1 })).toEqual(new TextEncoder().encode('{"a":1,"b":2}'));
  });
});
