import { describe, expect, it } from "vitest";
import { computeContentHashHex } from "../../src/pda/content-hash.js";

describe("§13.5 content-addressed template immutability", () => {
  it("is deterministic and changes when canonical template bytes change", () => {
    const template = { b: 2, a: { c: true } };
    const first = computeContentHashHex(template);
    const second = computeContentHashHex({ a: { c: true }, b: 2 });
    const patched = computeContentHashHex({ a: { c: false }, b: 2 });

    expect(first).toBe(second);
    expect(patched).not.toBe(first);
    expect(first).toBe(computeContentHashHex(template));
  });
});
