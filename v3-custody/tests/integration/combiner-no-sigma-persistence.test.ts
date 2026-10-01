import { describe, expect, it } from "vitest";
import { combineAndDecrypt } from "../../src/index.js";
import { makeFixture } from "./combiner-testkit.js";

describe("combiner sigma zeroization", () => {
  it("zeroizes caller-provided sigma buffers after combine", () => {
    const input = makeFixture();
    const sigmaRefs = input.sigmas.evidence.map((evidence) => evidence.sigmaBytes);
    const result = combineAndDecrypt(input);
    expect(result.ok).toBe(true);
    for (const sigma of sigmaRefs) {
      expect(Array.from(sigma)).toEqual(new Array(sigma.length).fill(0));
    }
  });
});
