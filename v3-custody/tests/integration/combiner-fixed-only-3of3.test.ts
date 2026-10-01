import { describe, expect, it } from "vitest";
import { combineAndDecrypt } from "../../src/combiner/index.js";
import { makeFixture, PLAINTEXT } from "./combiner-testkit.js";

describe("combiner FIXED_ONLY 3-of-3", () => {
  it("reconstructs file_key from Lit + G3 + G4 and decrypts payload", () => {
    const result = combineAndDecrypt(makeFixture());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.plaintext).toEqual(PLAINTEXT);
      expect(result.artifactDigest).toMatch(/^0x[0-9a-f]{64}$/);
    }
  });
});
