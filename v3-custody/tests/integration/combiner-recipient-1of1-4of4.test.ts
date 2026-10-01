import { describe, expect, it } from "vitest";
import { combineAndDecrypt } from "../../src/combiner/index.js";
import { makeFixture, PLAINTEXT, profile1of1 } from "./combiner-testkit.js";

describe("combiner RECIPIENT_1_OF_1 4-of-4", () => {
  it("requires the recipient top-level branch and decrypts", () => {
    const result = combineAndDecrypt(makeFixture({ profile: profile1of1() }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });
});
