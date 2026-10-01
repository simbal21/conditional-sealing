import { describe, expect, it } from "vitest";
import { combineAndDecrypt } from "../../src/combiner/index.js";
import { makeFixture, PLAINTEXT, profileKofN } from "./combiner-testkit.js";

describe("combiner RECIPIENT_K_OF_N nested profile", () => {
  it("reconstructs recipient aggregate from k conditional shares then decrypts top-level 4-of-4", () => {
    const result = combineAndDecrypt(makeFixture({ profile: profileKofN() }));
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });
});
