// Foundation test — composed wrapper caps (§6.6 lines 671-673).
//
// max depth 8, max leaves 32, max fields 16.
//
// Plus: claim_type code 5 maps to "composed" (§I.3 line 2224).

import { describe, it, expect } from "vitest";
import { COMPOSED_CAPS } from "../../src/types/composed.js";
import { CLAIM_TYPE_CODE } from "../../src/types/sd-claim-config.js";

describe("composed wrapper caps + claim_type code (§6.6 + §I.3)", () => {
  it("MAX_DEPTH = 8", () => {
    expect(COMPOSED_CAPS.MAX_DEPTH).toBe(8);
  });

  it("MAX_LEAVES = 32", () => {
    expect(COMPOSED_CAPS.MAX_LEAVES).toBe(32);
  });

  it("MAX_FIELDS = 16", () => {
    expect(COMPOSED_CAPS.MAX_FIELDS).toBe(16);
  });

  it("CLAIM_TYPE_CODE.COMPOSED = 5 (§I.3 line 2224)", () => {
    expect(CLAIM_TYPE_CODE.COMPOSED).toBe(5);
  });
});
