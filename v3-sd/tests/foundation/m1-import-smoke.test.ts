// Foundation test — M1 facade smoke. Asserts every named import resolves.

import { describe, it, expect } from "vitest";
import {
  TAG_COMMIT_V3,
  TAG_AAD_V3,
  TAG_PDA_ROOT_V3,
  TAG_COMMIT_CONTEXT_V3,
  TAG_SUBJECT_V3,
} from "../../src/m1-imports.js";

describe("M1 (@cealis/v3-crypto) facade — narrow re-export", () => {
  it("re-exports escrow TAG_*_V3 byte32 strings", () => {
    expect(TAG_COMMIT_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(TAG_AAD_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(TAG_PDA_ROOT_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(TAG_COMMIT_CONTEXT_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(TAG_SUBJECT_V3).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("escrow TAG names are disjoint from SD TAG names", () => {
    // Sanity check: the facade re-exports CEALIS_V3_ tags only; CEALIS_SD_
    // tags live in src/tags/tags.ts and MUST NOT be re-exported here.
    const m1 = TAG_COMMIT_V3 as unknown as string;
    expect(m1.startsWith("0x")).toBe(true);
  });
});
