// Foundation test — TAG_SD_*_V3 catalog. Asserts §3.2 lines 340-351 verbatim.
//
// SD-TAG-001 + SD-TAG-002 conformance.

import { describe, it, expect } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import {
  TAG_SD,
  TAG_SD_COUNT,
  SD_TAG_LABELS,
  type SdTagName,
} from "../../src/tags/tags.js";

describe("TAG_SD_*_V3 catalog (§3.2)", () => {
  it("contains exactly 12 entries (NOT 13)", () => {
    expect(Object.keys(TAG_SD).length).toBe(12);
    expect(TAG_SD_COUNT).toBe(12);
  });

  it("contains exactly the 12 expected names from §3.2 lines 340-351 (verbatim)", () => {
    const expected: ReadonlyArray<SdTagName> = [
      "TAG_SD_COMMIT_V3",
      "TAG_SD_FIELD_ID_V3",
      "TAG_SD_FIELD_V3",
      "TAG_SD_PROOF_V3",
      "TAG_SD_MERKLE_V3",
      "TAG_SD_SALT_V3",
      "TAG_SD_NULLIFIER_V3",
      "TAG_SD_CLAIM_V3",
      "TAG_SD_CLEARFIELD_V3",
      "TAG_SD_VERIFIER_V3",
      "TAG_SD_PLAN_V3",
      "TAG_SD_SALT_CONTEXT_V3",
    ];
    const actual = (Object.keys(TAG_SD) as SdTagName[]).sort();
    expect(actual).toEqual([...expected].sort());
  });

  it("every digest matches keccak256(utf8(label)) byte-by-byte (§3.1)", () => {
    for (const name of Object.keys(TAG_SD) as SdTagName[]) {
      const label = SD_TAG_LABELS[name];
      const expected = keccak_256(utf8ToBytes(label));
      expect(TAG_SD[name]).toEqual(expected);
    }
  });

  it("every digest is 32 bytes", () => {
    for (const name of Object.keys(TAG_SD) as SdTagName[]) {
      expect(TAG_SD[name].length).toBe(32);
    }
  });

  it("uses CEALIS_SD_ prefix (disjoint from CEALIS_V3_ escrow tags)", () => {
    for (const label of Object.values(SD_TAG_LABELS)) {
      expect(label.startsWith("CEALIS_SD_")).toBe(true);
      expect(label).not.toMatch(/^CEALIS_V3_/);
    }
  });
});
