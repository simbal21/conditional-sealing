// Foundation test — RETIRED tag absent.
//
// §3.4 line 410: TAG_SD_REVOCATION_V3 is RETIRED in Phase 2b. `disclosure_id`
// (§D.6 line 1818) is the unified Claim-proof policy handle keyed under
// `TAG_SD_COMMIT_V3`.
//
// Negative test: assert NONE of the retired tag names appear in TAG_SD.

import { describe, it, expect } from "vitest";
import { TAG_SD, RETIRED_SD_TAGS, SD_TAG_LABELS } from "../../src/tags/tags.js";

describe("RETIRED SD tags (negative catalog, §3.4)", () => {
  it("TAG_SD_REVOCATION_V3 is NOT present in TAG_SD", () => {
    expect(Object.keys(TAG_SD)).not.toContain("TAG_SD_REVOCATION_V3");
    expect(Object.keys(SD_TAG_LABELS)).not.toContain("TAG_SD_REVOCATION_V3");
  });

  it("every RETIRED tag name is absent from active TAG_SD catalog", () => {
    for (const retired of RETIRED_SD_TAGS) {
      expect(Object.keys(TAG_SD)).not.toContain(retired);
      expect(Object.keys(SD_TAG_LABELS)).not.toContain(retired);
    }
  });

  it("retired catalog includes the 4 known-stale aliases", () => {
    expect(RETIRED_SD_TAGS).toContain("TAG_SD_REVOCATION_V3");
    expect(RETIRED_SD_TAGS).toContain("TAG_SD_FIELD_COMMITMENT_V3");
    expect(RETIRED_SD_TAGS).toContain("TAG_SD_MERKLE_LEAF_V3");
    expect(RETIRED_SD_TAGS).toContain("TAG_SD_BUNDLE_V3");
  });
});
