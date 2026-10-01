// Foundation test — §15.2 failure-mode 7-row table.
//
// Asserts every row has `escrowEffect === "none"` (NORMATIVE asymmetric
// isolation).

import { describe, it, expect } from "vitest";
import {
  SD_FAILURE_TABLE,
  SD_FAILURE_STAGES,
  type SdFailureStage,
} from "../../src/types/failure-modes.js";

describe("§15.2 7-row failure-mode table", () => {
  it("exactly 7 stages, in canonical order", () => {
    const expected: ReadonlyArray<SdFailureStage> = [
      "schema_validation",
      "salt_derivation",
      "commitment_build",
      "proving",
      "response_assembly",
      "partner_verify",
      "revocation_check",
    ];
    expect(SD_FAILURE_STAGES).toEqual(expected);
  });

  it("table covers all 7 stages exactly once", () => {
    expect(SD_FAILURE_TABLE.length).toBe(7);
    const stages = SD_FAILURE_TABLE.map((row) => row.stage);
    const stageSet = new Set(stages);
    expect(stageSet.size).toBe(7);
  });

  it("EVERY row has escrowEffect = 'none' (NORMATIVE asymmetric isolation)", () => {
    for (const row of SD_FAILURE_TABLE) {
      expect(row.escrowEffect).toBe("none");
    }
  });

  it("every row has a non-empty sdEffect description", () => {
    for (const row of SD_FAILURE_TABLE) {
      expect(row.sdEffect.length).toBeGreaterThan(0);
    }
  });

  it("revocation_check row is included (PHASE-PLAN §0 item #10 enforcement)", () => {
    const row = SD_FAILURE_TABLE.find((r) => r.stage === "revocation_check");
    expect(row).toBeDefined();
    expect(row?.escrowEffect).toBe("none");
  });
});
