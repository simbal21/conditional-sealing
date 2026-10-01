import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES } from "../../src/errors.js";
import { assertG4Phase1Eligible, checkG4Phase1Eligibility } from "../../src/g4-phase1/eligibility-guard.js";

describe("G4 Phase 1 PDA eligibility guard", () => {
  it("accepts dev-scaffold PDA under Phase 1", () => {
    expect(checkG4Phase1Eligibility({ phase: 1, pdaClass: "dev-scaffold" }).ok).toBe(true);
  });

  it("rejects partner-ready PDA under Phase 1", () => {
    expect(() => assertG4Phase1Eligible({ phase: 1, pdaClass: "partner-ready" })).toThrow(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE,
    );
  });

  it("rejects legal-effect PDA under Phase 1", () => {
    expect(() => assertG4Phase1Eligible({ phase: 1, pdaType: "kyc_lending" })).toThrow(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE,
    );
  });
});
