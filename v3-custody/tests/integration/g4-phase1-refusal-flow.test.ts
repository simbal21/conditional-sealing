import { describe, expect, it } from "vitest";
import { RefusalCode } from "../../src/types/refusal.js";
import {
  REFUSAL_CODE_COUNT,
  isAdvisory,
  isBlocking,
  isEncryptedReasonMode,
  validateAdvisory,
  validateBlocking,
} from "../../src/g4-shared/refusal-runtime-validate.js";

describe("G4 Phase 1 refusal flow", () => {
  it("covers all 10 refusal codes", () => {
    expect(REFUSAL_CODE_COUNT).toBe(10);
    for (let code = RefusalCode.LegalCompel; code <= RefusalCode.OracleDeprecated; code++) {
      expect(isBlocking(code)).toBe(true);
      expect(() => validateBlocking(code)).not.toThrow();
    }
    expect(isAdvisory(RefusalCode.OptOutActive)).toBe(true);
    expect(() => validateAdvisory(RefusalCode.OptOutActive)).not.toThrow();
  });

  it("marks only 0x02 and 0x03 as encrypted-reason mode", () => {
    expect(isEncryptedReasonMode(RefusalCode.Art17Erasure)).toBe(true);
    expect(isEncryptedReasonMode(RefusalCode.Art18Restriction)).toBe(true);
    expect(isEncryptedReasonMode(RefusalCode.LegalCompel)).toBe(false);
    expect(isEncryptedReasonMode(RefusalCode.OptOutActive)).toBe(false);
  });
});
