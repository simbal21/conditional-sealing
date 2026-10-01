import { describe, it, expect } from "vitest";
import {
  G4RefusalCode,
  G4_REFUSAL_CODES,
  refusalClass,
  isBlocking,
  reasonRequiresEncryption,
} from "../../src/types/refusal-codes.js";

/**
 * Drift catch #9: 10 G4 refusal reason codes in 3 classes per WP §N +
 * S2-2 lines 1466–1472 + S2-3 §5 lines 583–589.
 *   - Per-subject (blocking, per-commit): 0x01..0x05
 *   - Class-wide deprecation (blocking, separate ops path): 0x06..0x09
 *   - Advisory (non-blocking): 0x0A
 */
describe("G4 refusal-code catalog (WP §N + S2-2 + S2-3)", () => {
  it("has exactly 10 codes", () => {
    expect(G4_REFUSAL_CODES).toHaveLength(10);
  });

  it("codes are byte values 0x01..0x0A consecutive", () => {
    const sorted = [...G4_REFUSAL_CODES].sort((a, b) => a - b);
    expect(sorted).toEqual([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a]);
  });

  it("classifies 0x01..0x05 as per_subject", () => {
    for (const code of [0x01, 0x02, 0x03, 0x04, 0x05] as const) {
      expect(refusalClass(code as G4RefusalCode)).toBe("per_subject");
      expect(isBlocking(code as G4RefusalCode)).toBe(true);
    }
  });

  it("classifies 0x06..0x09 as class_wide", () => {
    for (const code of [0x06, 0x07, 0x08, 0x09] as const) {
      expect(refusalClass(code as G4RefusalCode)).toBe("class_wide");
      expect(isBlocking(code as G4RefusalCode)).toBe(true);
    }
  });

  it("classifies 0x0A as advisory (non-blocking)", () => {
    expect(refusalClass(G4RefusalCode.OPT_OUT_ACTIVE)).toBe("advisory");
    expect(isBlocking(G4RefusalCode.OPT_OUT_ACTIVE)).toBe(false);
  });

  it("0x02 and 0x03 default to encrypted-reason mode (§0.9)", () => {
    expect(reasonRequiresEncryption(G4RefusalCode.ART_17)).toBe(true);
    expect(reasonRequiresEncryption(G4RefusalCode.ART_18)).toBe(true);
    // Other codes do not require encryption by default
    expect(reasonRequiresEncryption(G4RefusalCode.LEGAL_COMPEL)).toBe(false);
    expect(reasonRequiresEncryption(G4RefusalCode.INTEGRITY_FAIL)).toBe(false);
    expect(reasonRequiresEncryption(G4RefusalCode.OPT_OUT_ACTIVE)).toBe(false);
  });
});
