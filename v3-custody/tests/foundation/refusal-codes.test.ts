// Foundation test — 10-code refusal enum (S2-3 §7.7 + M2
// G4RefusalRegistry contract constants).
//
// Asserts:
//   - exactly 10 codes
//   - isBlocking(0x01..0x09) === true
//   - isBlocking(0x0A) === false
//   - isAdvisory(0x0A) === true
//   - isEncryptedReasonMode(0x02) === true
//   - isEncryptedReasonMode(0x03) === true
//   - isEncryptedReasonMode(any other) === false

import { describe, it, expect } from "vitest";

import {
  REFUSAL_CODES,
  REFUSAL_CODE_COUNT,
  RefusalCode,
  isBlocking,
  isAdvisory,
  isEncryptedReasonMode,
  validateBlocking,
  validateAdvisory,
} from "../../src/refusal/codes.js";
import { CustodyError } from "../../src/errors.js";

describe("Refusal-code helpers (S2-3 §7.7)", () => {
  it("has exactly 10 codes", () => {
    expect(REFUSAL_CODE_COUNT).toBe(10);
    expect(Object.keys(REFUSAL_CODES).length).toBe(10);
  });

  it("matches M2 contract constants byte-for-byte", () => {
    expect(REFUSAL_CODES.REASON_LEGAL_COMPEL).toBe(0x01);
    expect(REFUSAL_CODES.REASON_ART_17_ERASURE).toBe(0x02);
    expect(REFUSAL_CODES.REASON_ART_18_RESTRICTION).toBe(0x03);
    expect(REFUSAL_CODES.REASON_INTEGRITY_FAIL).toBe(0x04);
    expect(REFUSAL_CODES.REASON_CHAIN_MISMATCH).toBe(0x05);
    expect(REFUSAL_CODES.REASON_PLUGIN_DEPRECATED).toBe(0x06);
    expect(REFUSAL_CODES.REASON_AUTHORITY_DEPRECATED).toBe(0x07);
    expect(REFUSAL_CODES.REASON_DSL_DEPRECATED).toBe(0x08);
    expect(REFUSAL_CODES.REASON_ORACLE_DEPRECATED).toBe(0x09);
    expect(REFUSAL_CODES.REASON_OPT_OUT_ACTIVE).toBe(0x0a);
  });

  it("RefusalCode typed enum matches map values", () => {
    expect(RefusalCode.LegalCompel).toBe(0x01);
    expect(RefusalCode.Art17Erasure).toBe(0x02);
    expect(RefusalCode.Art18Restriction).toBe(0x03);
    expect(RefusalCode.IntegrityFail).toBe(0x04);
    expect(RefusalCode.ChainMismatch).toBe(0x05);
    expect(RefusalCode.PluginDeprecated).toBe(0x06);
    expect(RefusalCode.AuthorityDeprecated).toBe(0x07);
    expect(RefusalCode.DslDeprecated).toBe(0x08);
    expect(RefusalCode.OracleDeprecated).toBe(0x09);
    expect(RefusalCode.OptOutActive).toBe(0x0a);
  });

  describe("isBlocking()", () => {
    it("returns true for 0x01..0x09", () => {
      for (let c = 0x01; c <= 0x09; c++) {
        expect(isBlocking(c), `code 0x${c.toString(16)}`).toBe(true);
      }
    });
    it("returns false for 0x0A (advisory)", () => {
      expect(isBlocking(0x0a)).toBe(false);
    });
    it("returns false for out-of-range values", () => {
      expect(isBlocking(0x00)).toBe(false);
      expect(isBlocking(0x0b)).toBe(false);
      expect(isBlocking(255)).toBe(false);
    });
  });

  describe("isAdvisory()", () => {
    it("returns true ONLY for 0x0A", () => {
      expect(isAdvisory(0x0a)).toBe(true);
    });
    it("returns false for all blocking codes", () => {
      for (let c = 0x01; c <= 0x09; c++) {
        expect(isAdvisory(c)).toBe(false);
      }
    });
    it("returns false for out-of-range", () => {
      expect(isAdvisory(0x00)).toBe(false);
      expect(isAdvisory(0x0b)).toBe(false);
    });
  });

  describe("isEncryptedReasonMode()", () => {
    it("returns true ONLY for 0x02 (Art. 17) and 0x03 (Art. 18)", () => {
      expect(isEncryptedReasonMode(0x02)).toBe(true);
      expect(isEncryptedReasonMode(0x03)).toBe(true);
    });
    it("returns false for all other codes", () => {
      expect(isEncryptedReasonMode(0x01)).toBe(false);
      expect(isEncryptedReasonMode(0x04)).toBe(false);
      expect(isEncryptedReasonMode(0x05)).toBe(false);
      expect(isEncryptedReasonMode(0x06)).toBe(false);
      expect(isEncryptedReasonMode(0x07)).toBe(false);
      expect(isEncryptedReasonMode(0x08)).toBe(false);
      expect(isEncryptedReasonMode(0x09)).toBe(false);
      expect(isEncryptedReasonMode(0x0a)).toBe(false);
      expect(isEncryptedReasonMode(0x00)).toBe(false);
    });
  });

  describe("validateBlocking()", () => {
    it("does not throw for 0x01..0x09", () => {
      for (let c = 0x01; c <= 0x09; c++) {
        expect(() => validateBlocking(c)).not.toThrow();
      }
    });
    it("throws CustodyError(CUSTODY_ERR_G4_REFUSED) for 0x0A", () => {
      expect(() => validateBlocking(0x0a)).toThrow(CustodyError);
    });
    it("throws for 0x00 and out-of-range", () => {
      expect(() => validateBlocking(0x00)).toThrow(CustodyError);
      expect(() => validateBlocking(0xff)).toThrow(CustodyError);
    });
  });

  describe("validateAdvisory()", () => {
    it("does not throw for 0x0A", () => {
      expect(() => validateAdvisory(0x0a)).not.toThrow();
    });
    it("throws for all blocking codes", () => {
      for (let c = 0x01; c <= 0x09; c++) {
        expect(() => validateAdvisory(c)).toThrow(CustodyError);
      }
    });
  });
});
