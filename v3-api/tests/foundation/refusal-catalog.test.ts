import { describe, it, expect } from "vitest";
import {
  RefusalCode,
  REFUSAL_CODE_COUNT,
  REASON_VISIBILITY,
  REASON_LABEL,
  isBlockingRefusal,
  isEncryptedReason,
  asRefusalCode,
  formatRefusalCodeHex,
} from "../../src/types/refusal.js";

describe("G4 refusal code catalog (S2-5 §10.4 + S2-2 §14 — 10 verbatim)", () => {
  it("locks exactly 10 refusal codes (0x01 through 0x0A)", () => {
    expect(REFUSAL_CODE_COUNT).toBe(10);
    expect(Object.keys(RefusalCode).length).toBe(10);
  });

  it("codes are 0x01..0x0A inclusive", () => {
    const values = Object.values(RefusalCode);
    expect(values).toContain(0x01);
    expect(values).toContain(0x02);
    expect(values).toContain(0x03);
    expect(values).toContain(0x04);
    expect(values).toContain(0x05);
    expect(values).toContain(0x06);
    expect(values).toContain(0x07);
    expect(values).toContain(0x08);
    expect(values).toContain(0x09);
    expect(values).toContain(0x0a);
  });

  it("0x02 and 0x03 are encrypted; others plaintext", () => {
    expect(REASON_VISIBILITY[RefusalCode.LegalCompel]).toBe("plaintext");
    expect(REASON_VISIBILITY[RefusalCode.Art17Erasure]).toBe("encrypted");
    expect(REASON_VISIBILITY[RefusalCode.Art18Restriction]).toBe("encrypted");
    expect(REASON_VISIBILITY[RefusalCode.IntegrityFail]).toBe("plaintext");
    expect(REASON_VISIBILITY[RefusalCode.ChainMismatch]).toBe("plaintext");
    expect(REASON_VISIBILITY[RefusalCode.PluginDeprecated]).toBe("plaintext");
    expect(REASON_VISIBILITY[RefusalCode.AuthorityDeprecated]).toBe("plaintext");
    expect(REASON_VISIBILITY[RefusalCode.DslDeprecated]).toBe("plaintext");
    expect(REASON_VISIBILITY[RefusalCode.OracleDeprecated]).toBe("plaintext");
    expect(REASON_VISIBILITY[RefusalCode.OptOutActive]).toBe("plaintext");
  });

  it("0x0A is advisory (non-blocking); all others blocking", () => {
    expect(isBlockingRefusal(RefusalCode.OptOutActive)).toBe(false);
    expect(isBlockingRefusal(RefusalCode.LegalCompel)).toBe(true);
    expect(isBlockingRefusal(RefusalCode.Art17Erasure)).toBe(true);
    expect(isBlockingRefusal(RefusalCode.Art18Restriction)).toBe(true);
    expect(isBlockingRefusal(RefusalCode.IntegrityFail)).toBe(true);
    expect(isBlockingRefusal(RefusalCode.ChainMismatch)).toBe(true);
    expect(isBlockingRefusal(RefusalCode.PluginDeprecated)).toBe(true);
    expect(isBlockingRefusal(RefusalCode.AuthorityDeprecated)).toBe(true);
    expect(isBlockingRefusal(RefusalCode.DslDeprecated)).toBe(true);
    expect(isBlockingRefusal(RefusalCode.OracleDeprecated)).toBe(true);
  });

  it("isEncryptedReason matches REASON_VISIBILITY", () => {
    expect(isEncryptedReason(RefusalCode.Art17Erasure)).toBe(true);
    expect(isEncryptedReason(RefusalCode.Art18Restriction)).toBe(true);
    expect(isEncryptedReason(RefusalCode.LegalCompel)).toBe(false);
    expect(isEncryptedReason(RefusalCode.OptOutActive)).toBe(false);
  });

  it("REASON_LABEL strings match §10.4 enum naming", () => {
    expect(REASON_LABEL[RefusalCode.Art18Restriction]).toBe("art_18_restriction");
    expect(REASON_LABEL[RefusalCode.Art17Erasure]).toBe("art_17_erasure");
    expect(REASON_LABEL[RefusalCode.LegalCompel]).toBe("legal_compel");
    expect(REASON_LABEL[RefusalCode.OptOutActive]).toBe("opt_out_active");
  });

  it("asRefusalCode validates 0x01-0x0A range", () => {
    expect(asRefusalCode(0x01)).toBe(0x01);
    expect(asRefusalCode(0x0a)).toBe(0x0a);
    expect(() => asRefusalCode(0x00)).toThrow();
    expect(() => asRefusalCode(0x0b)).toThrow();
  });

  it("formatRefusalCodeHex produces lowercase two-digit hex per §10.4 line 1037", () => {
    expect(formatRefusalCodeHex(RefusalCode.LegalCompel)).toBe("0x01");
    expect(formatRefusalCodeHex(RefusalCode.Art18Restriction)).toBe("0x03");
    expect(formatRefusalCodeHex(RefusalCode.OptOutActive)).toBe("0x0a");
  });
});
