// Foundation test — §11.5 6-code revocation reason catalog (lines 1099-1106).

import { describe, it, expect } from "vitest";
import {
  SD_REVOCATION_REASON,
  SD_REVOCATION_REASON_COUNT,
  SD_REVOCATION_REASON_DOC_BLOCK,
  type SdRevocationReasonCode,
} from "../../src/types/sd-revocation.js";

describe("§11.5 SD revocation reason codes (6 entries)", () => {
  it("contains exactly 6 entries", () => {
    expect(Object.keys(SD_REVOCATION_REASON).length).toBe(6);
    expect(SD_REVOCATION_REASON_COUNT).toBe(6);
  });

  it("verbatim 0x01..0x06 mapping (§11.5 lines 1099-1106)", () => {
    expect(SD_REVOCATION_REASON.SUBJECT_ERASURE_OR_RESTRICTION).toBe(0x01);
    expect(SD_REVOCATION_REASON.PDA_SHRED_FINALIZED).toBe(0x02);
    expect(SD_REVOCATION_REASON.PARTNER_POLICY_WITHDRAWAL).toBe(0x03);
    expect(SD_REVOCATION_REASON.VERIFIER_OR_CIRCUIT_DEPRECATION).toBe(0x04);
    expect(SD_REVOCATION_REASON.TEE_INTEGRITY_INCIDENT).toBe(0x05);
    expect(SD_REVOCATION_REASON.CLAIM_UNDER_WRONG_PDA_OR_CONFIG).toBe(0x06);
  });

  it("0x07+ codes are unmapped", () => {
    const known = new Set<SdRevocationReasonCode>(Object.values(SD_REVOCATION_REASON));
    for (let i = 0x07; i <= 0xff; i++) {
      expect(known.has(i as SdRevocationReasonCode)).toBe(false);
    }
  });

  it("Solidity doc-block embeds all 6 reason codes", () => {
    expect(SD_REVOCATION_REASON_DOC_BLOCK).toContain("0x01");
    expect(SD_REVOCATION_REASON_DOC_BLOCK).toContain("0x02");
    expect(SD_REVOCATION_REASON_DOC_BLOCK).toContain("0x03");
    expect(SD_REVOCATION_REASON_DOC_BLOCK).toContain("0x04");
    expect(SD_REVOCATION_REASON_DOC_BLOCK).toContain("0x05");
    expect(SD_REVOCATION_REASON_DOC_BLOCK).toContain("0x06");
  });
});
