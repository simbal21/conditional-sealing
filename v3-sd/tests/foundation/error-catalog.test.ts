// Foundation test — 16-entry ERR_SD_* error catalog per §1.3 lines 186-202.

import { describe, it, expect } from "vitest";
import {
  SdErrorCode,
  SD_ERROR_TRIGGER_TABLE,
  SD_ERROR_COUNT,
} from "../../src/errors/codes.js";

describe("ERR_SD_* error catalog (§1.3)", () => {
  it("contains exactly 16 entries", () => {
    expect(Object.keys(SdErrorCode).length).toBe(16);
    expect(SD_ERROR_COUNT).toBe(16);
    expect(SD_ERROR_TRIGGER_TABLE.length).toBe(16);
  });

  it("every code value starts with ERR_SD_", () => {
    for (const v of Object.values(SdErrorCode)) {
      expect(v.startsWith("ERR_SD_")).toBe(true);
    }
  });

  it("contains the 16 expected codes verbatim from §1.3 lines 186-202", () => {
    const expected = [
      "ERR_SD_CONFIG_MODE_B_INCOMPATIBLE",
      "ERR_SD_FIELD_POLICY_UNKNOWN",
      "ERR_SD_FIELD_ENCODING_INVALID",
      "ERR_SD_SALT_DERIVATION_FAIL",
      "ERR_SD_SALT_ESCAPED_TEE",
      "ERR_SD_COMMITMENT_MISMATCH",
      "ERR_SD_MERKLE_PATH_INVALID",
      "ERR_SD_ROOT_BINDING_MISSING",
      "ERR_SD_PROOF_INVALID",
      "ERR_SD_PUBLIC_INPUT_MISMATCH",
      "ERR_SD_CLAIM_EXPIRED",
      "ERR_SD_CLAIM_REVOKED",
      "ERR_SD_PARTNER_MISMATCH",
      "ERR_SD_PDA_MISMATCH",
      "ERR_SD_AUTHORIZATION_MISMATCH",
      "ERR_SD_ONBOARDING_PARTIAL_FAILURE",
    ].sort();
    const actual = Object.values(SdErrorCode).slice().sort();
    expect(actual).toEqual(expected);
  });

  it("every trigger row has a non-empty trigger string", () => {
    for (const row of SD_ERROR_TRIGGER_TABLE) {
      expect(row.trigger.length).toBeGreaterThan(0);
    }
  });
});
