// Foundation test — CUSTODY_ERR_* operational error catalog.
//
// Asserts the catalog matches S2-3 §13.1 verbatim (37 codes — see
// `run-summary-A.md` for the §13.1 vs PHASE-PLAN "38" discrepancy
// surfaced during Phase A).

import { describe, it, expect } from "vitest";

import {
  CUSTODY_ERROR_CODES,
  CustodyError,
  isCustodyErrorCode,
  wrapS2_1Error,
  composeCustodyError,
  type CustodyErrorCode,
} from "../../src/errors.js";

describe("CUSTODY_ERR_* operational error catalog (S2-3 §13.1)", () => {
  it("contains exactly 37 codes (verbatim from §13.1)", () => {
    const keys = Object.keys(CUSTODY_ERROR_CODES);
    expect(keys.length).toBe(37);
  });

  it("every key === its value (catalog discipline)", () => {
    for (const [k, v] of Object.entries(CUSTODY_ERROR_CODES)) {
      expect(k).toBe(v);
    }
  });

  it("includes every §13.1-named code (verbatim spelling)", () => {
    // §13.1 verbatim list — order irrelevant for `Set` equality but
    // every name must be present.
    const expected = [
      "CUSTODY_ERR_FINALITY_PENDING",
      "CUSTODY_ERR_CHALLENGE_WINDOW_OPEN",
      "CUSTODY_ERR_GATES_CANNOT_SIGN",
      "CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE",
      "CUSTODY_ERR_LIT_ASSIGNMENT_MISSING",
      "CUSTODY_ERR_LIT_ASSIGNMENT_MISMATCH",
      "CUSTODY_ERR_LIT_ACC_REJECTED",
      "CUSTODY_ERR_LIT_DCAP_INVALID",
      "CUSTODY_ERR_LIT_QUOTE_REPLAY",
      "CUSTODY_ERR_LIT_SIG_INVALID",
      "CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED",
      "CUSTODY_ERR_DCIPHER_REGISTRY_UNAVAILABLE",
      "CUSTODY_ERR_DCIPHER_EPOCH_MISMATCH",
      "CUSTODY_ERR_DCIPHER_THRESHOLD_NOT_MET",
      "CUSTODY_ERR_DCIPHER_TOMBSTONED",
      "CUSTODY_ERR_DCIPHER_SIG_INVALID",
      "CUSTODY_ERR_DRAND_ROUND_PENDING",
      "CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE",
      "CUSTODY_ERR_DRAND_CHAIN_MISMATCH",
      "CUSTODY_ERR_DRAND_ROUND_MISMATCH",
      "CUSTODY_ERR_DRAND_SIG_INVALID",
      "CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE",
      "CUSTODY_ERR_G4_PHASE_MISMATCH",
      "CUSTODY_ERR_G4_DCAP_INVALID",
      "CUSTODY_ERR_G4_REFUSED",
      "CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION",
      "CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL",
      "CUSTODY_ERR_GATE_PUBKEY_MISMATCH",
      "CUSTODY_ERR_GATE_PUBKEY_ROTATION_MID_FLIGHT",
      "CUSTODY_ERR_SHRED_STATE_BLOCKED",
      "CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET",
      "CUSTODY_ERR_AEAD_FAIL",
      "CUSTODY_ERR_SD_ONBOARDING_PARTIAL_FAILURE",
      "CUSTODY_ERR_COMBINER_BINARY_MISMATCH",
      "CUSTODY_ERR_SIGMA_REDACTION_BREACH",
      "CUSTODY_ERR_SIGMA_CONFIDENTIALITY_BREACH",
      "CUSTODY_ERR_MODE3_RESERVED",
    ];
    const actual = new Set(Object.keys(CUSTODY_ERROR_CODES));
    for (const name of expected) {
      expect(actual.has(name), `Missing §13.1 code: ${name}`).toBe(true);
    }
    expect(actual.size).toBe(expected.length);
  });

  it("isCustodyErrorCode() type-guard works", () => {
    expect(isCustodyErrorCode("CUSTODY_ERR_LIT_SIG_INVALID")).toBe(true);
    expect(isCustodyErrorCode("CUSTODY_ERR_NOT_A_REAL_CODE")).toBe(false);
    expect(isCustodyErrorCode("")).toBe(false);
  });

  it("CustodyError carries code + sub-codes + metadata", () => {
    const code: CustodyErrorCode = "CUSTODY_ERR_LIT_SIG_INVALID";
    const err = new CustodyError(code, "test failure", {
      subCodes: ["ERR_SIGMA_LIT_PUBKEY_LENGTH"],
      metadata: { authorizationId: "0x1234", block: 100n },
    });
    expect(err.code).toBe(code);
    expect(err.subCodes).toEqual(["ERR_SIGMA_LIT_PUBKEY_LENGTH"]);
    expect(err.metadata).toEqual({ authorizationId: "0x1234", block: 100n });
    expect(err.message).toContain(code);
    expect(err.message).toContain("test failure");
    expect(err.name).toBe("CustodyError");
  });

  it("toLogObject() returns JSON-safe summary (no cause/stack)", () => {
    const err = new CustodyError("CUSTODY_ERR_LIT_SIG_INVALID", "x", {
      subCodes: ["ERR_X"],
      metadata: { foo: "bar" },
    });
    const obj = err.toLogObject();
    expect(obj.code).toBe("CUSTODY_ERR_LIT_SIG_INVALID");
    expect(obj.subCodes).toEqual(["ERR_X"]);
    expect(obj.metadata).toEqual({ foo: "bar" });
    expect((obj as { cause?: unknown }).cause).toBeUndefined();
  });

  it("wrapS2_1Error() composes correctly", () => {
    const err = wrapS2_1Error(
      "ERR_SIGMA_LIT_PUBKEY_LENGTH",
      "CUSTODY_ERR_LIT_SIG_INVALID",
      "pubkey length mismatch",
    );
    expect(err.code).toBe("CUSTODY_ERR_LIT_SIG_INVALID");
    expect(err.subCodes).toEqual(["ERR_SIGMA_LIT_PUBKEY_LENGTH"]);
  });

  it("composeCustodyError() supports multiple sub-codes", () => {
    const err = composeCustodyError(
      "CUSTODY_ERR_G4_REFUSED",
      ["ERR_G4_REFUSAL_REASON_INVALID", "ERR_G4_REFUSAL_BLOB_DECODE"],
      "compound refusal",
      { authorizationId: "0xabc" },
    );
    expect(err.subCodes.length).toBe(2);
    expect(err.metadata).toEqual({ authorizationId: "0xabc" });
  });

  it("includes the deprecated alias CUSTODY_ERR_SIGMA_CONFIDENTIALITY_BREACH", () => {
    // §13.1 explicitly notes "deprecated compatibility alias" but
    // keeps it in the catalog so old logs are still parseable.
    expect(CUSTODY_ERROR_CODES.CUSTODY_ERR_SIGMA_CONFIDENTIALITY_BREACH).toBe(
      "CUSTODY_ERR_SIGMA_CONFIDENTIALITY_BREACH",
    );
    expect(CUSTODY_ERROR_CODES.CUSTODY_ERR_SIGMA_REDACTION_BREACH).toBe(
      "CUSTODY_ERR_SIGMA_REDACTION_BREACH",
    );
  });
});
