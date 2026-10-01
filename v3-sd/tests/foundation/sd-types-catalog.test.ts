// Foundation test — App. I 11 normative data structures.
//
// Asserts:
//   - SD_BUNDLE_VERSION === "s2-7-1.0" (locked literal §I.4)
//   - SD_PLAN_VERSION === 0x0001 (locked literal §I.1)
//   - CLEARTEXT_POLICY_CODE === 1 (locked literal §I.5)
//   - PUBLIC_INPUTS_DECIMAL_REGEX matches decimal-only strings (§I.6 line 2312)
//   - ROOT_BINDING_LEVEL === "commit_AAD" (§I.4)
//   - SD_PROOF_SYSTEM === "plonk-bn254" (§I.9)
//   - SD_REVOCATION_REASON has 6 entries (§11.5)
//   - SD_FAILURE_TABLE has 7 entries all with escrowEffect === "none" (§15.2)
//   - COMPOSED_CAPS: depth=8, leaves=32, fields=16 (§6.6)
//   - CLAIM_TYPE_CODE.COMPOSED === 5 (§I.3 line 2224)

import { describe, it, expect } from "vitest";
import {
  SD_BUNDLE_VERSION,
  ROOT_BINDING_LEVEL,
} from "../../src/types/sd-bundle.js";
import { SD_PLAN_VERSION, MODE_A_INGESTION_MODE_CODE, MODE_B_INGESTION_MODE_CODE } from "../../src/types/sd-plan.js";
import { CLEARTEXT_POLICY_CODE } from "../../src/types/sd-cleartext-item.js";
import { PUBLIC_INPUTS_DECIMAL_REGEX } from "../../src/types/sd-claim-item.js";
import { SD_PROOF_SYSTEM } from "../../src/types/sd-proof.js";
import {
  SD_REVOCATION_REASON,
  SD_REVOCATION_REASON_COUNT,
} from "../../src/types/sd-revocation.js";
import {
  SD_FAILURE_STAGES,
  SD_FAILURE_TABLE,
  SD_FAILURE_STAGE_COUNT,
} from "../../src/types/failure-modes.js";
import {
  COMPOSED_CAPS,
  LEAF_PREDICATE_TYPES,
  LEAF_PREDICATE_COUNT,
} from "../../src/types/predicates.js";
import { CLAIM_TYPE_CODE } from "../../src/types/sd-claim-config.js";
import { CLEARTEXT_OPENING_MODE, CLEARTEXT_OPENING_DEFAULT_MODE } from "../../src/types/cleartext-opening.js";

describe("App. I + cross-spec locked literals", () => {
  it("SD_BUNDLE_VERSION is exactly 's2-7-1.0' (§I.4)", () => {
    expect(SD_BUNDLE_VERSION).toBe("s2-7-1.0");
  });

  it("SD_PLAN_VERSION is exactly 0x0001 (§I.1)", () => {
    expect(SD_PLAN_VERSION).toBe(0x0001);
  });

  it("ROOT_BINDING_LEVEL is exactly 'commit_AAD' (§I.4)", () => {
    expect(ROOT_BINDING_LEVEL).toBe("commit_AAD");
  });

  it("CLEARTEXT_POLICY_CODE is exactly 1 (§I.5)", () => {
    expect(CLEARTEXT_POLICY_CODE).toBe(1);
  });

  it("SD_PROOF_SYSTEM is exactly 'plonk-bn254' (§I.9)", () => {
    expect(SD_PROOF_SYSTEM).toBe("plonk-bn254");
  });

  it("public_inputs decimal-string regex matches integer strings only (§I.6)", () => {
    expect(PUBLIC_INPUTS_DECIMAL_REGEX.test("0")).toBe(true);
    expect(PUBLIC_INPUTS_DECIMAL_REGEX.test("12345")).toBe(true);
    expect(PUBLIC_INPUTS_DECIMAL_REGEX.test("0x1234")).toBe(false);
    expect(PUBLIC_INPUTS_DECIMAL_REGEX.test("12.34")).toBe(false);
    expect(PUBLIC_INPUTS_DECIMAL_REGEX.test("")).toBe(false);
    expect(PUBLIC_INPUTS_DECIMAL_REGEX.test("a1")).toBe(false);
    expect(PUBLIC_INPUTS_DECIMAL_REGEX.test("-1")).toBe(false);
  });

  it("MODE_A code is 0x01 and MODE_B code is 0x02", () => {
    expect(MODE_A_INGESTION_MODE_CODE).toBe(0x01);
    expect(MODE_B_INGESTION_MODE_CODE).toBe(0x02);
  });

  it("CLAIM_TYPE_CODE has all 5 entries and COMPOSED === 5 (§I.3)", () => {
    expect(CLAIM_TYPE_CODE.RANGE).toBe(1);
    expect(CLAIM_TYPE_CODE.EQUALITY).toBe(2);
    expect(CLAIM_TYPE_CODE.SET_MEMBERSHIP).toBe(3);
    expect(CLAIM_TYPE_CODE.NON_EQUALITY).toBe(4);
    expect(CLAIM_TYPE_CODE.COMPOSED).toBe(5);
  });

  it("SD_REVOCATION_REASON contains exactly 6 entries (§11.5)", () => {
    expect(Object.keys(SD_REVOCATION_REASON).length).toBe(6);
    expect(SD_REVOCATION_REASON_COUNT).toBe(6);
    expect(SD_REVOCATION_REASON.SUBJECT_ERASURE_OR_RESTRICTION).toBe(0x01);
    expect(SD_REVOCATION_REASON.PDA_SHRED_FINALIZED).toBe(0x02);
    expect(SD_REVOCATION_REASON.PARTNER_POLICY_WITHDRAWAL).toBe(0x03);
    expect(SD_REVOCATION_REASON.VERIFIER_OR_CIRCUIT_DEPRECATION).toBe(0x04);
    expect(SD_REVOCATION_REASON.TEE_INTEGRITY_INCIDENT).toBe(0x05);
    expect(SD_REVOCATION_REASON.CLAIM_UNDER_WRONG_PDA_OR_CONFIG).toBe(0x06);
  });

  it("SD_FAILURE_TABLE has 7 rows, every escrowEffect === 'none' (§15.2)", () => {
    expect(SD_FAILURE_STAGES.length).toBe(7);
    expect(SD_FAILURE_STAGE_COUNT).toBe(7);
    expect(SD_FAILURE_TABLE.length).toBe(7);
    for (const row of SD_FAILURE_TABLE) {
      expect(row.escrowEffect).toBe("none");
    }
  });

  it("LEAF_PREDICATE_TYPES has 4 entries (§6.6 + §App.I.3)", () => {
    expect(LEAF_PREDICATE_TYPES.length).toBe(4);
    expect(LEAF_PREDICATE_COUNT).toBe(4);
    expect(LEAF_PREDICATE_TYPES).toEqual([
      "range",
      "equality",
      "set_membership",
      "non_equality",
    ]);
  });

  it("COMPOSED_CAPS locks depth=8, leaves=32, fields=16 (§6.6)", () => {
    expect(COMPOSED_CAPS.MAX_DEPTH).toBe(8);
    expect(COMPOSED_CAPS.MAX_LEAVES).toBe(32);
    expect(COMPOSED_CAPS.MAX_FIELDS).toBe(16);
  });

  it("CLEARTEXT_OPENING_MODE default is ZK_OPENED === 1 (§4.4)", () => {
    expect(CLEARTEXT_OPENING_MODE.NONE).toBe(0);
    expect(CLEARTEXT_OPENING_MODE.ZK_OPENED).toBe(1);
    expect(CLEARTEXT_OPENING_MODE.TEE_ATTESTED).toBe(2);
    expect(CLEARTEXT_OPENING_DEFAULT_MODE).toBe(CLEARTEXT_OPENING_MODE.ZK_OPENED);
  });
});
