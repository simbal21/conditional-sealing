import { describe, expect, it } from "vitest";
import { COMMIT_AAD_FIELD_NAMES } from "../../src/types/commit-aad.js";
import type { CiCode } from "../../src/types/ci-codes.js";
import { PDA_ROOT_FIELD_NAMES } from "../../src/types/pda-root.js";
import { runStage1 } from "../../src/validate/syntax/index.js";
import {
  CI_CHECKS,
  checkCi01,
  checkCi02,
  checkCi03,
  checkCi04,
  checkCi05,
  checkCi06,
  checkCi07,
  checkCi08,
  checkCi09,
  checkCi10,
  checkCi11,
  checkCi12,
  checkCi13,
  checkCi14,
  checkCi15,
  checkCi16,
  checkCi17,
  checkCi18,
  checkCi19,
  checkCi20,
  runStage2,
  type CiCheck,
  type SubmittedPda,
} from "../../src/validate/crypto-invariant/index.js";

const HEX = `0x${"33".repeat(32)}`;
const ZERO = `0x${"00".repeat(32)}`;
const CID = "bafybeigdyrzt5sfp7udm7hu76u4n6v7i2c6h4oxf5kqj4f5b5x3a2z7lqi";

function validPda(): SubmittedPda {
  return {
    schema_version: 1,
    pda_id: HEX,
    pda_version: 1,
    partner_id: "partner_pipeline",
    template_id: HEX,
    schema: { fields: [{ path: "subject.age" }] },
    schema_mapping: { ageProof: "subject.age" },
    commit_version: 0x0302,
    pda_root_fields: [...PDA_ROOT_FIELD_NAMES],
    pda_root_extra_fields: [],
    commit_aad_fields: [...COMMIT_AAD_FIELD_NAMES],
    fixed_gates: ["Lit V3", "G3", "G4"],
    conditional_recipients: { n: 0, k: 0 },
    global_shamir_threshold: 3,
    delivery_mode: "PASSKEY_ACCOUNT",
    recipients: [{ delivery_mode: "PASSKEY_ACCOUNT" }],
    ingestion_mode: "ModeA",
    sd_enabled: false,
    sdMerkleRoot: `0x${"00".repeat(32)}`,
    sd_plan: { field_policies: { "subject.age": "escrow_only" } },
    sd_field_policies: { "subject.age": "escrow_only" },
    evidence_cid: CID,
    reveal_condition: { mode: "P", spec_hash: HEX },
    shred_condition: { mode: "P", spec_hash: HEX, mandatory_guardrail_present: true },
    g4_phase: 2,
    lit_vendor_family: "aws-nitro",
    g4_vendor_family: "azure-confidential",
    gate_recipient_pubkeys: [
      { gate_kind: "drand", lifecycle: "long_lived_committee" },
      { gate_kind: "lit", lifecycle: "per_commit_ephemeral" },
      { gate_kind: "g4", lifecycle: "per_commit_ephemeral" },
    ],
    registry_lookup_mode: "historical_at_authorization_block",
    historical_registry_lookup: true,
    reveal_shred_axes_separated: true,
    reveal_authorization_sources: ["RevealAuthorized"],
    sigma_usage: "authorization",
    dek_lifecycle: "A1_SHAMIR",
  };
}

const POSITIVE_CASES: readonly (readonly [CiCode, CiCheck])[] = [
  ["CI-01", checkCi01],
  ["CI-02", checkCi02],
  ["CI-03", checkCi03],
  ["CI-04", checkCi04],
  ["CI-05", checkCi05],
  ["CI-06", checkCi06],
  ["CI-07", checkCi07],
  ["CI-08", checkCi08],
  ["CI-09", checkCi09],
  ["CI-10", checkCi10],
  ["CI-11", checkCi11],
  ["CI-12", checkCi12],
  ["CI-13", checkCi13],
  ["CI-14", checkCi14],
  ["CI-15", checkCi15],
  ["CI-16", checkCi16],
  ["CI-17", checkCi17],
  ["CI-18", checkCi18],
  ["CI-19", checkCi19],
  ["CI-20", checkCi20],
] as const;

const NEGATIVE_CASES: readonly (readonly [CiCode, (pda: SubmittedPda) => void])[] = [
  ["CI-01", (pda) => void (pda["commit_version"] = 0x0301)],
  ["CI-02", (pda) => void (pda["sigma_handling"] = "sigma becomes HKDF IKM")],
  ["CI-03", (pda) => void (pda["wraps_full_dek_to_single_gate"] = true)],
  ["CI-04", (pda) => void (pda["fixed_gates"] = ["Lit V3", "G4"])],
  ["CI-05", (pda) => void (pda["global_shamir_threshold"] = 4)],
  ["CI-06", (pda) => void (pda["conditional_recipients"] = { n: 1, k: 2 })],
  ["CI-07", (pda) => void (pda["delivery_mode"] = "WALLET_EIP1271")],
  ["CI-08", (pda) => void (pda["sd_plan"] = { failure_blocks_escrow: true })],
  ["CI-09", (pda) => {
    pda["ingestion_mode"] = "ModeB";
    pda["sd_field_policies"] = { "subject.age": "zkp" };
  }],
  ["CI-10", (pda) => {
    pda["sd_enabled"] = true;
    pda["sdMerkleRoot"] = ZERO;
  }],
  ["CI-11", (pda) => void (pda["delivery_before_reveal_authorized"] = true)],
  ["CI-12", (pda) => void (pda["shred_condition"] = { mode: "P", spec_hash: HEX })],
  ["CI-13", (pda) => void (pda["pda_root_fields"] = [...PDA_ROOT_FIELD_NAMES].reverse())],
  ["CI-14", (pda) => void (pda["commit_aad_fields"] = COMMIT_AAD_FIELD_NAMES.filter((field) => field !== "sdMerkleRoot"))],
  ["CI-15", (pda) => void (pda["g4_phase"] = 9)],
  ["CI-16", (pda) => void (pda["g4_vendor_family"] = "aws-nitro")],
  ["CI-17", (pda) => void (pda["gate_recipient_pubkeys"] = [{ gate_kind: "drand", lifecycle: "per_commit_ephemeral" }])],
  ["CI-18", (pda) => void (pda["registry_lookup_mode"] = "current_head")],
  ["CI-19", (pda) => void (pda["reveal_terminal_state_implies_shred"] = true)],
  ["CI-20", (pda) => void (pda["disclosure_registry_authorizes_reveal"] = true)],
] as const;

describe("@cealis/v3-configurator — Stage 1 then Stage 2 pipeline", () => {
  it("passes both stages for a valid PDA", () => {
    const pda = validPda();
    expect(runStage1(pda)).toEqual([]);
    expect(runStage2(pda)).toEqual([]);
  });

  it("keeps Mode 3 syntactically valid and rejects it at Stage 2 CI-07", () => {
    const pda = { ...validPda(), delivery_mode: "WALLET_EIP1271" };
    expect(runStage1(pda)).toEqual([]);
    expect(runStage2(pda).map((failure) => failure.internal.originating_ci_code)).toContain("CI-07");
  });

  it("emits Stage 1 required-field failures", () => {
    const pda = validPda();
    delete pda["schema"];
    expect(runStage1(pda).map((failure) => failure.internal.surface_name)).toContain(
      "required_fields_present",
    );
  });

  it("rejects unknown fields unless explicit extension metadata is enabled", () => {
    expect(runStage1({ ...validPda(), surprise: true }).map((failure) => failure.internal.surface_name)).toContain(
      "unknown_fields_rejected",
    );
    expect(runStage1({ ...validPda(), schema_version_allows_extension_metadata: true, x_partner_note: true })).toEqual(
      [],
    );
  });

  it("rejects representative Stage 1 syntax failures", () => {
    expect(runStage1({ ...validPda(), trust_tier: "D" }).map((failure) => failure.stage_code)).toEqual(
      expect.arrayContaining([expect.stringContaining("UNKNOWN_ENUM_IDENTIFIER")]),
    );
    expect(runStage1({ ...validPda(), pda_id: "0x1234" }).map((failure) => failure.internal.surface_name)).toContain(
      "bytes32_hex_format",
    );
    expect(runStage1({ ...validPda(), evidence_cid: "not-a-cid" }).map((failure) => failure.internal.surface_name)).toContain(
      "cid_parse",
    );
    expect(
      runStage1({ ...validPda(), retention_seconds: 1.5 }).map((failure) => failure.internal.surface_name),
    ).toContain("duration_integer_seconds");
    expect(
      runStage1({ ...validPda(), retention_seconds: 1n }).map((failure) => failure.internal.surface_name),
    ).toContain("jcs_round_trip");
    expect(
      runStage1({ ...validPda(), schema_mapping: { missing: "subject.address" } }).map(
        (failure) => failure.internal.surface_name,
      ),
    ).toContain("schema_mapping_path_resolves");
  });

  it("exposes exactly 20 CI checks", () => {
    expect(CI_CHECKS).toHaveLength(20);
  });

  it.each(POSITIVE_CASES)("%s passes the valid baseline", (_code, check) => {
    expect(check(validPda())).toBeNull();
  });

  it.each(NEGATIVE_CASES)("%s emits its canonical owner", (code, mutate) => {
    const pda = validPda();
    mutate(pda);
    expect(runStage2(pda).map((failure) => failure.internal.originating_ci_code)).toContain(code);
  });

  it("accumulates Stage 2 failures and does not short-circuit", () => {
    const pda = validPda();
    pda["commit_version"] = 0x0301;
    pda["delivery_mode"] = "WALLET_EIP1271";
    expect(runStage2(pda).map((failure) => failure.internal.originating_ci_code)).toEqual(
      expect.arrayContaining(["CI-01", "CI-07"]),
    );
  });

  it("keeps CI-15 separate from CF-05 legal-effect Phase 1 ownership", () => {
    const legalEffectPhase1 = { ...validPda(), g4_phase: 1, legal_effect_expected: true, partner_ready: true };
    expect(runStage2(legalEffectPhase1).map((failure) => failure.internal.originating_ci_code)).not.toContain(
      "CI-15",
    );
    const semanticOverclaim = { ...legalEffectPhase1, phase_1_claim: "cryptographic_non_custody" };
    expect(runStage2(semanticOverclaim).map((failure) => failure.internal.originating_ci_code)).toContain(
      "CI-15",
    );
  });
});
