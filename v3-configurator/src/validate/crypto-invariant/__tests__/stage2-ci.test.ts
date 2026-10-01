import { describe, expect, it } from "vitest";
import { COMMIT_AAD_FIELD_NAMES } from "../../../types/commit-aad.js";
import { PDA_ROOT_FIELD_NAMES } from "../../../types/pda-root.js";
import type { CiCode } from "../../../types/ci-codes.js";
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
} from "../index.js";

const HEX = `0x${"22".repeat(32)}`;
const ZERO = `0x${"00".repeat(32)}`;

function basePda(): SubmittedPda {
  return {
    schema_version: 1,
    pda_id: HEX,
    pda_version: 1,
    partner_id: "partner_alpha",
    template_id: HEX,
    schema: { fields: [{ path: "subject.age" }] },
    schema_mapping: { ageProof: "subject.age" },
    commit_version: 0x0302,
    pda_root_fields: [...PDA_ROOT_FIELD_NAMES],
    pda_root_extra_fields: [],
    commit_aad_fields: [...COMMIT_AAD_FIELD_NAMES],
    fixed_gates: ["Lit V3", "G3", "G4"],
    conditional_recipients: { n: 2, k: 1 },
    global_shamir_threshold: 4,
    delivery_mode: "PASSKEY_ACCOUNT",
    recipients: [{ delivery_mode: "PASSKEY_ACCOUNT" }],
    ingestion_mode: "ModeA",
    sd_enabled: true,
    sdMerkleRoot: HEX,
    sd_plan: { field_policies: { "subject.age": "zkp" } },
    sd_field_policies: { "subject.age": "zkp" },
    reveal_condition: { mode: "P", spec_hash: HEX },
    shred_condition: {
      mode: "P",
      spec_hash: HEX,
      mandatory_guardrail_present: true,
    },
    g4_phase: 2,
    lit_vendor_family: "aws-nitro",
    g4_vendor_family: "azure-confidential",
    gate_recipient_pubkeys: [
      { gate_kind: "drand", lifecycle: "long_lived_committee" },
      { gate_kind: "lit", lifecycle: "per_commit_ephemeral" },
      { gate_kind: "g4", lifecycle: "per_commit_ephemeral" },
      { gate_kind: "conditional", lifecycle: "per_commit_ephemeral" },
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
  ["CI-05", (pda) => void (pda["global_shamir_threshold"] = 3)],
  ["CI-06", (pda) => void (pda["conditional_recipients"] = { n: 1, k: 2 })],
  ["CI-07", (pda) => void (pda["delivery_mode"] = "WALLET_EIP1271")],
  ["CI-08", (pda) => void (pda["sd_plan"] = { failure_blocks_escrow: true })],
  ["CI-09", (pda) => void (pda["ingestion_mode"] = "ModeB")],
  ["CI-10", (pda) => void (pda["sdMerkleRoot"] = ZERO)],
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

describe("@cealis/v3-configurator — Stage 2 crypto-invariants (§4.3)", () => {
  it("exposes exactly 20 CI checks", () => {
    expect(CI_CHECKS).toHaveLength(20);
  });

  it.each(POSITIVE_CASES)("%s passes the valid baseline", (_code, check) => {
    expect(check(basePda())).toBeNull();
  });

  it("dispatcher returns no failures for a valid baseline", () => {
    expect(runStage2(basePda())).toEqual([]);
  });

  it.each(NEGATIVE_CASES)("%s emits its canonical owner", (code, mutate) => {
    const pda = basePda();
    mutate(pda);
    const failures = runStage2(pda);
    expect(failures.map((failure) => failure.internal.originating_ci_code)).toContain(code);
  });

  it("accumulates failures and does not short-circuit", () => {
    const pda = basePda();
    pda["commit_version"] = 0x0301;
    pda["delivery_mode"] = "WALLET_EIP1271";
    const failures = runStage2(pda);
    expect(failures.map((failure) => failure.internal.originating_ci_code)).toEqual(
      expect.arrayContaining(["CI-01", "CI-07"]),
    );
  });

  it("keeps CI-15 separate from CF-05 legal-effect Phase 1 ownership", () => {
    const legalEffectPhase1 = { ...basePda(), g4_phase: 1, legal_effect_expected: true, partner_ready: true };
    expect(runStage2(legalEffectPhase1).map((failure) => failure.internal.originating_ci_code)).not.toContain(
      "CI-15",
    );
    const semanticOverclaim = { ...legalEffectPhase1, phase_1_claim: "cryptographic_non_custody" };
    expect(runStage2(semanticOverclaim).map((failure) => failure.internal.originating_ci_code)).toContain(
      "CI-15",
    );
  });
});
