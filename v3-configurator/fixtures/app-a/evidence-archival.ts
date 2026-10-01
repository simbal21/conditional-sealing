import { prepareSubmittedPda } from "../../src/pda/emit.js";
import { hashToHex32 } from "../../src/pda/pda-root.js";
import type { EvidenceArchivalScaffold } from "./evidence-archival.scaffold.js";

export const evidenceArchival: EvidenceArchivalScaffold = {
  use_case: "evidence",
  archetype: "tamper_proof_retention",
  template_id: hashToHex32("evidence_provenance_retention_v2"),
  template_name: "evidence_provenance_retention_v2",
  g3_choice: "dcipher",
  g4_phase: 2,
  trust_tier: "B",
  reveal_condition: {
    module: "OracleAttestation",
    template_pick: hashToHex32("evidence_oracle_attestation"),
    parameter_values: { evidence_class: "regulated_evidence" },
    oracle_attestation_refs: ["evidence-custodian-a", "evidence-custodian-b"],
  },
  shred_condition: {
    mode: "P",
    spec_hash: hashToHex32("evidence_provenance_retention_v2:shred"),
    mandatory_guardrail_present: true,
  },
  retention_seconds: 315_576_000n,
  minimum_shred_latency_seconds: 604_800n,
  reveal_challenge_window_seconds: 604_800n,
  shred_challenge_window_seconds: 604_800n,
  shred_authority: "Joint",
  archival_permanent_shred_disabled: false,
  sd_default: "escrow_only",
  sd_field_policies: {
    "evidence.digest": "escrow_only",
    "evidence.timestamp": "escrow_only",
  },
  evidence_schema_sd_availability: true,
  legal_effect_expected: false,
  partner_id: "partner_evidence",
};

export const evidenceArchivalSubmittedPda = prepareSubmittedPda(
  evidenceArchival as unknown as Record<string, unknown>,
);
