import { prepareSubmittedPda } from "../../src/pda/emit.js";
import { hashToHex32 } from "../../src/pda/pda-root.js";
import type { TestamentScaffold } from "./testament.scaffold.js";

export const testament: TestamentScaffold = {
  use_case: "testament",
  archetype: "irreversible_personal_reveal",
  template_id: hashToHex32("testament_vital_records_k_of_n_v2"),
  template_name: "testament_vital_records_k_of_n_v2",
  g3_choice: "drand",
  g4_phase: 2,
  trust_tier: "B",
  reveal_condition: {
    module: "MultiPartySignal",
    template_pick: hashToHex32("vital_records_k_of_n"),
    parameter_values: { vital_record_type: "death_certificate" },
    k_of_n: { k: 2, n: 3, independent_operators: true },
  },
  shred_condition: {
    mode: "P",
    spec_hash: hashToHex32("testament_vital_records_k_of_n_v2:shred"),
    mandatory_guardrail_present: true,
  },
  conditional_recipients: {
    n: 3,
    k: 1,
    role_tags: ["HEIR", "BENEFICIARY"],
    updatable: true,
  },
  reveal_challenge_window_seconds: 0n,
  shred_challenge_window_seconds: 0n,
  shred_authority: "Disabled",
  emergency_response_bricking_acknowledgment: false,
  legal_effect_expected: false,
  partner_id: "partner_testament",
  retention_seconds: 1_577_880_000n,
  fire_time_ttl_estimate_seconds: 1_577_880_000n,
};

export const testamentSubmittedPda = prepareSubmittedPda(testament as unknown as Record<string, unknown>);
