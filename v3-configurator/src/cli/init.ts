import { prepareSubmittedPda } from "../pda/emit.js";
import { hashToHex32 } from "../pda/pda-root.js";
import type { SubmittedPda } from "../validate/syntax/index.js";

export type ArchetypeName =
  | "kyc-lending"
  | "testament"
  | "evidence-archival"
  | "m-and-a-deal"
  | "dead-man-switch";

export const ARCHETYPE_NAMES: readonly ArchetypeName[] = [
  "kyc-lending",
  "testament",
  "evidence-archival",
  "m-and-a-deal",
  "dead-man-switch",
] as const;

export function initTemplate(template: string): SubmittedPda {
  const name = parseArchetypeName(template);
  return prepareSubmittedPda(scaffoldFor(name));
}

export function parseArchetypeName(value: string): ArchetypeName {
  if ((ARCHETYPE_NAMES as readonly string[]).includes(value)) return value as ArchetypeName;
  throw new Error(`Unknown template ${value}. Choose one of: ${ARCHETYPE_NAMES.join(", ")}`);
}

export function scaffoldFor(name: ArchetypeName): Record<string, unknown> {
  switch (name) {
    case "kyc-lending":
      return {
        use_case: "kyc-lending",
        archetype: "enforcement",
        template_id: hashToHex32("kyc_lending_payment_default_v2"),
        template_name: "kyc_lending_payment_default_v2",
        g3_choice: "dcipher",
        g4_phase: 2,
        trust_tier: "A",
        reveal_condition: {
          module: "PaymentObligation",
          template_pick: hashToHex32("PaymentObligationModule"),
          parameter_values: { payment_default_after_seconds: 0 },
        },
        shred_condition: { mode: "P", spec_hash: hashToHex32("kyc:shred"), mandatory_guardrail_present: true },
        reveal_challenge_window_seconds: 0,
        shred_challenge_window_seconds: 0,
        legal_effect_expected: true,
        cealis_class_wide_halt_opt_out: false,
        sd_field_policies: { "subject.identifier": "escrow_only", "claims.defaulted": "escrow_only" },
        partner_id: "partner_kyc_lending",
        retention_seconds: 94_608_000,
        minimum_shred_latency_seconds: 0,
      };
    case "testament":
      return {
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
        shred_condition: { mode: "P", spec_hash: hashToHex32("testament:shred"), mandatory_guardrail_present: true },
        conditional_recipients: { n: 3, k: 1, role_tags: ["HEIR", "BENEFICIARY"], updatable: true },
        reveal_challenge_window_seconds: 0,
        shred_challenge_window_seconds: 0,
        shred_authority: "Disabled",
        emergency_response_bricking_acknowledgment: false,
        legal_effect_expected: false,
        partner_id: "partner_testament",
        retention_seconds: 1_577_880_000,
        fire_time_ttl_estimate_seconds: 1_577_880_000,
      };
    case "evidence-archival":
      return {
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
          k_of_n: { k: 2, n: 3, independent_operators: true },
        },
        shred_condition: { mode: "P", spec_hash: hashToHex32("evidence:shred"), mandatory_guardrail_present: true },
        retention_seconds: 315_576_000,
        minimum_shred_latency_seconds: 604_800,
        reveal_challenge_window_seconds: 604_800,
        shred_challenge_window_seconds: 604_800,
        shred_authority: "Joint",
        archival_permanent_shred_disabled: false,
        sd_field_policies: { "evidence.digest": "escrow_only", "evidence.timestamp": "escrow_only" },
        evidence_schema_sd_availability: true,
        legal_effect_expected: false,
        partner_id: "partner_evidence",
      };
    case "m-and-a-deal":
      return {
        use_case: "m_and_a",
        archetype: "multi_party_commercial_escrow",
        template_id: hashToHex32("ma_deal_multiparty_closing_v2"),
        template_name: "ma_deal_multiparty_closing_v2",
        g3_choice: "dcipher",
        g4_phase: 2,
        trust_tier: "B",
        reveal_condition: {
          module: "MultiPartySignal",
          template_pick: hashToHex32("ma_deal_multiparty_closing"),
          parameter_values: { closing_board_resolution_required: true },
          k_of_n: { k: 2, n: 4, independent_operators: true, signer_roles: ["ACQUIRER_COUNSEL", "SELLER_COUNSEL", "BOARD_REPRESENTATIVE", "REGISTERED_ORACLE"] },
        },
        shred_condition: { mode: "P", spec_hash: hashToHex32("ma:shred"), mandatory_guardrail_present: true },
        conditional_recipients: { n: 2, k: 1, role_tags: ["ACQUIRER_COUNSEL"] },
        reveal_challenge_window_seconds: 1_209_600,
        shred_challenge_window_seconds: 1_209_600,
        applicable_jurisdiction: { shape: "scalar", scalar_code: "DE" },
        qes_subject_required: false,
        qtsp_provider_ref: `0x${"00".repeat(32)}`,
        pricing_tier: "pilot",
        pricing_amounts: { retainer: 5_000, per_identity: 500, per_obligation: 0, per_reveal: 0, percentage_basis_points: 100, cap: 25_000, floor: 0 },
        usage_quota: { per_period_seconds: 2_592_000, max_ops: 100 },
        legal_effect_expected: false,
        cealis_class_wide_halt_opt_out: false,
        partner_id: "partner_ma",
      };
    case "dead-man-switch":
      return {
        use_case: "dead_man_switch",
        archetype: "conditional_reveal_liveness",
        template_id: hashToHex32("dead_man_switch_heartbeat_release_v2"),
        template_name: "dead_man_switch_heartbeat_release_v2",
        g3_choice: "drand",
        g4_phase: 2,
        trust_tier: "B",
        reveal_condition: {
          module: "DeadManSwitch",
          evidence_template_pick: hashToHex32("heartbeat_release"),
          evidence_parameters: { heartbeat_interval_seconds: 2_592_000, grace_window_seconds: 604_800, notification_delay_seconds: 86_400 },
          k_of_n: { k: 2, n: 3, independent_operators: true },
          subject_liveness_oracle_ref: "vital-records-oracle",
        },
        shred_condition: { mode: "P", spec_hash: hashToHex32("dms:shred"), mandatory_guardrail_present: true },
        recipients: [{ role_tag: "BENEFICIARY", delivery_mode: "PASSKEY_ACCOUNT" }],
        conditional_recipients: { n: 2, k: 1, role_tags: ["BENEFICIARY"], updatable: true },
        pda_updatable: true,
        conditional_recipients_updatable: true,
        emergency_response_bricking_acknowledgment: false,
        fire_time_ttl_estimate_seconds: 946_728_000,
        reveal_challenge_window_seconds: 0,
        shred_challenge_window_seconds: 0,
        shred_authority: "Subject",
        legal_effect_expected: false,
        partner_id: "partner_dead_man_switch",
      };
  }
}
