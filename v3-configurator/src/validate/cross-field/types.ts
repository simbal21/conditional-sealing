import type { DualFormValidationFailure } from "../../errors/index.js";
import type { CfCode, CfDescriptor } from "../../types/cf-codes.js";
import type { SubClass } from "../../types/categories.js";

export type TrustTier = "A" | "B" | "C";
export type G4Phase = 1 | 2 | "Phase 1" | "Phase 2";

export interface CeremonyResolver {
  readonly type?: string;
}

export interface OracleRef {
  readonly oracle_id?: string;
  readonly id?: string;
  readonly tier: TrustTier;
  readonly operator_id?: string;
  readonly signer_identity?: string;
  readonly axis?: "reveal" | "shred" | "both";
  readonly classified_as_chain_native?: boolean;
}

export interface MultiPartySignalConfig {
  readonly k?: number;
  readonly n?: number;
  readonly independent_operators?: boolean;
  readonly signal_digest_bound?: boolean;
  readonly oracle_refs?: readonly OracleRef[];
  readonly signer_identities?: readonly string[];
  readonly operator_ids?: readonly string[];
}

export interface ConditionalRecipient {
  readonly role_tag: string;
  readonly delivery_mode?: string;
}

export interface ConditionalRecipientPolicy {
  readonly n?: number;
  readonly k?: number;
  readonly recipients?: readonly ConditionalRecipient[];
  readonly role_tags?: readonly string[];
  readonly updatable?: boolean;
}

export interface ArchetypeTemplate {
  readonly archetype?: string;
  readonly permits_multi_oracle_opt_out?: boolean;
  readonly permits_per_pda_mps_opt_out?: boolean;
  readonly irreversible_external_trigger?: boolean;
}

export interface InspectionSurfaceBinding {
  readonly partner_acknowledgments?: readonly string[];
  readonly bound_acknowledgments?: readonly string[];
}

export interface CrossFieldPda {
  readonly legal_effect_expected?: boolean;
  readonly trust_tier?: TrustTier;
  readonly relevant_reveal_condition_tiers?: readonly TrustTier[];
  readonly reveal_condition?: {
    readonly module?: string;
    readonly tier?: TrustTier;
    readonly k_of_n?: MultiPartySignalConfig;
  };
  readonly oracle_refs?: readonly OracleRef[];
  readonly reveal_challenge_window_seconds?: bigint | number;
  readonly challenge_window_seconds?: bigint | number;
  readonly archetype_floor_seconds?: bigint | number;
  readonly ceremony_resolver?: CeremonyResolver;
  readonly eligible_challengers_reveal?: readonly string[];
  readonly subject_id?: string;
  readonly minimum_shred_latency_seconds?: bigint | number;
  readonly minimum_shred_latency?: bigint | number;
  readonly cealis_class_wide_halt_opt_out?: boolean;
  readonly fire_time_ttl_estimate_seconds?: bigint | number;
  readonly fire_time_ttl_estimate?: bigint | number;
  readonly conditional_recipients_updatable?: boolean;
  readonly emergency_response_bricking_acknowledgment?: boolean;
  readonly conditional_recipients?: ConditionalRecipientPolicy;
  readonly conditional_recipient_policy?: ConditionalRecipientPolicy;
  readonly recipients?: readonly ConditionalRecipient[];
  readonly subject_liveness_required_at_fire?: boolean;
  readonly g4_phase?: G4Phase;
  readonly partner_ready?: boolean;
  readonly partner_upgraded_to_tier_c?: boolean;
  readonly tier_c_acknowledgment_bound?: boolean;
  readonly multi_party_signal?: MultiPartySignalConfig;
  readonly archetype?: string;
  readonly use_case?: string;
  readonly firing_condition_depends_on_external_event_source?: boolean;
  readonly archetype_template?: ArchetypeTemplate;
  readonly per_pda_mps_opt_out?: boolean;
  readonly partner_mps_opt_out_ack_bound?: boolean;
  readonly class_wide_mps_opt_out?: boolean;
  readonly class_wide_mps_opt_out_authorized_sub_class?: SubClass;
  readonly inspection_surface?: InspectionSurfaceBinding;
}

export interface CrossFieldValidationContext {
  readonly pda: CrossFieldPda;
  readonly archetype_template?: ArchetypeTemplate;
  readonly partner_ready?: boolean;
}

export type CrossFieldValidator = (
  context: CrossFieldValidationContext,
) => readonly DualFormValidationFailure[];

export interface CfFailureInput {
  readonly descriptor: CfDescriptor;
  readonly surface_name: string;
  readonly code: string;
  readonly failed_predicate: string;
  readonly source_field_path: string;
  readonly sanitized_value_class: string;
  readonly partner_friendly_field_label: string;
  readonly why_failed: string;
  readonly partner_action_text: string;
  readonly originating_cf_code?: CfCode;
  readonly governance_sub_class?: SubClass | null;
  readonly remediation?:
    | "adjust_pda_value"
    | "request_pda_plus_expansion"
    | "impossible_under_v2";
  readonly partner_action?:
    | "choose_different_allowed_option"
    | "request_pda_plus_change";
}
