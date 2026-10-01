import type { BoundaryClassification, Surface } from "./types.js";
import type { BoundaryContext } from "./test-1.js";

const DISCRETE_SURFACES = new Set<string>([
  "g3_choice",
  "g4_phase",
  "condition_module_template",
  "oracle_reference_pick",
  "trust_tier_declaration",
  "issuer_mode",
  "subject_authenticator_class",
  "pause_authority",
  "ceremony_resolver",
  "shred_authority",
  "delivery_mode",
  "sd_policy_enum_per_field",
] as const);

const CONTINUOUS_SURFACES = new Set<string>([
  "retention_window",
  "challenge_window",
  "heartbeat_interval",
  "grace_period",
  "time_lock_timestamp",
  "conditional_recipient_n",
  "conditional_recipient_k",
  "recipient_list_cardinality",
  "bond_amount",
  "usage_quota",
  "per_pda_price_tier_value",
  "expiry_window",
] as const);

export function runTest3(surface: Surface, context: BoundaryContext): BoundaryClassification {
  const kind =
    context.value_kind ??
    (CONTINUOUS_SURFACES.has(surface) ? "continuous" : DISCRETE_SURFACES.has(surface) ? "discrete" : "discrete");
  if (kind === "continuous") {
    return {
      test_exited_on: "3",
      category: "(c) PDA parameter",
      rationale:
        context.rationale ??
        `${surface} is a partner-supplied continuous or numeric value inside PDA+ bounds.`,
      derivation_pointer: null,
    };
  }
  return {
    test_exited_on: "3",
    category: "(b) PDA pick",
    rationale:
      context.rationale ??
      `${surface} is a partner-selected discrete value from a PDA+ allow-list.`,
    derivation_pointer: null,
  };
}
