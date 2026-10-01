import { CF_BY_ID } from "../../types/cf-codes.js";
import {
  enforceMultiPartySignalDefault,
  requiresMultiPartySignalDefault,
} from "../../multi-oracle/cf-07-enforcement.js";
import { routePerPdaOptOut } from "../../multi-oracle/opt-out-routing.js";
import { createCfFailure } from "./failure.js";
import {
  getMultiPartySignal,
  hasAcknowledgment,
  requiredCfDescriptor,
} from "./helpers.js";
import type { CrossFieldValidationContext } from "./types.js";

const CF_07 = CF_BY_ID.get("CF-07");

export function validateCf07(context: CrossFieldValidationContext) {
  const descriptor = requiredCfDescriptor(CF_07, "CF-07");
  const { pda } = context;
  const template = context.archetype_template ?? pda.archetype_template ?? {};
  if (!requiresMultiPartySignalDefault(pda)) return [];

  if (pda.class_wide_mps_opt_out === true) {
    if (pda.class_wide_mps_opt_out_authorized_sub_class === 3) return [];
    return [
      createCfFailure({
        descriptor,
        surface_name: "multi_party_signal_default",
        code: "CF-07_MULTIPARTY_SIGNAL_DEFAULT",
        failed_predicate:
          "class-wide MultiPartySignal opt-out requires sub-class 3 governance",
        source_field_path: "class_wide_mps_opt_out",
        sanitized_value_class: "class_wide_opt_out_without_sub_class_3",
        partner_friendly_field_label: "Class-wide multi-oracle opt-out",
        why_failed:
          "A class-wide opt-out from the irreversible-archetype multi-oracle default needs emergency governance routing.",
        partner_action_text:
          "Route the class-wide opt-out through sub-class 3 governance.",
        governance_sub_class: 3,
        remediation: "request_pda_plus_expansion",
        partner_action: "request_pda_plus_change",
      }),
    ];
  }

  if (pda.per_pda_mps_opt_out === true) {
    if (routePerPdaOptOut(pda, template)) return [];
    return [
      createCfFailure({
        descriptor,
        surface_name: "multi_party_signal_default",
        code: "CF-07_MULTIPARTY_SIGNAL_DEFAULT",
        failed_predicate:
          "per-PDA opt-out requires archetype permission and partner acknowledgment bound into inspection surface",
        source_field_path: "per_pda_mps_opt_out",
        sanitized_value_class:
          "per_pda_opt_out_without_template_permission_or_ack",
        partner_friendly_field_label: "Per-PDA multi-oracle opt-out",
        why_failed:
          "This PDA opts out of the irreversible-archetype multi-oracle default without both template permission and a bound partner acknowledgment.",
        partner_action_text:
          "Use the k-of-n default, or bind the opt-out acknowledgment on a template that permits it.",
      }),
    ];
  }

  const result = enforceMultiPartySignalDefault({
    pda,
    signal: getMultiPartySignal(pda),
    tier_c_acknowledgment_bound: hasAcknowledgment(
      pda,
      "tier_c_trust_acknowledgment",
    ),
  });
  if (result.ok) return [];
  return result.reasons.map((reason) =>
    createCfFailure({
      descriptor,
      surface_name: "multi_party_signal_default",
      code: "CF-07_MULTIPARTY_SIGNAL_DEFAULT",
      failed_predicate: reason,
      source_field_path: "multi_party_signal",
      sanitized_value_class: "multi_party_signal_default_not_satisfied",
      partner_friendly_field_label: "Multi-oracle firing default",
      why_failed:
        "This irreversible or high-consequence external-trigger deployment needs a k-of-n multi-oracle signal with independent signers and digest binding.",
      partner_action_text:
        "Configure MultiPartySignal with k at least 2, k no greater than n, independent operators, unique signers, tier-compatible oracle refs, and signal-digest binding.",
    }),
  );
}
