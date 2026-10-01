import { CF_BY_ID } from "../../types/cf-codes.js";
import { createCfFailure } from "./failure.js";
import { isPhase2, requiredCfDescriptor } from "./helpers.js";
import type { CrossFieldValidationContext } from "./types.js";

const CF_05 = CF_BY_ID.get("CF-05");

export function validateCf05(context: CrossFieldValidationContext) {
  const descriptor = requiredCfDescriptor(CF_05, "CF-05");
  const { pda } = context;
  const partnerReady =
    context.partner_ready === true || pda.partner_ready === true;
  if (
    (pda.legal_effect_expected === true || partnerReady) &&
    !isPhase2(pda.g4_phase)
  ) {
    return [
      createCfFailure({
        descriptor,
        surface_name: "g4_phase",
        code: "LEGAL_EFFECT_OR_PARTNER_READY_REQUIRES_PHASE_2",
        failed_predicate:
          "legal_effect_expected = true or partner_ready = true implies g4_phase = Phase 2",
        source_field_path: "g4_phase",
        sanitized_value_class: "phase_not_2",
        partner_friendly_field_label: "G4 phase",
        why_failed:
          "This deployment expects legal effects or is partner-ready, so G4 must be Phase 2.",
        partner_action_text:
          "Select Phase 2 G4 before partner-ready deployment.",
      }),
    ];
  }
  return [];
}
