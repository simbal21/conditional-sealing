import { CF_BY_ID } from "../../types/cf-codes.js";
import { createCfFailure } from "./failure.js";
import { requiredCfDescriptor } from "./helpers.js";
import type { CrossFieldValidationContext } from "./types.js";

const CF_02 = CF_BY_ID.get("CF-02");

export function validateCf02(context: CrossFieldValidationContext) {
  const descriptor = requiredCfDescriptor(CF_02, "CF-02");
  const { pda } = context;
  if (
    pda.legal_effect_expected !== true ||
    pda.cealis_class_wide_halt_opt_out !== true
  )
    return [];
  return [
    createCfFailure({
      descriptor,
      surface_name: "cealis_class_wide_halt_opt_out",
      code: "LEGAL_EFFECT_HALT_OPT_OUT_FORBIDDEN",
      failed_predicate:
        "legal_effect_expected = true implies cealis_class_wide_halt_opt_out = false",
      source_field_path: "cealis_class_wide_halt_opt_out",
      sanitized_value_class: "boolean_true",
      partner_friendly_field_label: "Cealis halt opt-out",
      why_failed:
        "This deployment expects legal effects, so it cannot opt out of Cealis's class-wide halt safety path.",
      partner_action_text:
        "Set halt opt-out to false, or run a separate non-legal-effect deployment.",
    }),
  ];
}
