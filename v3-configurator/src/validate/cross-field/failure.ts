import {
  formatStageCode,
  type DualFormValidationFailure,
} from "../../errors/index.js";
import type { CfFailureInput } from "./types.js";

export function createCfFailure(
  input: CfFailureInput,
): DualFormValidationFailure {
  const stage_code = formatStageCode(4, input.surface_name, input.code);
  return {
    stage_code,
    internal: {
      stage: 4,
      surface_name: input.surface_name,
      failed_predicate: input.failed_predicate,
      category: "(a) PDA+",
      governance_sub_class: input.governance_sub_class ?? 4,
      source_field_path: input.source_field_path,
      sanitized_value_class: input.sanitized_value_class,
      cross_references: `S2-4 §4.5 ${input.descriptor.id}; S2-4 §14.2 emit-all cross-field failures`,
      remediation: input.remediation ?? "adjust_pda_value",
      remediation_text: input.partner_action_text,
      originating_ci_code: null,
      originating_cf_code: input.originating_cf_code ?? input.descriptor.id,
    },
    partner_facing: {
      stage_code,
      partner_friendly_field_label: input.partner_friendly_field_label,
      why_failed: input.why_failed,
      partner_action: input.partner_action ?? "choose_different_allowed_option",
      partner_action_text: input.partner_action_text,
    },
  };
}
