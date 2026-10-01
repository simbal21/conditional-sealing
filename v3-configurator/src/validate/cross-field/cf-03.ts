import { CF_BY_ID } from "../../types/cf-codes.js";
import { createCfFailure } from "./failure.js";
import {
  conditionalRecipientPolicy,
  fireTimeTtl,
  FIVE_YEARS_SECONDS,
  requiredCfDescriptor,
} from "./helpers.js";
import type { CrossFieldValidationContext } from "./types.js";

const CF_03 = CF_BY_ID.get("CF-03");

export function validateCf03(context: CrossFieldValidationContext) {
  const descriptor = requiredCfDescriptor(CF_03, "CF-03");
  const { pda } = context;
  const longTtl = fireTimeTtl(pda) > FIVE_YEARS_SECONDS;
  const updatable =
    pda.conditional_recipients_updatable ??
    conditionalRecipientPolicy(pda)?.updatable;
  if (!longTtl || updatable !== false) return [];

  const policy = conditionalRecipientPolicy(pda);
  const n = policy?.n;
  const k = policy?.k;
  const redundant = n !== undefined && k !== undefined && n >= 2 * k;
  if (redundant || pda.emergency_response_bricking_acknowledgment === true)
    return [];

  return [
    createCfFailure({
      descriptor,
      surface_name: "conditional_recipients_updatable",
      code: "LONG_TTL_RECIPIENT_REDUNDANCY_MISSING",
      failed_predicate:
        "fire_time_ttl_estimate > 5 years and conditional_recipients_updatable = false requires n >= 2k or emergency_response_bricking_acknowledgment = true",
      source_field_path: "conditional_recipients",
      sanitized_value_class: "threshold_not_redundant_without_bricking_ack",
      partner_friendly_field_label: "Long-term recipient redundancy",
      why_failed:
        "This long-retention deployment freezes recipient updates without enough recipient redundancy or a bricking-risk acknowledgment.",
      partner_action_text:
        "Make recipients updatable, set n at least 2k, or bind the emergency-response bricking acknowledgment.",
    }),
  ];
}
