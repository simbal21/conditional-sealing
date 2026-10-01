import { CF_BY_ID } from "../../types/cf-codes.js";
import { createCfFailure } from "./failure.js";
import {
  allConditionalRecipients,
  archetypeKey,
  requiredCfDescriptor,
} from "./helpers.js";
import type { CrossFieldValidationContext } from "./types.js";

const CF_04 = CF_BY_ID.get("CF-04");

export function validateCf04(context: CrossFieldValidationContext) {
  const descriptor = requiredCfDescriptor(CF_04, "CF-04");
  const { pda } = context;
  const subjectSelfRecipients = allConditionalRecipients(pda).filter(
    (recipient) => recipient.role_tag === "SUBJECT_SELF",
  );
  if (subjectSelfRecipients.length === 0) return [];

  const failures = [];
  if (
    subjectSelfRecipients.some(
      (recipient) => recipient.delivery_mode !== "PASSKEY_ACCOUNT",
    )
  ) {
    failures.push(
      createCfFailure({
        descriptor,
        surface_name: "conditional_recipients",
        code: "SUBJECT_SELF_REQUIRES_PASSKEY_ACCOUNT",
        failed_predicate:
          "SUBJECT_SELF recipient has delivery_mode = PASSKEY_ACCOUNT",
        source_field_path: "conditional_recipients.recipients[*].delivery_mode",
        sanitized_value_class: "delivery_mode_not_passkey_account",
        partner_friendly_field_label: "Subject-self recipient mode",
        why_failed:
          "A subject-self recipient can only receive through a passkey account path.",
        partner_action_text:
          "Change SUBJECT_SELF delivery mode to PASSKEY_ACCOUNT.",
      }),
    );
  }

  if (pda.subject_liveness_required_at_fire !== true) {
    failures.push(
      createCfFailure({
        descriptor,
        surface_name: "subject_liveness_required_at_fire",
        code: "SUBJECT_SELF_REQUIRES_LIVENESS_AT_FIRE",
        failed_predicate: "subject_liveness_required_at_fire = true",
        source_field_path: "subject_liveness_required_at_fire",
        sanitized_value_class: "boolean_not_true",
        partner_friendly_field_label: "Subject liveness at fire",
        why_failed:
          "A subject-self recipient requires the subject to be alive at the firing point.",
        partner_action_text:
          "Require subject liveness at fire or remove the SUBJECT_SELF recipient.",
      }),
    );
  }

  if (archetypeKey(pda).includes("testament")) {
    failures.push(
      createCfFailure({
        descriptor,
        surface_name: "conditional_recipients",
        code: "TESTAMENT_REJECTS_SUBJECT_SELF",
        failed_predicate: "testament-style conditions reject SUBJECT_SELF",
        source_field_path: "conditional_recipients.recipients[*].role_tag",
        sanitized_value_class: "role_tag_subject_self",
        partner_friendly_field_label: "Testament recipient role",
        why_failed:
          "A testament-style condition fires when the subject is not alive, so SUBJECT_SELF cannot be a conditional recipient.",
        partner_action_text:
          "Use HEIR, BENEFICIARY, or another non-subject recipient role.",
      }),
    );
  }

  return failures;
}
