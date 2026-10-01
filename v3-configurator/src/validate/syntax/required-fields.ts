import type { DualFormValidationFailure } from "../../errors/index.js";
import { formatStageCode } from "../../errors/index.js";

export type SubmittedPda = Record<string, unknown>;

export interface SyntaxViolation {
  readonly surface_name: string;
  readonly code: string;
  readonly source_field_path: string;
  readonly failed_predicate: string;
  readonly sanitized_value_class: string;
  readonly partner_friendly_field_label: string;
  readonly why_failed: string;
  readonly partner_action_text: string;
}

export const REQUIRED_FIELDS: readonly string[] = [
  "schema_version",
  "pda_id",
  "pda_version",
  "partner_id",
  "template_id",
  "schema",
  "commit_version",
  "pda_root_fields",
  "commit_aad_fields",
  "reveal_condition",
  "shred_condition",
] as const;

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

export function valueClass(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "bigint") return "integer_bigint";
  if (Array.isArray(value)) return `array_length_${value.length}`;
  if (typeof value === "object") return "object";
  return typeof value;
}

export function makeStage1Failure(violation: SyntaxViolation): DualFormValidationFailure {
  const stage_code = formatStageCode(1, violation.surface_name, violation.code);
  return {
    stage_code,
    internal: {
      stage: 1,
      surface_name: violation.surface_name,
      failed_predicate: violation.failed_predicate,
      category: "(b) PDA pick",
      governance_sub_class: null,
      source_field_path: violation.source_field_path,
      sanitized_value_class: violation.sanitized_value_class,
      cross_references: "S2-4 §4.2 Stage 1 syntax; S2-4 §1.3 dual-form errors",
      remediation: "adjust_pda_value",
      remediation_text: violation.partner_action_text,
      originating_ci_code: null,
      originating_cf_code: null,
    },
    partner_facing: {
      stage_code,
      partner_friendly_field_label: violation.partner_friendly_field_label,
      why_failed: violation.why_failed,
      partner_action: "choose_different_allowed_option",
      partner_action_text: violation.partner_action_text,
    },
  };
}

export function checkRequiredFields(pda: SubmittedPda): readonly SyntaxViolation[] {
  const failures: SyntaxViolation[] = [];
  for (const field of REQUIRED_FIELDS) {
    if (!hasOwn(pda, field) || pda[field] === undefined || pda[field] === null) {
      failures.push({
        surface_name: "required_fields_present",
        code: "MISSING_REQUIRED_FIELD",
        source_field_path: field,
        failed_predicate: `${field} is present`,
        sanitized_value_class: valueClass(pda[field]),
        partner_friendly_field_label: field,
        why_failed: `This deployment is missing ${field}, so the configurator cannot build the frozen PDA shape.`,
        partner_action_text: `Provide ${field} before validation continues.`,
      });
    }
  }
  return failures;
}
