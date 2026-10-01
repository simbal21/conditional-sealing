// S2-4 §4.4 — Stage 3 discrete-choice allow-list check for category (b).

import type { DualFormValidationFailure } from "../../errors/index.js";
import { formatStageCode } from "../../errors/index.js";
import type { ClassTableRow, RowId } from "../../types/class-table.js";

export type Stage3Scalar = string | number | boolean | bigint | null;
export type Stage3Value = Stage3Scalar | readonly Stage3Scalar[];
export type Stage3PolicyRecord<T> = { readonly [key: string]: T | undefined };
export type Stage3PolicyMap<T> = ReadonlyMap<string, T> | Stage3PolicyRecord<T>;

export interface AllowListCheckInput {
  readonly row: ClassTableRow;
  readonly value: Stage3Value | undefined;
  readonly allowLists: Stage3PolicyMap<readonly Stage3Value[]> | undefined;
  readonly sourceFieldPath?: string;
}

export type AllowListPolicyMap = Stage3PolicyMap<readonly Stage3Value[]>;

/**
 * Category-(b) class-table rows whose discrete pick is a CONTENT-ADDRESSED
 * TEMPLATE id, not an enumerated allow-list value. These surfaces are validated
 * by `checkTemplateIdActive` against the registered template catalog — NOT by an
 * allow-list. `checkAllowList` MUST defer on them, otherwise every shipping
 * fixture reports a spurious `ALLOW_LIST_MISSING` (the rows 54 / 56.1 gap).
 *
 * Source of truth shared with `src/pda/emit.ts` STAGE3_TEMPLATE_PICK_ROWS.
 */
export const TEMPLATE_PICK_ROW_IDS: ReadonlySet<RowId> = new Set<RowId>(["54", "56.1"]);

export function checkAllowList(input: AllowListCheckInput): DualFormValidationFailure | null {
  const { row, value, allowLists } = input;
  if (row.category !== "(b) PDA pick") return null;
  // Template-pick surfaces are validated by `checkTemplateIdActive` against the
  // registered template catalog, not by an allow-list. Defer here so a
  // legitimate registered template_id does not trip ALLOW_LIST_MISSING.
  if (TEMPLATE_PICK_ROW_IDS.has(row.id)) return null;

  const allowedValues = readStage3Policy(allowLists, row);
  if (allowedValues === undefined) {
    return createStage3Failure({
      row,
      code: "ALLOW_LIST_MISSING",
      failedPredicate: "PDA+ allow-list is missing for category (b) surface",
      sanitizedValueClass: stage3ValueClass(value),
      sourceFieldPath: input.sourceFieldPath,
      partnerAction: "request_pda_plus_change",
      remediationText: "Add or activate a PDA+ allow-list before this discrete surface can be emitted.",
    });
  }

  const valueKey = value === undefined ? null : stage3ValueKey(value);
  const allowed = valueKey !== null && allowedValues.some((allowedValue) => stage3ValueKey(allowedValue) === valueKey);
  if (allowed) return null;

  return createStage3Failure({
    row,
    code: "ALLOW_LIST_VALUE_NOT_ALLOWED",
    failedPredicate: "submitted value is not in the effective PDA+ allow-list",
    sanitizedValueClass: stage3ValueClass(value),
    sourceFieldPath: input.sourceFieldPath,
    partnerAction: "choose_different_allowed_option",
    remediationText: "Choose a value from the effective PDA+ allow-list for this archetype, use-case, trust tier, and date.",
  });
}

export function readStage3Policy<T>(
  source: Stage3PolicyMap<T> | undefined,
  row: Pick<ClassTableRow, "id" | "surface_name">,
): T | undefined {
  if (source === undefined) return undefined;
  if (isStage3PolicyReadonlyMap(source)) return source.get(row.id) ?? source.get(row.surface_name);
  return source[row.id] ?? source[row.surface_name];
}

export function stage3ValueKey(value: Stage3Value): string {
  if (isStage3ScalarArray(value)) return `array:[${value.map((entry) => stage3ScalarKey(entry)).join(",")}]`;
  return stage3ScalarKey(value);
}

export function stage3ValueClass(value: Stage3Value | undefined): string {
  if (value === undefined) return "missing";
  if (Array.isArray(value)) return `array_length_${String(value.length)}`;
  if (value === null) return "null";
  if (typeof value === "string") {
    if (/^sha256:[a-f0-9]{64}$/i.test(value) || /^0x[a-f0-9]{64}$/i.test(value)) return "content_addressed_id";
    return "string_enum_or_identifier";
  }
  if (typeof value === "number") return Number.isFinite(value) ? "number_finite" : "number_non_finite";
  return typeof value;
}

export interface Stage3FailureInput {
  readonly row: ClassTableRow;
  readonly code: string;
  readonly failedPredicate: string;
  readonly sanitizedValueClass: string;
  readonly sourceFieldPath?: string;
  readonly partnerAction: "choose_different_allowed_option" | "request_pda_plus_change";
  readonly remediationText: string;
}

export function createStage3Failure(input: Stage3FailureInput): DualFormValidationFailure {
  const stageCode = formatStageCode(3, input.row.surface_name, input.code);
  const partnerActionText =
    input.partnerAction === "choose_different_allowed_option"
      ? "Choose a different value that is allowed by the active PDA+ policy."
      : "Request a Cealis-internal PDA+ policy update before emitting this PDA.";

  return {
    stage_code: stageCode,
    internal: {
      stage: 3,
      surface_name: input.row.surface_name,
      failed_predicate: input.failedPredicate,
      category: input.row.category,
      governance_sub_class:
        input.row.governance_sub_class === "N/A" ? null : input.row.governance_sub_class,
      source_field_path: input.sourceFieldPath ?? input.row.cross_ref_to_pda_root_field,
      sanitized_value_class: input.sanitizedValueClass,
      cross_references: `S2-4 §4.4 Stage 3; S2-4 §5.2 row ${input.row.id}; ${input.row.cross_ref_to_pda_root_field}`,
      remediation:
        input.partnerAction === "choose_different_allowed_option"
          ? "adjust_pda_value"
          : "request_pda_plus_expansion",
      remediation_text: input.remediationText,
      originating_ci_code: null,
      originating_cf_code: null,
    },
    partner_facing: {
      stage_code: stageCode,
      partner_friendly_field_label: humanizeSurfaceName(input.row.surface_name),
      why_failed:
        "This configuration is outside the active Cealis PDA+ policy for the selected deployment context.",
      partner_action: input.partnerAction,
      partner_action_text: partnerActionText,
    },
  };
}

function stage3ScalarKey(value: Stage3Scalar): string {
  if (typeof value === "bigint") return `bigint:${value.toString()}`;
  if (value === null) return "null";
  return `${typeof value}:${String(value)}`;
}

function humanizeSurfaceName(surfaceName: string): string {
  return surfaceName
    .split("_")
    .filter((part) => part.length > 0)
    .map((part) => `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`)
    .join(" ");
}

function isStage3PolicyReadonlyMap<T>(source: Stage3PolicyMap<T>): source is ReadonlyMap<string, T> {
  return typeof (source as ReadonlyMap<string, T>).get === "function";
}

function isStage3ScalarArray(value: Stage3Value): value is readonly Stage3Scalar[] {
  return Array.isArray(value);
}

export type { RowId };
