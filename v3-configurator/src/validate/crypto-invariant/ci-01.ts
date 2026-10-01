import type { Category, SubClass } from "../../types/categories.js";
import { CI_BY_ID, type CiDescriptor } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { formatStageCode } from "../../errors/index.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-01")!; // verbatim spec anchor

export interface CiFailureInput {
  readonly descriptor: CiDescriptor;
  readonly surface_name: string;
  readonly code: string;
  readonly source_field_path: string;
  readonly failed_predicate: string;
  readonly sanitized_value_class: string;
  readonly cross_references: string;
  readonly why_failed: string;
  readonly partner_action_text: string;
  readonly remediation?: "adjust_pda_value" | "request_pda_plus_expansion" | "impossible_under_v2";
  readonly category?: Category;
  readonly governance_sub_class?: SubClass | null;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function makeCiFailure(input: CiFailureInput): DualFormValidationFailure {
  const stage_code = formatStageCode(2, input.surface_name, input.code);
  return {
    stage_code,
    internal: {
      stage: 2,
      surface_name: input.surface_name,
      failed_predicate: input.failed_predicate,
      category: input.category ?? "(d) architectural fact",
      governance_sub_class: input.governance_sub_class ?? null,
      source_field_path: input.source_field_path,
      sanitized_value_class: input.sanitized_value_class,
      cross_references: input.cross_references,
      remediation: input.remediation ?? "impossible_under_v2",
      remediation_text: input.partner_action_text,
      originating_ci_code: input.descriptor.id,
      originating_cf_code: null,
    },
    partner_facing: {
      stage_code,
      partner_friendly_field_label: input.surface_name,
      why_failed: input.why_failed,
      partner_action:
        input.remediation === "request_pda_plus_expansion"
          ? "request_pda_plus_change"
          : "choose_different_allowed_option",
      partner_action_text: input.partner_action_text,
    },
  };
}

export function valueClass(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "bigint") return "integer_bigint";
  if (Array.isArray(value)) return `array_length_${value.length}`;
  if (typeof value === "object") return "object";
  return typeof value;
}

export function numberValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "bigint" && value <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(value);
  return null;
}

export function stringValue(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function booleanValue(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

export function arrayValue(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

export function recordValue(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null;
}

export function isZeroBytes32(value: unknown): boolean {
  return typeof value === "string" && /^0x0{64}$/i.test(value);
}

export function deepStringIncludes(value: unknown, needles: readonly RegExp[]): boolean {
  if (typeof value === "string") {
    return needles.some((needle) => needle.test(value));
  }
  if (Array.isArray(value)) {
    return value.some((entry) => deepStringIncludes(entry, needles));
  }
  if (isRecord(value)) {
    return Object.entries(value).some(([key, child]) => {
      return needles.some((needle) => needle.test(key)) || deepStringIncludes(child, needles);
    });
  }
  return false;
}

export function checkCi01(pda: SubmittedPda): DualFormValidationFailure | null {
  const commitVersion = numberValue(pda["commit_version"]);
  const migrationCeremony = pda["versioned_migration_ceremony"] === true;
  if (commitVersion === 0x0302 || migrationCeremony) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "commit_version_0x0302",
    code: "COMMIT_VERSION_UNSUPPORTED",
    source_field_path: "commit_version",
    failed_predicate: "commit_version === 0x0302 or explicit migration ceremony exists",
    sanitized_value_class: valueClass(pda["commit_version"]),
    cross_references: "S2-1 §4 commit_AAD.commit_version; S2-4 §4.3 CI-01",
    why_failed:
      "This deployment targets a commit version other than 0x0302 without a versioned migration ceremony.",
    partner_action_text: "Set commit_version to 0x0302 for new V2/V3-custody PDA emissions.",
    remediation: "adjust_pda_value",
  });
}
