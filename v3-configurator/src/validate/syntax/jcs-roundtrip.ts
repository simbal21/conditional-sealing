import type { SubmittedPda, SyntaxViolation } from "./required-fields.js";

function canonicalizeForStage1(value: unknown): string | undefined {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "bigint" || typeof value === "function" || typeof value === "undefined") {
    return undefined;
  }
  if (Array.isArray(value)) {
    const children = value.map((entry) => canonicalizeForStage1(entry));
    if (children.some((entry) => entry === undefined)) return undefined;
    return `[${children.join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const entries: string[] = [];
    for (const key of Object.keys(record).sort()) {
      const child = canonicalizeForStage1(record[key]);
      if (child === undefined) return undefined;
      entries.push(`${JSON.stringify(key)}:${child}`);
    }
    return `{${entries.join(",")}}`;
  }
  return undefined;
}

export function checkJcsRoundTrip(pda: SubmittedPda): readonly SyntaxViolation[] {
  try {
    const canonical = canonicalizeForStage1(pda);
    if (typeof canonical !== "string") {
      return [
        {
          surface_name: "jcs_round_trip",
          code: "JCS_CANONICALIZE_FAILED",
          source_field_path: "$",
          failed_predicate: "canonical JSON can be produced",
          sanitized_value_class: "non_canonicalizable",
          partner_friendly_field_label: "PDA JSON",
          why_failed: "This deployment cannot be converted into canonical JSON for hashing and audit.",
          partner_action_text: "Remove unsupported JSON values before validation continues.",
        },
      ];
    }
    JSON.parse(canonical);
    return [];
  } catch {
    return [
      {
        surface_name: "jcs_round_trip",
        code: "JCS_ROUND_TRIP_FAILED",
        source_field_path: "$",
        failed_predicate: "canonical JSON round-trips through JSON.parse",
        sanitized_value_class: "non_canonicalizable",
        partner_friendly_field_label: "PDA JSON",
        why_failed: "This deployment cannot round-trip through canonical JSON.",
        partner_action_text: "Remove unsupported JSON values before validation continues.",
      },
    ];
  }
}
