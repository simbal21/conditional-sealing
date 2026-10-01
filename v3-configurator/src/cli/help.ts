import type { DualFormValidationFailure } from "../errors/index.js";

export function serializeForCli(value: unknown): string {
  return `${JSON.stringify(toJsonValue(value), null, 2)}\n`;
}

export function renderDualFormErrors(failures: readonly DualFormValidationFailure[]): string {
  if (failures.length === 0) return "No validation failures.\n";
  return failures
    .map((failure) => {
      return [
        `stage_code: ${failure.stage_code}`,
        `internal.surface: ${failure.internal.surface_name}`,
        `internal.failed_predicate: ${failure.internal.failed_predicate}`,
        `internal.source: ${failure.internal.source_field_path}`,
        `partner.field: ${failure.partner_facing.partner_friendly_field_label}`,
        `partner.why: ${failure.partner_facing.why_failed}`,
        `partner.action: ${failure.partner_facing.partner_action_text}`,
      ].join("\n");
    })
    .join("\n\n");
}

export function toJsonValue(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Uint8Array) {
    return `0x${Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  }
  if (value instanceof Map) {
    return Object.fromEntries([...value.entries()].map(([key, entry]) => [String(key), toJsonValue(entry)]));
  }
  if (Array.isArray(value)) return value.map((entry) => toJsonValue(entry));
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) out[key] = toJsonValue(entry);
    return out;
  }
  return value;
}
