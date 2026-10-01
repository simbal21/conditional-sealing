import type { SubmittedPda, SyntaxViolation } from "./required-fields.js";
import { isRecord, valueClass } from "./required-fields.js";

const DURATION_KEY_PATTERN = /(seconds$|_window$|_ttl$|latency|retention|interval|grace|expiry)/;

function isIntegerSeconds(value: unknown): boolean {
  if (typeof value === "bigint") return value >= 0n;
  if (typeof value === "number") return Number.isSafeInteger(value) && value >= 0;
  return false;
}

function walk(value: unknown, path: string, key: string, failures: SyntaxViolation[]): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => walk(entry, `${path}[${String(index)}]`, key, failures));
    return;
  }
  if (isRecord(value)) {
    for (const [childKey, child] of Object.entries(value)) {
      const childPath = path.length === 0 ? childKey : `${path}.${childKey}`;
      walk(child, childPath, childKey, failures);
    }
    return;
  }
  if (DURATION_KEY_PATTERN.test(key) && !isIntegerSeconds(value)) {
    failures.push({
      surface_name: "duration_integer_seconds",
      code: "DURATION_SECONDS_INVALID",
      source_field_path: path,
      failed_predicate: `${path} is integer seconds`,
      sanitized_value_class: valueClass(value),
      partner_friendly_field_label: path,
      why_failed: `This deployment uses a duration at ${path}, but durations must be integer seconds.`,
      partner_action_text: `Set ${path} to a non-negative integer number of seconds.`,
    });
  }
}

export function checkDurationSeconds(pda: SubmittedPda): readonly SyntaxViolation[] {
  const failures: SyntaxViolation[] = [];
  walk(pda, "", "", failures);
  return failures;
}
