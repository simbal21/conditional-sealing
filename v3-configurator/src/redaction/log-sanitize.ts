import {
  findPiiMatch,
  PII_EXCLUSION_PATTERNS,
} from "../types/audit-trail.js";
import type {
  RedactedValue,
  RedactionResult,
} from "./index.js";

export function redact(input: unknown): RedactionResult {
  const matches = new Set<string>();
  const sanitized = sanitize(input, matches, "");
  return {
    sanitized,
    patterns_matched: [...matches].sort(),
    clean: matches.size === 0,
  };
}

export function assertNoPiiPatterns(input: unknown): void {
  const result = redact(input);
  if (!result.clean) {
    throw new Error(`redaction: excluded patterns matched: ${result.patterns_matched.join(", ")}`);
  }
}

function sanitize(value: unknown, matches: Set<string>, key: string): unknown {
  const keyMatch = findPiiMatch(key);
  if (keyMatch !== null) {
    matches.add(keyMatch);
    return redactedValue(value, keyMatch);
  }

  if (typeof value === "string") {
    const valueMatch = findPiiMatch(value);
    if (valueMatch !== null) {
      matches.add(valueMatch);
      return redactedValue(value, valueMatch);
    }
    return value;
  }

  if (
    value === null ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  ) {
    return value;
  }

  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (Array.isArray(value)) return value.map((entry) => sanitize(entry, matches, key));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) {
      out[childKey] = sanitize(child, matches, childKey);
    }
    return out;
  }

  return null;
}

function redactedValue(value: unknown, pattern: string): RedactedValue {
  return {
    __redacted: true,
    matched_pattern: pattern,
    original_byte_length: byteLength(value),
  };
}

function byteLength(value: unknown): number {
  if (typeof value === "string") return new TextEncoder().encode(value).length;
  if (value instanceof Uint8Array) return value.byteLength;
  const serialized = JSON.stringify(value, (_key, entry: unknown) =>
    typeof entry === "bigint" ? entry.toString() : entry,
  );
  return serialized === undefined ? 0 : new TextEncoder().encode(serialized).length;
}

export { PII_EXCLUSION_PATTERNS, findPiiMatch };
