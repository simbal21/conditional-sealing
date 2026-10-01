// Log-record σ-redaction filter.
//
// Defense-in-depth alongside `SigmaBuffer`. Adapters/combiner SHOULD
// always wrap σ in `SigmaBuffer` at the boundary, but legacy code paths
// or accidentally-passed raw `Uint8Array`s still happen. This filter
// inspects an arbitrary record (object, array, primitive) and replaces
// any field that looks like a σ value with a redacted placeholder.
//
// Heuristics applied (intentionally conservative — false-positive on
// the side of redaction):
//   1. Field names matching /(sigma|signature)$/i, /(sigma|signature)_/i,
//      or starting with `sigma`.
//   2. `SigmaBuffer` instances → replaced with `{ "$sigmaBuffer": "<digest>", "length": N }`.
//   3. `Uint8Array` whose length matches a known σ size (32, 48, 64, 96, 168) AND
//      whose field name matches the σ-name pattern.
//   4. Hex strings matching `/^0x[0-9a-f]{64,}$/i` AND matching the
//      σ-name pattern.
//
// The filter is recursive. It MUST NOT mutate the input.

import { SigmaBuffer } from "./sigma-buffer.js";

/** Field names that trigger redaction. */
const SIGMA_NAME = /^(sigma|σ)/i;
const SIGMA_INFIX = /(sigma|σ|signature)/i;

/** σ byte sizes likely to indicate a σ value. */
const KNOWN_SIGMA_SIZES = new Set([32, 48, 64, 96, 168]);

const REDACTED = "[REDACTED:sigma]";

/**
 * Recursively inspect `value` and return a sanitized clone with σ-like
 * fields replaced by `[REDACTED:sigma]` (or a SigmaBuffer placeholder).
 * Pure function — does not mutate input.
 */
export function sanitizeLog(value: unknown): unknown {
  return sanitize(value, "");
}

function sanitize(value: unknown, fieldName: string): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") {
    if (SIGMA_INFIX.test(fieldName) && /^0x[0-9a-f]{64,}$/i.test(value)) {
      return REDACTED;
    }
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return value;
  }
  if (value instanceof SigmaBuffer) {
    return {
      $sigmaBuffer: value.digestHex.slice(0, 16) + "…",
      length: value.length,
    };
  }
  if (value instanceof Uint8Array) {
    if (SIGMA_NAME.test(fieldName) || (SIGMA_INFIX.test(fieldName) && KNOWN_SIGMA_SIZES.has(value.length))) {
      return REDACTED;
    }
    // Non-σ Uint8Array — return short summary, NOT raw bytes.
    return { $bytes: `length=${value.length}` };
  }
  if (Array.isArray(value)) {
    return value.map((item, i) => sanitize(item, `${fieldName}[${i}]`));
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as object)) {
      out[k] = sanitize(v, k);
    }
    return out;
  }
  return value;
}

/**
 * Convenience: stringify a log record after sanitization. Use this
 * instead of raw `JSON.stringify(record)` in any code path that might
 * see σ bytes.
 */
export function safeStringify(value: unknown, indent?: number): string {
  return JSON.stringify(sanitizeLog(value), bigintReplacer, indent);
}

function bigintReplacer(_key: string, val: unknown): unknown {
  return typeof val === "bigint" ? val.toString() + "n" : val;
}
