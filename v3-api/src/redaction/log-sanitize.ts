// Log-sanitize filter — wires `src/redaction/safe-refs.ts` into Pino.
//
// LOCKED at Phase A (signatures only). Phase D Fastify integration consumes
// these helpers to install hooks on req/res serialization.
//
// Per §10.2 lines 1002-1012: error bodies, logs, metric labels, webhook events,
// dead-letter rows, and audit exports MUST NOT contain σ, shares, decap material,
// DEK, plaintext, partial AAD, SD salts/witnesses/transcripts, raw passkey
// pubkeys, sensitive refusal plaintext for 0x02/0x03, or delivery URL bearer
// tokens after expiry.

import { FORBIDDEN_TOKEN_PATTERNS, SAFE_REF_KEY_SET } from "./safe-refs.js";

/**
 * Recursively traverse a value and replace forbidden-pattern matches with
 * `"[REDACTED]"`. Used by Pino formatter at egress.
 *
 * Strategy:
 *   - For strings: scan against FORBIDDEN_TOKEN_PATTERNS, replace matches.
 *   - For objects: walk keys. If key is in SAFE_REF_KEY_SET, keep value as-is.
 *     If key is NOT safe-ref and value is "PII-shaped" (long hex string, JWT,
 *     or contains forbidden tokens), replace value with `"[REDACTED]"`.
 *   - For arrays: recurse element-wise.
 *
 * Phase A: signature + smoke test (asserts forbidden patterns reduced to
 * `[REDACTED]` placeholder).
 * Phase D: production hook into Pino + Fastify error handler.
 */
export function sanitize(value: unknown, depth = 0): unknown {
  if (depth > 16) return "[REDACTED:depth_limit]";
  if (value === null || value === undefined) return value;

  if (typeof value === "string") {
    let out = value;
    for (const pattern of FORBIDDEN_TOKEN_PATTERNS) {
      if (pattern.test(out)) {
        out = "[REDACTED]";
        break;
      }
    }
    return out;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((v) => sanitize(v, depth + 1));
  }

  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>)) {
      const inner = (value as Record<string, unknown>)[key];
      // Safe-ref keys keep their values (still recurse for nested redaction).
      if (SAFE_REF_KEY_SET.has(key)) {
        out[key] = sanitize(inner, depth + 1);
        continue;
      }
      // Forbidden-key heuristics (key name itself signals PII).
      const lc = key.toLowerCase();
      if (
        lc.includes("sigma") ||
        lc === "dek" ||
        lc === "file_key" ||
        lc.includes("share") ||
        lc === "plaintext" ||
        lc.includes("decap") ||
        lc === "salt" ||
        lc.includes("witness")
      ) {
        out[key] = "[REDACTED]";
        continue;
      }
      out[key] = sanitize(inner, depth + 1);
    }
    return out;
  }

  return value;
}

/**
 * Pino formatter integration — Phase D wires:
 *
 *   pino({
 *     formatters: { log: (obj) => sanitize(obj) as Record<string, unknown> },
 *   });
 */
export function pinoLogFormatter(obj: Record<string, unknown>): Record<string, unknown> {
  return sanitize(obj) as Record<string, unknown>;
}
