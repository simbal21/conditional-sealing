// Safe-refs allow-list — verbatim from S2-5 §10.2 line 1014.
//
// LOCKED at Phase A. The ONLY references permitted in error bodies, log lines,
// webhook payloads, dead-letter rows, and audit exports.
//
// Phase D auth middleware + webhook signer + Pino log formatter consult this
// allow-list. Phase F tripwire grep asserts no PII strings (σ, share, DEK,
// kdf, plaintext, file_key) appear in source under `src/{webhooks,redaction,
// auth,errors}/`.

/**
 * Allowed safe references — verbatim from §10.2 line 1014:
 *
 *   "Allowed safe refs include authorizationId, h_commit, event id, block
 *    number, registry ref, PDA id, partner id, artifact digest, and encrypted
 *    diagnostic ref."
 *
 * Phase A locks the canonical key names; Phase D middleware filters logs/
 * payloads against this set.
 */
export const SAFE_REF_KEYS = [
  "authorizationId",
  "h_commit",
  "event_id",
  "block_number",
  "registry_ref",
  "pda_id",
  "partner_id",
  "artifact_digest",
  "encrypted_diagnostic_ref",
] as const;

export type SafeRefKey = (typeof SAFE_REF_KEYS)[number];

export const SAFE_REF_KEY_SET: ReadonlySet<string> = new Set(SAFE_REF_KEYS);

/**
 * Predicate: is this property key safe to include in error/webhook/log output?
 */
export function isSafeRefKey(key: string): boolean {
  return SAFE_REF_KEY_SET.has(key);
}

/**
 * Filter an arbitrary object to only safe-ref keys. Used by webhook payload
 * builder + log formatter at egress boundaries.
 *
 * Returns a NEW object — never mutates input.
 */
export function pickSafeRefs(
  obj: Record<string, unknown>,
): Record<SafeRefKey, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {};
  for (const key of Object.keys(obj)) {
    if (!isSafeRefKey(key)) continue;
    const value = obj[key];
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out[key] = value;
    }
  }
  return out as Record<SafeRefKey, string | number | boolean>;
}

/**
 * Forbidden token patterns — Phase A locked.
 *
 * Per §10.2 lines 1002-1012, these substrings MUST NEVER appear in any
 * outbound payload, log line, or error body. Phase F tripwire grep
 * enforces in source code; this constant is consulted by the log
 * formatter at runtime.
 *
 * Note: these are CASE-INSENSITIVE regex sources. The redaction filter
 * compiles them at load.
 */
export const FORBIDDEN_TOKEN_PATTERNS: readonly RegExp[] = [
  // σ raw or partial bytes
  /\bsigma_(?:subject|lit|g3|g4|conditional)_bytes\b/i,
  // Shamir share bytes
  /\bshamir_share(?:_bytes)?\b/i,
  // KEM decap material
  /\bkem_(?:decap|shared_secret)\b/i,
  // DEK / file_key
  /\bdek\b/i,
  /\bfile_key\b/i,
  // SD salts/witnesses/transcripts
  /\bsd_salt\b/i,
  /\bsd_witness\b/i,
  /\bproof_transcript\b/i,
  // Passkey public key (raw — not just digest)
  /\bpasskey_pubkey\b/i,
  // Bearer / delivery URL secrets
  /\bbearer\s+ey/i, // catches "Bearer eyJ..." JWT-style leaks
];
