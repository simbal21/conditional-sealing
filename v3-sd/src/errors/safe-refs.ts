// Logging discipline allow-list per §1.4 lines 204-208 (NORMATIVE).
//
// Allowed log fields:
//   correlation id, authorizationId, h_commit, pda_id, partner_id, claim_id,
//   field_id (hash), circuit id, verifier ref, proof length, stage name,
//   error code, monotonic timing.
//
// Forbidden log fields:
//   plaintext values, cleartext payloads, salts, witness assignments,
//   proving key material, raw proof transcript, malformed input bodies,
//   generated partner output bodies.
//
// Phase A LOCKED: foundation test asserts every `SdError.safeRefs` field name
// belongs to ALLOWED_SAFE_REF_KEYS.

export const ALLOWED_SAFE_REF_KEYS = Object.freeze([
  "correlationId",
  "authorizationId",
  "h_commit",
  "pda_id",
  "pda_version",
  "partner_id",
  "claim_id",
  "field_id",
  "circuit_id",
  "circuit_family_id",
  "circuit_version",
  "verifier_ref",
  "disclosure_id",
  "schema_digest",
  "sd_plan_digest",
  "sd_bundle_digest",
  "sd_salt_context_digest",
  "sdMerkleRoot",
  "proof_length",
  "public_input_length",
  "stage",
  "code",
  "error_code",
  "duration_ms",
  "timestamp",
  "field_index",
  "leaf_count",
  "merkle_depth",
  "policy_code",
  "claim_type",
  "expiry_timestamp",
  "reason_code",
  "evidence_ref",
] as const);

export type AllowedSafeRefKey = typeof ALLOWED_SAFE_REF_KEYS[number];

/**
 * Strict shape for `SdError.safeRefs` — only keys in the allow-list are
 * permitted; values must be hashes (hex), ids, enum values, timestamps, or
 * lengths. Foundation test enforces.
 */
export type SafeRefs = Partial<Record<AllowedSafeRefKey, string | number | bigint>>;

/**
 * Validate a `SafeRefs` object — returns true iff every key is in the
 * allow-list AND every value is `string | number | bigint`. Used by SdError
 * constructor + foundation tests.
 */
export function isSafeRefs(obj: unknown): obj is SafeRefs {
  if (obj === null || typeof obj !== "object") return false;
  const set = new Set<string>(ALLOWED_SAFE_REF_KEYS);
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (!set.has(k)) return false;
    if (v === undefined) continue;
    const t = typeof v;
    if (t !== "string" && t !== "number" && t !== "bigint") return false;
  }
  return true;
}

/**
 * BANNED safeRefs keys — these names would smuggle PII / witnesses / salts
 * into log lines and MUST never appear in SdError instances. Foundation test
 * asserts these are NOT in ALLOWED_SAFE_REF_KEYS.
 */
export const BANNED_LOG_KEYS = Object.freeze([
  "plaintext",
  "cleartext_payload",
  "salt",
  "sd_field_salt",
  "sd_master_salt",
  "witness",
  "witness_assignments",
  "proving_key",
  "proof_bytes",
  "proof_transcript",
  "malformed_input",
  "partner_output_body",
  "sigma",
  "dek",
  "subject_pii",
] as const);
