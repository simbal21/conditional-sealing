// Error category enum + HTTP status map — verbatim from S2-5 §1.4 (lines 189-202).
//
// LOCKED at Phase A. Spec body grep-verified 2026-05-11: 12 entries.
// Phase A foundation test asserts count = 12.

export const ERROR_CATEGORIES = [
  "REQUEST",
  "AUTH",
  "ATTESTATION",
  "VAULT",
  "CHAIN",
  "COMBINER",
  "SCHEMA",
  "IDEMPOTENCY",
  "RATE_LIMIT",
  "TRANSPORT",
  "GOVERNANCE",
  "RETRY_EXHAUSTED",
] as const;

export type ErrorCategory = (typeof ERROR_CATEGORIES)[number];

export const ERROR_CATEGORY_COUNT: number = ERROR_CATEGORIES.length;

/**
 * Default HTTP status for each category — verbatim from §1.4 table.
 * Some categories span multiple statuses (e.g. ATTESTATION 409/424);
 * route-specific codes pick the correct one via `errorStatus[code]`.
 */
export const CATEGORY_DEFAULT_HTTP_STATUS: Readonly<Record<ErrorCategory, number>> = {
  REQUEST: 400,
  AUTH: 401,
  ATTESTATION: 424,
  VAULT: 404,
  CHAIN: 409,
  COMBINER: 409,
  SCHEMA: 422,
  IDEMPOTENCY: 409,
  RATE_LIMIT: 429,
  TRANSPORT: 502,
  GOVERNANCE: 409,
  RETRY_EXHAUSTED: 409,
} as const;

/**
 * Meaning text per category — verbatim from §1.4 table (Meaning column).
 * Used by Problem+JSON `title` defaults and OpenAPI doc generation.
 */
export const CATEGORY_MEANING: Readonly<Record<ErrorCategory, string>> = {
  REQUEST: "Malformed request, unsupported content type, invalid JSON, invalid field encoding",
  AUTH: "Missing, expired, bad, or insufficient credential",
  ATTESTATION: "Endpoint attestation, DCAP, registry, binary hash, or client pre-flight failed",
  VAULT: "Vault object missing, retention state, already shredded, vault unavailable",
  CHAIN: "Chain finality, event proof, registry read, condition, challenge, or shred state failed",
  COMBINER:
    "Combiner manifest, σ verification, share threshold, artifact assembly, or Mode 3 rejection failed",
  SCHEMA: "PDA schema, SD field mapping, payload classification, or recipient selector failed",
  IDEMPOTENCY: "Idempotency key replay with divergent request body",
  RATE_LIMIT: "Per-key or per-IP limit exceeded",
  TRANSPORT: "Gate, vendor, vault, chain RPC, or webhook transport failure",
  GOVERNANCE: "Registry tombstone, halt, refusal, pause, or phase restriction",
  RETRY_EXHAUSTED: "Bounded retry budget exhausted",
} as const;
