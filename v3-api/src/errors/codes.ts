// Error code constants — special cases locked verbatim from S2-5 §2.8, §3.6,
// §7.5, §10.4, §15. Phase B/C/D throw via the `problemFromCode(code, safeRefs)`
// helper in `./problem.ts`.
//
// Code naming convention: `CATEGORY.CODE_TAG` per §1.4 example
// `ATTESTATION.ENDPOINT_CHECK_FAILED`. Stage-indexed `S2_5_<surface>.<code>`
// IS NOT used in code values themselves — only in stage diagnostic correlation
// (§F.7 tripwire grep asserts).
//
// Pattern: enum-as-const-object so Phase B/C/D can import individual codes
// without runtime string sprawl.

import type { ErrorCategory } from "./categories.js";

/**
 * Catalog of all special-case codes locked at Phase A per PHASE-PLAN A6.
 *
 * Phase B/C/D may add additional codes; new codes MUST follow the
 * `CATEGORY.CODE_TAG` pattern and amend SPEC-COMPLIANCE-GUARD-M5.md §6.
 */
export const ErrorCode = {
  // §2.8 — attestation failures (4 specific codes verbatim)
  ATTESTATION_LIT_ASSIGNMENT_MISSING: {
    code: "ATTESTATION.LIT_ASSIGNMENT_MISSING",
    category: "ATTESTATION" as ErrorCategory,
    httpStatus: 424,
    title: "Lit V3 assignment record missing for authorizationIdCandidate",
  },
  ATTESTATION_DCAP_INVALID: {
    code: "ATTESTATION.DCAP_INVALID",
    category: "ATTESTATION" as ErrorCategory,
    httpStatus: 424,
    title: "Commit-time per-op DCAP quote invalid or user-data mismatch",
  },
  ATTESTATION_G3_PUBKEY_INVALID: {
    code: "ATTESTATION.G3_PUBKEY_INVALID",
    category: "ATTESTATION" as ErrorCategory,
    httpStatus: 424,
    title: "G3 gate-recipient KEM pubkey unavailable or mismatched",
  },
  ATTESTATION_G4_AUTHORITY_INVALID: {
    code: "ATTESTATION.G4_AUTHORITY_INVALID",
    category: "ATTESTATION" as ErrorCategory,
    httpStatus: 424,
    title: "G4 Phase 1/2 authority invalid",
  },
  // §2.8 — schema failures
  SCHEMA_PDA_SCHEMA_MISMATCH: {
    code: "SCHEMA.PDA_SCHEMA_MISMATCH",
    category: "SCHEMA" as ErrorCategory,
    httpStatus: 422,
    title: "PDA schema mismatch",
  },
  // §2.8 — Mode B reserved-path (Rule 6b SD-D9 + §2.8 line 421)
  SCHEMA_MODE_B_RESERVED: {
    code: "SCHEMA.MODE_B_RESERVED",
    category: "SCHEMA" as ErrorCategory,
    httpStatus: 409,
    title: "Mode B is reserved; live Mode A endpoint rejects Mode B requests",
  },
  // §2.8 — vault availability
  VAULT_UNAVAILABLE: {
    code: "VAULT.UNAVAILABLE",
    category: "VAULT" as ErrorCategory,
    httpStatus: 503,
    title: "Vault unavailable before chain anchor",
  },
  // §2.8 — chain anchor retry exhausted
  CHAIN_ANCHOR_RETRY_EXHAUSTED: {
    code: "CHAIN.ANCHOR_RETRY_EXHAUSTED",
    category: "CHAIN" as ErrorCategory,
    httpStatus: 503,
    title: "Chain anchor retry budget exhausted",
  },
  // §1.5 + §1.4 — idempotency
  IDEMPOTENCY_KEY_CONFLICT: {
    code: "IDEMPOTENCY.KEY_CONFLICT",
    category: "IDEMPOTENCY" as ErrorCategory,
    httpStatus: 409,
    title: "Idempotency key replay with divergent request body",
  },
  // §10.4 — G4 refusal as governance/halt (NOT a generic error)
  GOVERNANCE_G4_REFUSED: {
    code: "GOVERNANCE.G4_REFUSED",
    category: "GOVERNANCE" as ErrorCategory,
    httpStatus: 409,
    title: "G4 refused to sign — reveal halted",
  },
  // §3.6 — combiner failure-mode surface
  COMBINER_GATE_AUTHORIZATION_MISSING: {
    code: "COMBINER.GATE_AUTHORIZATION_MISSING",
    category: "COMBINER" as ErrorCategory,
    httpStatus: 424,
    title: "Gate refused or σ missing",
  },
  GOVERNANCE_REGISTRY_DEPRECATED_PRE_AUTHORIZATION: {
    code: "GOVERNANCE.REGISTRY_DEPRECATED_PRE_AUTHORIZATION",
    category: "GOVERNANCE" as ErrorCategory,
    httpStatus: 423,
    title: "Registry deprecated before authorization block",
  },
  VAULT_COMMIT_SHREDDED: {
    code: "VAULT.COMMIT_SHREDDED",
    category: "VAULT" as ErrorCategory,
    httpStatus: 409,
    title: "Commit shredded — vault object deleted",
  },
  CHAIN_SHRED_FINALIZED: {
    code: "CHAIN.SHRED_FINALIZED",
    category: "CHAIN" as ErrorCategory,
    httpStatus: 409,
    title: "Shred finalized on-chain — reveal blocked",
  },
  COMBINER_SUPERSEDED_COMMIT_LINEAGE_BROKEN: {
    code: "COMBINER.SUPERSEDED_COMMIT_LINEAGE_BROKEN",
    category: "COMBINER" as ErrorCategory,
    httpStatus: 409,
    title: "Re-key lineage walk failed",
  },
  COMBINER_MODE_3_NOT_SHIPPED_AT_V2: {
    code: "COMBINER.MODE_3_NOT_SHIPPED_AT_V2",
    category: "COMBINER" as ErrorCategory,
    httpStatus: 409,
    title: "Mode 3 (WALLET_EIP1271) not shipped at V2",
  },
  COMBINER_RECIPIENT_SELECTOR_INVALID: {
    code: "COMBINER.RECIPIENT_SELECTOR_INVALID",
    category: "COMBINER" as ErrorCategory,
    httpStatus: 409,
    title: "Recipient schema selector references missing field",
  },
  // §5 + §6 + §7 — auth/rate-limit
  AUTH_UNAUTHENTICATED: {
    code: "AUTH.UNAUTHENTICATED",
    category: "AUTH" as ErrorCategory,
    httpStatus: 401,
    title: "Missing or invalid credentials",
  },
  AUTH_FORBIDDEN: {
    code: "AUTH.FORBIDDEN",
    category: "AUTH" as ErrorCategory,
    httpStatus: 403,
    title: "Insufficient scope or expired credential",
  },
  AUTH_REPLAY: {
    code: "AUTH.REPLAY",
    category: "AUTH" as ErrorCategory,
    httpStatus: 401,
    title: "Timestamp outside replay window or nonce reused",
  },
  RATE_LIMIT_EXCEEDED: {
    code: "RATE_LIMIT.EXCEEDED",
    category: "RATE_LIMIT" as ErrorCategory,
    httpStatus: 429,
    title: "Per-key or per-IP rate limit exceeded",
  },
  // §7 — transport
  TRANSPORT_WEBHOOK_FAILURE: {
    code: "TRANSPORT.WEBHOOK_FAILURE",
    category: "TRANSPORT" as ErrorCategory,
    httpStatus: 502,
    title: "Webhook delivery failed",
  },
  RETRY_EXHAUSTED_WEBHOOK: {
    code: "RETRY_EXHAUSTED.WEBHOOK",
    category: "RETRY_EXHAUSTED" as ErrorCategory,
    httpStatus: 503,
    title: "Webhook delivery retry budget exhausted; entry moved to dead-letter",
  },
  // §11 — Phase 1 / Phase 2 G4 binding
  GOVERNANCE_PHASE_1_REJECTED_FOR_PARTNER_READY: {
    code: "GOVERNANCE.PHASE_1_REJECTED_FOR_PARTNER_READY",
    category: "GOVERNANCE" as ErrorCategory,
    httpStatus: 423,
    title: "Phase 1 G4 not permitted for partner-ready or legal-effect PDAs",
  },
  // §1.4 - general request
  REQUEST_MALFORMED: {
    code: "REQUEST.MALFORMED",
    category: "REQUEST" as ErrorCategory,
    httpStatus: 400,
    title: "Malformed request",
  },
} as const;

export type ErrorCodeKey = keyof typeof ErrorCode;
export type ErrorCodeDescriptor = (typeof ErrorCode)[ErrorCodeKey];
