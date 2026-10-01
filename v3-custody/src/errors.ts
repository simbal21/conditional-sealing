// CUSTODY_ERR_* operational error catalog.
//
// Source of truth: `docs/specs/custody-integration-spec.md` §13.1 — the
// 37 codes below are reproduced VERBATIM from the spec body's
// enumerated list. Adding a code without an §13.1 amendment is a spec
// violation; Codex chunks MUST consume from this catalog and MUST NOT
// invent codes.
//
// PHASE-PLAN note: the M3 plan said "38 codes"; the spec actually
// enumerates 37. The spec is canonical (Rule 0). The discrepancy is
// surfaced in `run-summary-A.md`.
//
// Composite-error pattern (S2-3 §13.2): one top-level `CUSTODY_ERR_*`
// class carries one or more forensic sub-codes (S2-1 `ERR_*`, M2
// custom errors, registry entry ids, etc.). σ bytes, plaintext, and
// raw quotes MUST NOT appear in `metadata` per S2-3 §13.2.

/**
 * Frozen const map of all 37 operational error codes from S2-3 §13.1.
 * Each value is identical to its key — the map exists to give
 * compile-time guarantees that downstream code references a known code.
 */
export const CUSTODY_ERROR_CODES = Object.freeze({
  CUSTODY_ERR_FINALITY_PENDING: "CUSTODY_ERR_FINALITY_PENDING",
  CUSTODY_ERR_CHALLENGE_WINDOW_OPEN: "CUSTODY_ERR_CHALLENGE_WINDOW_OPEN",
  CUSTODY_ERR_GATES_CANNOT_SIGN: "CUSTODY_ERR_GATES_CANNOT_SIGN",
  CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE: "CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE",
  CUSTODY_ERR_LIT_ASSIGNMENT_MISSING: "CUSTODY_ERR_LIT_ASSIGNMENT_MISSING",
  CUSTODY_ERR_LIT_ASSIGNMENT_MISMATCH: "CUSTODY_ERR_LIT_ASSIGNMENT_MISMATCH",
  CUSTODY_ERR_LIT_ACC_REJECTED: "CUSTODY_ERR_LIT_ACC_REJECTED",
  CUSTODY_ERR_LIT_DCAP_INVALID: "CUSTODY_ERR_LIT_DCAP_INVALID",
  CUSTODY_ERR_LIT_QUOTE_REPLAY: "CUSTODY_ERR_LIT_QUOTE_REPLAY",
  CUSTODY_ERR_LIT_SIG_INVALID: "CUSTODY_ERR_LIT_SIG_INVALID",
  CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED: "CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED",
  CUSTODY_ERR_DCIPHER_REGISTRY_UNAVAILABLE: "CUSTODY_ERR_DCIPHER_REGISTRY_UNAVAILABLE",
  CUSTODY_ERR_DCIPHER_EPOCH_MISMATCH: "CUSTODY_ERR_DCIPHER_EPOCH_MISMATCH",
  CUSTODY_ERR_DCIPHER_THRESHOLD_NOT_MET: "CUSTODY_ERR_DCIPHER_THRESHOLD_NOT_MET",
  CUSTODY_ERR_DCIPHER_TOMBSTONED: "CUSTODY_ERR_DCIPHER_TOMBSTONED",
  CUSTODY_ERR_DCIPHER_SIG_INVALID: "CUSTODY_ERR_DCIPHER_SIG_INVALID",
  CUSTODY_ERR_DRAND_ROUND_PENDING: "CUSTODY_ERR_DRAND_ROUND_PENDING",
  CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE: "CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE",
  CUSTODY_ERR_DRAND_CHAIN_MISMATCH: "CUSTODY_ERR_DRAND_CHAIN_MISMATCH",
  CUSTODY_ERR_DRAND_ROUND_MISMATCH: "CUSTODY_ERR_DRAND_ROUND_MISMATCH",
  CUSTODY_ERR_DRAND_SIG_INVALID: "CUSTODY_ERR_DRAND_SIG_INVALID",
  CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE: "CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE",
  CUSTODY_ERR_G4_PHASE_MISMATCH: "CUSTODY_ERR_G4_PHASE_MISMATCH",
  CUSTODY_ERR_G4_DCAP_INVALID: "CUSTODY_ERR_G4_DCAP_INVALID",
  CUSTODY_ERR_G4_REFUSED: "CUSTODY_ERR_G4_REFUSED",
  CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION: "CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION",
  CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL: "CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL",
  CUSTODY_ERR_GATE_PUBKEY_MISMATCH: "CUSTODY_ERR_GATE_PUBKEY_MISMATCH",
  CUSTODY_ERR_GATE_PUBKEY_ROTATION_MID_FLIGHT: "CUSTODY_ERR_GATE_PUBKEY_ROTATION_MID_FLIGHT",
  CUSTODY_ERR_SHRED_STATE_BLOCKED: "CUSTODY_ERR_SHRED_STATE_BLOCKED",
  CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET: "CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET",
  CUSTODY_ERR_AEAD_FAIL: "CUSTODY_ERR_AEAD_FAIL",
  CUSTODY_ERR_SD_ONBOARDING_PARTIAL_FAILURE: "CUSTODY_ERR_SD_ONBOARDING_PARTIAL_FAILURE",
  CUSTODY_ERR_COMBINER_BINARY_MISMATCH: "CUSTODY_ERR_COMBINER_BINARY_MISMATCH",
  CUSTODY_ERR_SIGMA_REDACTION_BREACH: "CUSTODY_ERR_SIGMA_REDACTION_BREACH",
  // §13.1: "deprecated compatibility alias; new SDKs emit
  // `CUSTODY_ERR_SIGMA_REDACTION_BREACH`". Kept in the catalog so old
  // logs are still parseable.
  CUSTODY_ERR_SIGMA_CONFIDENTIALITY_BREACH: "CUSTODY_ERR_SIGMA_CONFIDENTIALITY_BREACH",
  CUSTODY_ERR_MODE3_RESERVED: "CUSTODY_ERR_MODE3_RESERVED",
} as const);

/** Union type of all valid `CUSTODY_ERR_*` codes. */
export type CustodyErrorCode = keyof typeof CUSTODY_ERROR_CODES;

/** Returns true iff `code` is a known `CUSTODY_ERR_*` value. */
export function isCustodyErrorCode(code: string): code is CustodyErrorCode {
  return Object.prototype.hasOwnProperty.call(CUSTODY_ERROR_CODES, code);
}

/**
 * `CustodyError` — operational error class. Carries one top-level
 * `code` (a CUSTODY_ERR_*) and an optional ordered list of forensic
 * `subCodes` per S2-3 §13.2 composite-error semantics.
 *
 * Forbidden in `metadata`: σ bytes, plaintext content, raw vendor
 * quote bodies, partial commit_AAD. `metadata` should carry only
 * structured forensic IDs (entry ids, deprecation blocks, disclosure
 * CIDs, etc.). The redaction guard in `src/redaction/log-sanitize.ts`
 * provides additional defense-in-depth.
 */
export class CustodyError extends Error {
  public readonly code: CustodyErrorCode;
  public readonly subCodes: readonly string[];
  public readonly metadata: Readonly<Record<string, string | number | bigint>>;

  constructor(
    code: CustodyErrorCode,
    message: string,
    options?: {
      subCodes?: readonly string[];
      metadata?: Record<string, string | number | bigint>;
      cause?: unknown;
    },
  ) {
    super(`${code}: ${message}`);
    this.name = "CustodyError";
    this.code = code;
    this.subCodes = options?.subCodes ?? [];
    this.metadata = Object.freeze({ ...(options?.metadata ?? {}) });
    if (options?.cause !== undefined) {
      // ES2022 Error cause
      (this as { cause?: unknown }).cause = options.cause;
    }
  }

  /**
   * Returns a JSON-safe summary suitable for logging. Does NOT include
   * `cause` or stack — only `code`, `subCodes`, and `metadata`. Use
   * `JSON.stringify(err.toLogObject())` rather than `JSON.stringify(err)`
   * to avoid leaking cause-chain contents that might contain σ bytes.
   */
  public toLogObject(): {
    code: string;
    subCodes: readonly string[];
    metadata: Readonly<Record<string, string | number | bigint>>;
  } {
    return {
      code: this.code,
      subCodes: this.subCodes,
      metadata: this.metadata,
    };
  }
}

/**
 * Wrap an S2-1 cryptographic error code as a forensic sub-code under a
 * top-level operational `CUSTODY_ERR_*` per S2-3 §13.2. Returns a
 * `CustodyError` carrying the S2-1 code as the first sub-code.
 *
 * @param s2_1_code   Forensic sub-code from S2-1 (e.g. "ERR_SIGMA_LIT_PUBKEY_LENGTH").
 *                    Free-form string; the catalog of S2-1 codes is owned by M1.
 * @param custodyCode Top-level operational class.
 * @param message     Human-readable detail (must not include σ / plaintext).
 * @param cause       Optional underlying error.
 */
export function wrapS2_1Error(
  s2_1_code: string,
  custodyCode: CustodyErrorCode,
  message: string,
  cause?: unknown,
): CustodyError {
  return new CustodyError(custodyCode, message, {
    subCodes: [s2_1_code],
    cause,
  });
}

/**
 * Compose a `CustodyError` with multiple sub-codes (e.g. a Lit-channel
 * failure that wraps both an S2-1 ERR_SIGMA_LIT_* and an M2
 * registry-entry-id reference).
 */
export function composeCustodyError(
  custodyCode: CustodyErrorCode,
  subCodes: readonly string[],
  message: string,
  metadata?: Record<string, string | number | bigint>,
  cause?: unknown,
): CustodyError {
  return new CustodyError(custodyCode, message, { subCodes, metadata, cause });
}
