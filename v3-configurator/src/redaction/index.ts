// S2-4 §1.4 + SPEC-COMPLIANCE-GUARD §9 / §23 — PII redaction guard.
//
// Phase A locks the TYPE SURFACE. Phase E's `log-sanitize.ts` implements
// the body — Phase E owns runtime grep + stringified-record sanitization.
//
// Phase A exports:
//   - `RedactedValue` marker for sanitized scalars.
//   - `RedactionResult` for sanitized-payload reporting.
//   - `redact()` signature (body implemented Phase E).
//
// Per §1.4 NEVER-logged set:
//   - σ values (sigma_lit / sigma_g3 / sigma_g4 / sigma_subject)
//   - Shamir shares
//   - DEK material
//   - SD salts
//   - raw KYC fields
//   - plaintext refusal reasons for 0x02 / 0x03 G4 codes
//   - delivery URL bodies
//   - recipient secrets

import { findPiiMatch, PII_EXCLUSION_PATTERNS } from "../types/audit-trail.js";

export { PII_EXCLUSION_PATTERNS, findPiiMatch };

/**
 * Sanitized scalar marker. When redact() strips a PII match it replaces
 * the value with this opaque marker; downstream serializers MUST NOT
 * un-mark it.
 */
export interface RedactedValue {
  readonly __redacted: true;
  /** The matched PII pattern that triggered redaction (audit hint). */
  readonly matched_pattern: string;
  /** Byte length of the original value (NOT the value itself). */
  readonly original_byte_length: number;
}

/**
 * Result of a redact() call.
 */
export interface RedactionResult {
  /** Sanitized payload (deep clone with PII replaced by RedactedValue markers). */
  readonly sanitized: unknown;
  /** Patterns that fired during sanitization (audit hint). */
  readonly patterns_matched: ReadonlyArray<string>;
  /** Whether the payload was clean (no PII detected). */
  readonly clean: boolean;
}

/**
 * Redact PII from an arbitrary JSON-serializable value.
 *
 * Phase A signature ONLY — Phase E implements. Phase A foundation
 * test asserts `typeof redact === "function"`.
 */
export type RedactSignature = (input: unknown) => RedactionResult;

/**
 * Runtime implementation lives in `log-sanitize.ts`.
 */
export { redact, assertNoPiiPatterns } from "./log-sanitize.js";
