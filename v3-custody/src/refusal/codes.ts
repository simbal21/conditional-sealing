// Refusal-code runtime validation helpers.
//
// Source of truth: M2 `G4RefusalRegistry.sol` `_validateBlockingReason`
// (codes 0x01..0x09) + `_validateAdvisoryReason` (code 0x0A only).
// Per SPEC-COMPLIANCE-GUARD-M3 §2: 10 codes total. V1 PoF's 5-code
// enum is forbidden in V3.
//
// Encrypted-reason mode per S2-3 §7.7:
//   0x02 (Art. 17 Erasure)         → encrypted reason blob on-chain
//   0x03 (Art. 18 Restriction)     → encrypted reason blob on-chain
//   all other codes                → public reason / proofRef path

import { RefusalCode, type RefusalCodeValue } from "../types/refusal.js";
import { CustodyError, CUSTODY_ERROR_CODES } from "../errors.js";

/**
 * Frozen map of all 10 refusal codes by symbolic name → numeric value.
 * Mirrors M2 contract constants byte-for-byte.
 */
export const REFUSAL_CODES = Object.freeze<Record<string, number>>({
  REASON_LEGAL_COMPEL: RefusalCode.LegalCompel, // 0x01
  REASON_ART_17_ERASURE: RefusalCode.Art17Erasure, // 0x02
  REASON_ART_18_RESTRICTION: RefusalCode.Art18Restriction, // 0x03
  REASON_INTEGRITY_FAIL: RefusalCode.IntegrityFail, // 0x04
  REASON_CHAIN_MISMATCH: RefusalCode.ChainMismatch, // 0x05
  REASON_PLUGIN_DEPRECATED: RefusalCode.PluginDeprecated, // 0x06
  REASON_AUTHORITY_DEPRECATED: RefusalCode.AuthorityDeprecated, // 0x07
  REASON_DSL_DEPRECATED: RefusalCode.DslDeprecated, // 0x08
  REASON_ORACLE_DEPRECATED: RefusalCode.OracleDeprecated, // 0x09
  REASON_OPT_OUT_ACTIVE: RefusalCode.OptOutActive, // 0x0a
});

/**
 * Returns true iff `code` is in the BLOCKING set (`0x01..0x09`).
 * Blocking codes halt the gate-signing path. Combiner MUST treat
 * G4-refused-blocking as `CUSTODY_ERR_G4_REFUSED` and ABORT — no
 * automatic retry, no fallback path.
 */
export function isBlocking(code: number): boolean {
  return code >= RefusalCode.LegalCompel && code <= RefusalCode.OracleDeprecated;
}

/**
 * Returns true iff `code` is in the ADVISORY set (`0x0A` only).
 * Advisory codes signal a soft preference (e.g. opt-out preference)
 * but do NOT halt gate signing. Combiner SHOULD log advisory codes
 * but MUST proceed with the reveal.
 */
export function isAdvisory(code: number): boolean {
  return code === RefusalCode.OptOutActive;
}

/**
 * Returns true iff `code` REQUIRES encrypted-reason mode per S2-3 §7.7.
 * The two GDPR codes (0x02 Art. 17 Erasure, 0x03 Art. 18 Restriction)
 * use encrypted-reason mode because the plaintext reason itself
 * constitutes processing of subject's data and would create a
 * disclosure obligation.
 *
 * Adapter logs MUST log only `RefusalSignal` event payload + encrypted
 * blob hash for these codes — NEVER plaintext reason. See §3 of GUARD.
 */
export function isEncryptedReasonMode(code: number): boolean {
  return code === RefusalCode.Art17Erasure || code === RefusalCode.Art18Restriction;
}

/**
 * Throws `CustodyError(CUSTODY_ERR_G4_REFUSED)` if `code` is not a
 * valid blocking code. Mirrors M2's `_validateBlockingReason`.
 */
export function validateBlocking(code: number): void {
  if (!isBlocking(code)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_REFUSED,
      `validateBlocking: code 0x${code.toString(16).padStart(2, "0")} not in blocking set 0x01..0x09`,
    );
  }
}

/**
 * Throws `CustodyError` if `code` is not the advisory code 0x0A.
 * Mirrors M2's `_validateAdvisoryReason`.
 */
export function validateAdvisory(code: number): void {
  if (!isAdvisory(code)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_REFUSED,
      `validateAdvisory: code 0x${code.toString(16).padStart(2, "0")} is not the advisory code 0x0A`,
    );
  }
}

/** Total count of refusal codes (10). Used in the foundation test. */
export const REFUSAL_CODE_COUNT: number = Object.keys(REFUSAL_CODES).length;

/**
 * Re-export the canonical typed enum for adapters that prefer
 * `RefusalCode.LegalCompel` over `REFUSAL_CODES.REASON_LEGAL_COMPEL`.
 */
export { RefusalCode };
export type { RefusalCodeValue };
