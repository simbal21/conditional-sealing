// G4 refusal codes — verbatim from S2-5 §10.4 (lines 1030-1043) + S2-2 §14.
//
// LOCKED at Phase A. Spec body grep-verified 2026-05-11: 10 entries (0x01-0x0A).
// Phase A foundation test asserts count = 10.
//
// reason_visibility discriminator (per §10.4):
//   - "encrypted" for 0x02 (Art. 17 erasure) and 0x03 (Art. 18 restriction).
//   - "plaintext" for all others.
//
// Blocking semantics (per §10.4 + internal build brief lines 124-128):
//   - 0x01-0x09 are BLOCKING — G4 refuses to sign σ_G4, reveal halts.
//   - 0x0A (opt_out_active) is ADVISORY — G4 still signs but emits the signal.

export const RefusalCode = {
  /** 0x01 — legal compel: external court order or regulator demand. */
  LegalCompel: 0x01 as const,
  /** 0x02 — Art. 17 erasure (GDPR right-to-be-forgotten). Reason encrypted. */
  Art17Erasure: 0x02 as const,
  /** 0x03 — Art. 18 restriction. Reason encrypted. NO REST freeze endpoint. */
  Art18Restriction: 0x03 as const,
  /** 0x04 — integrity fail: pre-σ pipeline detected snapshot mismatch. */
  IntegrityFail: 0x04 as const,
  /** 0x05 — chain mismatch: registry/event/snapshot drift. */
  ChainMismatch: 0x05 as const,
  /** 0x06 — plugin deprecated: PluginHashRegistry tombstoned. */
  PluginDeprecated: 0x06 as const,
  /** 0x07 — authority deprecated: G4AuthorityRegistry tombstoned. */
  AuthorityDeprecated: 0x07 as const,
  /** 0x08 — DSL deprecated: DSLVersionRegistry tombstoned. */
  DslDeprecated: 0x08 as const,
  /** 0x09 — oracle deprecated: OracleRegistry tombstoned. */
  OracleDeprecated: 0x09 as const,
  /** 0x0A — opt-out active: ADVISORY (non-blocking) per §10.4. */
  OptOutActive: 0x0a as const,
} as const;

export type RefusalCodeValue = (typeof RefusalCode)[keyof typeof RefusalCode];

export const REFUSAL_CODE_COUNT: number = Object.keys(RefusalCode).length;

export type ReasonVisibility = "encrypted" | "plaintext";

/**
 * Reason-visibility class for each code (per §10.4 lines 1032-1043).
 * Codes 0x02 + 0x03 are encrypted; all others plaintext.
 */
export const REASON_VISIBILITY: Readonly<Record<RefusalCodeValue, ReasonVisibility>> = {
  [RefusalCode.LegalCompel]: "plaintext",
  [RefusalCode.Art17Erasure]: "encrypted",
  [RefusalCode.Art18Restriction]: "encrypted",
  [RefusalCode.IntegrityFail]: "plaintext",
  [RefusalCode.ChainMismatch]: "plaintext",
  [RefusalCode.PluginDeprecated]: "plaintext",
  [RefusalCode.AuthorityDeprecated]: "plaintext",
  [RefusalCode.DslDeprecated]: "plaintext",
  [RefusalCode.OracleDeprecated]: "plaintext",
  [RefusalCode.OptOutActive]: "plaintext",
} as const;

/**
 * Reason-label lookup table — labels are themselves safe (no PII).
 * Verbatim from §10.4 line 1038 example + S2-2 §14 enum naming.
 */
export const REASON_LABEL: Readonly<Record<RefusalCodeValue, string>> = {
  [RefusalCode.LegalCompel]: "legal_compel",
  [RefusalCode.Art17Erasure]: "art_17_erasure",
  [RefusalCode.Art18Restriction]: "art_18_restriction",
  [RefusalCode.IntegrityFail]: "integrity_fail",
  [RefusalCode.ChainMismatch]: "chain_mismatch",
  [RefusalCode.PluginDeprecated]: "plugin_deprecated",
  [RefusalCode.AuthorityDeprecated]: "authority_deprecated",
  [RefusalCode.DslDeprecated]: "dsl_deprecated",
  [RefusalCode.OracleDeprecated]: "oracle_deprecated",
  [RefusalCode.OptOutActive]: "opt_out_active",
} as const;

/**
 * Predicate: does this refusal code halt reveal (i.e., G4 refuses σ_G4)?
 *
 * 0x01-0x09 are BLOCKING; 0x0A is advisory-only and reveal continues.
 */
export function isBlockingRefusal(code: RefusalCodeValue): boolean {
  return code !== RefusalCode.OptOutActive;
}

/**
 * Predicate: is the reason encrypted?
 */
export function isEncryptedReason(code: RefusalCodeValue): boolean {
  return REASON_VISIBILITY[code] === "encrypted";
}

/**
 * Validation guard: assert a numeric input is a valid 0x01-0x0A code.
 * Used by Phase B/C/D before persisting refusal entries.
 */
export function asRefusalCode(value: number): RefusalCodeValue {
  if (value >= 0x01 && value <= 0x0a) {
    return value as RefusalCodeValue;
  }
  throw new Error(`Invalid refusal code: 0x${value.toString(16)}. Valid range: 0x01-0x0A.`);
}

/**
 * Hex-string formatter — `0x01` lowercase two-digit form per §10.4 line 1037.
 */
export function formatRefusalCodeHex(code: RefusalCodeValue): string {
  return `0x${code.toString(16).padStart(2, "0")}`;
}

/**
 * Problem+JSON-shaped refusal body discriminator.
 *
 * For encrypted reasons (0x02/0x03), API response/webhook payload carries:
 *   { code, reason_code, reason_label, reason_visibility: "encrypted",
 *     encrypted_reason_ref, retryable: false }
 *
 * For plaintext reasons, the same body shape but reason_visibility = "plaintext"
 * and `encrypted_reason_ref` is absent.
 *
 * Phase D webhook payload builder + Phase A error formatter consume this type.
 */
export type RefusalProblemBody =
  | {
      code: "GOVERNANCE.G4_REFUSED";
      reason_code: string; // formatRefusalCodeHex(...)
      reason_label: string;
      reason_visibility: "encrypted";
      encrypted_reason_ref: string;
      retryable: false;
    }
  | {
      code: "GOVERNANCE.G4_REFUSED";
      reason_code: string;
      reason_label: string;
      reason_visibility: "plaintext";
      retryable: false;
    };
