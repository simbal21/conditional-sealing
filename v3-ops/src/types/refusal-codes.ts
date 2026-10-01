/**
 * G4 refusal reason codes per WP §N + S2-2 lines 1466–1472 + S2-3 §5
 * lines 583–589.
 *
 * 10 codes in 3 classes:
 *   - Per-subject refusal (blocking, per-commit): 0x01..0x05
 *   - Class-wide deprecation (blocking, separate ops path): 0x06..0x09
 *   - Advisory (non-blocking): 0x0A
 *
 * Foundation test `refusal-code-classes.test.ts` asserts 10 distinct codes
 * in 3 classes + names verbatim.
 */
export const G4RefusalCode = {
  // Per-subject refusal (per-commit, blocking)
  LEGAL_COMPEL: 0x01,
  ART_17: 0x02, // encrypted-reason mode default per §0.9
  ART_18: 0x03, // encrypted-reason mode default per §0.9
  INTEGRITY_FAIL: 0x04,
  CHAIN_MISMATCH: 0x05,
  // Class-wide deprecation (blocking, separate ops path)
  PLUGIN_DEPRECATED: 0x06,
  AUTHORITY_DEPRECATED: 0x07,
  DSL_DEPRECATED: 0x08,
  ORACLE_DEPRECATED: 0x09,
  // Advisory (non-blocking)
  OPT_OUT_ACTIVE: 0x0a,
} as const;

export type G4RefusalCode = (typeof G4RefusalCode)[keyof typeof G4RefusalCode];

export type G4RefusalClass = "per_subject" | "class_wide" | "advisory";

export function refusalClass(code: G4RefusalCode): G4RefusalClass {
  if (code >= 0x01 && code <= 0x05) return "per_subject";
  if (code >= 0x06 && code <= 0x09) return "class_wide";
  if (code === 0x0a) return "advisory";
  // Unreachable under the type; defensive throw at runtime would leak a
  // refusal context into a log message, which the PII discipline forbids.
  // Return a non-classified marker the caller must handle.
  throw new Error("UNCLASSIFIED_REFUSAL_CODE");
}

export const G4_REFUSAL_CODES: readonly G4RefusalCode[] = Object.freeze([
  G4RefusalCode.LEGAL_COMPEL,
  G4RefusalCode.ART_17,
  G4RefusalCode.ART_18,
  G4RefusalCode.INTEGRITY_FAIL,
  G4RefusalCode.CHAIN_MISMATCH,
  G4RefusalCode.PLUGIN_DEPRECATED,
  G4RefusalCode.AUTHORITY_DEPRECATED,
  G4RefusalCode.DSL_DEPRECATED,
  G4RefusalCode.ORACLE_DEPRECATED,
  G4RefusalCode.OPT_OUT_ACTIVE,
]);

/**
 * Whether the refusal halts the commit. 0x01..0x09 halt; 0x0A is advisory
 * only (G4 still signs, advisory signal emitted).
 */
export function isBlocking(code: G4RefusalCode): boolean {
  return code !== G4RefusalCode.OPT_OUT_ACTIVE;
}

/**
 * Whether the refusal reason must be emitted encrypted-only per §0.9.
 * 0x02 and 0x03 default to encrypted-reason mode.
 */
export function reasonRequiresEncryption(code: G4RefusalCode): boolean {
  return code === G4RefusalCode.ART_17 || code === G4RefusalCode.ART_18;
}
