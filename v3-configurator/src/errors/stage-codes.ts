// S2-4 §1.3 + §4.7 — Stage-indexed validation error code format.
//
// Format: `S2_4_STAGE_<N>.<SURFACE_NAME>.<CODE>` per §1.3.
//
// Example from §4.7:
//   `S2_4_STAGE_4.cealis_class_wide_halt_opt_out.LEGAL_EFFECT_FORBIDDEN`
//
// The internal audit form includes: stage number, surface name, failed
// predicate, category, sub-class (if applicable), source field path,
// sanitized value class (NOT raw PII), S2-x cross-ref, remediation path.
//
// The partner-facing form is shorter: field/concept that failed, why
// the current configuration cannot deploy, whether the partner can
// choose a different allowed option or must request a Cealis-internal
// PDA+ change. Partner-facing messages NEVER say "cryptographic-invariant
// violation" without plain-language explanation.

/**
 * The five verification-gate stages per §4.1.
 *
 * 1 = Syntax
 * 2 = Crypto-invariant (CI-01..CI-20)
 * 3 = PDA+ allow-list and bounds
 * 4 = Cross-field rules (CF-01..CF-07)
 * 5 = Simulation + human Cealis-operator review
 */
export type Stage = 1 | 2 | 3 | 4 | 5;

export const STAGE_VALUES: readonly Stage[] = [1, 2, 3, 4, 5] as const;

/**
 * Format a stage-indexed error code per §1.3.
 *
 * @param stage Stage 1-5.
 * @param surface_name Stable snake_case surface identifier from class-table row.
 * @param code Failure-class code (e.g., "LEGAL_EFFECT_FORBIDDEN", "MODE_3_RESERVED").
 *
 * @returns `S2_4_STAGE_<N>.<surface>.<code>` string.
 *
 * @throws if any input contains whitespace or a `.` (those break the
 *   `<stage>.<surface>.<code>` tokenization).
 */
export function formatStageCode(stage: Stage, surface_name: string, code: string): string {
  if (!Number.isInteger(stage) || stage < 1 || stage > 5) {
    throw new Error(`formatStageCode: invalid stage ${String(stage)}; must be 1..5`);
  }
  if (surface_name.length === 0 || /[\s.]/.test(surface_name)) {
    throw new Error(`formatStageCode: invalid surface_name ${JSON.stringify(surface_name)}`);
  }
  if (code.length === 0 || /[\s.]/.test(code)) {
    throw new Error(`formatStageCode: invalid code ${JSON.stringify(code)}`);
  }
  return `S2_4_STAGE_${String(stage)}.${surface_name}.${code}`;
}

/**
 * Parse a stage-indexed error code into its three components.
 *
 * Returns `null` if the input does not match the canonical
 * `S2_4_STAGE_<N>.<surface>.<code>` form.
 */
export function parseStageCode(
  formatted: string,
): { stage: Stage; surface_name: string; code: string } | null {
  const match = /^S2_4_STAGE_([1-5])\.([^.\s]+)\.([^.\s]+)$/.exec(formatted);
  if (!match) return null;
  const stageStr = match[1];
  const surface_name = match[2];
  const code = match[3];
  if (stageStr === undefined || surface_name === undefined || code === undefined) return null;
  const stage = Number(stageStr) as Stage;
  return { stage, surface_name, code };
}

/** Stage-code prefix per §1.3 (`S2_4_STAGE_`). */
export const STAGE_CODE_PREFIX = "S2_4_STAGE_" as const;
