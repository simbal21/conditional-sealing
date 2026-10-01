import type { SdIsolationInput, SimulationSubStepResult } from "./types.js";

export function runSdIsolation(
  input: SdIsolationInput,
): SimulationSubStepResult {
  const auditDiff = new Set(input.audit_diff_fields);
  const missing = input.non_escrow_only_fields.filter(
    (field) => !auditDiff.has(field),
  );
  const ok = input.escrow_succeeds_when_sd_fails && missing.length === 0;
  return {
    step: "sd-isolation",
    ok,
    details: ok
      ? "Escrow succeeds when SD fails, and non-escrow-only fields appear in audit diff."
      : "SD isolation replay failed: escrow did not survive SD failure or audit diff missed non-escrow-only fields.",
  };
}
