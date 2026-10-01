import type { SchemaCompatInput, SimulationSubStepResult } from "./types.js";

export function runSchemaCompat(
  input: SchemaCompatInput,
): SimulationSubStepResult {
  const failures = input.claims.filter(
    (claim) => !claim.type_checks_against_registry_example,
  );
  return {
    step: "schema-compat",
    ok: failures.length === 0,
    details:
      failures.length === 0
        ? "Every Claim path type-checks against OracleSchemaRegistry examples."
        : `Claim paths failed registry example type-check: ${failures.map((claim) => claim.path).join(",")}.`,
  };
}
