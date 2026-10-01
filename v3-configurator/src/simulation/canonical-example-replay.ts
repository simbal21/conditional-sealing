import type {
  CanonicalExampleReplayInput,
  SimulationSubStepResult,
} from "./types.js";

export function runCanonicalExampleReplay(
  input: CanonicalExampleReplayInput,
): SimulationSubStepResult {
  const failures = input.examples.filter(
    (example) =>
      !example.registered_valid_example_passed ||
      !example.registered_invalid_example_failed,
  );
  return {
    step: "canonical-example-replay",
    ok: failures.length === 0,
    details:
      failures.length === 0
        ? "Each Claim passes registered valid examples and fails registered invalid examples."
        : `Canonical example replay failed for: ${failures.map((example) => example.claim_path).join(",")}.`,
  };
}
