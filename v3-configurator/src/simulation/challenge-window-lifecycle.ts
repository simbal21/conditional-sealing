import type {
  ChallengeWindowLifecycleInput,
  SimulationSubStepResult,
} from "./types.js";

export function runChallengeWindowLifecycle(
  input: ChallengeWindowLifecycleInput,
): SimulationSubStepResult {
  const ok = input.zero_window_replayed && input.non_zero_window_replayed;
  return {
    step: "challenge-window-lifecycle",
    ok,
    details: ok
      ? "Zero-window and non-zero-window lifecycle paths replay correctly."
      : "Zero-window or non-zero-window lifecycle replay is missing.",
  };
}
