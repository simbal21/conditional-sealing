import type {
  SimulationSubStepResult,
  UniversalTripwireNegativeInput,
} from "./types.js";

export function runUniversalTripwireNegative(
  input: UniversalTripwireNegativeInput,
): SimulationSubStepResult {
  const ok =
    !input.delivery_fired_before_on_chain_condition &&
    !input.delivery_fired_before_gate_eligibility;
  return {
    step: "universal-tripwire-negative",
    ok,
    details: ok
      ? "No delivery path fires before on-chain condition and gate eligibility."
      : "A delivery path fired before on-chain condition or gate eligibility.",
  };
}
