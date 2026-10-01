import type { AxisSeparationInput, SimulationSubStepResult } from "./types.js";

export function runAxisSeparation(
  input: AxisSeparationInput,
): SimulationSubStepResult {
  const reveal = new Set(input.reveal_terminal_states);
  const overlap = input.shred_terminal_states.filter((state) =>
    reveal.has(state),
  );
  return {
    step: "axis-separation",
    ok: overlap.length === 0,
    details:
      overlap.length === 0
        ? "Reveal and shred terminal states are separated."
        : `Reveal and shred terminal states overlap: ${overlap.join(",")}.`,
  };
}
