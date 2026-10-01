import type { FsmReachabilityInput, SimulationSubStepResult } from "./types.js";

export function runFsmReachability(
  input: FsmReachabilityInput,
): SimulationSubStepResult {
  const reachable = new Set<string>([input.initial]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const transition of input.transitions) {
      if (reachable.has(transition.from) && !reachable.has(transition.to)) {
        reachable.add(transition.to);
        changed = true;
      }
    }
  }
  const allStatesReachable = input.states.every((state) =>
    reachable.has(state),
  );
  const terminalsReachable = input.terminal_firing_states.every((state) =>
    reachable.has(state),
  );
  return {
    step: "fsm-reachability",
    ok: allStatesReachable && terminalsReachable,
    details:
      allStatesReachable && terminalsReachable
        ? "Every state and terminal firing state is reachable from initial."
        : "At least one state or terminal firing state is unreachable from initial.",
  };
}
