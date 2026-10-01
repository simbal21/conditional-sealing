import type { GasBudgetInput, SimulationSubStepResult } from "./types.js";

function toBigInt(value: bigint | number): bigint {
  return typeof value === "bigint" ? value : BigInt(Math.trunc(value));
}

export function runGasBudget(input: GasBudgetInput): SimulationSubStepResult {
  const budget = toBigInt(input.pda_budget_gas);
  const worstCase =
    toBigInt(input.advance_fsm_worst_case_gas) +
    toBigInt(input.predicate_worst_case_gas);
  return {
    step: "gas-budget",
    ok: worstCase <= budget,
    details:
      worstCase <= budget
        ? "Worst-case advanceFSM plus predicate paths fit within PDA budget."
        : "Worst-case advanceFSM plus predicate paths exceed PDA budget.",
  };
}
