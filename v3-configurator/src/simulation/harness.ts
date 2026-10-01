import { runAxisSeparation } from "./axis-separation.js";
import { runCanonicalExampleReplay } from "./canonical-example-replay.js";
import { runChallengeWindowLifecycle } from "./challenge-window-lifecycle.js";
import { computeSimulationDigest } from "./digest.js";
import { runFsmReachability } from "./fsm-reachability.js";
import { runGasBudget } from "./gas-budget.js";
import { runRecipientPolicyReplay } from "./recipient-policy-replay.js";
import { runRegistryOverlayReplay } from "./registry-overlay-replay.js";
import { runSchemaCompat } from "./schema-compat.js";
import { runSdIsolation } from "./sd-isolation.js";
import { runUniversalTripwireNegative } from "./universal-tripwire-negative.js";
import type {
  SimulationHarnessInput,
  SimulationHarnessResult,
} from "./types.js";

export function runSimulationHarness(
  input: SimulationHarnessInput,
): SimulationHarnessResult {
  const steps = [
    runFsmReachability(input.fsm_reachability),
    runAxisSeparation(input.axis_separation),
    runGasBudget(input.gas_budget),
    runSchemaCompat(input.schema_compat),
    runCanonicalExampleReplay(input.canonical_examples),
    runChallengeWindowLifecycle(input.challenge_windows),
    runRegistryOverlayReplay(input.registry_overlay),
    runSdIsolation(input.sd_isolation),
    runRecipientPolicyReplay(input.recipient_policy),
    runUniversalTripwireNegative(input.universal_tripwire_negative),
  ] as const;
  return {
    ok: steps.every((step) => step.ok),
    steps,
    simulation_digest: computeSimulationDigest(steps),
  };
}
