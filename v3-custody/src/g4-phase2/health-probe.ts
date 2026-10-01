import { GateKind } from "../types/gate-recipient.js";
import type { HealthProbeResult } from "../adapters/gate-adapter.js";
import { G4_PHASE2_DEFERRED_REASON } from "./deferred-marker.js";

export async function healthProbe(): Promise<HealthProbeResult> {
  return {
    status: "unavailable",
    gateKind: GateKind.G4,
    detail: G4_PHASE2_DEFERRED_REASON,
    metadata: { deferred: "true" },
    observedAt: BigInt(Math.floor(Date.now() / 1000)),
  };
}
