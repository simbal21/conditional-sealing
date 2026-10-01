import { GateKind } from "../types/gate-recipient.js";
import type { HealthProbeResult } from "../adapters/gate-adapter.js";

export async function healthProbe(endpoint: URL): Promise<HealthProbeResult> {
  const observedAt = BigInt(Math.floor(Date.now() / 1000));
  try {
    const response = await fetch(new URL("/health", endpoint));
    return {
      status: response.ok ? "ok" : "degraded",
      gateKind: GateKind.G4,
      detail: response.ok ? "G4 Phase 1 daemon health endpoint reachable" : `health returned ${response.status}`,
      metadata: { endpoint: endpoint.origin },
      observedAt,
    };
  } catch {
    return {
      status: "unavailable",
      gateKind: GateKind.G4,
      detail: "G4 Phase 1 daemon health endpoint unavailable",
      metadata: { endpoint: endpoint.origin },
      observedAt,
    };
  }
}
