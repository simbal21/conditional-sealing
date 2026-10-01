import type { HealthProbeResult } from "../adapters/gate-adapter.js";
import { GateKind } from "../types/gate-recipient.js";
import { loadDcipherSdk } from "./sdk-loader.js";

export async function dcipherHealthProbe(): Promise<HealthProbeResult> {
  const load = loadDcipherSdk();
  return {
    status: load.included ? "ok" : "unavailable",
    gateKind: GateKind.Dcipher,
    detail:
      load.status.status === "pinned"
        ? "dcipher SDK present"
        : "dcipher SDK deferred; drand-only build",
    metadata:
      load.status.status === "pinned"
        ? {
            packageName: load.status.packageName,
            version: load.status.version,
          }
        : {
            status: load.status.status,
            reason: load.status.reason,
            expectedPackage: load.status.expectedPackage,
          },
    observedAt: BigInt(Date.now()),
  };
}
