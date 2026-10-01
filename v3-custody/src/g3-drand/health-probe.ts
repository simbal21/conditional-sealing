import type { HealthProbeResult } from "../adapters/gate-adapter.js";
import { GateKind } from "../types/gate-recipient.js";
import type { DrandClient } from "./client.js";

export async function drandHealthProbe(client: DrandClient): Promise<HealthProbeResult> {
  const endpoints = client.getEndpoints();
  const chain = client.getChainProfile();
  const expectedRound = currentRound(chain.genesisTime, chain.periodSeconds);
  const endpointIds = endpoints.map((endpoint) => endpoint.id).join(",");

  return {
    status: "ok",
    gateKind: GateKind.Drand,
    detail: "drand adapter configured with pinned HTTPS endpoints",
    metadata: {
      versionPin: "drand-client@1.4.2",
      endpointCount: endpoints.length,
      endpointIds,
      chainHash: chain.chainHash,
      expectedRound,
      committeeKeyRef: chain.committeeKeyRef,
      governanceTimelockRef: chain.governanceTimelockRef,
    },
    observedAt: BigInt(Date.now()),
  };
}

function currentRound(genesisTime: number, periodSeconds: number): bigint {
  const nowSeconds = Math.floor(Date.now() / 1_000);
  if (nowSeconds <= genesisTime) return 1n;
  return BigInt(Math.floor((nowSeconds - genesisTime) / periodSeconds) + 1);
}
