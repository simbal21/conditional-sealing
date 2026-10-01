import type { Hex32 } from "@cealis/v3-crypto";
import type { HealthProbeResult } from "../adapters/gate-adapter.js";
import { GateKind } from "../types/gate-recipient.js";
import type { LitChipotleClient } from "./chipotle-client.js";

export interface LitHealthProbeInput {
  readonly client: LitChipotleClient;
  readonly registryHead?: bigint;
  readonly lastSuccessfulVectorVerification?: Hex32;
  readonly lastRefusalOrDeprecationSignal?: string;
}

export async function litHealthProbe(input: LitHealthProbeInput): Promise<HealthProbeResult> {
  const observedAt = BigInt(Date.now());
  try {
    const response = await input.client.health();
    return {
      status: response.ok ? "ok" : "degraded",
      gateKind: GateKind.LitV3,
      detail: response.ok ? "Lit Chipotle reachable" : "Lit Chipotle health probe degraded",
      metadata: {
        apiVersion: input.client.versionArtifact.apiVersion,
        litNodeClientVersion: input.client.versionArtifact.litNodeClientVersion,
        contractsSdkVersion: input.client.versionArtifact.contractsSdkVersion,
        endpointLatencyMs: response.latencyMs,
        registryHead: response.registryHead ?? input.registryHead ?? 0n,
        lastSuccessfulVectorVerification: input.lastSuccessfulVectorVerification ?? "0x0000000000000000000000000000000000000000000000000000000000000000",
        lastRefusalOrDeprecationSignal: response.lastRefusalOrDeprecationSignal ?? input.lastRefusalOrDeprecationSignal ?? "none",
      },
      observedAt,
    };
  } catch (err) {
    return {
      status: "unavailable",
      gateKind: GateKind.LitV3,
      detail: "Lit Chipotle health probe failed",
      metadata: {
        apiVersion: input.client.versionArtifact.apiVersion,
        error: err instanceof Error ? err.name : "unknown",
      },
      observedAt,
    };
  }
}
