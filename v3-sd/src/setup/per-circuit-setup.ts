import type { CircuitName } from "../circuits/index.js";

export interface PerCircuitSetupArtifact {
  readonly circuit: CircuitName;
  readonly r1csPath: string;
  readonly wasmPath: string;
  readonly zkeyPath: string;
  readonly vkeyPath: string;
  readonly solidityVerifierPath: string;
  readonly constraints: number;
}
