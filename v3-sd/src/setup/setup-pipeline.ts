import type { PtauSelection } from "./ptau-loader.js";
import type { PerCircuitSetupArtifact } from "./per-circuit-setup.js";

export interface SetupPipelineResult {
  readonly ptau: PtauSelection;
  readonly circuits: readonly PerCircuitSetupArtifact[];
  readonly constraintReportPath: string;
  readonly vkeyDigestReportPath: string;
}
