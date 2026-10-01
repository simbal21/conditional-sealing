import { throwProblem } from "../errors/problem.js";
import type { RouteRegistry } from "../openapi/scaffold.js";
import type { CombinerManifest } from "../types/combiner-manifest.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";
import type { RevealArtifactRepository } from "../bundle/persist.js";

export interface GetCombinerManifestParams {
  readonly authorizationId: Hex32;
}

export function registerGetCombinerManifestRoute(registry: RouteRegistry): void {
  registry.register({
    operationId: "getCombinerManifest",
    method: "GET",
    url: "/reveals/{authorizationId}/delivery-manifest",
  });
}

export async function getCombinerManifest(
  repository: RevealArtifactRepository,
  params: GetCombinerManifestParams,
): Promise<CombinerManifest> {
  const manifest = await repository.getManifest(params.authorizationId);
  if (manifest === undefined) {
    throwProblem("REQUEST_MALFORMED", params.authorizationId, {
      detail: "Combiner manifest is unavailable for authorizationId.",
      safe_refs: { authorizationId: params.authorizationId },
    });
  }
  return manifest;
}
