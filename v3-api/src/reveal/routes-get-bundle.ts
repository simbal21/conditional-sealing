import { throwProblem } from "../errors/problem.js";
import type { RouteRegistry } from "../openapi/scaffold.js";
import type { Hex32, RevealArtifactBundle } from "../types/reveal-artifact-bundle.js";
import type { RevealArtifactRepository } from "../bundle/persist.js";

export interface GetRevealArtifactBundleParams {
  readonly authorizationId: Hex32;
  readonly recipient_ref: string;
}

export function registerGetRevealArtifactBundleRoute(registry: RouteRegistry): void {
  registry.register({
    operationId: "getRevealArtifactBundle",
    method: "GET",
    url: "/reveals/{authorizationId}/artifact-bundles/{recipient_ref}",
  });
}

export async function getRevealArtifactBundle(
  repository: RevealArtifactRepository,
  params: GetRevealArtifactBundleParams,
): Promise<RevealArtifactBundle> {
  const record = await repository.getBundle(params.authorizationId, params.recipient_ref);
  if (record === undefined) {
    throwProblem("REQUEST_MALFORMED", params.authorizationId, {
      detail: "Reveal artifact bundle is unavailable for recipient_ref.",
      safe_refs: { authorizationId: params.authorizationId },
    });
  }
  return record.bundle;
}
