import { throwProblem } from "../errors/problem.js";
import type { RouteRegistry } from "../openapi/scaffold.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";
import type { RevealArtifactRepository, RevealStatusRecord } from "../bundle/persist.js";

export interface GetRevealStatusParams {
  readonly authorizationId: Hex32;
}

export function registerGetRevealStatusRoute(registry: RouteRegistry): void {
  registry.register({
    operationId: "getRevealStatus",
    method: "GET",
    url: "/reveals/{authorizationId}",
  });
}

export async function getRevealStatus(
  repository: RevealArtifactRepository,
  params: GetRevealStatusParams,
): Promise<RevealStatusRecord> {
  const status = await repository.getStatus(params.authorizationId);
  if (status === undefined) {
    throwProblem("REQUEST_MALFORMED", params.authorizationId, {
      detail: "Reveal authorizationId is unknown.",
      safe_refs: { authorizationId: params.authorizationId },
    });
  }
  return status;
}
