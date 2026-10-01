import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { HttpProblem } from "../errors/index.js";
import type { RouteRegistry } from "../openapi/scaffold.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";
import type { RevealArtifactRepository } from "../bundle/persist.js";
import { registerGetRevealArtifactBundleRoute, getRevealArtifactBundle } from "./routes-get-bundle.js";
import { registerGetCombinerManifestRoute, getCombinerManifest } from "./routes-get-manifest.js";
import { registerGetRevealStatusRoute, getRevealStatus } from "./routes-get-status.js";

export * from "./routes-get-status.js";
export * from "./routes-get-manifest.js";
export * from "./routes-get-bundle.js";
export * from "./reveal-coordinator.js";

export function registerRevealReadRoutes(registry: RouteRegistry): void {
  registerGetRevealStatusRoute(registry);
  registerGetCombinerManifestRoute(registry);
  registerGetRevealArtifactBundleRoute(registry);
}

function sendProblem(reply: FastifyReply, error: HttpProblem): void {
  reply.status(error.body.status).type("application/problem+json").send(error.body);
}

/**
 * Bind the three reveal-read GET handlers onto Fastify from a DB-backed
 * `RevealArtifactRepository` (Wave-5 T2.1). The canonical S2-5 §3 paths
 * (OPERATION_TO_PATH) are partner-HMAC-authed and event-driven (no POST). The
 * business-logic functions already exist; this binds them to the FastifyInstance
 * so the combiner-written reveal status / manifest / bundle are actually served.
 */
export function registerRevealReadHandlers(
  app: FastifyInstance,
  repository: RevealArtifactRepository,
): void {
  const wrap = async (reply: FastifyReply, fn: () => Promise<unknown>): Promise<void> => {
    try {
      reply.send(await fn());
    } catch (error) {
      if (error instanceof HttpProblem) {
        sendProblem(reply, error);
        return;
      }
      throw error;
    }
  };

  app.get(
    "/v1/reveals/:authorizationId",
    async (request: FastifyRequest<{ Params: { authorizationId: string } }>, reply) =>
      wrap(reply, () => getRevealStatus(repository, { authorizationId: request.params.authorizationId as Hex32 })),
  );

  app.get(
    "/v1/reveals/:authorizationId/delivery-manifest",
    async (request: FastifyRequest<{ Params: { authorizationId: string } }>, reply) =>
      wrap(reply, () => getCombinerManifest(repository, { authorizationId: request.params.authorizationId as Hex32 })),
  );

  app.get(
    "/v1/reveals/:authorizationId/artifact-bundles/:recipient_ref",
    async (
      request: FastifyRequest<{ Params: { authorizationId: string; recipient_ref: string } }>,
      reply,
    ) =>
      wrap(reply, () =>
        getRevealArtifactBundle(repository, {
          authorizationId: request.params.authorizationId as Hex32,
          recipient_ref: request.params.recipient_ref,
        }),
      ),
  );
}
