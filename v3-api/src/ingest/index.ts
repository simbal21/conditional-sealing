import type { FastifyInstance } from "fastify";
import { RouteRegistry } from "../openapi/scaffold.js";
import {
  registerCreateModeAIngestionRoute,
  type IngestionDependencies,
} from "./routes-create-mode-a.js";
import { registerGetG4EndpointAttestationRoute } from "./routes-get-attestation.js";
import { registerGetIngestionStatusRoute } from "./routes-get-status.js";

export * from "./routes-create-mode-a.js";
export * from "./routes-get-attestation.js";
export * from "./routes-get-status.js";

export function registerIngestRoutes(
  app: FastifyInstance,
  dependencies: IngestionDependencies,
  routeRegistry = new RouteRegistry(),
): RouteRegistry {
  registerGetG4EndpointAttestationRoute(app, dependencies, routeRegistry);
  registerCreateModeAIngestionRoute(app, dependencies, routeRegistry);
  registerGetIngestionStatusRoute(app, dependencies.repository, routeRegistry);
  return routeRegistry;
}

