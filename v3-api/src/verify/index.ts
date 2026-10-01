import type { FastifyInstance } from "fastify";
import { registerGetSdkVersionsRoute } from "./routes-get-sdk-versions.js";
import { registerGetVerificationNetworksRoute } from "./routes-get-networks.js";
import { registerVerifyArtifactBundleRoute, type VerifyRouteContext } from "./routes-verify-artifact-bundle.js";

export * from "./routes-verify-artifact-bundle.js";
export * from "./routes-get-networks.js";
export * from "./routes-get-sdk-versions.js";
export * from "./network-manifest.js";
export * from "./sdk-manifest.js";

export function registerVerifyRoutes(app: FastifyInstance, context: VerifyRouteContext = {}): void {
  registerVerifyArtifactBundleRoute(app, context);
  registerGetVerificationNetworksRoute(app);
  registerGetSdkVersionsRoute(app);
}
