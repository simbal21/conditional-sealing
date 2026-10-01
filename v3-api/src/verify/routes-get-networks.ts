import type { FastifyInstance } from "fastify";
import { getNetworkVerificationManifest } from "./network-manifest.js";

export function registerGetVerificationNetworksRoute(app: FastifyInstance): void {
  app.get("/v1/verification/networks", async () => getNetworkVerificationManifest());
}
