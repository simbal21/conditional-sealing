import type { FastifyInstance } from "fastify";
import { getSdkVersionManifest } from "./sdk-manifest.js";

export function registerGetSdkVersionsRoute(app: FastifyInstance): void {
  app.get("/v1/verification/sdk-versions", async () => getSdkVersionManifest());
}
