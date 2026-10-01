import type { FastifyInstance } from "fastify";
import { registerVaultRetentionRoute, type VaultRouteContext } from "./routes-get-retention.js";

export * from "./retention-status.js";
export * from "./routes-get-retention.js";
export * from "./cealis-v3-vault.js";
export * from "./vault-store.js";
export * from "./cealis-v3-vault-impl.js";
export * from "./backends/postgres-blob.js";
export * from "./backends/postgres-vault-store.js";
export * from "./backends/filesystem.js";
export * from "./backends/filesystem-vault-store.js";

export function registerVaultRoutes(app: FastifyInstance, context: VaultRouteContext): void {
  registerVaultRetentionRoute(app, context);
}
