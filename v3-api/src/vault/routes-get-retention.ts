import type { FastifyInstance, preHandlerHookHandler } from "fastify";
import type { OperationId } from "../types/operation-ids.js";
import { buildRetentionStatus, type RetentionStatus } from "./retention-status.js";

export interface VaultRouteContext {
  readonly retention: Map<string, RetentionStatus>;
  readonly preHandlers?: (operationId: OperationId) => preHandlerHookHandler[];
}

export function createVaultRouteContext(): VaultRouteContext {
  const hCommit = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  return {
    retention: new Map([[hCommit, buildRetentionStatus({ h_commit: hCommit })]]),
  };
}

export function getVaultRetention(context: VaultRouteContext, h_commit: string): RetentionStatus {
  return context.retention.get(h_commit) ?? buildRetentionStatus({ h_commit });
}

export function registerVaultRetentionRoute(app: FastifyInstance, context: VaultRouteContext): void {
  app.get<{ Params: { h_commit: string } }>(
    "/v1/vault/retention/:h_commit",
    { preHandler: context.preHandlers?.("getVaultRetention") },
    async (request) => getVaultRetention(context, request.params.h_commit),
  );
}
