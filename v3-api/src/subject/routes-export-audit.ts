import type { FastifyInstance } from "fastify";
import { pickSafeRefs } from "../redaction/safe-refs.js";
import { TIER_BEHAVIOR_MATRIX } from "../types/tier-behavior.js";
import { requireSubjectPrincipal, type SubjectRouteContext } from "./routes-list-escrows.js";

export function exportSubjectAuditLog(context: SubjectRouteContext, user_id: string): Record<string, unknown> {
  const rows = context.store.auditRows.get(user_id) ?? [];
  return {
    scope: TIER_BEHAVIOR_MATRIX.audit_export.consumer,
    records: rows.map((row) => ({
      ...pickSafeRefs(row),
      action: typeof row.action === "string" ? row.action : "event",
    })),
  };
}

export function registerExportSubjectAuditRoute(app: FastifyInstance, context: SubjectRouteContext): void {
  app.get(
    "/v1/subjects/me/audit-log",
    { preHandler: context.preHandlers?.("exportSubjectAuditLog") },
    async (request) => exportSubjectAuditLog(context, requireSubjectPrincipal(request).user_id),
  );
}
