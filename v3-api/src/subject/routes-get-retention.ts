import type { FastifyInstance } from "fastify";
import { requireSubjectPrincipal, type SubjectRouteContext } from "./routes-list-escrows.js";

export function getSubjectRetention(context: SubjectRouteContext, user_id: string): { items: Record<string, unknown>[] } {
  const items = [...context.store.retention.entries()]
    .filter(([key]) => key.startsWith(`${user_id}:`))
    .map(([, value]) => value);
  return { items };
}

export function registerGetSubjectRetentionRoute(app: FastifyInstance, context: SubjectRouteContext): void {
  app.get(
    "/v1/subjects/me/retention",
    { preHandler: context.preHandlers?.("getSubjectRetention") },
    async (request) => getSubjectRetention(context, requireSubjectPrincipal(request).user_id),
  );
}
