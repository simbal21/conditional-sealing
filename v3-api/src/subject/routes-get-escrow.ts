import type { FastifyInstance } from "fastify";
import { getSubjectEscrowRecord, requireSubjectPrincipal, type SubjectRouteContext } from "./routes-list-escrows.js";

export function registerGetSubjectEscrowRoute(app: FastifyInstance, context: SubjectRouteContext): void {
  app.get<{ Params: { h_commit: string } }>(
    "/v1/subjects/me/escrows/:h_commit",
    { preHandler: context.preHandlers?.("getSubjectEscrowStatus") },
    async (request) => getSubjectEscrowRecord(context, requireSubjectPrincipal(request), request.params.h_commit),
  );
}
