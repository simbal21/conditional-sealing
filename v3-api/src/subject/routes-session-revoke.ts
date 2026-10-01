import type { FastifyInstance } from "fastify";
import { requireSubjectPrincipal, type SubjectRouteContext } from "./routes-list-escrows.js";

export function registerSubjectSessionRevokeRoute(app: FastifyInstance, context: SubjectRouteContext): void {
  app.post(
    "/v1/subjects/sessions/revoke",
    { preHandler: context.preHandlers?.("revokeSubjectSession") },
    async (request) => {
      const principal = requireSubjectPrincipal(request);
      context.sessions.revoke(principal.session_id);
      return { revoked: true, session_id: principal.session_id };
    },
  );
}
