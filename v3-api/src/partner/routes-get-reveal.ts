import type { FastifyInstance } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import { requirePartnerPrincipal, type PartnerRouteContext } from "./routes-list-pdas.js";

export function getPartnerReveal(context: PartnerRouteContext, partner_id: string, authorizationId: string): Record<string, unknown> {
  const record = context.store.reveals.get(`${partner_id}:${authorizationId}`);
  if (!record) {
    throw new HttpProblem(
      problemFromCode("AUTH_FORBIDDEN", "partner_reveal", {
        detail: "Reveal status is not visible to this partner.",
        safe_refs: { partner_id, authorizationId },
      }),
    );
  }
  return record;
}

export function registerGetPartnerRevealRoute(app: FastifyInstance, context: PartnerRouteContext): void {
  app.get<{ Params: { authorizationId: string } }>(
    "/v1/partners/me/reveals/:authorizationId",
    { preHandler: context.preHandlers?.("getPartnerRevealStatus") },
    async (request) => getPartnerReveal(context, requirePartnerPrincipal(request).partner_id, request.params.authorizationId),
  );
}
