import type { FastifyInstance } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import { requirePartnerPrincipal, type PartnerRouteContext } from "./routes-list-pdas.js";

export function getPartnerObligation(context: PartnerRouteContext, partner_id: string, obligationId: string): Record<string, unknown> {
  const record = context.store.obligations.get(`${partner_id}:${obligationId}`);
  if (!record) {
    throw new HttpProblem(
      problemFromCode("REQUEST_MALFORMED", "partner_obligation", {
        detail: "Obligation status exists only for PDA condition modules that use obligations.",
        safe_refs: { partner_id },
        statusOverride: 404,
      }),
    );
  }
  return record;
}

export function registerGetPartnerObligationRoute(app: FastifyInstance, context: PartnerRouteContext): void {
  app.get<{ Params: { obligationId: string } }>(
    "/v1/partners/me/obligations/:obligationId",
    { preHandler: context.preHandlers?.("getPartnerObligationStatus") },
    async (request) => getPartnerObligation(context, requirePartnerPrincipal(request).partner_id, request.params.obligationId),
  );
}
