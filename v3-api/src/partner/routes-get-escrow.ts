import type { FastifyInstance } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import { requirePartnerPrincipal, type PartnerRouteContext } from "./routes-list-pdas.js";

export function getPartnerEscrow(context: PartnerRouteContext, partner_id: string, h_commit: string): Record<string, unknown> {
  const record = context.store.escrows.get(`${partner_id}:${h_commit}`);
  if (!record) {
    throw new HttpProblem(
      problemFromCode("VAULT_UNAVAILABLE", "partner_escrow", {
        detail: "Escrow status is unavailable for this partner and commit.",
        safe_refs: { partner_id, h_commit },
        statusOverride: 404,
      }),
    );
  }
  return record;
}

export function registerGetPartnerEscrowRoute(app: FastifyInstance, context: PartnerRouteContext): void {
  app.get<{ Params: { h_commit: string } }>(
    "/v1/partners/me/escrows/:h_commit",
    { preHandler: context.preHandlers?.("getPartnerEscrowStatus") },
    async (request) => getPartnerEscrow(context, requirePartnerPrincipal(request).partner_id, request.params.h_commit),
  );
}
