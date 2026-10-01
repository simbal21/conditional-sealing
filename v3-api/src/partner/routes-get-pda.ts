import type { FastifyInstance } from "fastify";
import { getPartnerPdaRecord, requirePartnerPrincipal, type PartnerRouteContext } from "./routes-list-pdas.js";

export function getPartnerPda(context: PartnerRouteContext, partner_id: string, pda_id: string): Record<string, unknown> {
  const record = context.store.pdas.get(`${partner_id}:${pda_id}`);
  if (!record) return {};
  return record.inspection;
}

export function registerGetPartnerPdaRoute(app: FastifyInstance, context: PartnerRouteContext): void {
  app.get<{ Params: { pda_id: string } }>(
    "/v1/partners/me/pdas/:pda_id",
    { preHandler: context.preHandlers?.("getPartnerPda") },
    async (request) => getPartnerPdaRecord(context, requirePartnerPrincipal(request), request.params.pda_id).inspection,
  );
}
