import type { FastifyInstance } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import { requirePartnerPrincipal, type PartnerRouteContext } from "./routes-list-pdas.js";

export function getPartnerShred(context: PartnerRouteContext, partner_id: string, h_commit: string): Record<string, unknown> {
  const record = context.store.shreds.get(`${partner_id}:${h_commit}`);
  if (!record) {
    throw new HttpProblem(
      problemFromCode("VAULT_COMMIT_SHREDDED", "partner_shred_status", {
        detail: "No shred status is available for this partner commit.",
        safe_refs: { partner_id, h_commit },
        statusOverride: 404,
      }),
    );
  }
  return record;
}

export function registerGetPartnerShredRoute(app: FastifyInstance, context: PartnerRouteContext): void {
  app.get<{ Params: { h_commit: string } }>(
    "/v1/partners/me/shreds/:h_commit",
    { preHandler: context.preHandlers?.("getPartnerShredStatus") },
    async (request) => getPartnerShred(context, requirePartnerPrincipal(request).partner_id, request.params.h_commit),
  );
}
