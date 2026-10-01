import type { FastifyInstance } from "fastify";
import type { PreSigmaConfirmationRequest } from "../pre-sigma/index.js";
import { getPreSigmaPayload } from "./routes-pre-sigma-payload.js";
import type { SubjectRouteContext } from "./routes-list-escrows.js";

export function submitPreSigmaConfirmations(
  context: SubjectRouteContext,
  token: string,
  request: PreSigmaConfirmationRequest,
): { pre_sigma_session_id: string } {
  const payload = getPreSigmaPayload(context, token);
  const session = context.confirmations.submit({
    onboarding_link_id: payload.onboarding_link_id,
    partner_id: payload.partner_id,
    pda_id: payload.pda_id,
    payload,
    request,
    now: context.now?.() ?? new Date(),
  });
  return { pre_sigma_session_id: session.session_id };
}

export function registerPreSigmaConfirmationsRoute(app: FastifyInstance, context: SubjectRouteContext): void {
  app.post<{ Params: { token: string }; Body: PreSigmaConfirmationRequest }>(
    "/v1/onboarding/:token/pre-sigma-confirmations",
    { preHandler: context.preHandlers?.("submitPreSigmaConfirmations") },
    async (request) => submitPreSigmaConfirmations(context, request.params.token, request.body),
  );
}
