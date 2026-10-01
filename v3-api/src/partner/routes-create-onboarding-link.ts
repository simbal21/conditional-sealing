import type { FastifyInstance } from "fastify";
import { newOnboardingId, requirePartnerPrincipal, type PartnerRouteContext } from "./routes-list-pdas.js";

export interface OnboardingLinkRequestBody {
  readonly pda_id: string;
  readonly label?: string;
  readonly expires_at?: string;
  readonly max_uses?: number;
  readonly redirect_url?: string;
  readonly subject_hint?: Record<string, unknown>;
}

export function createOnboardingLink(
  context: PartnerRouteContext,
  partner_id: string,
  body: OnboardingLinkRequestBody,
): Record<string, unknown> {
  const onboarding_link_id = newOnboardingId();
  const token = `onb_${onboarding_link_id.replace(/-/g, "")}`;
  const token_expires_at = body.expires_at ?? new Date((context.now?.() ?? new Date()).getTime() + 24 * 60 * 60 * 1000).toISOString();
  const response = {
    onboarding_link_id,
    url: `${context.onboardingBaseUrl ?? "https://app.cealis.local/onboarding"}/${token}`,
    token,
    token_expires_at,
    pda_id: body.pda_id,
    pda_version: "1",
    active: true,
    partner_id,
    label: body.label ?? null,
    max_uses: body.max_uses ?? null,
    redirect_url: body.redirect_url ?? null,
  };
  context.store.onboardingLinks.set(token, response);
  return response;
}

export function registerCreateOnboardingLinkRoute(app: FastifyInstance, context: PartnerRouteContext): void {
  app.post<{ Body: OnboardingLinkRequestBody }>(
    "/v1/partners/me/onboarding-links",
    { preHandler: context.preHandlers?.("createOnboardingLink") },
    async (request, reply) => {
      const principal = requirePartnerPrincipal(request);
      const body = createOnboardingLink(context, principal.partner_id, request.body);
      return reply.code(201).send(body);
    },
  );
}
