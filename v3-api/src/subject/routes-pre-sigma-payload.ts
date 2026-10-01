import type { FastifyInstance } from "fastify";
import { buildPreSigmaPayload, type PreSigmaPayload } from "../pre-sigma/index.js";
import type { SubjectRouteContext } from "./routes-list-escrows.js";

export function getPreSigmaPayload(context: SubjectRouteContext, token: string): PreSigmaPayload & { onboarding_link_id: string } {
  const existing = context.store.onboardingPayloads.get(token);
  if (existing) return existing;
  const payload = buildPreSigmaPayload({
    token,
    partner_id: "partner_demo",
    pda_id: "pda_demo",
    pda_version: "1",
    condition_summary: "PaymentObligation P",
    shred_summary: "Subject request with mandatory guardrail",
    schema_digest: "0x2222222222222222222222222222222222222222222222222222222222222222",
    h_commit_inputs: { pda_id: "pda_demo" },
    recipients: [{ role_tag: "RECIPIENT", delivery_mode: "PASSKEY_ACCOUNT" }],
  });
  const stored = { ...payload, onboarding_link_id: `link_${token}` };
  context.store.onboardingPayloads.set(token, stored);
  return stored;
}

export function registerPreSigmaPayloadRoute(app: FastifyInstance, context: SubjectRouteContext): void {
  app.get<{ Params: { token: string } }>(
    "/v1/onboarding/:token/pre-sigma-payload",
    { preHandler: context.preHandlers?.("getPreSigmaPayload") },
    async (request) => getPreSigmaPayload(context, request.params.token),
  );
}
