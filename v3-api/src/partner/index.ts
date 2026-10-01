import type { FastifyInstance } from "fastify";
import { registerCreateOnboardingLinkRoute } from "./routes-create-onboarding-link.js";
import { registerCreatePartnerShredRequestRoute } from "./routes-create-shred-request.js";
import { registerGetPartnerEscrowRoute } from "./routes-get-escrow.js";
import { registerGetPartnerObligationRoute } from "./routes-get-obligation.js";
import { registerGetPartnerPdaRoute } from "./routes-get-pda.js";
import { registerGetPartnerRevealRoute } from "./routes-get-reveal.js";
import { registerGetPartnerShredRoute } from "./routes-get-shred.js";
import { registerListPartnerPdasRoute, type PartnerRouteContext } from "./routes-list-pdas.js";

export * from "./routes-list-pdas.js";
export * from "./routes-get-pda.js";
export * from "./routes-create-onboarding-link.js";
export * from "./routes-get-escrow.js";
export * from "./routes-create-shred-request.js";
export * from "./routes-get-reveal.js";
export * from "./routes-get-obligation.js";
export * from "./routes-get-shred.js";

export function registerPartnerRoutes(app: FastifyInstance, context: PartnerRouteContext): void {
  registerListPartnerPdasRoute(app, context);
  registerGetPartnerPdaRoute(app, context);
  registerCreateOnboardingLinkRoute(app, context);
  registerGetPartnerEscrowRoute(app, context);
  registerCreatePartnerShredRequestRoute(app, context);
  registerGetPartnerRevealRoute(app, context);
  registerGetPartnerObligationRoute(app, context);
  registerGetPartnerShredRoute(app, context);
}
