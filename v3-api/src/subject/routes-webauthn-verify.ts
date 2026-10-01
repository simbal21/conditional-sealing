import type { FastifyInstance } from "fastify";
import { verifyWebAuthnAssertion, type WebAuthnAssertion } from "../webauthn/index.js";
import type { SubjectRouteContext } from "./routes-list-escrows.js";

export interface WebAuthnVerifyBody {
  readonly challenge_id: string;
  readonly assertion: WebAuthnAssertion;
}

export function registerSubjectWebAuthnVerifyRoute(app: FastifyInstance, context: SubjectRouteContext): void {
  app.post<{ Body: WebAuthnVerifyBody }>(
    "/v1/subjects/webauthn/verify",
    { preHandler: context.preHandlers?.("verifySubjectWebAuthn") },
    async (request) =>
      verifyWebAuthnAssertion({
        challenge_id: request.body.challenge_id,
        assertion: request.body.assertion,
        challenges: context.challenges,
        sessions: context.sessions,
        now: context.now?.() ?? new Date(),
      }),
  );
}
