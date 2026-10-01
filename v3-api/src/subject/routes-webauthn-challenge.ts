import type { FastifyInstance } from "fastify";
import type { WebAuthnPurpose } from "../webauthn/index.js";
import type { SubjectRouteContext } from "./routes-list-escrows.js";

export interface WebAuthnChallengeBody {
  readonly purpose: WebAuthnPurpose;
  readonly user_id?: string;
}

export function registerSubjectWebAuthnChallengeRoute(app: FastifyInstance, context: SubjectRouteContext): void {
  app.post<{ Body: WebAuthnChallengeBody }>(
    "/v1/subjects/webauthn/challenge",
    { preHandler: context.preHandlers?.("createSubjectWebAuthnChallenge") },
    async (request) => {
      const challenge = context.challenges.create({
        purpose: request.body.purpose,
        user_id: request.body.user_id,
        now: context.now?.() ?? new Date(),
      });
      return {
        challenge_id: challenge.challenge_id,
        challenge: challenge.challenge,
        expires_at: challenge.expires_at,
      };
    },
  );
}
