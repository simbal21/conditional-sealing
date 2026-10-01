import type { FastifyReply, FastifyRequest, preHandlerHookHandler } from "fastify";
import { HttpProblem, problemFromCode } from "../errors/index.js";
import type { SubjectPrincipal } from "../types/auth.js";
import { type SubjectSessionReader, verifySubjectSessionToken } from "../webauthn/session.js";

export function extractBearerToken(headers: Record<string, string | string[] | undefined>): string | undefined {
  const value = headers.authorization ?? headers.Authorization;
  const header = Array.isArray(value) ? value[0] : value;
  if (!header) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1];
}

export async function verifyBearerInput(input: {
  readonly headers: Record<string, string | string[] | undefined>;
  readonly sessions: SubjectSessionReader;
  readonly now?: Date;
  readonly correlationId?: string;
}): Promise<SubjectPrincipal> {
  const token = extractBearerToken(input.headers);
  if (!token) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", input.correlationId ?? "subject", {
        detail: "Subject bearer token is missing.",
      }),
    );
  }
  const principal = await verifySubjectSessionToken(input.sessions, token, input.now ?? new Date());
  if (!principal) {
    throw new HttpProblem(
      problemFromCode("AUTH_UNAUTHENTICATED", input.correlationId ?? "subject", {
        detail: "Subject bearer token is expired, revoked, or unknown.",
      }),
    );
  }
  return principal;
}

export function createSubjectBearerPreHandler(options: {
  readonly sessions: SubjectSessionReader;
  readonly now?: () => Date;
}): preHandlerHookHandler {
  return (request: FastifyRequest, _reply: FastifyReply, done): void => {
    void verifyBearerInput({
      headers: request.headers as Record<string, string | string[] | undefined>,
      sessions: options.sessions,
      now: options.now?.() ?? new Date(),
      correlationId: request.id,
    })
      .then((principal) => {
        request.subjectPrincipal = principal;
        done();
      })
      .catch((error: unknown) => done(error as Error));
  };
}
