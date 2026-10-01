// Security-audit-2026-06-02 F-1 (HIGH): this used to assert a "happy path"
// where POST /v1/subjects/webauthn/verify with a forged assertion
// (client-chosen user_id, no signature) minted a bearer session — that WAS the
// vulnerability. The verify path is now fail-closed: with no credential store /
// RP binding wired into the default subject context, the route rejects with no
// session. A subject session can only be obtained via a real, cryptographically
// verified assertion against a registered credential (see
// tests/webauthn/F-1-webauthn-forged-assertion-rejected.test.ts).
//
// We still exercise the challenge issuance, the bearer-protected route guard,
// and session revoke using a directly-minted session (the unit boundary for the
// session store), so this integration test keeps covering the subject surface
// without depending on the removed fake-success path.

import { describe, expect, it } from "vitest";
import Fastify from "fastify";
import { createSubjectBearerPreHandler } from "../../src/auth/index.js";
import { createDefaultSubjectRouteContext, registerSubjectRoutes } from "../../src/subject/index.js";
import { HttpProblem } from "../../src/errors/index.js";
import type { OperationId } from "../../src/types/index.js";

describe("subject WebAuthn surface (post F-1 fail-closed)", () => {
  it("forged assertion no longer mints a session; a real session still guards subject routes", async () => {
    const app = Fastify();
    app.setErrorHandler((error, _request, reply) => {
      if (error instanceof HttpProblem) {
        void reply.code(error.body.status).send(error.body);
        return;
      }
      void reply.send(error);
    });
    const baseContext = createDefaultSubjectRouteContext();
    const bearer = createSubjectBearerPreHandler({ sessions: baseContext.sessions });
    const context = {
      ...baseContext,
      preHandlers: (operationId: OperationId) =>
        operationId === "createSubjectWebAuthnChallenge" ||
        operationId === "verifySubjectWebAuthn" ||
        operationId === "getPreSigmaPayload" ||
        operationId === "submitPreSigmaConfirmations"
          ? []
          : [bearer],
    };
    registerSubjectRoutes(app, context);

    // (1) Challenge issuance still works.
    const challengeResponse = await app.inject({
      method: "POST",
      url: "/v1/subjects/webauthn/challenge",
      payload: { purpose: "login", user_id: "subject_demo" },
    });
    expect(challengeResponse.statusCode).toBe(200);
    const challenge = challengeResponse.json<{ challenge_id: string; challenge: string }>();

    // (2) A forged assertion (client-chosen user_id, no signature) is REJECTED —
    //     this is the F-1 closure at the HTTP boundary. Pre-fix this returned 200
    //     with a bearer_token for an arbitrary user.
    const forgedResponse = await app.inject({
      method: "POST",
      url: "/v1/subjects/webauthn/verify",
      payload: {
        challenge_id: challenge.challenge_id,
        assertion: {
          id: "forged-cred",
          rawId: "forged-cred",
          response: { clientDataJSON: "Zm9yZ2Vk", authenticatorData: "Zm9yZ2Vk", signature: "Zm9yZ2Vk" },
          clientExtensionResults: {},
          type: "public-key",
          user_id: "victim_subject",
        },
      },
    });
    expect(forgedResponse.statusCode).toBe(401);
    expect(forgedResponse.json<{ code: string }>().code).toBe("AUTH.UNAUTHENTICATED");
    expect(forgedResponse.json<{ bearer_token?: string }>().bearer_token).toBeUndefined();

    // (3) A real session (minted server-side after a genuine verification) still
    //     authorizes the bearer-guarded subject routes and can be revoked.
    const minted = baseContext.sessions.create({ user_id: "subject_demo" });
    const listResponse = await app.inject({
      method: "GET",
      url: "/v1/subjects/me/escrows",
      headers: { authorization: `Bearer ${minted.token}` },
    });
    expect(listResponse.statusCode).toBe(200);
    expect(listResponse.json<{ escrows: unknown[] }>().escrows).toHaveLength(1);

    const hCommit = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for (const url of [
      `/v1/subjects/me/escrows/${hCommit}`,
      `/v1/subjects/me/escrows/${hCommit}/vault-blob`,
      "/v1/subjects/me/audit-log",
      "/v1/subjects/me/retention",
    ]) {
      const response = await app.inject({
        method: "GET",
        url,
        headers: { authorization: `Bearer ${minted.token}` },
      });
      expect(response.statusCode).toBe(200);
    }
    const shredResponse = await app.inject({
      method: "POST",
      url: `/v1/subjects/me/escrows/${hCommit}/shred-requests`,
      headers: { authorization: `Bearer ${minted.token}` },
      payload: { request_reason_ref: "subject_requested" },
    });
    expect(shredResponse.statusCode).toBe(202);
    const revokeResponse = await app.inject({
      method: "POST",
      url: "/v1/subjects/sessions/revoke",
      headers: { authorization: `Bearer ${minted.token}` },
      payload: {},
    });
    expect(revokeResponse.statusCode).toBe(200);
  });
});
