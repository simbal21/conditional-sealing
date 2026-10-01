import { describe, expect, it } from "vitest";
import Fastify from "fastify";
import { HttpProblem } from "../../src/errors/index.js";
import {
  InMemoryNonceStore,
  createPartnerHmacPreHandler,
  createScopePreHandler,
  signPartnerRequest,
  type PartnerCredentialRecord,
} from "../../src/auth/index.js";
import { createPartnerStatusStore, registerPartnerRoutes } from "../../src/partner/index.js";
import type { ApiScope, OperationId } from "../../src/types/index.js";
import { createVaultRouteContext, registerVaultRoutes } from "../../src/vault/index.js";
import { registerVerifyRoutes } from "../../src/verify/index.js";

describe("partner scope enforcement", () => {
  it("rejects reveal route without reveal:read and accepts with reveal:read", async () => {
    const now = new Date("2026-05-11T12:00:00.000Z");
    const credential: { current: PartnerCredentialRecord } = {
      current: credentialWithScopes(["pda:read"]),
    };
    const app = Fastify();
    app.setErrorHandler((error, _request, reply) => {
      if (error instanceof HttpProblem) {
        void reply.code(error.body.status).send(error.body);
        return;
      }
      void reply.send(error);
    });
    const hmac = createPartnerHmacPreHandler({
      nonceStore: new InMemoryNonceStore(),
      now: () => now,
      lookupCredential: () => credential.current,
    });
    registerPartnerRoutes(app, {
      store: createPartnerStatusStore(),
      preHandlers: (operationId: OperationId) => [hmac, createScopePreHandler(operationId)],
    });
    registerVaultRoutes(app, {
      ...createVaultRouteContext(),
      preHandlers: (operationId: OperationId) => [hmac, createScopePreHandler(operationId)],
    });
    registerVerifyRoutes(app, {
      preHandlers: (operationId: OperationId) => [hmac, createScopePreHandler(operationId)],
    });
    const url = "/v1/partners/me/reveals/0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const denied = await app.inject({
      method: "GET",
      url,
      headers: signPartnerRequest({
        method: "GET",
        pathWithQuery: url,
        rawRequestBody: new Uint8Array(),
        keyId: "key_demo",
        signingSecret: "secret_demo",
        timestamp: Math.floor(now.getTime() / 1000).toString(),
        nonce: "nonce_denied",
      }),
    });
    expect(denied.statusCode).toBe(403);
    credential.current = credentialWithScopes(["pda:read", "reveal:read"]);
    const allowed = await app.inject({
      method: "GET",
      url,
      headers: signPartnerRequest({
        method: "GET",
        pathWithQuery: url,
        rawRequestBody: new Uint8Array(),
        keyId: "key_demo",
        signingSecret: "secret_demo",
        timestamp: Math.floor(now.getTime() / 1000).toString(),
        nonce: "nonce_allowed",
      }),
    });
    expect(allowed.statusCode).toBe(200);
    expect(allowed.json<{ status: string }>().status).toBe("finalized");

    credential.current = credentialWithScopes([
      "pda:read",
      "onboarding_link:create",
      "escrow:read",
      "reveal:read",
      "vault:read_partner",
      "verification:read",
    ]);
    await expectGet(app, "/v1/partners/me/pdas", "nonce_pdas", now, 200);
    await expectGet(app, "/v1/partners/me/pdas/pda_demo", "nonce_pda", now, 200);
    await expectPost(
      app,
      "/v1/partners/me/onboarding-links",
      { pda_id: "pda_demo", label: "demo" },
      "nonce_onboarding",
      now,
      201,
    );
    await expectGet(
      app,
      "/v1/partners/me/escrows/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "nonce_escrow",
      now,
      200,
    );
    await expectPost(
      app,
      "/v1/partners/me/escrows/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/shred-requests",
      { actor_role: "joint" },
      "nonce_partner_shred",
      now,
      202,
    );
    await expectGet(app, "/v1/partners/me/obligations/obl_demo", "nonce_obligation", now, 200);
    await expectGet(
      app,
      "/v1/partners/me/shreds/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "nonce_shred_status",
      now,
      200,
    );
    await expectGet(
      app,
      "/v1/vault/retention/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "nonce_vault_retention",
      now,
      200,
    );
    await expectPost(app, "/v1/verify/artifact-bundles", { bundle: {} }, "nonce_verify_bundle", now, 200);
    expect((await app.inject({ method: "GET", url: "/v1/verification/networks" })).statusCode).toBe(200);
    expect((await app.inject({ method: "GET", url: "/v1/verification/sdk-versions" })).statusCode).toBe(200);
    await expectGet(app, "/v1/partners/me/pdas/unknown", "nonce_missing_pda", now, 403);
    await expectGet(
      app,
      "/v1/partners/me/escrows/0x9999999999999999999999999999999999999999999999999999999999999999",
      "nonce_missing_escrow",
      now,
      404,
    );
    await expectGet(
      app,
      "/v1/partners/me/reveals/0x9999999999999999999999999999999999999999999999999999999999999999",
      "nonce_missing_reveal",
      now,
      403,
    );
    await expectGet(app, "/v1/partners/me/obligations/missing", "nonce_missing_obligation", now, 404);
    await expectGet(
      app,
      "/v1/partners/me/shreds/0x9999999999999999999999999999999999999999999999999999999999999999",
      "nonce_missing_shred",
      now,
      404,
    );
  });
});

function credentialWithScopes(scopes: ApiScope[]): PartnerCredentialRecord {
  return {
    partner_id: "partner_demo",
    key_id: "key_demo",
    signing_secret: "secret_demo",
    scopes,
  };
}

async function expectGet(
  app: ReturnType<typeof Fastify>,
  url: string,
  nonce: string,
  now: Date,
  statusCode: number,
): Promise<void> {
  const response = await app.inject({
    method: "GET",
    url,
    headers: signPartnerRequest({
      method: "GET",
      pathWithQuery: url,
      rawRequestBody: new Uint8Array(),
      keyId: "key_demo",
      signingSecret: "secret_demo",
      timestamp: Math.floor(now.getTime() / 1000).toString(),
      nonce,
    }),
  });
  expect(response.statusCode).toBe(statusCode);
}

async function expectPost(
  app: ReturnType<typeof Fastify>,
  url: string,
  payload: Record<string, unknown>,
  nonce: string,
  now: Date,
  statusCode: number,
): Promise<void> {
  const rawRequestBody = new TextEncoder().encode(JSON.stringify(payload));
  const response = await app.inject({
    method: "POST",
    url,
    payload,
    headers: signPartnerRequest({
      method: "POST",
      pathWithQuery: url,
      rawRequestBody,
      keyId: "key_demo",
      signingSecret: "secret_demo",
      timestamp: Math.floor(now.getTime() / 1000).toString(),
      nonce,
    }),
  });
  expect(response.statusCode).toBe(statusCode);
}
