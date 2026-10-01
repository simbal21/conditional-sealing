// Closure test for Security-audit-2026-06-02 F-3 (MEDIUM):
// "G4 endpoint-attestation GET fails OPEN: malformed hex coerced to zero-hash,
//  no partner auth, no body schema."
//
// Pre-fix:
//   - malformed hex query params were coerced to an all-zero 32-byte hash
//     (assertHex fallback) → a zero-bound attestation instead of a 400,
//   - partner_id defaulted to a hardcoded UUID when omitted,
//   - the route had no auth preHandler — any caller could mint an attestation
//     for any pda_id.
//
// These tests exercise the unit-level business function (direct, deterministic)
// AND the wired Fastify route with partner-HMAC auth.

import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import {
  getG4EndpointAttestation,
  registerGetG4EndpointAttestationRoute,
  type PdaInspectionForIngest,
} from "../../src/ingest/index.js";
import { createPartnerHmacPreHandler, InMemoryNonceStore, signPartnerRequest } from "../../src/auth/index.js";
import { STRICT_AJV_OPTIONS } from "../../src/server/index.js";
import { HttpProblem } from "../../src/errors/index.js";
import type { Hex32 } from "../../src/h-commit/index.js";
import type { ApiScope } from "../../src/types/index.js";

const hex32 = (seed: string): Hex32 => `0x${seed.repeat(64).slice(0, 64)}`;
const PARTNER_ID = "22222222-2222-4222-8222-222222222222";

const pda: PdaInspectionForIngest = {
  pda_id: "11111111-1111-4111-8111-111111111111",
  pda_version: "1",
  partner_id: PARTNER_ID,
  pda_root: hex32("a"),
  schema_digest: hex32("b"),
  g3_choice: "dcipher",
  g4_phase: 2,
  operational_class: "b2b_partner",
  trust_tier: "tier_b",
  retention_seconds: 94_608_000n,
  partner_ready: true,
  legal_effect_expected: false,
};

const deps = { inspectPda: () => pda };

describe("F-3 attestation business function fails CLOSED on malformed input", () => {
  it("rejects malformed authorizationIdCandidate with REQUEST.MALFORMED (no zero-hash coercion)", async () => {
    await expect(
      getG4EndpointAttestation(
        {
          pda_id: pda.pda_id,
          partner_id: PARTNER_ID,
          authorizationIdCandidate: "garbage-not-hex",
          preflight_context_digest: hex32("c"),
          commit_block_number: 100,
          commit_block_hash: hex32("d"),
        },
        deps,
        { partnerId: PARTNER_ID, correlationId: "t" },
      ),
    ).rejects.toMatchObject({ body: expect.objectContaining({ code: "REQUEST.MALFORMED" }) });
  });

  it("rejects a missing partner_id (no hardcoded default)", async () => {
    await expect(
      getG4EndpointAttestation(
        {
          pda_id: pda.pda_id,
          authorizationIdCandidate: hex32("1"),
          preflight_context_digest: hex32("c"),
          commit_block_number: 100,
          commit_block_hash: hex32("d"),
        },
        deps,
        { partnerId: PARTNER_ID, correlationId: "t" },
      ),
    ).rejects.toMatchObject({ body: expect.objectContaining({ code: "REQUEST.MALFORMED" }) });
  });

  it("rejects a partner_id that does not match the authenticated partner (403)", async () => {
    await expect(
      getG4EndpointAttestation(
        {
          pda_id: pda.pda_id,
          partner_id: "99999999-9999-4999-8999-999999999999",
          authorizationIdCandidate: hex32("1"),
          preflight_context_digest: hex32("c"),
          commit_block_number: 100,
          commit_block_hash: hex32("d"),
        },
        deps,
        { partnerId: PARTNER_ID, correlationId: "t" },
      ),
    ).rejects.toMatchObject({ body: expect.objectContaining({ code: "AUTH.FORBIDDEN" }) });
  });

  it("returns a real attestation for valid, partner-matched input", async () => {
    const result = await getG4EndpointAttestation(
      {
        pda_id: pda.pda_id,
        partner_id: PARTNER_ID,
        authorizationIdCandidate: hex32("1"),
        preflight_context_digest: hex32("c"),
        commit_block_number: 100,
        commit_block_hash: hex32("d"),
      },
      deps,
      { partnerId: PARTNER_ID, correlationId: "t" },
    );
    expect(result.pda_id).toBe(pda.pda_id);
    // The attestation binds the REAL authorizationId, not the zero-hash fallback.
    expect(result.authorizationIdCandidate).toBe(hex32("1"));
  });
});

describe("F-3 attestation route requires partner auth at the HTTP edge", () => {
  it("returns 401 when no partner credential is presented", async () => {
    const app = Fastify({ ajv: STRICT_AJV_OPTIONS });
    app.setErrorHandler((error, _req, reply) => {
      if (error instanceof HttpProblem) void reply.code(error.body.status).send(error.body);
      else void reply.send(error);
    });
    const nonceStore = new InMemoryNonceStore();
    const now = () => new Date("2026-06-02T12:00:00.000Z");
    const preHandler = createPartnerHmacPreHandler({
      lookupCredential: () => ({
        partner_id: PARTNER_ID,
        key_id: "key_demo",
        signing_secret: "secret_demo",
        scopes: ["pda:read"] satisfies ApiScope[],
      }),
      nonceStore,
      now,
    });
    registerGetG4EndpointAttestationRoute(app, deps, undefined, { preHandler });

    const response = await app.inject({
      method: "GET",
      url: `/v1/g4/attestation?pda_id=${pda.pda_id}&partner_id=${PARTNER_ID}&authorizationIdCandidate=${hex32("1")}&preflight_context_digest=${hex32("c")}&commit_block_number=100&commit_block_hash=${hex32("d")}`,
      // no HMAC headers → preHandler rejects → 401
    });
    expect(response.statusCode).toBe(401);
  });

  it("returns a signed attestation for an authenticated partner", async () => {
    const app = Fastify({ ajv: STRICT_AJV_OPTIONS });
    app.setErrorHandler((error, _req, reply) => {
      if (error instanceof HttpProblem) void reply.code(error.body.status).send(error.body);
      else void reply.send(error);
    });
    const nonceStore = new InMemoryNonceStore();
    const fixedNow = new Date("2026-06-02T12:00:00.000Z");
    const preHandler = createPartnerHmacPreHandler({
      lookupCredential: () => ({
        partner_id: PARTNER_ID,
        key_id: "key_demo",
        signing_secret: "secret_demo",
        scopes: ["pda:read"] satisfies ApiScope[],
      }),
      nonceStore,
      now: () => fixedNow,
    });
    registerGetG4EndpointAttestationRoute(app, deps, undefined, { preHandler });

    const pathWithQuery = `/v1/g4/attestation?pda_id=${pda.pda_id}&partner_id=${PARTNER_ID}&authorizationIdCandidate=${hex32("1")}&preflight_context_digest=${hex32("c")}&commit_block_number=100&commit_block_hash=${hex32("d")}`;
    const headers = signPartnerRequest({
      method: "GET",
      pathWithQuery,
      rawRequestBody: new Uint8Array(),
      keyId: "key_demo",
      signingSecret: "secret_demo",
      timestamp: Math.floor(fixedNow.getTime() / 1000).toString(),
      nonce: "nonce-f3-once",
    });
    const response = await app.inject({ method: "GET", url: pathWithQuery, headers });
    expect(response.statusCode).toBe(200);
    expect(response.json<{ pda_id: string }>().pda_id).toBe(pda.pda_id);
  });
});
