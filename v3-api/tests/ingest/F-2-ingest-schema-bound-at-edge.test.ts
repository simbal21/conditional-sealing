// Closure test for Security-audit-2026-06-02 F-2 (TS-API-F-01 / TS-API-F-04):
// "Ingest body schema with additionalProperties:false is never bound to Fastify
//  — runtime validation absent."
//
// Pre-fix, the TypeBox schema lived only on the discarded RouteRegistry, so
// Fastify performed ZERO body validation: unknown top-level keys, wrong types,
// and missing required fields all flowed into the handler. These tests register
// the route exactly as production does and assert the validator rejects bad
// bodies at the EDGE (before the handler runs).

import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import {
  registerIngestRoutes,
  type IngestionDependencies,
  type PdaInspectionForIngest,
} from "../../src/ingest/index.js";
import { buildSyntheticAttestationForRequest } from "../../src/ingest/routes-create-mode-a.js";
import { STRICT_AJV_OPTIONS } from "../../src/server/index.js";
import { jcsDigestHex32, payloadDigestHex32, type Hex32 } from "../../src/h-commit/index.js";

const hex32 = (seed: string): Hex32 => `0x${seed.repeat(64).slice(0, 64)}`;

const pda: PdaInspectionForIngest = {
  pda_id: "11111111-1111-4111-8111-111111111111",
  pda_version: "1",
  partner_id: "22222222-2222-4222-8222-222222222222",
  pda_root: hex32("a"),
  schema_digest: hex32("b"),
  g3_choice: "dcipher",
  g4_phase: 2,
  operational_class: "b2b_partner",
  trust_tier: "tier_b",
  retention_seconds: 94_608_000n,
  retention_policy_id: "obligation_plus_3y",
  partner_ready: true,
  legal_effect_expected: false,
  recipients_root: hex32("c"),
};

function buildValidBody(payload: Record<string, unknown>): Record<string, unknown> {
  const authorizationIdCandidate = hex32("1");
  const preflight_commit_context = {
    authorizationIdCandidate,
    pda_id: pda.pda_id,
    pda_version: pda.pda_version,
    partner_id: pda.partner_id,
    schema_digest: pda.schema_digest,
    payload_digest: payloadDigestHex32(payload, "jcs_json"),
    payload_canonicalization: "jcs_json" as const,
    pda_root: pda.pda_root,
    g3_choice: pda.g3_choice,
    g4_phase: pda.g4_phase,
    commit_block_number: 987_654,
    commit_block_hash: hex32("d"),
  };
  const base = {
    pda_id: pda.pda_id,
    pda_version: pda.pda_version,
    partner_id: pda.partner_id,
    authorizationIdCandidate,
    preflight_commit_context,
    preflight_context_digest: jcsDigestHex32(preflight_commit_context),
    schema_digest: pda.schema_digest,
    payload_classification: { pii_class: "kyc", media_type: "application/json" },
    plaintext_payload: payload,
    client_attestation_digest: hex32("0"),
  };
  const attestation = buildSyntheticAttestationForRequest(base);
  return {
    ...base,
    attestation_preflight: attestation.attestation_preflight,
    client_attestation_digest: attestation.attestation_preflight.digest,
  };
}

function buildApp(bodyLimit?: number) {
  const dependencies: IngestionDependencies = {
    inspectPda: () => pda,
    vault: { async write(input) { return { vault_ref: `mock://${input.h_commit}` }; } },
    now: () => new Date("2026-06-02T00:00:00.000Z"),
  };
  const app = Fastify({ ajv: STRICT_AJV_OPTIONS, ...(bodyLimit ? { bodyLimit } : {}) });
  registerIngestRoutes(app, dependencies);
  return app;
}

describe("F-2 ingest body schema is enforced at the Fastify edge", () => {
  it("rejects an unknown top-level key with 400 (additionalProperties:false is now live)", async () => {
    const app = buildApp();
    const body = { ...buildValidBody({ name: "Alice" }), smuggled_field: "attacker-controlled" };
    const response = await app.inject({
      method: "POST",
      url: "/v1/ingestions",
      headers: { "idempotency-key": "f2-unknown-key" },
      payload: body,
    });
    expect(response.statusCode).toBe(400);
  });

  it("rejects a malformed hex field that violates the pattern (non-coercible) with 400", async () => {
    const app = buildApp();
    const body = buildValidBody({ name: "Bob" });
    // schema_digest carries a strict ^0x[0-9a-fA-F]{64}$ pattern — ajv cannot
    // coerce a string into a different pattern, so this is a hard reject. Pre-fix
    // this flowed to the handler unvalidated.
    (body as { schema_digest: unknown }).schema_digest = "not-a-valid-hex-string";
    const response = await app.inject({
      method: "POST",
      url: "/v1/ingestions",
      headers: { "idempotency-key": "f2-bad-hex" },
      payload: body,
    });
    expect(response.statusCode).toBe(400);
  });

  it("rejects a missing required field (schema_digest absent) with 400", async () => {
    const app = buildApp();
    const body = buildValidBody({ name: "Carol" });
    delete (body as { schema_digest?: unknown }).schema_digest;
    const response = await app.inject({
      method: "POST",
      url: "/v1/ingestions",
      headers: { "idempotency-key": "f2-missing-field" },
      payload: body,
    });
    expect(response.statusCode).toBe(400);
  });

  it("accepts a fully-valid body (no false-positive rejection)", async () => {
    const app = buildApp();
    const body = buildValidBody({ name: "Dave", country: "DE" });
    const response = await app.inject({
      method: "POST",
      url: "/v1/ingestions",
      headers: {
        "idempotency-key": "f2-valid",
        "x-cealis-client-attestation-digest": (body as { client_attestation_digest: string }).client_attestation_digest,
      },
      payload: body,
    });
    expect(response.statusCode).toBe(201);
  });

  it("enforces an explicit bodyLimit — an oversized body is rejected (413)", async () => {
    const app = buildApp(2048); // 2 KiB cap for the test
    const body = buildValidBody({ blob: "x".repeat(8192) }); // payload > cap
    const response = await app.inject({
      method: "POST",
      url: "/v1/ingestions",
      headers: { "idempotency-key": "f2-oversized" },
      payload: body,
    });
    expect(response.statusCode).toBe(413);
  });
});
