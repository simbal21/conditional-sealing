import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import {
  InMemoryIngestionRepository,
  registerIngestRoutes,
  buildSyntheticAttestationForRequest,
  type IngestionDependencies,
} from "../../src/ingest/index.js";
import { STRICT_AJV_OPTIONS } from "../../src/server/index.js";
import { jcsDigestHex32, payloadDigestHex32, type Hex32 } from "../../src/h-commit/index.js";

// Security-audit-2026-06-02 F-2: the ingest body schema is now bound to Fastify
// and enforced at the edge (additionalProperties:false + required + format). A
// Mode-B request is a COMPLETE, well-formed ingestion request that merely
// selects mode "B"; the reserved-path 409 is produced by the handler's
// assertModeAOnly AFTER schema validation passes. (Pre-fix this test sent a
// structurally-incomplete body that only happened to reach the handler because
// no schema validation ran.)

const hex32 = (seed: string): Hex32 => `0x${seed.repeat(64).slice(0, 64)}`;

function dependencies(): IngestionDependencies {
  return {
    repository: new InMemoryIngestionRepository(),
    inspectPda: () => {
      throw new Error("Mode B rejection must happen before PDA inspection");
    },
  };
}

function buildModeBBody(extra: Record<string, unknown>): Record<string, unknown> {
  const payload = { name: "Alice" };
  const authorizationIdCandidate = hex32("1");
  const preflight_commit_context = {
    authorizationIdCandidate,
    pda_id: "11111111-1111-4111-8111-111111111111",
    pda_version: "1",
    partner_id: "22222222-2222-4222-8222-222222222222",
    schema_digest: hex32("b"),
    payload_digest: payloadDigestHex32(payload, "jcs_json"),
    payload_canonicalization: "jcs_json" as const,
    pda_root: hex32("a"),
    g3_choice: "dcipher" as const,
    g4_phase: 2 as const,
    commit_block_number: 987_654,
    commit_block_hash: hex32("d"),
  };
  const base = {
    pda_id: "11111111-1111-4111-8111-111111111111",
    pda_version: "1",
    partner_id: "22222222-2222-4222-8222-222222222222",
    authorizationIdCandidate,
    preflight_commit_context,
    preflight_context_digest: jcsDigestHex32(preflight_commit_context),
    schema_digest: hex32("b"),
    payload_classification: { pii_class: "kyc" },
    plaintext_payload: payload,
    client_attestation_digest: hex32("0"),
  };
  const attestation = buildSyntheticAttestationForRequest(base);
  return {
    ...base,
    attestation_preflight: attestation.attestation_preflight,
    client_attestation_digest: attestation.attestation_preflight.digest,
    ...extra,
  };
}

async function postModeB(extra: Record<string, unknown>) {
  const app = Fastify({ ajv: STRICT_AJV_OPTIONS });
  registerIngestRoutes(app, dependencies());
  return app.inject({
    method: "POST",
    url: "/v1/ingestions",
    headers: {
      "idempotency-key": "idem-mode-b",
      "x-cealis-client-attestation-digest": "0x0000000000000000000000000000000000000000000000000000000000000000",
    },
    payload: buildModeBBody(extra),
  });
}

describe("Mode B reserved-path rejection", () => {
  it("rejects mode=B with exact 409 SCHEMA.MODE_B_RESERVED", async () => {
    const response = await postModeB({ mode: "B" });
    expect(response.statusCode).toBe(409);
    expect(response.json<{ code: string }>().code).toBe("SCHEMA.MODE_B_RESERVED");
  });

  it("rejects mode=B + sd_enabled=true with the same 409 code", async () => {
    const response = await postModeB({ mode: "B", sd_enabled: true });
    expect(response.statusCode).toBe(409);
    expect(response.json<{ code: string }>().code).toBe("SCHEMA.MODE_B_RESERVED");
  });
});
