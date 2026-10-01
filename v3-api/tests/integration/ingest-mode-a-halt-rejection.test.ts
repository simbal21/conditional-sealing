import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import {
  InMemoryIngestionRepository,
  buildSyntheticAttestationForRequest,
  registerIngestRoutes,
  type IngestionDependencies,
  type ModeAIngestionRequest,
  type PdaInspectionForIngest,
} from "../../src/ingest/index.js";
import { jcsDigestHex32, payloadDigestHex32, type Hex32 } from "../../src/h-commit/index.js";

const hex32 = (seed: string): Hex32 => `0x${seed.repeat(64).slice(0, 64)}`;

const haltedPda: PdaInspectionForIngest = {
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
  partner_ready: true,
  legal_effect_expected: false,
  halted: true,
  halt_reason: "ConditionEngine paused",
};

function request(): ModeAIngestionRequest {
  const payload = { halted: true };
  const authorizationIdCandidate = hex32("1");
  const preflight_commit_context = {
    authorizationIdCandidate,
    pda_id: haltedPda.pda_id,
    pda_version: haltedPda.pda_version,
    partner_id: haltedPda.partner_id,
    schema_digest: haltedPda.schema_digest,
    payload_digest: payloadDigestHex32(payload, "jcs_json"),
    payload_canonicalization: "jcs_json" as const,
    pda_root: haltedPda.pda_root,
    g3_choice: haltedPda.g3_choice,
    g4_phase: haltedPda.g4_phase,
    commit_block_number: 123,
    commit_block_hash: hex32("d"),
  };
  const base = {
    pda_id: haltedPda.pda_id,
    pda_version: haltedPda.pda_version,
    partner_id: haltedPda.partner_id,
    authorizationIdCandidate,
    preflight_commit_context,
    preflight_context_digest: jcsDigestHex32(preflight_commit_context),
    schema_digest: haltedPda.schema_digest,
    payload_classification: { pii_class: "kyc" },
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

describe("Mode A halt rejection", () => {
  it("returns a GOVERNANCE problem when PDA inspection is halted", async () => {
    const app = Fastify();
    const dependencies: IngestionDependencies = {
      repository: new InMemoryIngestionRepository(),
      inspectPda: () => haltedPda,
    };
    registerIngestRoutes(app, dependencies);
    const payload = request();
    const response = await app.inject({
      method: "POST",
      url: "/v1/ingestions",
      headers: {
        "idempotency-key": "idem-halted",
        "x-cealis-client-attestation-digest": payload.client_attestation_digest,
      },
      payload,
    });
    expect(response.statusCode).toBe(409);
    const problem = response.json<{ code: string; category: string }>();
    expect(problem.code).toBe("GOVERNANCE.G4_REFUSED");
    expect(problem.category).toBe("GOVERNANCE");
  });
});

