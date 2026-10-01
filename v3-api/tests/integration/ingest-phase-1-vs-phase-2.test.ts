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
import { PHASE_1_TRUST_STATEMENT } from "../../src/g4/index.js";

const hex32 = (seed: string): Hex32 => `0x${seed.repeat(64).slice(0, 64)}`;

function pda(overrides: Partial<PdaInspectionForIngest>): PdaInspectionForIngest {
  return {
    pda_id: "11111111-1111-4111-8111-111111111111",
    pda_version: "1",
    partner_id: "22222222-2222-4222-8222-222222222222",
    pda_root: hex32("a"),
    schema_digest: hex32("b"),
    g3_choice: "dcipher",
    g4_phase: 1,
    operational_class: "b2b_partner",
    trust_tier: "tier_b",
    retention_seconds: 94_608_000n,
    partner_ready: true,
    legal_effect_expected: false,
    recipients_root: hex32("c"),
    ...overrides,
  };
}

function requestFor(inspection: PdaInspectionForIngest): ModeAIngestionRequest {
  const payload = { subject: "phase-test" };
  const authorizationIdCandidate = hex32("1");
  const preflight_commit_context = {
    authorizationIdCandidate,
    pda_id: inspection.pda_id,
    pda_version: inspection.pda_version,
    partner_id: inspection.partner_id,
    schema_digest: inspection.schema_digest,
    payload_digest: payloadDigestHex32(payload, "jcs_json"),
    payload_canonicalization: "jcs_json" as const,
    pda_root: inspection.pda_root,
    g3_choice: inspection.g3_choice,
    g4_phase: inspection.g4_phase,
    commit_block_number: 123,
    commit_block_hash: hex32("d"),
  };
  const base = {
    pda_id: inspection.pda_id,
    pda_version: inspection.pda_version,
    partner_id: inspection.partner_id,
    authorizationIdCandidate,
    preflight_commit_context,
    preflight_context_digest: jcsDigestHex32(preflight_commit_context),
    schema_digest: inspection.schema_digest,
    payload_classification: { pii_class: "dev" },
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

async function postWith(inspection: PdaInspectionForIngest, authorization = "Cealis-HMAC test") {
  const app = Fastify();
  const dependencies: IngestionDependencies = {
    repository: new InMemoryIngestionRepository(),
    inspectPda: () => inspection,
    now: () => new Date("2026-05-11T00:00:00.000Z"),
  };
  registerIngestRoutes(app, dependencies);
  const payload = requestFor(inspection);
  return app.inject({
    method: "POST",
    url: "/v1/ingestions",
    headers: {
      authorization,
      "idempotency-key": `idem-${inspection.operational_class}-${String(inspection.partner_ready)}`,
      "x-cealis-client-attestation-digest": payload.client_attestation_digest,
    },
    payload,
  });
}

describe("Phase 1 versus Phase 2 G4 discipline", () => {
  it("rejects partner-ready Phase 1 commits with exact governance code", async () => {
    const response = await postWith(pda({ operational_class: "b2b_partner", partner_ready: true }));
    expect(response.statusCode).toBe(423);
    expect(response.json<{ code: string }>().code).toBe(
      "GOVERNANCE.PHASE_1_REJECTED_FOR_PARTNER_READY",
    );
  });

  it("allows non-partner-ready consumer Phase 1 dev-scaffold and carries the trust statement", async () => {
    const response = await postWith(
      pda({ operational_class: "consumer", partner_ready: false, legal_effect_expected: false }),
      "Bearer subject-session",
    );
    expect(response.statusCode).toBe(201);
    expect(response.json<{ phase_trust_statement: string }>().phase_trust_statement).toBe(
      PHASE_1_TRUST_STATEMENT,
    );
  });
});

