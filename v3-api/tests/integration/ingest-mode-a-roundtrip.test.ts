import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { ChainAnchorClient, IngestionAnchorInput, IngestionAnchorResult } from "../../src/chain-anchor/index.js";
import {
  InMemoryIngestionRepository,
  buildSyntheticAttestationForRequest,
  registerIngestRoutes,
  type IngestionDependencies,
  type ModeAIngestionRequest,
  type PdaInspectionForIngest,
} from "../../src/ingest/index.js";
import { jcsDigestHex32, payloadDigestHex32, type Hex32 } from "../../src/h-commit/index.js";

const hex32 = (seed: string): Hex32 => {
  const repeated = seed.repeat(64).slice(0, 64);
  return `0x${repeated}`;
};

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
  shred_authority: "joint",
  shred_condition_summary: "joint or operator guarded shred",
};

class MockAnchor implements ChainAnchorClient {
  async anchor(input: IngestionAnchorInput, attempt: number): Promise<IngestionAnchorResult> {
    return {
      commit_tx_hash: `0x${input.h_commit.slice(2)}`,
      commit_block: 12_345 + attempt,
      commit_block_hash: input.commit_block_hash,
      attempts: attempt,
    };
  }
}

function buildRequest(payload: Record<string, unknown>): ModeAIngestionRequest {
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

describe("Mode A ingestion roundtrip", () => {
  it("creates a commit and returns status with retention echo", async () => {
    const repository = new InMemoryIngestionRepository();
    const dependencies: IngestionDependencies = {
      repository,
      inspectPda: () => pda,
      chainAnchor: new MockAnchor(),
      vault: {
        async write(input) {
          expect(input.plaintext.length).toBeGreaterThan(0);
          return { vault_ref: `mock-vault://${input.h_commit}` };
        },
      },
      now: () => new Date("2026-05-11T00:00:00.000Z"),
    };
    const app = Fastify();
    registerIngestRoutes(app, dependencies);

    const request = buildRequest({ name: "Alice", country: "DE" });
    const create = await app.inject({
      method: "POST",
      url: "/v1/ingestions",
      headers: {
        "idempotency-key": "idem-roundtrip-1",
        "cealis-api-version": "1.0-draft",
        "x-cealis-client-attestation-digest": request.client_attestation_digest,
      },
      payload: request,
    });

    expect(create.statusCode).toBe(201);
    const created = create.json<{
      api_version: string;
      commit_version: string;
      h_commit: string;
      status: string;
      vault_ref: string;
      g4_phase: number;
      retention_expires_at: string;
    }>();
    expect(created.api_version).toBe("1.0-draft");
    expect(created.commit_version).toBe("0x0302");
    expect(created.h_commit).toMatch(/^0x[0-9a-f]{64}$/);
    expect(created.status).toBe("committed");
    expect(created.vault_ref).toBe(`mock-vault://${created.h_commit}`);
    expect(created.g4_phase).toBe(2);
    expect(created.retention_expires_at).toBe("2029-05-10T00:00:00.000Z");

    const status = await app.inject({
      method: "GET",
      url: `/v1/ingestions/${created.h_commit}`,
    });
    expect(status.statusCode).toBe(200);
    const statusBody = status.json<{ h_commit: string; status: string; retention: { retention_policy_id: string } }>();
    expect(statusBody.h_commit).toBe(created.h_commit);
    expect(statusBody.status).toBe("committed");
    expect(statusBody.retention.retention_policy_id).toBe("obligation_plus_3y");
  });
});

