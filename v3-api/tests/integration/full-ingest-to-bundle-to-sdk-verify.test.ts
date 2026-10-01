import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { ChainAnchorClient, IngestionAnchorInput, IngestionAnchorResult } from "../../src/chain-anchor/index.js";
import {
  buildSyntheticAttestationForRequest,
  InMemoryIngestionRepository,
  registerIngestRoutes,
  type IngestionDependencies,
  type ModeAIngestionRequest,
  type PdaInspectionForIngest,
} from "../../src/ingest/index.js";
import { jcsDigestHex32, payloadDigestHex32, type Hex32 } from "../../src/h-commit/index.js";
import {
  InMemoryRevealArtifactRepository,
  normalizeRevealAuthorizedLog,
  processRevealAuthorizedEvent,
} from "../../src/index.js";
import type { ChainProofs, RegistrySnapshots, RevealArtifactBundle, SigmaBlock } from "../../src/types/reveal-artifact-bundle.js";
import { makeRevealCombinerDoubles } from "../_helpers/reveal-combiner-testkit.js";

type VerifyArtifactBundleFn = (
  bundle: RevealArtifactBundle,
  options?: { readonly now?: Date; readonly expectedRecipientRef?: string },
) => Promise<{ readonly overall: string; readonly checks: Record<string, { readonly status: string; readonly code: string }> }>;

interface AppFixture {
  readonly name: string;
  readonly submitted: Record<string, unknown>;
}

describe("M5 full Mode A ingest -> bundle -> verify-sdk", () => {
  it("round-trips an M4 fixture through B+C surfaces and verifies offline", async () => {
    const { APP_A_FIXTURES } = await importSource<{ readonly APP_A_FIXTURES: readonly AppFixture[] }>(
      "../../../v3-configurator/fixtures/app-a/index.ts",
    );
    const { verifyArtifactBundle } = await importSource<{ readonly verifyArtifactBundle: VerifyArtifactBundleFn }>(
      "../../../verify-sdk/src/index.ts",
    );
    const fixture = APP_A_FIXTURES[0];
    expect(fixture).toBeDefined();
    const pda = pdaFromSubmitted(fixture!.submitted);
    const ingestionRepository = new InMemoryIngestionRepository();
    const dependencies = ingestionDependencies(pda, ingestionRepository);
    const app = Fastify();
    registerIngestRoutes(app, dependencies);

    const request = buildRequest(pda, { legal_name: "Alice", country: "DE" });
    const create = await app.inject({
      method: "POST",
      url: "/v1/ingestions",
      headers: {
        "idempotency-key": "m5-full-roundtrip",
        "cealis-api-version": "1.0-draft",
        "x-cealis-client-attestation-digest": request.client_attestation_digest,
      },
      payload: request,
    });
    expect(create.statusCode).toBe(201);
    const committed = create.json<{ authorizationId: Hex32; h_commit: Hex32 }>();

    const revealRepository = new InMemoryRevealArtifactRepository();
    const event = normalizeRevealAuthorizedLog({
      args: {
        authorizationId: committed.authorizationId,
        hCommit: committed.h_commit,
        pdaRoot: pda.pda_root,
        authorizationBlock: 200n,
        authorizationTimestamp: 1_778_457_600n,
        challengeWindow: 60,
        conditionRef: hex(4),
      },
      transactionHash: hex(22),
      logIndex: 0,
      blockHash: hex(3),
      blockNumber: 200n,
    });

    const built = revealInput({ event, pda, full_plaintext: { legal_name: "Alice", country: "DE" } });
    const reveal = await processRevealAuthorizedEvent(built.input, {
      repository: revealRepository,
      sigmaGatherer: built.doubles.sigmaGatherer,
      vault: built.doubles.vault,
      combineAndDecryptRunner: built.doubles.combineAndDecryptRunner,
      now: () => new Date("2026-05-11T00:02:00.000Z"),
    });
    expect(reveal.status).toBe("finalized");
    expect(reveal.bundles).toHaveLength(1);

    const verification = await verifyArtifactBundle(reveal.bundles[0]!, {
      now: new Date("2026-05-11T00:03:00.000Z"),
      expectedRecipientRef: "recipient-a",
    });
    if (verification.overall !== "pass") {
      throw new Error(JSON.stringify(verification.checks, null, 2));
    }
    expect(verification.overall).toBe("pass");
  });
});

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

function ingestionDependencies(
  pda: PdaInspectionForIngest,
  repository = new InMemoryIngestionRepository(),
): IngestionDependencies {
  return {
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
}

function buildRequest(pda: PdaInspectionForIngest, payload: Record<string, unknown>): ModeAIngestionRequest {
  const authorizationIdCandidate = hex(1);
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
    commit_block_hash: hex(9),
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
    client_attestation_digest: hex(0),
  };
  const attestation = buildSyntheticAttestationForRequest(base);
  return {
    ...base,
    attestation_preflight: attestation.attestation_preflight,
    client_attestation_digest: attestation.attestation_preflight.digest,
  };
}

function revealInput(input: {
  readonly event: ReturnType<typeof normalizeRevealAuthorizedLog>;
  readonly pda: PdaInspectionForIngest;
  readonly full_plaintext: Record<string, unknown>;
}): {
  readonly input: Parameters<typeof processRevealAuthorizedEvent>[0];
  readonly doubles: ReturnType<typeof makeRevealCombinerDoubles>;
} {
  // F-API-1: the combiner (doubled here) PRODUCES the plaintext from gathered σ +
  // vault ciphertext; the request carries only a combiner_input reference.
  const doubles = makeRevealCombinerDoubles(input.full_plaintext, {
    authId: input.event.authorizationId,
    hCommit: input.event.h_commit,
    blockHash: input.event.block_hash ?? hex(3),
    g3_choice: input.pda.g3_choice,
    partner_id: input.pda.partner_id,
    pda_id: input.pda.pda_id,
  });
  const revealEventInput: Parameters<typeof processRevealAuthorizedEvent>[0] = {
    event: input.event,
    partner_id: input.pda.partner_id,
    pda: {
      pda_id: input.pda.pda_id,
      pda_version: input.pda.pda_version,
      trust_tier: input.pda.trust_tier,
      operational_class: input.pda.operational_class,
    },
    g3_choice: input.pda.g3_choice,
    g4_phase: input.pda.g4_phase,
    schema_digest: input.pda.schema_digest,
    preconditions: {
      challenge_window_closed: true,
      shred_state_allows_reveal: true,
      registry_deprecation_acceptable: true,
      recipient_policy_identified: true,
    },
    combiner_input: doubles.combinerInput,
    recipient_selectors: [
      {
        recipient_ref: "recipient-a",
        recipient_pubkey_id: "pubkey-a",
        schema_selector_digest: hex(6),
        fields: Object.keys(input.full_plaintext).slice(0, 1),
      },
    ],
    sigma_block: sampleSigmaBlock(),
    chain_proofs: sampleChainProofs(input.event.authorizationId, input.event.h_commit, input.pda.pda_root),
    registry_snapshots: sampleRegistrySnapshots(),
    shred_state: {
      h_commit: input.event.h_commit,
      shred_state: "not_shredded",
      checked_at_block: 200,
      checked_at_block_hash: hex(3),
    },
    sd_refs: { status: "present", sdMerkleRoot: hex(100), disclosure_refs: ["sd://fixture"] },
    gate_endpoints: { lit: "https://lit.example", g4: "https://g4.example" },
    registry_snapshot_refs: { authorization: hex(3) },
    recipient_policy: { recipients: ["recipient-a"] },
    m3_scaffold: {
      artifact_type: "RevealArtifactBundle",
      authorizationId: input.event.authorizationId,
      hCommit: input.event.h_commit,
    },
  };
  return { input: revealEventInput, doubles };
}

function pdaFromSubmitted(submitted: Record<string, unknown>): PdaInspectionForIngest {
  return {
    pda_id: stringField(submitted, "pda_id"),
    pda_version: String(submitted.pda_version ?? "1"),
    partner_id: stringField(submitted, "partner_id"),
    pda_root: hexField(submitted, "pda_id"),
    schema_digest: hexField(submitted, "schema_digest"),
    g3_choice: submitted.g3_choice === "drand" ? "drand" : "dcipher",
    g4_phase: submitted.g4_phase === 1 ? 1 : 2,
    operational_class: submitted.legal_effect_expected === true ? "legal_effect" : "b2b_partner",
    trust_tier: trustTier(submitted.trust_tier),
    retention_seconds: BigInt(numberField(submitted, "retention_seconds", 94_608_000)),
    retention_policy_id: "fixture_retention_floor",
    partner_ready: true,
    legal_effect_expected: submitted.legal_effect_expected === true,
    recipients_root: hex(10),
    shred_authority: "joint",
    shred_condition_summary: "fixture shred condition with mandatory guardrail",
  };
}

function sampleSigmaBlock(): SigmaBlock {
  return {
    sigma_lit: { sigma: "0x11", authority_ref: hex(11), public_after_reveal: true },
    sigma_g3: { sigma: "0x22", authority_ref: hex(12), variant: "dcipher", public_after_reveal: true },
    sigma_g4: { sigma: "0x33", authority_ref: hex(13), phase: 2, public_after_reveal: true },
    sigma_conditional: [],
  };
}

function sampleChainProofs(authorizationId: Hex32, hCommit: Hex32, pdaRoot: Hex32): ChainProofs {
  return {
    chain_id: 8453,
    condition_engine_address: "0x0000000000000000000000000000000000000001",
    reveal_authorized_emitter: "0x0000000000000000000000000000000000000001",
    reveal_authorized_event_signature: "RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)",
    reveal_authorized_topics: [authorizationId, hCommit, pdaRoot],
    receipt_proof: { proof_type: "mock_receipt", block_number: 200, block_hash: hex(3), log_index: 0 },
    commit_tx_hash: hex(20),
    commit_block: 100,
    commit_block_hash: hex(21),
    reveal_authorized_tx_hash: hex(22),
    reveal_authorized_log_index: 0,
    reveal_authorized_block: 200,
    reveal_authorized_block_hash: hex(3),
    base_finality_confirmations: 32,
    conditionRef: hex(4),
    shred_registry_state_at_reveal: "not_shredded",
  };
}

function sampleRegistrySnapshots(): RegistrySnapshots {
  return { authorization_block: 200, authorization_block_hash: hex(3), registry_contracts: {} };
}

function trustTier(value: unknown): PdaInspectionForIngest["trust_tier"] {
  if (value === "A" || value === "tier_a") return "tier_a";
  if (value === "C" || value === "tier_c") return "tier_c";
  return "tier_b";
}

function stringField(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  return typeof value === "string" ? value : `${key}_fixture`;
}

function hexField(record: Record<string, unknown>, key: string): Hex32 {
  const value = record[key];
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value) ? (value as Hex32) : hex(99);
}

function numberField(record: Record<string, unknown>, key: string, fallback: number): number {
  const value = record[key];
  return typeof value === "number" && Number.isInteger(value) ? value : fallback;
}

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}

async function importSource<T>(relativePath: string): Promise<T> {
  return (await import(new URL(relativePath, import.meta.url).href)) as T;
}
