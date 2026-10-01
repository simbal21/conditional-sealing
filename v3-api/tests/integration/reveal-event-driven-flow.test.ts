import { describe, expect, it } from "vitest";
import {
  InMemoryRevealArtifactRepository,
  normalizeRevealAuthorizedLog,
  processRevealAuthorizedEvent,
} from "../../src/index.js";
import type { WebhookEnvelope } from "../../src/types/webhook-events.js";
import type { ChainProofs, Hex32, RegistrySnapshots, SigmaBlock } from "../../src/types/reveal-artifact-bundle.js";
import { makeRevealCombinerDoubles } from "../_helpers/reveal-combiner-testkit.js";

// F-API-1: plaintext provenance is the combiner, not the request body. The
// combiner-double yields this known plaintext (was the old `full_plaintext`).
const KNOWN_PLAINTEXT = { legal_name: "Alice", address: "Aachen" } as const;

describe("Phase C event-driven reveal flow", () => {
  it("processes a synthetic RevealAuthorized log into a persisted artifact bundle", async () => {
    const repository = new InMemoryRevealArtifactRepository();
    const events: WebhookEnvelope<Record<string, unknown>>[] = [];
    const event = normalizeRevealAuthorizedLog({
      args: {
        authorizationId: hex(1),
        hCommit: hex(2),
        pdaRoot: hex(5),
        authorizationBlock: 200n,
        authorizationTimestamp: 1_778_489_600n,
        challengeWindow: 60,
        conditionRef: hex(4),
      },
      transactionHash: hex(22),
      logIndex: 0,
      blockHash: hex(3),
      blockNumber: 200n,
    });

    const doubles = makeRevealCombinerDoubles(KNOWN_PLAINTEXT, {
      authId: hex(1),
      hCommit: hex(2),
      blockHash: hex(3),
      g3_choice: "dcipher",
    });

    const result = await processRevealAuthorizedEvent(
      {
        event,
        ...baseRevealInput(),
        combiner_input: doubles.combinerInput,
        recipient_selectors: [
          {
            recipient_ref: "recipient-a",
            recipient_pubkey_id: "pubkey-a",
            schema_selector_digest: hex(6),
            fields: ["legal_name"],
          },
        ],
      },
      {
        repository,
        sigmaGatherer: doubles.sigmaGatherer,
        vault: doubles.vault,
        combineAndDecryptRunner: doubles.combineAndDecryptRunner,
        eventBus: { emit: (webhookEvent) => { events.push(webhookEvent); } },
        now: () => new Date("2026-05-11T00:02:00.000Z"),
      },
    );

    expect(result.status).toBe("finalized");
    expect(result.bundles).toHaveLength(1);
    await expect(repository.getBundle(hex(1), "recipient-a")).resolves.toBeDefined();
    await expect(repository.getManifest(hex(1))).resolves.toMatchObject({
      authorizationId: hex(1),
      h_commit: hex(2),
    });
    expect(events.some((webhookEvent) => webhookEvent.event_type === "reveal.finalized")).toBe(true);
  });
});

function baseRevealInput(): Omit<
  Parameters<typeof processRevealAuthorizedEvent>[0],
  "event" | "recipient_selectors" | "combiner_input"
> {
  return {
    partner_id: "11111111-1111-4111-8111-111111111111",
    pda: {
      pda_id: "22222222-2222-4222-8222-222222222222",
      pda_version: "m4-fixture",
      trust_tier: "tier_b",
      operational_class: "regulated",
    },
    g3_choice: "dcipher",
    g4_phase: 2,
    schema_digest: hex(7),
    preconditions: {
      challenge_window_closed: true,
      shred_state_allows_reveal: true,
      registry_deprecation_acceptable: true,
      recipient_policy_identified: true,
    },
    sigma_block: sampleSigmaBlock(),
    chain_proofs: sampleChainProofs(),
    registry_snapshots: sampleRegistrySnapshots(),
    shred_state: {
      h_commit: hex(2),
      shred_state: "not_shredded",
      checked_at_block: 200,
      checked_at_block_hash: hex(3),
    },
    sd_refs: { status: "failed", disclosure_refs: ["sd://failed"] },
    gate_endpoints: { lit: "https://lit.example", g4: "https://g4.example" },
    registry_snapshot_refs: { authorization: hex(3) },
    recipient_policy: { recipients: ["recipient-a"] },
    m3_scaffold: {
      artifact_type: "RevealArtifactBundle",
      authorizationId: hex(1),
      hCommit: hex(2),
    },
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

function sampleChainProofs(): ChainProofs {
  return {
    chain_id: 8453,
    condition_engine_address: "0x0000000000000000000000000000000000000001",
    reveal_authorized_emitter: "0x0000000000000000000000000000000000000001",
    reveal_authorized_event_signature: "RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)",
    reveal_authorized_topics: [hex(1), hex(2), hex(5)],
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
  return {
    authorization_block: 200,
    authorization_block_hash: hex(3),
    registry_contracts: {},
  };
}

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}
