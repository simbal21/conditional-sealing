import { describe, expect, it } from "vitest";
import {
  InMemoryRevealArtifactRepository,
  normalizeRevealAuthorizedLog,
  processRevealAuthorizedEvent,
} from "../../src/index.js";
import type { ChainProofs, Hex32, RegistrySnapshots, SigmaBlock } from "../../src/types/reveal-artifact-bundle.js";
import { makeRevealCombinerDoubles } from "../_helpers/reveal-combiner-testkit.js";

// F-API-1: plaintext provenance is the combiner, not the request body.
const KNOWN_PLAINTEXT = { legal_name: "Alice", address: "Aachen", score: 720 } as const;

describe("Phase C multi-recipient delivery", () => {
  it("emits one distinct filtered bundle per recipient", async () => {
    const repository = new InMemoryRevealArtifactRepository();
    const doubles = makeRevealCombinerDoubles(KNOWN_PLAINTEXT, {
      authId: hex(71),
      hCommit: hex(72),
      blockHash: hex(73),
      g3_choice: "dcipher",
    });
    const result = await processRevealAuthorizedEvent(
      {
        event: sampleEvent(),
        ...baseRevealInput(),
        combiner_input: doubles.combinerInput,
        recipient_selectors: [
          selector("recipient-a", "legal_name", 61),
          selector("recipient-b", "address", 62),
          selector("recipient-c", "score", 63),
        ],
      },
      {
        repository,
        sigmaGatherer: doubles.sigmaGatherer,
        vault: doubles.vault,
        combineAndDecryptRunner: doubles.combineAndDecryptRunner,
        now: () => new Date("2026-05-11T00:02:00.000Z"),
      },
    );

    expect(result.bundles).toHaveLength(3);
    expect(result.bundles.map((bundle) => bundle.recipient.recipient_ref)).toEqual([
      "recipient-a",
      "recipient-b",
      "recipient-c",
    ]);
    expect(Object.keys(result.bundles[0]?.plaintext.fields ?? {})).toEqual(["legal_name"]);
    expect(Object.keys(result.bundles[1]?.plaintext.fields ?? {})).toEqual(["address"]);
    expect(Object.keys(result.bundles[2]?.plaintext.fields ?? {})).toEqual(["score"]);
    expect(new Set(result.bundles.map((bundle) => bundle.verification.artifact_bundle_digest)).size).toBe(3);
  });
});

function selector(recipientRef: string, field: string, digestSeed: number) {
  return {
    recipient_ref: recipientRef,
    recipient_pubkey_id: `${recipientRef}-pubkey`,
    schema_selector_digest: hex(digestSeed),
    fields: [field],
  };
}

function sampleEvent(): ReturnType<typeof normalizeRevealAuthorizedLog> {
  return normalizeRevealAuthorizedLog({
    args: {
      authorizationId: hex(71),
      hCommit: hex(72),
      pdaRoot: hex(75),
      authorizationBlock: 200n,
      authorizationTimestamp: 1_778_489_600n,
      challengeWindow: 60,
      conditionRef: hex(74),
    },
    blockHash: hex(73),
    blockNumber: 200n,
    logIndex: 0,
  });
}

function baseRevealInput(): Omit<Parameters<typeof processRevealAuthorizedEvent>[0], "event" | "recipient_selectors" | "combiner_input"> {
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
    schema_digest: hex(77),
    preconditions: {
      challenge_window_closed: true,
      shred_state_allows_reveal: true,
      registry_deprecation_acceptable: true,
      recipient_policy_identified: true,
    },
    sigma_block: sampleSigmaBlock(),
    chain_proofs: sampleChainProofs(),
    registry_snapshots: sampleRegistrySnapshots(),
    shred_state: { h_commit: hex(72), shred_state: "not_shredded", checked_at_block: 200, checked_at_block_hash: hex(73) },
    sd_refs: { status: "partial_failure", disclosure_refs: ["sd://partial"] },
    gate_endpoints: { lit: "https://lit.example", g4: "https://g4.example" },
    registry_snapshot_refs: { authorization: hex(73) },
    recipient_policy: { recipients: ["recipient-a", "recipient-b", "recipient-c"] },
    m3_scaffold: { artifact_type: "RevealArtifactBundle", authorizationId: hex(71), hCommit: hex(72) },
  };
}

function sampleSigmaBlock(): SigmaBlock {
  return {
    sigma_lit: { sigma: "0x11", authority_ref: hex(81), public_after_reveal: true },
    sigma_g3: { sigma: "0x22", authority_ref: hex(82), variant: "dcipher", public_after_reveal: true },
    sigma_g4: { sigma: "0x33", authority_ref: hex(83), phase: 2, public_after_reveal: true },
    sigma_conditional: [],
  };
}

function sampleChainProofs(): ChainProofs {
  return {
    chain_id: 8453,
    condition_engine_address: "0x0000000000000000000000000000000000000001",
    reveal_authorized_emitter: "0x0000000000000000000000000000000000000001",
    reveal_authorized_event_signature: "RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)",
    reveal_authorized_topics: [hex(71), hex(72), hex(75)],
    receipt_proof: { proof_type: "mock_receipt", block_number: 200, block_hash: hex(73), log_index: 0 },
    commit_tx_hash: hex(90),
    commit_block: 100,
    commit_block_hash: hex(91),
    reveal_authorized_tx_hash: hex(92),
    reveal_authorized_log_index: 0,
    reveal_authorized_block: 200,
    reveal_authorized_block_hash: hex(73),
    base_finality_confirmations: 32,
    conditionRef: hex(74),
    shred_registry_state_at_reveal: "not_shredded",
  };
}

function sampleRegistrySnapshots(): RegistrySnapshots {
  return { authorization_block: 200, authorization_block_hash: hex(73), registry_contracts: {} };
}

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}
