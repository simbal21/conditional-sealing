import { describe, expect, it } from "vitest";
import {
  InMemoryRevealArtifactRepository,
  RefusalCode,
  isBlockingRefusal,
  normalizeRevealAuthorizedLog,
  processRevealAuthorizedEvent,
  type RefusalCodeValue,
} from "../../src/index.js";
import type { ChainProofs, Hex32, RegistrySnapshots, SigmaBlock } from "../../src/types/reveal-artifact-bundle.js";
import { makeRevealCombinerDoubles } from "../_helpers/reveal-combiner-testkit.js";

// F-API-1: plaintext provenance is the combiner, not the request body. Only the
// advisory (non-blocking) code reaches the combine+decrypt join; blocking codes
// return before it, so the doubles are inert for them.
const KNOWN_PLAINTEXT = { legal_name: "Alice", address: "Aachen" } as const;

describe("Phase C G4 refusal handling — all 10 codes", () => {
  it("halts 0x01-0x09 and allows advisory 0x0A to continue", async () => {
    const codes: RefusalCodeValue[] = [
      RefusalCode.LegalCompel,
      RefusalCode.Art17Erasure,
      RefusalCode.Art18Restriction,
      RefusalCode.IntegrityFail,
      RefusalCode.ChainMismatch,
      RefusalCode.PluginDeprecated,
      RefusalCode.AuthorityDeprecated,
      RefusalCode.DslDeprecated,
      RefusalCode.OracleDeprecated,
      RefusalCode.OptOutActive,
    ];

    for (const code of codes) {
      const seed = 100 + code;
      const repository = new InMemoryRevealArtifactRepository();
      const event = sampleEvent(seed);
      const doubles = makeRevealCombinerDoubles(KNOWN_PLAINTEXT, {
        authId: hex(seed),
        hCommit: hex(seed + 1),
        blockHash: hex(seed + 4),
        g3_choice: "dcipher",
      });
      const result = await processRevealAuthorizedEvent(
        {
          event,
          ...baseRevealInput(seed),
          combiner_input: doubles.combinerInput,
          recipient_selectors: [selector("recipient-a", "legal_name", seed + 20)],
          refusal: {
            reason_code: code,
            ...(code === RefusalCode.Art17Erasure || code === RefusalCode.Art18Restriction
              ? { encrypted_reason_ref: `vault://encrypted-reasons/${code}` }
              : {}),
          },
        },
        {
          repository,
          sigmaGatherer: doubles.sigmaGatherer,
          vault: doubles.vault,
          combineAndDecryptRunner: doubles.combineAndDecryptRunner,
          now: () => new Date("2026-05-11T00:02:00.000Z"),
        },
      );

      if (isBlockingRefusal(code)) {
        expect(result.bundles).toHaveLength(0);
        expect(result.status === "refused" || result.status === "deferred").toBe(true);
        await expect(repository.getBundle(event.authorizationId, "recipient-a")).resolves.toBeUndefined();
      } else {
        expect(result.status).toBe("finalized");
        expect(result.bundles).toHaveLength(1);
        await expect(repository.getBundle(event.authorizationId, "recipient-a")).resolves.toBeDefined();
      }
    }
  });
});

function sampleEvent(seed: number): ReturnType<typeof normalizeRevealAuthorizedLog> {
  return normalizeRevealAuthorizedLog({
    args: {
      authorizationId: hex(seed),
      hCommit: hex(seed + 1),
      pdaRoot: hex(seed + 2),
      authorizationBlock: 200n,
      authorizationTimestamp: 1_778_489_600n,
      challengeWindow: 60,
      conditionRef: hex(seed + 3),
    },
    blockHash: hex(seed + 4),
    blockNumber: 200n,
    logIndex: 0,
  });
}

function selector(recipientRef: string, field: string, digestSeed: number) {
  return {
    recipient_ref: recipientRef,
    recipient_pubkey_id: `${recipientRef}-pubkey`,
    schema_selector_digest: hex(digestSeed),
    fields: [field],
  };
}

function baseRevealInput(seed: number): Omit<Parameters<typeof processRevealAuthorizedEvent>[0], "event" | "recipient_selectors" | "refusal" | "combiner_input"> {
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
    schema_digest: hex(seed + 30),
    preconditions: {
      challenge_window_closed: true,
      shred_state_allows_reveal: true,
      registry_deprecation_acceptable: true,
      recipient_policy_identified: true,
    },
    sigma_block: sampleSigmaBlock(seed),
    chain_proofs: sampleChainProofs(seed),
    registry_snapshots: sampleRegistrySnapshots(seed),
    shred_state: {
      h_commit: hex(seed + 1),
      shred_state: "not_shredded",
      checked_at_block: 200,
      checked_at_block_hash: hex(seed + 4),
    },
    sd_refs: { status: "not_configured" },
    gate_endpoints: { lit: "https://lit.example", g4: "https://g4.example" },
    registry_snapshot_refs: { authorization: hex(seed + 4) },
    recipient_policy: { recipients: ["recipient-a"] },
    m3_scaffold: {
      artifact_type: "RevealArtifactBundle",
      authorizationId: hex(seed),
      hCommit: hex(seed + 1),
    },
  };
}

function sampleSigmaBlock(seed: number): SigmaBlock {
  return {
    sigma_lit: { sigma: "0x11", authority_ref: hex(seed + 40), public_after_reveal: true },
    sigma_g3: { sigma: "0x22", authority_ref: hex(seed + 41), variant: "dcipher", public_after_reveal: true },
    sigma_g4: { sigma: "0x33", authority_ref: hex(seed + 42), phase: 2, public_after_reveal: true },
    sigma_conditional: [],
  };
}

function sampleChainProofs(seed: number): ChainProofs {
  return {
    chain_id: 8453,
    condition_engine_address: "0x0000000000000000000000000000000000000001",
    reveal_authorized_emitter: "0x0000000000000000000000000000000000000001",
    reveal_authorized_event_signature: "RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)",
    reveal_authorized_topics: [hex(seed), hex(seed + 1), hex(seed + 2)],
    receipt_proof: { proof_type: "mock_receipt", block_number: 200, block_hash: hex(seed + 4), log_index: 0 },
    commit_tx_hash: hex(seed + 50),
    commit_block: 100,
    commit_block_hash: hex(seed + 51),
    reveal_authorized_tx_hash: hex(seed + 52),
    reveal_authorized_log_index: 0,
    reveal_authorized_block: 200,
    reveal_authorized_block_hash: hex(seed + 4),
    base_finality_confirmations: 32,
    conditionRef: hex(seed + 3),
    shred_registry_state_at_reveal: "not_shredded",
  };
}

function sampleRegistrySnapshots(seed: number): RegistrySnapshots {
  return { authorization_block: 200, authorization_block_hash: hex(seed + 4), registry_contracts: {} };
}

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}
