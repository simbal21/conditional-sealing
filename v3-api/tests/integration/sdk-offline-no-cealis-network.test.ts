import { afterEach, describe, expect, it, vi } from "vitest";
import { assembleRevealArtifactBundle } from "../../src/bundle/index.js";
import type { ChainProofs, Hex32, RegistrySnapshots, RevealArtifactBundle, SigmaBlock } from "../../src/types/reveal-artifact-bundle.js";

type VerifyArtifactBundleFn = (
  bundle: RevealArtifactBundle,
  options?: { readonly now?: Date; readonly chainRpcUrl?: string; readonly expectedRecipientRef?: string },
) => Promise<{ readonly overall: string; readonly checks: Record<string, { readonly status: string; readonly code: string }> }>;

describe("SDK offline verification without Cealis network", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("verifies a v3-api assembled bundle without calling any Cealis API", async () => {
    vi.stubGlobal("fetch", () => {
      throw new Error("Cealis API intentionally unreachable in offline SDK test.");
    });
    const { verifyArtifactBundle } = await importSource<{ readonly verifyArtifactBundle: VerifyArtifactBundleFn }>(
      "../../../verify-sdk/src/index.ts",
    );

    const bundle = validBundle();
    const result = await verifyArtifactBundle(bundle, {
      now: new Date("2026-05-11T00:03:00.000Z"),
      chainRpcUrl: "http://127.0.0.1:8545",
      expectedRecipientRef: "recipient-a",
    });

    expect(result.overall).toBe("pass");
    expect(result.checks.chainProof?.status).toBe("pass");
  });
});

function validBundle(): RevealArtifactBundle {
  return assembleRevealArtifactBundle({
    authorization: {
      authorizationId: hex(1),
      h_commit: hex(2),
      commit_version: "0x0302",
      authorization_block: 200,
      authorization_block_hash: hex(3),
      authorization_timestamp: "2026-05-11T00:00:00.000Z",
      conditionRef: hex(4),
      challenge_window_seconds: 60,
      challenge_window_expired_at: "2026-05-11T00:01:00.000Z",
      finalized_at: "2026-05-11T00:02:00.000Z",
    },
    pda: {
      pda_id: "pda_demo",
      pda_version: "1",
      pda_root: hex(5),
      trust_tier: "tier_b",
      operational_class: "b2b_partner",
    },
    recipient: { recipient_ref: "recipient-a", recipient_pubkey_id: "pubkey-a", schema_selector_digest: hex(6) },
    plaintext: {
      schema_selector_digest: hex(6),
      schema_digest: hex(7),
      content_encoding: "application/json+jcs",
      fields: { legal_name: "Alice" },
      field_hashes: { legal_name: hex(8) },
    },
    sigma_block: sampleSigmaBlock(),
    chain_proofs: sampleChainProofs(),
    registry_snapshots: sampleRegistrySnapshots(),
    shred_state: { h_commit: hex(2), shred_state: "not_shredded", checked_at_block: 200, checked_at_block_hash: hex(3) },
    sd_refs: { status: "present", sdMerkleRoot: hex(9), disclosure_refs: ["sd://fixture"] },
  }).bundle;
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
  return { authorization_block: 200, authorization_block_hash: hex(3), registry_contracts: {} };
}

async function importSource<T>(relativePath: string): Promise<T> {
  return (await import(new URL(relativePath, import.meta.url).href)) as T;
}

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}
