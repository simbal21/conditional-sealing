import { describe, expect, it } from "vitest";
import {
  assembleRevealArtifactBundle,
  canonicalizeJcsString,
  jcsDigest,
} from "../../src/bundle/index.js";
import {
  REVEAL_ARTIFACT_BUNDLE_TOP_KEYS,
  type ChainProofs,
  type Hex32,
  type RegistrySnapshots,
  type SigmaBlock,
} from "../../src/types/reveal-artifact-bundle.js";

describe("Phase C bundle assembly — 15 keys + JCS determinism", () => {
  it("assembles all 15 top-level keys in locked order and canonicalizes byte-identically", () => {
    const first = assembleRevealArtifactBundle(sampleBundleInput()).bundle;
    const second = assembleRevealArtifactBundle(sampleBundleInput()).bundle;

    expect(Object.keys(first)).toEqual([...REVEAL_ARTIFACT_BUNDLE_TOP_KEYS]);
    expect(Object.keys(second)).toEqual([...REVEAL_ARTIFACT_BUNDLE_TOP_KEYS]);
    expect(canonicalizeJcsString(first)).toBe(canonicalizeJcsString(second));
    expect(jcsDigest(first)).toBe(jcsDigest(second));
    expect(first.bundle_version).toBe("s2-5.1");
    expect(first.pii_statement).toBe("recipient_filtered_plaintext_after_valid_reveal");
  });
});

function sampleBundleInput(): Parameters<typeof assembleRevealArtifactBundle>[0] {
  return {
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
      pda_id: "11111111-1111-4111-8111-111111111111",
      pda_version: "m4-fixture",
      pda_root: hex(5),
      trust_tier: "tier_b",
      operational_class: "regulated",
    },
    recipient: {
      recipient_ref: "recipient-a",
      recipient_pubkey_id: "pubkey-a",
      schema_selector_digest: hex(6),
    },
    plaintext: {
      schema_selector_digest: hex(6),
      schema_digest: hex(7),
      content_encoding: "application/json",
      fields: { legal_name: "Alice" },
      field_hashes: { legal_name: hex(8) },
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
    sd_refs: {
      status: "failed",
      disclosure_refs: ["sd://failed-but-non-blocking"],
    },
    verification: {
      verifier_version: "test",
      checks: { sdRefs: "failed" },
    },
    m3_scaffold: {
      artifact_type: "RevealArtifactBundle",
      authorizationId: hex(1),
      hCommit: hex(2),
    },
  };
}

function sampleSigmaBlock(): SigmaBlock {
  return {
    sigma_subject: "0x1234",
    sigma_lit: { sigma: "0x11", authority_ref: hex(11), public_after_reveal: true },
    sigma_g3: {
      sigma: "0x22",
      authority_ref: hex(12),
      variant: "dcipher",
      public_after_reveal: true,
    },
    sigma_g4: {
      sigma: "0x33",
      authority_ref: hex(13),
      phase: 2,
      public_after_reveal: true,
    },
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
    receipt_proof: {
      proof_type: "mock_receipt",
      block_number: 200,
      block_hash: hex(3),
      log_index: 0,
    },
    commit_tx_hash: hex(20),
    commit_block: 100,
    commit_block_hash: hex(21),
    reveal_authorized_tx_hash: hex(22),
    reveal_authorized_log_index: 0,
    reveal_authorized_block: 200,
    reveal_authorized_block_hash: hex(3),
    base_finality_confirmations: 32,
    finalized_at: "2026-05-11T00:02:00.000Z",
    challenge_window_expired_at: "2026-05-11T00:01:00.000Z",
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
