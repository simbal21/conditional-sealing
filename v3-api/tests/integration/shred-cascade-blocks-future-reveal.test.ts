import { describe, expect, it } from "vitest";
import { assembleRevealArtifactBundle } from "../../src/bundle/index.js";
import { InMemoryRevealArtifactRepository, normalizeRevealAuthorizedLog, processRevealAuthorizedEvent } from "../../src/index.js";
import { createPartnerStatusStore, getPartnerShred } from "../../src/partner/index.js";
import type { ChainProofs, Hex32, RegistrySnapshots, RevealArtifactBundle, SigmaBlock } from "../../src/types/reveal-artifact-bundle.js";
import { makeRevealCombinerDoubles } from "../_helpers/reveal-combiner-testkit.js";

// F-API-1: plaintext provenance is the combiner, not the request body. This
// reveal call REJECTS at the precondition gate (shred blocks reveal) BEFORE the
// combine+decrypt join, so the doubles are inert here — supplied only to satisfy
// the input type.
const KNOWN_PLAINTEXT = { legal_name: "Alice" } as const;

type VerifyArtifactBundleFn = (
  bundle: RevealArtifactBundle,
  options?: { readonly now?: Date; readonly expectedRecipientRef?: string },
) => Promise<{ readonly overall: string; readonly checks: Record<string, { readonly status: string; readonly code: string }> }>;

describe("shred cascade blocks future reveal", () => {
  it("treats finalized shred as chain + G4 + vault block and rejects future bundle verification", async () => {
    const { verifyArtifactBundle } = await importSource<{ readonly verifyArtifactBundle: VerifyArtifactBundleFn }>(
      "../../../verify-sdk/src/index.ts",
    );
    const hCommit = hex(2);
    const store = createPartnerStatusStore({ h_commit: hCommit });
    store.shreds.set(`partner_demo:${hCommit}`, {
      h_commit: hCommit,
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      status: "finalized",
      vault_deletion_status: "deleted",
      blocked_future_reveal: true,
      chain_refusal_code: "CHAIN.SHRED_FINALIZED",
      g4_refusal_code: "0x04",
      vault_error_code: "VAULT.COMMIT_SHREDDED",
    });

    expect(getPartnerShred({ store }, "partner_demo", hCommit)).toMatchObject({
      status: "finalized",
      vault_deletion_status: "deleted",
      blocked_future_reveal: true,
      chain_refusal_code: "CHAIN.SHRED_FINALIZED",
      vault_error_code: "VAULT.COMMIT_SHREDDED",
    });

    const doubles = makeRevealCombinerDoubles(KNOWN_PLAINTEXT, {
      authId: hex(1),
      hCommit,
      blockHash: hex(3),
      g3_choice: "dcipher",
    });

    await expect(
      processRevealAuthorizedEvent(
        {
          event: sampleEvent(),
          ...baseRevealInput(),
          combiner_input: doubles.combinerInput,
          preconditions: {
            challenge_window_closed: true,
            shred_state_allows_reveal: false,
            registry_deprecation_acceptable: true,
            recipient_policy_identified: true,
          },
          recipient_selectors: [selector()],
          shred_state: { h_commit: hCommit, shred_state: "shred_finalized", checked_at_block: 201, checked_at_block_hash: hex(3) },
        },
        {
          repository: new InMemoryRevealArtifactRepository(),
          sigmaGatherer: doubles.sigmaGatherer,
          vault: doubles.vault,
          combineAndDecryptRunner: doubles.combineAndDecryptRunner,
          now: () => new Date("2026-05-11T00:03:00.000Z"),
        },
      ),
    ).rejects.toThrow("shred state blocks reveal");

    const verification = await verifyArtifactBundle(shreddedBundle(), {
      now: new Date("2026-05-11T00:03:00.000Z"),
      expectedRecipientRef: "recipient-a",
    });
    expect(verification.overall).toBe("fail");
    expect(verification.checks.shredState).toMatchObject({
      status: "fail",
      code: "SHRED_STATE.FINALIZED_BEFORE_REVEAL",
    });
  });
});

function shreddedBundle(): RevealArtifactBundle {
  return assembleRevealArtifactBundle({
    authorization: authorization(),
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
    shred_state: { h_commit: hex(2), shred_state: "shred_finalized", checked_at_block: 201, checked_at_block_hash: hex(3) },
    sd_refs: { status: "present", sdMerkleRoot: hex(9), disclosure_refs: ["sd://fixture"] },
  }).bundle;
}

function sampleEvent(): ReturnType<typeof normalizeRevealAuthorizedLog> {
  return normalizeRevealAuthorizedLog({
    args: {
      authorizationId: hex(1),
      hCommit: hex(2),
      pdaRoot: hex(5),
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
}

function baseRevealInput(): Omit<Parameters<typeof processRevealAuthorizedEvent>[0], "event" | "recipient_selectors" | "preconditions" | "shred_state" | "combiner_input"> {
  return {
    partner_id: "partner_demo",
    pda: { pda_id: "pda_demo", pda_version: "1", trust_tier: "tier_b", operational_class: "b2b_partner" },
    g3_choice: "dcipher",
    g4_phase: 2,
    schema_digest: hex(7),
    sigma_block: sampleSigmaBlock(),
    chain_proofs: sampleChainProofs(),
    registry_snapshots: sampleRegistrySnapshots(),
    sd_refs: { status: "present", sdMerkleRoot: hex(9), disclosure_refs: ["sd://fixture"] },
    gate_endpoints: { lit: "https://lit.example", g4: "https://g4.example" },
    registry_snapshot_refs: { authorization: hex(3) },
    recipient_policy: { recipients: ["recipient-a"] },
    m3_scaffold: { artifact_type: "RevealArtifactBundle", authorizationId: hex(1), hCommit: hex(2) },
  };
}

function selector() {
  return {
    recipient_ref: "recipient-a",
    recipient_pubkey_id: "pubkey-a",
    schema_selector_digest: hex(6),
    fields: ["legal_name"],
  };
}

function authorization(): RevealArtifactBundle["authorization"] {
  return {
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
    shred_registry_state_at_reveal: "shred_finalized",
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
