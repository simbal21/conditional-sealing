// Round 1 — Step 3 isolated: chain anchor verification.
//
// Synthetic adapter pattern: in CI mode, the M5 mock anchor returns
// `commit_tx_hash` + echoes `commit_block_hash`. Real anvil-fork watchEvent
// integration deferred to Phase F/G live deploy.
//
// PDARegistered is the actual M2 anchor event (see
// `contracts/out/ConditionEngine.sol/ConditionEngine.json`),
// emitting (authorizationId, hCommit, pdaRoot, partnerId). This test
// asserts the synthetic anchor surface returns a 32-byte hex commit_tx_hash
// and the synthesised RevealAuthorized event carries hCommit byte-for-byte.

import { describe, expect, it } from "vitest";
import {
  runRound1,
  synthesizeRevealAuthorizedEvent,
  synthesizeChainProofs,
} from "../../src/rounds/round1.js";
import { M2_EVENT_NAMES, M2_ABIS } from "../../src/m2-imports.js";

describe("Round 1 — Step 3 chain anchor verification", () => {
  it("commit_tx_hash echoed from synthetic anchor is 32-byte hex", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.commitTxHash).toMatch(/^0x[0-9a-fA-F]{64}$/);
  });

  it("M2 ConditionEngine ABI carries PDARegistered (the actual anchor event)", () => {
    const abi = M2_ABIS.ConditionEngine;
    const pdaRegistered = abi.find(
      (entry) =>
        (entry as { type?: string }).type === "event" &&
        (entry as { name?: string }).name === "PDARegistered",
    );
    expect(pdaRegistered).toBeDefined();
  });

  it("M2 ConditionEngine ABI carries RevealAuthorized event", () => {
    const abi = M2_ABIS.ConditionEngine;
    const event = abi.find(
      (entry) =>
        (entry as { type?: string }).type === "event" &&
        (entry as { name?: string }).name === M2_EVENT_NAMES.RevealAuthorized,
    );
    expect(event).toBeDefined();
  });

  it("synthesised RevealAuthorized event carries hCommit + authorizationId + pdaRoot byte-for-byte", () => {
    const fakeResponse = {
      api_version: "1.0-draft" as const,
      commit_version: "0x0302" as const,
      ingestion_id: "test",
      authorizationId: "0x" + "ab".repeat(32),
      h_commit: "0x" + "cd".repeat(32),
      pda_id: "pda_x",
      pda_version: "1",
      partner_id: "partner_x",
      vault_ref: "mock://x",
      status: "committed" as const,
    };
    const pda = {
      pda_id: "pda_x",
      pda_version: "1",
      partner_id: "partner_x",
      pda_root: "0x" + "ef".repeat(32),
      schema_digest: "0x" + "f0".repeat(32),
      g3_choice: "drand" as const,
      g4_phase: 1 as const,
      operational_class: "b2b_partner" as const,
      trust_tier: "tier_b" as const,
      retention_seconds: 86_400n,
      partner_ready: true,
      legal_effect_expected: false,
    };
    const event = synthesizeRevealAuthorizedEvent(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      fakeResponse as any,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      pda as any,
    );
    expect(event.authorizationId).toBe(fakeResponse.authorizationId);
    expect(event.h_commit).toBe(fakeResponse.h_commit);
    expect(event.pda_root).toBe(pda.pda_root);
  });

  it("synthesizeChainProofs produces verify-sdk-conformant chain_proofs structure", () => {
    const authId = `0x${"01".repeat(32)}` as const;
    const hCommit = `0x${"02".repeat(32)}` as const;
    const pdaRoot = `0x${"03".repeat(32)}` as const;
    const proofs = synthesizeChainProofs(authId, hCommit, pdaRoot);
    expect(proofs.commit_tx_hash).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(proofs.commit_block_hash).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(proofs.reveal_authorized_block_hash).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(proofs.reveal_authorized_block).toBe(200);
    expect(proofs.receipt_proof.block_number).toBe(proofs.reveal_authorized_block);
    expect(proofs.receipt_proof.block_hash).toBe(proofs.reveal_authorized_block_hash);
    expect(proofs.receipt_proof.log_index).toBe(proofs.reveal_authorized_log_index);
    expect(proofs.reveal_authorized_topics).toEqual([authId, hCommit, pdaRoot]);
  });
});
