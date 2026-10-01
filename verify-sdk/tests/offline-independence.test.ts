import { describe, expect, it, vi } from "vitest";
import { verifyArtifactBundle, verifySdOutput, verifyWebhook } from "../src/index.js";
import { webhookSignatureHex } from "../src/verify-webhook.js";
import type { Hex32, RevealArtifactBundle } from "../src/types.js";
import { computeArtifactBundleDigest, ZERO_HEX32 } from "../src/checks/canonicalization.js";
import { readRevealAuthorizedTopicRefs } from "../src/chain-reader/event-decode.js";
import { createPartnerRpcClient, verifyRevealAuthorizedReceipt } from "../src/chain-reader/partner-rpc.js";

const viemMock = vi.hoisted(() => ({
  receipt: {
    blockHash: "0x0000000000000000000000000000000000000000000000000000000000000003",
    logs: [{ logIndex: 0 }],
  },
}));

vi.mock("viem", () => ({
  createPublicClient: () => ({
    getTransactionReceipt: async () => viemMock.receipt,
  }),
  http: (url: string) => ({ url }),
}));

const textEncoder = new TextEncoder();

describe("verify-sdk offline independence", () => {
  it("verifies artifact, SD output, and webhook without Cealis network access", async () => {
    const artifact = await verifyArtifactBundle(validBundle(), {
      chainRpcUrl: "http://127.0.0.1:9",
      requireOnlineRegistryChecks: false,
      now: new Date("2026-05-11T00:03:00.000Z"),
    });
    expect(artifact.overall).toBe("pass");

    const sd = await verifySdOutput({ status: "complete", sdMerkleRoot: artifact.artifact_bundle_digest });
    expect(sd.overall).toBe("pass");

    const secret = textEncoder.encode("webhook_secret");
    const rawBody = textEncoder.encode('{"event_id":"evt_offline","event_type":"reveal.finalized"}');
    const timestamp = "1778500800";
    const webhook = await verifyWebhook(
      rawBody,
      {
        "x-cealis-signature": `sha256=${webhookSignatureHex(timestamp, rawBody, secret)}`,
        "x-cealis-timestamp": timestamp,
        "x-cealis-event": "reveal.finalized",
        "x-cealis-delivery": "evt_offline",
      },
      secret,
      new Date(Number(timestamp) * 1000),
    );
    expect(webhook.overall).toBe("pass");
  });

  it("keeps partner RPC explicit and decodes RevealAuthorized topics locally", async () => {
    expect(() => createPartnerRpcClient({ chainRpcUrl: "" })).toThrow("chainRpcUrl is required");
    expect(createPartnerRpcClient({ chainRpcUrl: "http://127.0.0.1:8545", chainId: 8453 })).toBeDefined();
    expect(
      readRevealAuthorizedTopicRefs({
        topics: [hex(99), hex(1), hex(2), hex(5), "0xnotbytes32"],
      }),
    ).toEqual({
      event_topic: hex(99),
      authorizationId: hex(1),
      h_commit: hex(2),
      pda_root: hex(5),
    });
  });

  it("requires partner-supplied RPC before any online receipt check", async () => {
    const artifact = await verifyArtifactBundle(validBundle(), {
      requireOnlineRegistryChecks: true,
      now: new Date("2026-05-11T00:03:00.000Z"),
    });
    expect(artifact.overall).toBe("fail");
    expect(artifact.checks.chainProof.code).toBe("CHAIN_PROOF.RPC_URL_REQUIRED");
  });

  it("threads online receipt results back through the chainProof check", async () => {
    viemMock.receipt = { blockHash: hex(3), logs: [{ logIndex: 0 }] };
    const passing = await verifyArtifactBundle(validBundle(), {
      requireOnlineRegistryChecks: true,
      chainRpcUrl: "http://127.0.0.1:8545",
      now: new Date("2026-05-11T00:03:00.000Z"),
    });
    expect(passing.checks.chainProof.status).toBe("pass");

    viemMock.receipt = { blockHash: hex(99), logs: [{ logIndex: 0 }] };
    const failing = await verifyArtifactBundle(validBundle(), {
      requireOnlineRegistryChecks: true,
      chainRpcUrl: "http://127.0.0.1:8545",
      now: new Date("2026-05-11T00:03:00.000Z"),
    });
    expect(failing.checks.chainProof.code).toBe("CHAIN_PROOF.ONLINE_RECEIPT_MISMATCH");
  });

  it("verifies online receipts only through the partner-supplied RPC client", async () => {
    viemMock.receipt = { blockHash: hex(3), logs: [{ logIndex: 0 }] };
    await expect(
      verifyRevealAuthorizedReceipt({
        chainRpcUrl: "http://127.0.0.1:8545",
        txHash: hex(22),
        expectedBlockHash: hex(3),
        expectedLogIndex: 0,
      }),
    ).resolves.toEqual({ ok: true });

    viemMock.receipt = { blockHash: hex(99), logs: [{ logIndex: 0 }] };
    await expect(
      verifyRevealAuthorizedReceipt({
        chainRpcUrl: "http://127.0.0.1:8545",
        txHash: hex(22),
        expectedBlockHash: hex(3),
        expectedLogIndex: 0,
      }),
    ).resolves.toEqual({ ok: false, reason: "Receipt blockHash does not match bundle proof." });

    viemMock.receipt = { blockHash: hex(3), logs: [{ logIndex: 1 }] };
    await expect(
      verifyRevealAuthorizedReceipt({
        chainRpcUrl: "http://127.0.0.1:8545",
        txHash: hex(22),
        expectedBlockHash: hex(3),
        expectedLogIndex: 0,
      }),
    ).resolves.toEqual({ ok: false, reason: "Receipt does not contain expected RevealAuthorized log index." });
  });
});

function validBundle(): RevealArtifactBundle {
  const bundle: RevealArtifactBundle = {
    bundle_version: "s2-5.1",
    canonicalization: {
      format: "JCS",
      rfc: "RFC8785",
      hash: "keccak256(utf8(jcs(reveal_artifact_bundle_json_object)))",
    },
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
    pda: { pda_id: "pda-demo", pda_version: "1", pda_root: hex(5), trust_tier: "tier_b", operational_class: "regulated" },
    recipient: { recipient_ref: "recipient-a", schema_selector_digest: hex(6) },
    plaintext: { schema_selector_digest: hex(6), schema_digest: hex(7), content_encoding: "application/json", fields: { ok: true } },
    issuer_attestation: { status: "not_configured" },
    provenance: { status: "not_configured" },
    sigma_block: {
      sigma_lit: { sigma: "0x11", authority_ref: hex(11), public_after_reveal: true },
      sigma_g3: { sigma: "0x22", authority_ref: hex(12), public_after_reveal: true },
      sigma_g4: { sigma: "0x33", authority_ref: hex(13), phase: 2, public_after_reveal: true },
      sigma_conditional: [],
    },
    chain_proofs: {
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
    },
    registry_snapshots: { authorization_block: 200, authorization_block_hash: hex(3), registry_contracts: {} },
    shred_state: { h_commit: hex(2), shred_state: "not_shredded", checked_at_block: 200, checked_at_block_hash: hex(3) },
    sd_refs: { status: "not_configured" },
    verification: { artifact_bundle_digest: ZERO_HEX32, verifier_version: "test" },
    pii_statement: "recipient_filtered_plaintext_after_valid_reveal",
  };
  return { ...bundle, verification: { ...bundle.verification, artifact_bundle_digest: computeArtifactBundleDigest(bundle) } };
}

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}
