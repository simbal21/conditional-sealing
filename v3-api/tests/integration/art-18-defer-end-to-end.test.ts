import { describe, expect, it } from "vitest";
import {
  Art18DeferredDeliveryQueue,
  InMemoryRevealArtifactRepository,
  RefusalCode,
  normalizeRevealAuthorizedLog,
  processRevealAuthorizedEvent,
} from "../../src/index.js";
import type { WebhookEnvelope } from "../../src/types/webhook-events.js";
import type { ChainProofs, Hex32, RegistrySnapshots, RevealArtifactBundle, SigmaBlock } from "../../src/types/reveal-artifact-bundle.js";
import { makeRevealCombinerDoubles } from "../_helpers/reveal-combiner-testkit.js";

// F-API-1: plaintext provenance is the combiner, not the request body. Only the
// resumed (post-lift) call reaches the combine+decrypt join.
const KNOWN_PLAINTEXT = { legal_name: "Alice", address: "Aachen" } as const;

type VerifyArtifactBundleFn = (
  bundle: RevealArtifactBundle,
  options?: { readonly now?: Date; readonly expectedRecipientRef?: string },
) => Promise<{ readonly overall: string; readonly checks: Record<string, { readonly status: string; readonly code: string }> }>;

describe("Art. 18 defer end-to-end with SDK verification", () => {
  it("halts on refusal 0x03, resumes after lift, and produces a SDK-verifiable bundle", async () => {
    const { verifyArtifactBundle } = await importSource<{ readonly verifyArtifactBundle: VerifyArtifactBundleFn }>(
      "../../../verify-sdk/src/index.ts",
    );
    const repository = new InMemoryRevealArtifactRepository();
    const events: WebhookEnvelope<Record<string, unknown>>[] = [];
    const queue = new Art18DeferredDeliveryQueue<Awaited<ReturnType<typeof processRevealAuthorizedEvent>>>();
    const event = sampleEvent();
    const doubles = makeRevealCombinerDoubles(KNOWN_PLAINTEXT, {
      authId: hex(31),
      hCommit: hex(32),
      blockHash: hex(33),
      g3_choice: "dcipher",
    });

    const halted = await processRevealAuthorizedEvent(
      {
        event,
        ...baseRevealInput(),
        combiner_input: doubles.combinerInput,
        recipient_selectors: [selector("recipient-a", "legal_name")],
        refusal: {
          reason_code: RefusalCode.Art18Restriction,
          encrypted_reason_ref: "vault://encrypted-reasons/art18",
        },
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

    expect(halted.status).toBe("deferred");
    expect(halted.bundles).toHaveLength(0);
    expect(events.find((webhookEvent) => webhookEvent.event_type === "g4.refused")?.data).toMatchObject({
      reason_code: "0x03",
      reason_visibility: "encrypted",
      encrypted_reason_ref: "vault://encrypted-reasons/art18",
    });

    queue.defer({
      authorizationId: event.authorizationId,
      h_commit: event.h_commit,
      reason_code: RefusalCode.Art18Restriction,
      resume: () =>
        processRevealAuthorizedEvent(
          {
            event,
            ...baseRevealInput(),
            combiner_input: doubles.combinerInput,
            recipient_selectors: [selector("recipient-a", "legal_name")],
          },
          {
            repository,
            sigmaGatherer: doubles.sigmaGatherer,
            vault: doubles.vault,
            combineAndDecryptRunner: doubles.combineAndDecryptRunner,
            eventBus: { emit: (webhookEvent) => { events.push(webhookEvent); } },
            now: () => new Date("2026-05-11T00:03:00.000Z"),
          },
        ),
    });

    const resumed = await queue.liftAndResume(event.authorizationId);
    expect(resumed.status).toBe("finalized");
    expect(resumed.bundles).toHaveLength(1);

    const verification = await verifyArtifactBundle(resumed.bundles[0]!, {
      now: new Date("2026-05-11T00:04:00.000Z"),
      expectedRecipientRef: "recipient-a",
    });
    expect(verification.overall).toBe("pass");
    expect(verification.checks.sigmaG4?.status).toBe("pass");
  });
});

function sampleEvent(): ReturnType<typeof normalizeRevealAuthorizedLog> {
  return normalizeRevealAuthorizedLog({
    args: {
      authorizationId: hex(31),
      hCommit: hex(32),
      pdaRoot: hex(35),
      authorizationBlock: 200n,
      authorizationTimestamp: 1_778_457_600n,
      challengeWindow: 60,
      conditionRef: hex(34),
    },
    blockHash: hex(33),
    blockNumber: 200n,
    logIndex: 0,
  });
}

function selector(recipientRef: string, field: string) {
  return {
    recipient_ref: recipientRef,
    recipient_pubkey_id: `${recipientRef}-pubkey`,
    schema_selector_digest: hex(36),
    fields: [field],
  };
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
    schema_digest: hex(37),
    preconditions: {
      challenge_window_closed: true,
      shred_state_allows_reveal: true,
      registry_deprecation_acceptable: true,
      recipient_policy_identified: true,
    },
    sigma_block: sampleSigmaBlock(),
    chain_proofs: sampleChainProofs(),
    registry_snapshots: sampleRegistrySnapshots(),
    shred_state: { h_commit: hex(32), shred_state: "not_shredded", checked_at_block: 200, checked_at_block_hash: hex(33) },
    sd_refs: { status: "present", sdMerkleRoot: hex(60), disclosure_refs: ["sd://ok"] },
    gate_endpoints: { lit: "https://lit.example", g4: "https://g4.example" },
    registry_snapshot_refs: { authorization: hex(33) },
    recipient_policy: { recipients: ["recipient-a"] },
    m3_scaffold: { artifact_type: "RevealArtifactBundle", authorizationId: hex(31), hCommit: hex(32) },
  };
}

function sampleSigmaBlock(): SigmaBlock {
  return {
    sigma_lit: { sigma: "0x11", authority_ref: hex(41), public_after_reveal: true },
    sigma_g3: { sigma: "0x22", authority_ref: hex(42), variant: "dcipher", public_after_reveal: true },
    sigma_g4: { sigma: "0x33", authority_ref: hex(43), phase: 2, public_after_reveal: true },
    sigma_conditional: [],
  };
}

function sampleChainProofs(): ChainProofs {
  return {
    chain_id: 8453,
    condition_engine_address: "0x0000000000000000000000000000000000000001",
    reveal_authorized_emitter: "0x0000000000000000000000000000000000000001",
    reveal_authorized_event_signature: "RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)",
    reveal_authorized_topics: [hex(31), hex(32), hex(35)],
    receipt_proof: { proof_type: "mock_receipt", block_number: 200, block_hash: hex(33), log_index: 0 },
    commit_tx_hash: hex(50),
    commit_block: 100,
    commit_block_hash: hex(51),
    reveal_authorized_tx_hash: hex(52),
    reveal_authorized_log_index: 0,
    reveal_authorized_block: 200,
    reveal_authorized_block_hash: hex(33),
    base_finality_confirmations: 32,
    conditionRef: hex(34),
    shred_registry_state_at_reveal: "not_shredded",
  };
}

function sampleRegistrySnapshots(): RegistrySnapshots {
  return { authorization_block: 200, authorization_block_hash: hex(33), registry_contracts: {} };
}

async function importSource<T>(relativePath: string): Promise<T> {
  return (await import(new URL(relativePath, import.meta.url).href)) as T;
}

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}
