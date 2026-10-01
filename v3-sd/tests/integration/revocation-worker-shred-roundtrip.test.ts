import { describe, expect, it } from "vitest";
import type { PublicClient, WalletClient } from "viem";

import { RevocationWorker } from "../../src/onchain/revocation-worker.js";
import { shredFinalizedEvidenceRef } from "../../src/onchain/evidence-ref.js";
import { SD_REVOCATION_REASON } from "../../src/types/sd-revocation.js";

const authorizationId = `0x${"11".repeat(32)}` as const;
const disclosureA = `0x${"22".repeat(32)}` as const;
const disclosureB = `0x${"33".repeat(32)}` as const;
const hCommit = `0x${"44".repeat(32)}` as const;
const proofShred = `0x${"55".repeat(32)}` as const;
const revocationRegistryAddress = `0x${"66".repeat(20)}` as const;
const shredRegistryAddress = `0x${"77".repeat(20)}` as const;

describe("RevocationWorker shred-trigger bridge", () => {
  it("calls revokeDisclosure(disclosure_id, 0x02, evidenceRef) for each active disclosure", async () => {
    const calls: unknown[] = [];
    const walletClient = {
      writeContract: async (call: unknown) => {
        calls.push(call);
        return `0x${calls.length.toString(16).padStart(64, "0")}`;
      },
    } as unknown as WalletClient;

    const worker = new RevocationWorker({
      publicClient: {} as PublicClient,
      walletClient,
      shredRegistryAddress,
      revocationRegistryAddress,
      disclosureIndex: {
        listActiveUnexpiredDisclosureIds: async (auth) => {
          expect(auth).toBe(authorizationId);
          return [disclosureA, disclosureB];
        },
      },
    });

    const result = await worker.handleShredFinalized({
      authorizationId,
      hCommit,
      proofShred,
      blockNumber: 42n,
    });

    const evidenceRef = shredFinalizedEvidenceRef(authorizationId, 42n);
    expect(result).toMatchObject({ attempted: 2, revoked: 2, failed: 0, evidenceRef });
    expect(calls).toHaveLength(2);
    for (const [idx, call] of calls.entries()) {
      const typed = call as { functionName: string; address: string; args: readonly unknown[] };
      expect(typed.address).toBe(revocationRegistryAddress);
      expect(typed.functionName).toBe("revokeDisclosure");
      expect(typed.args).toEqual([
        idx === 0 ? disclosureA : disclosureB,
        SD_REVOCATION_REASON.PDA_SHRED_FINALIZED,
        evidenceRef,
      ]);
    }
  });

  it("does not throw into escrow flow when disclosure enumeration fails", async () => {
    const errors: unknown[] = [];
    const worker = new RevocationWorker({
      publicClient: {} as PublicClient,
      walletClient: {} as WalletClient,
      shredRegistryAddress,
      revocationRegistryAddress,
      disclosureIndex: {
        listActiveUnexpiredDisclosureIds: async () => {
          throw new Error("index unavailable");
        },
      },
      onError: (error) => {
        errors.push(error);
      },
    });

    const result = await worker.handleShredFinalized({
      authorizationId,
      hCommit,
      proofShred,
      blockNumber: 42n,
    });

    expect(result.failed).toBe(1);
    expect(result.attempted).toBe(0);
    expect(errors).toHaveLength(1);
  });
});

