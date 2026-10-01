import type { Address, Hex, PublicClient, WalletClient } from "viem";

import { SD_REVOCATION_REASON, SD_REVOCATION_REASON_DOC_BLOCK } from "../types/sd-revocation.js";
import { shredFinalizedEvidenceRef } from "./evidence-ref.js";
import { watchShredFinalized, type ShredFinalizedLog } from "./shred-listener.js";

export const DISCLOSURE_REVOCATION_REGISTRY_ABI = [
  {
    type: "function",
    name: "revokeDisclosure",
    stateMutability: "nonpayable",
    inputs: [
      { name: "disclosureId", type: "bytes32" },
      { name: "reasonCode", type: "uint8" },
      { name: "evidenceRef", type: "bytes32" },
    ],
    outputs: [],
  },
] as const;

export interface ActiveDisclosureIndex {
  listActiveUnexpiredDisclosureIds(authorizationId: Hex): Promise<readonly Hex[]>;
}

export interface RevocationWorkerOptions {
  readonly publicClient: PublicClient;
  readonly walletClient: WalletClient;
  readonly shredRegistryAddress: Address;
  readonly revocationRegistryAddress: Address;
  readonly disclosureIndex: ActiveDisclosureIndex;
  readonly onError?: (error: unknown, context: RevocationWorkerErrorContext) => void | Promise<void>;
}

export interface RevocationWorkerErrorContext {
  readonly authorizationId: Hex;
  readonly disclosureId?: Hex;
  readonly evidenceRef: Hex;
}

export interface RevocationWorkerResult {
  readonly authorizationId: Hex;
  readonly evidenceRef: Hex;
  readonly attempted: number;
  readonly revoked: number;
  readonly failed: number;
  readonly transactionHashes: readonly Hex[];
}

export class RevocationWorker {
  readonly reasonDocBlock = SD_REVOCATION_REASON_DOC_BLOCK;

  constructor(private readonly options: RevocationWorkerOptions) {}

  start(): () => void {
    return watchShredFinalized({
      publicClient: this.options.publicClient,
      shredRegistryAddress: this.options.shredRegistryAddress,
      onShredFinalized: async (event) => {
        await this.handleShredFinalized(event);
      },
    });
  }

  async handleShredFinalized(event: ShredFinalizedLog): Promise<RevocationWorkerResult> {
    const evidenceRef = shredFinalizedEvidenceRef(event.authorizationId, event.blockNumber);
    let disclosureIds: readonly Hex[] = [];
    try {
      disclosureIds = await this.options.disclosureIndex.listActiveUnexpiredDisclosureIds(event.authorizationId);
    } catch (error) {
      await this.reportError(error, { authorizationId: event.authorizationId, evidenceRef });
      return {
        authorizationId: event.authorizationId,
        evidenceRef,
        attempted: 0,
        revoked: 0,
        failed: 1,
        transactionHashes: [],
      };
    }

    let revoked = 0;
    let failed = 0;
    const transactionHashes: Hex[] = [];
    for (const disclosureId of disclosureIds) {
      try {
        // SD revocation reason codes (uint8) — §11.5 lines 1099-1106:
        //   0x01 subject_erasure_or_restriction
        //   0x02 pda_shred_finalized
        //   0x03 partner_policy_withdrawal
        //   0x04 verifier_or_circuit_deprecation
        //   0x05 tee_integrity_incident
        //   0x06 claim_under_wrong_pda_or_config
        const writeContract = this.options.walletClient.writeContract as (parameters: {
          address: Address;
          abi: typeof DISCLOSURE_REVOCATION_REGISTRY_ABI;
          functionName: "revokeDisclosure";
          args: readonly [Hex, number, Hex];
        }) => Promise<Hex>;
        const hash = await writeContract({
          address: this.options.revocationRegistryAddress,
          abi: DISCLOSURE_REVOCATION_REGISTRY_ABI,
          functionName: "revokeDisclosure",
          args: [disclosureId, SD_REVOCATION_REASON.PDA_SHRED_FINALIZED, evidenceRef],
        });
        transactionHashes.push(hash);
        revoked += 1;
      } catch (error) {
        failed += 1;
        await this.reportError(error, { authorizationId: event.authorizationId, disclosureId, evidenceRef });
      }
    }

    return {
      authorizationId: event.authorizationId,
      evidenceRef,
      attempted: disclosureIds.length,
      revoked,
      failed,
      transactionHashes,
    };
  }

  private async reportError(error: unknown, context: RevocationWorkerErrorContext): Promise<void> {
    await this.options.onError?.(error, context);
  }
}
