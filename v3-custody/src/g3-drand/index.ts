import type {
  GateAdapter,
  PrepareCommitBindingInput,
  RequestSigmaInput,
  RequestSigmaResult,
  VerifySigmaResult,
} from "../adapters/gate-adapter.js";
import { GateKind } from "../types/gate-recipient.js";
import { SigmaBuffer } from "../redaction/sigma-buffer.js";
import type { Hex32 } from "../m1-imports.js";
import { DrandClient, type DrandClientConfig } from "./client.js";
import { DrandFinalityCache, isDrandRoundFinal } from "./finality.js";
import { verifyDrandSigma } from "./sigma-verify.js";
import { drandHealthProbe } from "./health-probe.js";

export type DrandKemPubkey = Uint8Array;
export type SigmaG3 = Uint8Array;

export interface DrandPrepareExtras {
  readonly committeePubkey?: Uint8Array;
}

export interface DrandRequestExtras {
  readonly targetRound: bigint;
  readonly chainHash: string;
  readonly committeePubkey: Uint8Array;
}

export interface DrandAdapterConfig extends DrandClientConfig {
  readonly finalityCache?: DrandFinalityCache;
}

export type DrandAdapter = GateAdapter<
  SigmaG3,
  DrandKemPubkey,
  DrandRequestExtras,
  DrandPrepareExtras
>;

export function createDrandAdapter(config: DrandAdapterConfig): DrandAdapter {
  const client = new DrandClient(config);
  const finalityCache = config.finalityCache ?? new DrandFinalityCache();

  return {
    gateKind: GateKind.Drand,

    async prepareCommitBinding(
      input: PrepareCommitBindingInput<DrandPrepareExtras>,
    ): Promise<DrandKemPubkey> {
      void input.authorizationId;
      void input.hCommit;
      void input.commitBlock;
      return new Uint8Array(
        input.extras.committeePubkey ?? client.getChainProfile().publicKey,
      );
    },

    async requestSigma(
      input: RequestSigmaInput<DrandRequestExtras>,
    ): Promise<RequestSigmaResult & { sigma: SigmaG3 }> {
      assertRequestMatchesChain(input.extras.chainHash, client.getChainProfile().chainHash);
      const cached = finalityCache.get(input.extras.chainHash, input.extras.targetRound);
      const round =
        cached === null
          ? await client.fetchRound(input.extras.targetRound)
          : {
              round: cached.round,
              signature: cached.signature,
              chainHash: cached.chainHash,
              publicKey: input.extras.committeePubkey,
              endpointId: "cache",
              independentEndpointCount: 1,
            };
      if (!isDrandRoundFinal(round)) {
        return {
          sigma: new Uint8Array(0),
          gateKind: GateKind.Drand,
          metadata: {
            status: "pending",
            targetRound: input.extras.targetRound,
            chainHash: input.extras.chainHash,
          },
        };
      }
      const sigma = new SigmaBuffer(round.signature);
      finalityCache.put({
        chainHash: round.chainHash,
        round: round.round,
        signature: sigma.unwrap(),
      });
      try {
        return {
          sigma: sigma.unwrap(),
          gateKind: GateKind.Drand,
          metadata: {
            targetRound: round.round,
            chainHash: round.chainHash,
            endpointId: round.endpointId,
            endpointCount: round.independentEndpointCount,
          },
        };
      } finally {
        sigma.zeroize();
      }
    },

    async verifySigma(
      input: RequestSigmaInput<DrandRequestExtras> & { sigma: SigmaG3 },
    ): Promise<VerifySigmaResult> {
      const authorizationId: Hex32 = input.authorizationId;
      const hCommit: Hex32 = input.hCommit;
      const blockHash: Hex32 = input.blockHash;
      return verifyDrandSigma({
        targetRound: input.extras.targetRound,
        signature: input.sigma,
        committeePubkey: input.extras.committeePubkey,
        authorizationId,
        hCommit,
        blockHash,
      });
    },

    healthProbe() {
      return drandHealthProbe(client);
    },
  };
}

function assertRequestMatchesChain(actual: string, expected: string): void {
  if (actual !== expected) {
    throw new Error("drand request chain hash does not match adapter profile");
  }
}

export * from "./client.js";
export * from "./round-target.js";
export * from "./tlock-decap.js";
export * from "./sigma-verify.js";
export * from "./finality.js";
export * from "./health-probe.js";
