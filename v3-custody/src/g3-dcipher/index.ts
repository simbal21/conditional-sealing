import type {
  GateAdapter,
  PrepareCommitBindingInput,
  RequestSigmaInput,
  RequestSigmaResult,
  VerifySigmaResult,
} from "../adapters/gate-adapter.js";
import { GateKind } from "../types/gate-recipient.js";
import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";
import { loadDcipherSdk } from "./sdk-loader.js";
import {
  fetchDcipherCommitteeAtAuthorization,
  type DcipherCommitteeFetcher,
} from "./committee-fetch.js";
import {
  hex32ToBytes,
  verifyDcipherSigma,
} from "./sigma-verify.js";
import { dcipherHealthProbe } from "./health-probe.js";

export type DcipherKemPubkey = Uint8Array;
export type SigmaG3Dcipher = Uint8Array;

export interface DcipherPrepareExtras {
  readonly commitKemPubkey: Uint8Array;
}

export interface DcipherRequestExtras {
  readonly committeeEpoch?: bigint;
  readonly committeeFetcher?: DcipherCommitteeFetcher;
  readonly expectedSignatureLength?: number;
}

export type DcipherAdapter = GateAdapter<
  SigmaG3Dcipher,
  DcipherKemPubkey,
  DcipherRequestExtras,
  DcipherPrepareExtras
>;

export function createDcipherAdapter(): DcipherAdapter {
  return {
    gateKind: GateKind.Dcipher,

    async prepareCommitBinding(
      input: PrepareCommitBindingInput<DcipherPrepareExtras>,
    ): Promise<DcipherKemPubkey> {
      ensureIncluded();
      void input.authorizationId;
      void input.hCommit;
      void input.commitBlock;
      return new Uint8Array(input.extras.commitKemPubkey);
    },

    async requestSigma(
      input: RequestSigmaInput<DcipherRequestExtras>,
    ): Promise<RequestSigmaResult & { sigma: SigmaG3Dcipher }> {
      ensureIncluded();
      const committee = await fetchDcipherCommitteeAtAuthorization(
        {
          authorizationBlock: input.authorizationBlock,
          expectedEpoch: input.extras.committeeEpoch,
        },
        input.extras.committeeFetcher,
      );
      return {
        sigma: new Uint8Array(0),
        gateKind: GateKind.Dcipher,
        metadata: {
          committeeEpoch: committee.committeeEpoch,
          committeeId: committee.committeeId,
          registryEntryId: committee.registryEntryId,
        },
      };
    },

    async verifySigma(
      input: RequestSigmaInput<DcipherRequestExtras> & { sigma: SigmaG3Dcipher },
    ): Promise<VerifySigmaResult> {
      ensureIncluded();
      const committee = await fetchDcipherCommitteeAtAuthorization(
        {
          authorizationBlock: input.authorizationBlock,
          expectedEpoch: input.extras.committeeEpoch,
        },
        input.extras.committeeFetcher,
      );
      return verifyDcipherSigma({
        authorizationId: hex32ToBytes(input.authorizationId),
        hCommit: hex32ToBytes(input.hCommit),
        blockHash: hex32ToBytes(input.blockHash),
        signature: input.sigma,
        committeePubkey: committee.verificationPubkey,
        expectedSignatureLength: input.extras.expectedSignatureLength,
      });
    },

    healthProbe() {
      return dcipherHealthProbe();
    },
  };
}

function ensureIncluded(): void {
  const load = loadDcipherSdk();
  if (!load.included) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED,
      load.status.status === "deferred"
        ? load.status.reason
        : "dcipher SDK is not included",
    );
  }
}

export * from "./sdk-loader.js";
export * from "./committee-fetch.js";
export * from "./ibe-binding.js";
export * from "./sigma-verify.js";
export * from "./kem-continuity.js";
export * from "./health-probe.js";
