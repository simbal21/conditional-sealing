import type { Hex32 } from "@cealis/v3-crypto";
import type {
  GateAdapter,
  HealthProbeResult,
  PrepareCommitBindingInput,
  RequestSigmaInput,
  RequestSigmaResult,
  VerifySigmaResult,
} from "../adapters/gate-adapter.js";
import { GateKind, type GateRecipientPubkeyEntry } from "../types/gate-recipient.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import type { RegistryReader } from "../chain/registry-reader.js";
import { G4Phase } from "../g4-shared/pda-type-guard.js";
import { runG4PresignChecklist, type PresignChecklistInput } from "../g4-shared/presign-checklist.js";
import { assertG4Phase1Eligible, type G4Phase1EligibilityInput } from "./eligibility-guard.js";
import {
  type G4Phase1KemDecapProof,
  type G4Phase1KemPubkey,
  verifyG4Phase1KemBindingProof,
} from "./kem-binding-proof.js";
import { verifyG4Phase1Sigma, hex32ToBytes } from "./sigma-verify.js";
import { healthProbe as defaultHealthProbe } from "./health-probe.js";

export interface G4Phase1RequestExtras {
  readonly timestamp: bigint;
  readonly binaryHash: Hex32;
  readonly authorityPubkey: Uint8Array;
  readonly pda: G4Phase1EligibilityInput;
  readonly currentBlock: bigint;
  readonly finalityDepth: bigint;
  readonly challengeWindowClosed: boolean;
  readonly kemProof?: G4Phase1KemDecapProof;
}

export interface G4Phase1PrepareExtras {
  readonly kemPubkey: Uint8Array;
  readonly attestationRef: Hex32;
}

export interface G4Phase1DaemonTransport {
  sign(input: RequestSigmaInput<G4Phase1RequestExtras>): Promise<{
    readonly sigma: Uint8Array;
    readonly kemProof?: G4Phase1KemDecapProof;
    readonly metadata?: Readonly<Record<string, string | number | bigint | Hex32>>;
  }>;
}

export interface G4Phase1AdapterConfig {
  readonly endpoint: URL;
  readonly registryReader: RegistryReader;
  readonly transport?: G4Phase1DaemonTransport;
}

export class G4Phase1Adapter
  implements GateAdapter<Uint8Array, G4Phase1KemPubkey, G4Phase1RequestExtras, G4Phase1PrepareExtras>
{
  public readonly gateKind = GateKind.G4;

  constructor(private readonly config: G4Phase1AdapterConfig) {}

  public async prepareCommitBinding(
    input: PrepareCommitBindingInput<G4Phase1PrepareExtras>,
  ): Promise<G4Phase1KemPubkey> {
    return {
      authorizationId: input.authorizationId,
      kemPubkey: new Uint8Array(input.extras.kemPubkey),
      attestationRef: input.extras.attestationRef,
    };
  }

  public async requestSigma(
    input: RequestSigmaInput<G4Phase1RequestExtras>,
  ): Promise<RequestSigmaResult & { sigma: Uint8Array }> {
    assertG4Phase1Eligible({ ...input.extras.pda, phase: G4Phase.Phase1 });
    await this.runAdmissionChecklist(input);

    const transport = this.config.transport ?? unsupportedNetworkTransport();
    const response = await transport.sign(input);
    return {
      sigma: new Uint8Array(response.sigma),
      gateKind: GateKind.G4,
      metadata: {
        ...(response.metadata ?? {}),
        phase: 1,
        endpoint: this.config.endpoint.origin,
      },
    };
  }

  public async verifySigma(
    input: RequestSigmaInput<G4Phase1RequestExtras> & { sigma: Uint8Array },
  ): Promise<VerifySigmaResult> {
    try {
      assertG4Phase1Eligible({ ...input.extras.pda, phase: G4Phase.Phase1 });
      await this.runAdmissionChecklist(input);
      const entry = await this.fetchG4KemEntry(input);
      verifyG4Phase1KemBindingProof(input.extras.kemProof, entry);
      return verifyG4Phase1Sigma({
        sigma: input.sigma,
        binaryHash: hex32ToBytes(input.extras.binaryHash),
        blockHash: hex32ToBytes(input.blockHash),
        authorizationId: hex32ToBytes(input.authorizationId),
        hCommit: hex32ToBytes(input.hCommit),
        timestamp: input.extras.timestamp,
        authorityPubkey: input.extras.authorityPubkey,
      });
    } catch (error) {
      if (error instanceof CustodyError) {
        return { ok: false, code: error.code, detail: error.message };
      }
      return {
        ok: false,
        code: CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_MISMATCH,
        detail: error instanceof Error ? error.message : "G4 Phase 1 sigma verification failed",
      };
    }
  }

  public healthProbe(): Promise<HealthProbeResult> {
    return defaultHealthProbe(this.config.endpoint);
  }

  private async runAdmissionChecklist(input: RequestSigmaInput<G4Phase1RequestExtras>) {
    const checklistInput: PresignChecklistInput = {
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      authorizationBlock: input.authorizationBlock,
      blockHash: input.blockHash,
      currentBlock: input.extras.currentBlock,
      finalityDepth: input.extras.finalityDepth,
      challengeWindowClosed: input.extras.challengeWindowClosed,
      reader: this.config.registryReader,
    };
    return runG4PresignChecklist(checklistInput);
  }

  private fetchG4KemEntry(
    input: RequestSigmaInput<G4Phase1RequestExtras>,
  ): Promise<GateRecipientPubkeyEntry | null> {
    return this.config.registryReader.getGateRecipientPubkeyAt(
      input.authorizationId,
      GateKind.G4,
      0,
      input.authorizationBlock,
    );
  }
}

function unsupportedNetworkTransport(): G4Phase1DaemonTransport {
  return {
    async sign(): Promise<never> {
      throw new CustodyError(
        CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_MISMATCH,
        "G4 Phase 1 mTLS transport is not configured in this test SDK instance",
      );
    },
  };
}
