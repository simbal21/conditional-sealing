import type { Hex32 } from "@cealis/v3-crypto";
import type {
  GateAdapter,
  HealthProbeResult,
  PrepareCommitBindingInput,
  RequestSigmaInput,
  RequestSigmaResult,
  VerifySigmaResult,
} from "../adapters/gate-adapter.js";
import { GateKind } from "../types/gate-recipient.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import { assertG4Phase2Eligible } from "./eligibility-guard.js";
import { G4_PHASE2_DEFERRED_REASON, IS_DEFERRED } from "./deferred-marker.js";
import { healthProbe as phase2HealthProbe } from "./health-probe.js";
import { verifyG4Phase2DcapQuote } from "./dcap-verify.js";
import type { G4Phase2QuoteStub, G4Phase2VerificationContext } from "./dcap-quote-types.js";

export interface G4Phase2KemPubkey {
  readonly authorizationId: Hex32;
  readonly kemPubkey: Uint8Array;
  readonly attestationRef: Hex32;
}

export interface G4Phase2RequestExtras extends Pick<G4Phase2VerificationContext, "expectedMeasurement" | "expectedVerifierRef"> {
  readonly pda: Parameters<typeof assertG4Phase2Eligible>[0];
  readonly quote?: G4Phase2QuoteStub;
}

export interface G4Phase2PrepareExtras {
  readonly kemPubkey: Uint8Array;
  readonly attestationRef: Hex32;
}

export class G4Phase2Adapter
  implements GateAdapter<Uint8Array, G4Phase2KemPubkey, G4Phase2RequestExtras, G4Phase2PrepareExtras>
{
  public readonly gateKind = GateKind.G4;
  public readonly isDeferred = IS_DEFERRED;

  public async prepareCommitBinding(
    input: PrepareCommitBindingInput<G4Phase2PrepareExtras>,
  ): Promise<G4Phase2KemPubkey> {
    return {
      authorizationId: input.authorizationId,
      kemPubkey: new Uint8Array(input.extras.kemPubkey),
      attestationRef: input.extras.attestationRef,
    };
  }

  public async requestSigma(
    _input: RequestSigmaInput<G4Phase2RequestExtras>,
  ): Promise<RequestSigmaResult & { sigma: Uint8Array }> {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_DCAP_INVALID,
      G4_PHASE2_DEFERRED_REASON,
    );
  }

  public async verifySigma(
    input: RequestSigmaInput<G4Phase2RequestExtras> & { sigma: Uint8Array },
  ): Promise<VerifySigmaResult> {
    try {
      assertG4Phase2Eligible(input.extras.pda);
      if (input.extras.quote === undefined) {
        return { ok: false, code: CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_DCAP_INVALID, detail: "DCAP quote missing" };
      }
      const result = verifyG4Phase2DcapQuote(input.extras.quote, {
        authorizationId: input.authorizationId,
        hCommit: input.hCommit,
        blockHash: input.blockHash,
        expectedMeasurement: input.extras.expectedMeasurement,
        expectedVerifierRef: input.extras.expectedVerifierRef,
      });
      return result.ok
        ? { ok: true }
        : { ok: false, code: result.code ?? CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_DCAP_INVALID };
    } catch (error) {
      if (error instanceof CustodyError) return { ok: false, code: error.code, detail: error.message };
      return { ok: false, code: CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_DCAP_INVALID };
    } finally {
      input.sigma.fill(0);
    }
  }

  public healthProbe(): Promise<HealthProbeResult> {
    return phase2HealthProbe();
  }
}
