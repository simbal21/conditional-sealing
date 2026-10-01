import { SdError } from "../errors/sd-error.js";
import { SdErrorCode } from "../errors/codes.js";
import type { SdBoundary, EscrowResult, SdFailure, SdOutcome, SdSuccess } from "./types.js";
import type { SdFailureStage } from "../types/failure-modes.js";

export class DefaultSdBoundary implements SdBoundary {
  async executeIfEscrowOk<E, F, S>(
    escrowResult: EscrowResult<E, F>,
    sdFn: (escrowValue: E) => Promise<SdSuccess<S> | SdFailure>,
  ): Promise<{ readonly escrow: EscrowResult<E, F>; readonly sd: SdOutcome<S> }> {
    if (escrowResult.kind === "err") {
      return { escrow: escrowResult, sd: { kind: "sd_skipped", reason: "escrow_failed" } };
    }
    try {
      const sd = await sdFn(escrowResult.value);
      return { escrow: escrowResult, sd };
    } catch (cause) {
      if (cause instanceof SdError) {
        return {
          escrow: escrowResult,
          sd: {
            kind: "sd_err",
            stage: (cause.stage ?? "response_assembly") as SdFailureStage,
            code: cause.code,
            partial: false,
          },
        };
      }
      return {
        escrow: escrowResult,
        sd: {
          kind: "sd_err",
          stage: "response_assembly",
          code: SdErrorCode.ONBOARDING_PARTIAL_FAILURE,
          partial: false,
        },
      };
    }
  }
}

export const SdBoundaryImpl = new DefaultSdBoundary();
