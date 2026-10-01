import type { Hex32 } from "../m1-imports.js";
import {
  G3_CHOICE,
  verifySigmaG3,
} from "../m1-imports.js";
import {
  CUSTODY_ERROR_CODES,
  type CustodyErrorCode,
} from "../errors.js";
import { SigmaBuffer } from "../redaction/sigma-buffer.js";
import type { VerifySigmaResult } from "../adapters/gate-adapter.js";

export interface DrandSigmaVerifyInput {
  readonly targetRound: bigint;
  readonly signature: Uint8Array | SigmaBuffer;
  readonly committeePubkey: Uint8Array;
  readonly authorizationId?: Hex32;
  readonly hCommit?: Hex32;
  readonly blockHash?: Hex32;
}

export function verifyDrandSigma(
  input: DrandSigmaVerifyInput,
): VerifySigmaResult {
  const signature =
    input.signature instanceof SigmaBuffer
      ? input.signature.unwrap()
      : new Uint8Array(input.signature);
  try {
    const result = verifySigmaG3({
      g3_choice: G3_CHOICE.DRAND,
      target_drand_round: input.targetRound,
      signature,
      committee_pubkey: input.committeePubkey,
    });
    if (result.ok) return { ok: true };
    return {
      ok: false,
      code: mapDrandSigmaError(result.error),
      detail: result.error,
    };
  } finally {
    signature.fill(0);
  }
}

export function mapDrandSigmaError(error: string): CustodyErrorCode {
  if (error === "ERR_SIGMA_G3_FIELD_LENGTH") {
    return CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_SIG_INVALID;
  }
  if (error === "ERR_SIGMA_G3_PATH_MISMATCH") {
    return CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_CHAIN_MISMATCH;
  }
  return CUSTODY_ERROR_CODES.CUSTODY_ERR_DRAND_SIG_INVALID;
}
