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

export interface DcipherSigmaVerifyInput {
  readonly authorizationId: Uint8Array;
  readonly hCommit: Uint8Array;
  readonly blockHash: Uint8Array;
  readonly signature: Uint8Array | SigmaBuffer;
  readonly committeePubkey: Uint8Array;
  readonly expectedSignatureLength?: number;
}

export function verifyDcipherSigma(
  input: DcipherSigmaVerifyInput,
): VerifySigmaResult {
  const signature =
    input.signature instanceof SigmaBuffer
      ? input.signature.unwrap()
      : new Uint8Array(input.signature);
  try {
    if (
      input.expectedSignatureLength !== undefined &&
      signature.length !== input.expectedSignatureLength
    ) {
      return {
        ok: false,
        code: CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_SIG_INVALID,
        detail: "dcipher signature length does not match pinned variant",
      };
    }
    const result = verifySigmaG3({
      g3_choice: G3_CHOICE.DCIPHER,
      authorizationId: input.authorizationId,
      h_commit: input.hCommit,
      block_hash: input.blockHash,
      signature,
      committee_pubkey: input.committeePubkey,
    });
    if (result.ok) return { ok: true };
    return {
      ok: false,
      code: mapDcipherSigmaError(result.error),
      detail: result.error,
    };
  } finally {
    signature.fill(0);
  }
}

export function hex32ToBytes(value: Hex32): Uint8Array {
  const stripped = value.slice(2);
  const out = new Uint8Array(32);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function mapDcipherSigmaError(error: string): CustodyErrorCode {
  if (error === "ERR_SIGMA_G3_DCIPHER_VERIFY_STUB") {
    return CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED;
  }
  if (error === "ERR_SIGMA_G3_FIELD_LENGTH") {
    return CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_SIG_INVALID;
  }
  return CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_SIG_INVALID;
}
