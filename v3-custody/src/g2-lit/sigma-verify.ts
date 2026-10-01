import type { Hex32 } from "@cealis/v3-crypto";
import {
  TAG_LIT_ACC_BINDING_V3,
  verifySigmaLit,
} from "../m1-imports.js";
import {
  CUSTODY_ERROR_CODES,
  wrapS2_1Error,
} from "../errors.js";
import { SigmaBuffer } from "../redaction/sigma-buffer.js";
import type { VerifySigmaResult } from "../adapters/gate-adapter.js";
import {
  hexToBytes32,
  litAccBindingDigest,
} from "./acc-canonicalize.js";

export interface VerifyLitSigmaInput {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
  readonly sigma: SigmaBuffer | Uint8Array;
  readonly assignedTeePubkey: Uint8Array;
  readonly canonicalAccBytes: Uint8Array;
  readonly zeroizeAfterVerify?: boolean;
}

export function computeLitAccBindingDigest(canonicalAccBytes: Uint8Array): Uint8Array {
  return litAccBindingDigest(canonicalAccBytes, TAG_LIT_ACC_BINDING_V3);
}

export function verifyLitSigma(input: VerifyLitSigmaInput): VerifySigmaResult {
  const sigmaBuffer = input.sigma instanceof SigmaBuffer ? input.sigma : new SigmaBuffer(input.sigma);
  try {
    const result = verifySigmaLit({
      authorizationId: hexToBytes32(input.authorizationId),
      h_commit: hexToBytes32(input.hCommit),
      block_hash: hexToBytes32(input.blockHash),
      signature: sigmaBuffer.unwrap(),
      pubkey: input.assignedTeePubkey,
      lit_acc_binding_digest: computeLitAccBindingDigest(input.canonicalAccBytes),
    });
    if (result.ok) return { ok: true };
    const err = wrapS2_1Error(
      result.error,
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_SIG_INVALID,
      "Lit sigma verification failed",
    );
    return { ok: false, code: err.code, detail: result.error };
  } finally {
    if (input.zeroizeAfterVerify !== false) sigmaBuffer.zeroize();
  }
}
