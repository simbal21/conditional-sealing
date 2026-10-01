import type { Hex32 } from "@cealis/v3-crypto";
import {
  verifySigmaG4,
  type SigmaG4Phase1Input,
} from "../m1-imports.js";
import { CUSTODY_ERROR_CODES, wrapS2_1Error } from "../errors.js";
import { SigmaBuffer } from "../redaction/sigma-buffer.js";
import type { VerifySigmaResult } from "../adapters/gate-adapter.js";

export interface VerifyG4Phase1SigmaInput {
  readonly sigma: Uint8Array | SigmaBuffer;
  readonly binaryHash: Uint8Array;
  readonly blockHash: Uint8Array;
  readonly authorizationId: Uint8Array;
  readonly hCommit: Uint8Array;
  readonly timestamp: bigint;
  readonly authorityPubkey: Uint8Array;
}

export function verifyG4Phase1Sigma(input: VerifyG4Phase1SigmaInput): VerifySigmaResult {
  const sigma = input.sigma instanceof SigmaBuffer ? input.sigma.unwrap() : new Uint8Array(input.sigma);
  try {
    const m1Input: SigmaG4Phase1Input = {
      phase: 1,
      binary_hash: input.binaryHash,
      block_hash: input.blockHash,
      authorizationId: input.authorizationId,
      h_commit: input.hCommit,
      timestamp: input.timestamp,
      signature: sigma,
      authority_pubkey: input.authorityPubkey,
    };
    const result = verifySigmaG4(m1Input);
    if (result.ok) return { ok: true };
    return {
      ok: false,
      code: wrapS2_1Error(
        result.error,
        CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_PHASE_MISMATCH,
        "G4 Phase 1 sigma verification failed",
      ).code,
      detail: result.error,
    };
  } finally {
    if (input.sigma instanceof SigmaBuffer) input.sigma.zeroize();
    sigma.fill(0);
  }
}

export function hex32ToBytes(hex: Hex32): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (stripped.length !== 64) {
    throw new Error(`hex32ToBytes expected 32-byte hex, got ${stripped.length / 2} bytes`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
