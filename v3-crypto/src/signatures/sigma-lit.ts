// σ_Lit verifier-only API per docs/specs/cryptography-spec.md §7.
//
// σ values authorize share release. This module returns only a boolean/typed
// failure; it never returns key material, digest bytes, or derivation inputs.

import { bls12_381 as bls12_381 } from "@noble/curves/bls12-381";
import type { Bytes, Bytes32 } from "../types.js";

export const SigmaLitError = {
  ERR_SIGMA_LIT_MISSING_FIELD: "ERR_SIGMA_LIT_MISSING_FIELD",
  ERR_SIGMA_LIT_FIELD_LENGTH: "ERR_SIGMA_LIT_FIELD_LENGTH",
  ERR_SIGMA_LIT_VERIFY_FAIL: "ERR_SIGMA_LIT_VERIFY_FAIL",
  ERR_SIGMA_LIT_INTERNAL: "ERR_SIGMA_LIT_INTERNAL",
} as const;

export type SigmaLitErrorCode = keyof typeof SigmaLitError;
export type SigmaLitVerifyResult = { ok: true } | { ok: false; error: SigmaLitErrorCode };

export interface SigmaLitInput {
  authorizationId: Bytes32;
  h_commit: Bytes32;
  block_hash: Bytes32;
  signature: Bytes;
  pubkey: Bytes;
  lit_acc_binding_digest: Bytes32;
}

class SigmaLitTypedError extends Error {
  constructor(
    public readonly code: SigmaLitErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "SigmaLitTypedError";
  }
}

function assertBytes(name: string, value: unknown, length: number): asserts value is Bytes {
  if (!(value instanceof Uint8Array)) {
    throw new SigmaLitTypedError("ERR_SIGMA_LIT_MISSING_FIELD", `${name} must be Uint8Array`);
  }
  if (value.length !== length) {
    throw new SigmaLitTypedError("ERR_SIGMA_LIT_FIELD_LENGTH", `${name} must be ${length} bytes, got ${value.length}`);
  }
}

function concatBytes(parts: readonly Bytes[]): Bytes {
  const len = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const part of parts) {
    out.set(part, off);
    off += part.length;
  }
  return out;
}

export function buildSigmaLitSigningInput(input: Pick<SigmaLitInput, "authorizationId" | "h_commit" | "block_hash">): Bytes {
  assertBytes("authorizationId", input.authorizationId, 32);
  assertBytes("h_commit", input.h_commit, 32);
  assertBytes("block_hash", input.block_hash, 32);
  return concatBytes([input.authorizationId, input.h_commit, input.block_hash]);
}

export function verifySigmaLit(input: SigmaLitInput): SigmaLitVerifyResult {
  try {
    assertBytes("signature", input.signature, 96);
    assertBytes("pubkey", input.pubkey, 48);
    assertBytes("lit_acc_binding_digest", input.lit_acc_binding_digest, 32);
    // TODO(S2-3 SDK): verify lit_acc_binding_digest against the registered Lit
    // operator set / ACC assignment before admitting this BLS authorization.
    const signingInput = buildSigmaLitSigningInput(input);
    let verified = false;
    try {
      verified = bls12_381.verify(input.signature, signingInput, input.pubkey);
    } catch {
      throw new SigmaLitTypedError("ERR_SIGMA_LIT_VERIFY_FAIL", "BLS12-381 verification failed");
    }
    return verified ? { ok: true } : { ok: false, error: "ERR_SIGMA_LIT_VERIFY_FAIL" };
  } catch (error) {
    if (error instanceof SigmaLitTypedError) return { ok: false, error: error.code };
    return { ok: false, error: "ERR_SIGMA_LIT_INTERNAL" };
  }
}
