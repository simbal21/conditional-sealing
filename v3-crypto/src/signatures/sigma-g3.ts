// σ_G3 verifier-only API per docs/specs/cryptography-spec.md §8.
//
// σ values authorize share release. This module returns only a boolean/typed
// failure; it never returns key material, digest bytes, or derivation inputs.

import { bls12_381 as bls12_381 } from "@noble/curves/bls12-381";
import type { Bytes, Bytes32 } from "../types.js";

export const G3_CHOICE = {
  DCIPHER: 0,
  DRAND: 1,
} as const;

export const SigmaG3Error = {
  ERR_SIGMA_G3_MISSING_FIELD: "ERR_SIGMA_G3_MISSING_FIELD",
  ERR_SIGMA_G3_FIELD_LENGTH: "ERR_SIGMA_G3_FIELD_LENGTH",
  ERR_SIGMA_G3_PATH_MISMATCH: "ERR_SIGMA_G3_PATH_MISMATCH",
  ERR_SIGMA_G3_DCIPHER_VERIFY_STUB: "ERR_SIGMA_G3_DCIPHER_VERIFY_STUB",
  ERR_SIGMA_G3_DCIPHER_INVALID: "ERR_SIGMA_G3_DCIPHER_INVALID",
  ERR_SIGMA_G3_DRAND_INVALID: "ERR_SIGMA_G3_DRAND_INVALID",
  ERR_SIGMA_G3_INTERNAL: "ERR_SIGMA_G3_INTERNAL",
} as const;

export type SigmaG3ErrorCode = keyof typeof SigmaG3Error;
export type SigmaG3VerifyResult = { ok: true } | { ok: false; error: SigmaG3ErrorCode };

export interface SigmaG3DcipherInput {
  g3_choice: 0;
  authorizationId: Bytes32;
  h_commit: Bytes32;
  block_hash: Bytes32;
  signature: Bytes;
  committee_pubkey: Bytes;
}

export interface SigmaG3DrandInput {
  g3_choice: 1;
  target_drand_round: bigint;
  signature: Bytes;
  committee_pubkey: Bytes;
}

export type SigmaG3Input = SigmaG3DcipherInput | SigmaG3DrandInput;

const DCIPHER_STUB_MESSAGE = "dcipher verify is S2-3 SDK integration — Phase C stub";
const UINT64_MAX = (1n << 64n) - 1n;

class SigmaG3TypedError extends Error {
  constructor(
    public readonly code: SigmaG3ErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "SigmaG3TypedError";
  }
}

function assertBytes(name: string, value: unknown, length?: number): asserts value is Bytes {
  if (!(value instanceof Uint8Array)) {
    throw new SigmaG3TypedError("ERR_SIGMA_G3_MISSING_FIELD", `${name} must be Uint8Array`);
  }
  if (length !== undefined && value.length !== length) {
    throw new SigmaG3TypedError("ERR_SIGMA_G3_FIELD_LENGTH", `${name} must be ${length} bytes, got ${value.length}`);
  }
}

function assertUint64(name: string, value: unknown): asserts value is bigint {
  if (typeof value !== "bigint" || value < 0n || value > UINT64_MAX) {
    throw new SigmaG3TypedError("ERR_SIGMA_G3_FIELD_LENGTH", `${name} must be uint64 bigint`);
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

function uint64BE(value: bigint): Bytes {
  assertUint64("target_drand_round", value);
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function buildSigmaG3DcipherSigningInput(
  input: Pick<SigmaG3DcipherInput, "authorizationId" | "h_commit" | "block_hash">,
): Bytes {
  assertBytes("authorizationId", input.authorizationId, 32);
  assertBytes("h_commit", input.h_commit, 32);
  assertBytes("block_hash", input.block_hash, 32);
  return concatBytes([input.authorizationId, input.h_commit, input.block_hash]);
}

export function buildDrandRoundMessage(target_drand_round: bigint): Bytes {
  return uint64BE(target_drand_round);
}

function verifyDcipherSignature(): never {
  throw new Error(DCIPHER_STUB_MESSAGE);
}

function verifySigmaG3Dcipher(input: SigmaG3DcipherInput): SigmaG3VerifyResult {
  buildSigmaG3DcipherSigningInput(input);
  assertBytes("signature", input.signature);
  assertBytes("committee_pubkey", input.committee_pubkey);
  try {
    verifyDcipherSignature();
  } catch (error) {
    if (error instanceof Error && error.message === DCIPHER_STUB_MESSAGE) {
      throw new SigmaG3TypedError("ERR_SIGMA_G3_DCIPHER_VERIFY_STUB", DCIPHER_STUB_MESSAGE);
    }
    throw error;
  }
  return { ok: false, error: "ERR_SIGMA_G3_DCIPHER_VERIFY_STUB" };
}

function verifySigmaG3Drand(input: SigmaG3DrandInput): SigmaG3VerifyResult {
  assertUint64("target_drand_round", input.target_drand_round);
  assertBytes("signature", input.signature, 96);
  assertBytes("committee_pubkey", input.committee_pubkey, 48);
  const roundMessage = buildDrandRoundMessage(input.target_drand_round);
  let verified = false;
  try {
    verified = bls12_381.verify(input.signature, roundMessage, input.committee_pubkey);
  } catch {
    throw new SigmaG3TypedError("ERR_SIGMA_G3_DRAND_INVALID", "drand BLS12-381 verification failed");
  }
  return verified ? { ok: true } : { ok: false, error: "ERR_SIGMA_G3_DRAND_INVALID" };
}

export function verifySigmaG3(input: SigmaG3Input): SigmaG3VerifyResult {
  try {
    const choice = (input as { g3_choice?: unknown }).g3_choice;
    if (choice === G3_CHOICE.DRAND) return verifySigmaG3Drand(input as SigmaG3DrandInput);
    if (choice === G3_CHOICE.DCIPHER) return verifySigmaG3Dcipher(input as SigmaG3DcipherInput);
    return { ok: false, error: "ERR_SIGMA_G3_PATH_MISMATCH" };
  } catch (error) {
    if (error instanceof SigmaG3TypedError) return { ok: false, error: error.code };
    return { ok: false, error: "ERR_SIGMA_G3_INTERNAL" };
  }
}
