// σ_G4 verifier-only API per docs/specs/cryptography-spec.md §9.
//
// σ values authorize share release. This module returns only a boolean/typed
// failure; it never returns key material, digest bytes, or derivation inputs.

import { ed25519 } from "@noble/curves/ed25519";
import { TAG_G4_ATTESTATION_V3, type Hex32 } from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";

export const G4_PHASE = {
  PHASE_1: 1,
  PHASE_2: 2,
} as const;

export const G4_PHASE1_SIGNING_INPUT_BYTES = 168;

export const SigmaG4Error = {
  ERR_SIGMA_G4_MISSING_FIELD: "ERR_SIGMA_G4_MISSING_FIELD",
  ERR_SIGMA_G4_FIELD_LENGTH: "ERR_SIGMA_G4_FIELD_LENGTH",
  ERR_SIGMA_G4_PHASE_MISMATCH: "ERR_SIGMA_G4_PHASE_MISMATCH",
  ERR_SIGMA_G4_PHASE1_INVALID: "ERR_SIGMA_G4_PHASE1_INVALID",
  ERR_SIGMA_G4_PHASE2_VERIFY_STUB: "ERR_SIGMA_G4_PHASE2_VERIFY_STUB",
  ERR_SIGMA_G4_PHASE2_DCAP_INVALID: "ERR_SIGMA_G4_PHASE2_DCAP_INVALID",
  ERR_SIGMA_G4_INTERNAL: "ERR_SIGMA_G4_INTERNAL",
} as const;

export type SigmaG4ErrorCode = keyof typeof SigmaG4Error;
export type SigmaG4VerifyResult = { ok: true } | { ok: false; error: SigmaG4ErrorCode };

export interface SigmaG4Phase1Input {
  phase: 1;
  binary_hash: Bytes32;
  block_hash: Bytes32;
  authorizationId: Bytes32;
  h_commit: Bytes32;
  timestamp: bigint;
  signature: Bytes;
  authority_pubkey: Bytes;
}

export interface SigmaG4Phase2Input {
  phase: 2;
  dcap_quote: Bytes;
}

export type SigmaG4Input = SigmaG4Phase1Input | SigmaG4Phase2Input;

const PHASE2_STUB_MESSAGE = "Phase 2 DCAP verify is S2-3 territory — Phase C stub";
const UINT64_MAX = (1n << 64n) - 1n;

class SigmaG4TypedError extends Error {
  constructor(
    public readonly code: SigmaG4ErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "SigmaG4TypedError";
  }
}

function assertBytes(name: string, value: unknown, length?: number): asserts value is Bytes {
  if (!(value instanceof Uint8Array)) {
    throw new SigmaG4TypedError("ERR_SIGMA_G4_MISSING_FIELD", `${name} must be Uint8Array`);
  }
  if (length !== undefined && value.length !== length) {
    throw new SigmaG4TypedError("ERR_SIGMA_G4_FIELD_LENGTH", `${name} must be ${length} bytes, got ${value.length}`);
  }
}

function assertUint64(name: string, value: unknown): asserts value is bigint {
  if (typeof value !== "bigint" || value < 0n || value > UINT64_MAX) {
    throw new SigmaG4TypedError("ERR_SIGMA_G4_FIELD_LENGTH", `${name} must be uint64 bigint`);
  }
}

function tagToBytes(tag: Hex32): Bytes {
  const hex = tag.slice(2);
  if (hex.length !== 64) throw new Error("tag must be 32-byte hex");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function uint64BE(value: bigint): Bytes {
  assertUint64("timestamp", value);
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
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

export function buildSigmaG4Phase1SigningInput(
  input: Pick<SigmaG4Phase1Input, "binary_hash" | "block_hash" | "authorizationId" | "h_commit" | "timestamp">,
): Bytes {
  assertBytes("binary_hash", input.binary_hash, 32);
  assertBytes("block_hash", input.block_hash, 32);
  assertBytes("authorizationId", input.authorizationId, 32);
  assertBytes("h_commit", input.h_commit, 32);
  const signingInput = concatBytes([
    tagToBytes(TAG_G4_ATTESTATION_V3),
    input.binary_hash,
    input.block_hash,
    input.authorizationId,
    input.h_commit,
    uint64BE(input.timestamp),
  ]);
  if (signingInput.length !== G4_PHASE1_SIGNING_INPUT_BYTES) {
    throw new SigmaG4TypedError("ERR_SIGMA_G4_FIELD_LENGTH", "Phase 1 signing input must be 168 bytes");
  }
  return signingInput;
}

function verifySigmaG4Phase1(input: SigmaG4Phase1Input): SigmaG4VerifyResult {
  assertBytes("signature", input.signature, 64);
  assertBytes("authority_pubkey", input.authority_pubkey, 32);
  const signingInput = buildSigmaG4Phase1SigningInput(input);
  let verified = false;
  try {
    verified = ed25519.verify(input.signature, signingInput, input.authority_pubkey);
  } catch {
    throw new SigmaG4TypedError("ERR_SIGMA_G4_PHASE1_INVALID", "Ed25519 verification failed");
  }
  return verified ? { ok: true } : { ok: false, error: "ERR_SIGMA_G4_PHASE1_INVALID" };
}

function verifyPhase2Dcap(): never {
  throw new Error(PHASE2_STUB_MESSAGE);
}

function verifySigmaG4Phase2(input: SigmaG4Phase2Input): SigmaG4VerifyResult {
  assertBytes("dcap_quote", input.dcap_quote);
  try {
    verifyPhase2Dcap();
  } catch (error) {
    if (error instanceof Error && error.message === PHASE2_STUB_MESSAGE) {
      throw new SigmaG4TypedError("ERR_SIGMA_G4_PHASE2_VERIFY_STUB", PHASE2_STUB_MESSAGE);
    }
    throw error;
  }
  return { ok: false, error: "ERR_SIGMA_G4_PHASE2_VERIFY_STUB" };
}

export function verifySigmaG4(input: SigmaG4Input): SigmaG4VerifyResult {
  try {
    const phase = (input as { phase?: unknown }).phase;
    if (phase === G4_PHASE.PHASE_1) return verifySigmaG4Phase1(input as SigmaG4Phase1Input);
    if (phase === G4_PHASE.PHASE_2) return verifySigmaG4Phase2(input as SigmaG4Phase2Input);
    return { ok: false, error: "ERR_SIGMA_G4_PHASE_MISMATCH" };
  } catch (error) {
    if (error instanceof SigmaG4TypedError) return { ok: false, error: error.code };
    return { ok: false, error: "ERR_SIGMA_G4_INTERNAL" };
  }
}
