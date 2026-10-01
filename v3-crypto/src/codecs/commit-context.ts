// commit_context_digest_N and attestation_context_digest_N builders per
// docs/specs/cryptography-spec.md §3.4 + h-commit-acyclic-schedule.md.

import { keccak_256 } from "@noble/hashes/sha3";
import {
  TAG_AAD_V3,
  TAG_ATTESTATION_CONTEXT_V3,
  TAG_COMMIT_CONTEXT_V3,
  TAG_COMMIT_V3,
  type Hex32,
} from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";
import {
  ACTIVE_COMMIT_VERSION,
  computeAADDigest,
  type CommitAADInput,
} from "./commit-aad.js";

export const COMMIT_CONTEXT_PREIMAGE_BYTES = 340;
export const ZERO32: Bytes32 = new Uint8Array(32);

export interface CommitContextInput {
  authorizationId: Bytes32;
  pda_root: Bytes32;
  schema_digest: Bytes32;
  aad_digest: Bytes32;
  composite_identity_digest: Bytes32;
  endpoint_attestation_digest: Bytes32;
  retention_window: bigint;
  shred_authority_id: Bytes32;
  recipients_root: Bytes32;
  reveal_challenge_window: number;
  shred_challenge_window: number;
  g3_choice: number;
  phase: number;
  commit_version: number;
}

export const CommitContextError = {
  ERR_COMMIT_CONTEXT_MISSING_FIELD: "ERR_COMMIT_CONTEXT_MISSING_FIELD",
  ERR_COMMIT_CONTEXT_BYTES32_LENGTH: "ERR_COMMIT_CONTEXT_BYTES32_LENGTH",
  ERR_COMMIT_CONTEXT_FIELD_RANGE: "ERR_COMMIT_CONTEXT_FIELD_RANGE",
  ERR_ATTESTATION_AAD_ENDPOINT_NOT_ZERO: "ERR_ATTESTATION_AAD_ENDPOINT_NOT_ZERO",
} as const;

export type CommitContextErrorCode = keyof typeof CommitContextError;

export class CommitContextValidationError extends Error {
  constructor(
    public readonly code: CommitContextErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "CommitContextValidationError";
  }
}

const BYTES32_FIELDS = [
  "authorizationId",
  "pda_root",
  "schema_digest",
  "aad_digest",
  "composite_identity_digest",
  "endpoint_attestation_digest",
  "shred_authority_id",
  "recipients_root",
] as const satisfies readonly (keyof CommitContextInput)[];

function tagToBytes(tag: Hex32): Bytes {
  const hex = tag.slice(2);
  if (hex.length !== 64) throw new Error(`tag must be 32 bytes hex, got ${hex.length} hex chars`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function assertPresent(record: Record<string, unknown>, field: keyof CommitContextInput): void {
  if (!(field in record) || record[field] === undefined || record[field] === null) {
    throw new CommitContextValidationError("ERR_COMMIT_CONTEXT_MISSING_FIELD", `${String(field)} is required`);
  }
}

function assertBytes32(record: Record<string, unknown>, field: (typeof BYTES32_FIELDS)[number]): void {
  assertPresent(record, field);
  const value = record[field];
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    const got = value instanceof Uint8Array ? value.length : typeof value;
    throw new CommitContextValidationError(
      "ERR_COMMIT_CONTEXT_BYTES32_LENGTH",
      `${String(field)} must be 32 bytes, got ${got}`,
    );
  }
}

function assertU8(record: Record<string, unknown>, field: keyof CommitContextInput): number {
  assertPresent(record, field);
  const value = record[field];
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xff) {
    throw new CommitContextValidationError("ERR_COMMIT_CONTEXT_FIELD_RANGE", `${String(field)} must be uint8`);
  }
  return value as number;
}

function assertU16(record: Record<string, unknown>, field: keyof CommitContextInput): number {
  assertPresent(record, field);
  const value = record[field];
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xffff) {
    throw new CommitContextValidationError("ERR_COMMIT_CONTEXT_FIELD_RANGE", `${String(field)} must be uint16`);
  }
  return value as number;
}

function assertU32(record: Record<string, unknown>, field: keyof CommitContextInput): number {
  assertPresent(record, field);
  const value = record[field];
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xffff_ffff) {
    throw new CommitContextValidationError("ERR_COMMIT_CONTEXT_FIELD_RANGE", `${String(field)} must be uint32`);
  }
  return value as number;
}

function assertU64(record: Record<string, unknown>, field: keyof CommitContextInput): bigint {
  assertPresent(record, field);
  const value = record[field];
  if (typeof value !== "bigint" || value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new CommitContextValidationError("ERR_COMMIT_CONTEXT_FIELD_RANGE", `${String(field)} must be uint64`);
  }
  return value;
}

function u64BE(value: bigint): Bytes {
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function u32BE(value: number): Bytes {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function u16BE(value: number): Bytes {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function isZero32(value: Bytes32): boolean {
  if (value.length !== 32) return false;
  let any = 0;
  for (const byte of value) any |= byte;
  return any === 0;
}

export function validateCommitContextInput(input: CommitContextInput): void {
  const record = input as unknown as Record<string, unknown>;
  for (const field of BYTES32_FIELDS) assertBytes32(record, field);

  assertU64(record, "retention_window");
  assertU32(record, "reveal_challenge_window");
  assertU32(record, "shred_challenge_window");
  const g3Choice = assertU8(record, "g3_choice");
  const phase = assertU8(record, "phase");
  const commitVersion = assertU16(record, "commit_version");

  if (g3Choice !== 0 && g3Choice !== 1) {
    throw new CommitContextValidationError("ERR_COMMIT_CONTEXT_FIELD_RANGE", "g3_choice must be 0 or 1");
  }
  if (phase !== 1 && phase !== 2) {
    throw new CommitContextValidationError("ERR_COMMIT_CONTEXT_FIELD_RANGE", "phase must be 1 or 2");
  }
  if (commitVersion !== ACTIVE_COMMIT_VERSION) {
    throw new CommitContextValidationError(
      "ERR_COMMIT_CONTEXT_FIELD_RANGE",
      `commit_version must be 0x0302, got 0x${commitVersion.toString(16).padStart(4, "0")}`,
    );
  }
}

export function buildCommitContextPreimage(input: CommitContextInput): Bytes {
  validateCommitContextInput(input);
  const out = new Uint8Array(COMMIT_CONTEXT_PREIMAGE_BYTES);
  let off = 0;
  const writeBytes = (value: Bytes): void => {
    out.set(value, off);
    off += value.length;
  };

  writeBytes(tagToBytes(TAG_COMMIT_CONTEXT_V3));
  writeBytes(input.authorizationId);
  writeBytes(input.pda_root);
  writeBytes(input.schema_digest);
  writeBytes(ZERO32);
  writeBytes(input.aad_digest);
  writeBytes(input.composite_identity_digest);
  writeBytes(input.endpoint_attestation_digest);
  writeBytes(u64BE(input.retention_window));
  writeBytes(input.shred_authority_id);
  writeBytes(input.recipients_root);
  writeBytes(u32BE(input.reveal_challenge_window));
  writeBytes(u32BE(input.shred_challenge_window));
  out[off++] = input.g3_choice;
  out[off++] = input.phase;
  writeBytes(u16BE(input.commit_version));

  if (off !== COMMIT_CONTEXT_PREIMAGE_BYTES) {
    throw new CommitContextValidationError(
      "ERR_COMMIT_CONTEXT_FIELD_RANGE",
      `commit_context preimage wrote ${off} bytes, expected ${COMMIT_CONTEXT_PREIMAGE_BYTES}`,
    );
  }
  return out;
}

export function computeCommitContextDigest(input: CommitContextInput): Bytes32 {
  return keccak_256(buildCommitContextPreimage(input));
}

// Same byte count as commit_context preimage. Mirror-export from sigma-subject.ts
// avoided to prevent a typecheck ambiguity (signatures/sigma-subject.ts already
// exports this constant via the package barrel). Functions below use the local
// numeric literal so the public-facing constant stays single-sourced from
// sigma-subject.ts.
const H_COMMIT_PREIMAGE_BYTES_LOCAL = 340;

/**
 * Builds the final `h_commit_N` 340-byte preimage per S2-1 §3.4.1 lines 695-720.
 *
 * Layout is identical to `commit_context` EXCEPT:
 *  - Prefix is `TAG_COMMIT_V3` (not `TAG_COMMIT_CONTEXT_V3`).
 *  - Slot 4 carries `ciphertext_digest_N = keccak256(age_envelope_N)`
 *    (commit_context places ZERO32 here because envelope bytes do not exist
 *    yet at the pre-finalization KDF/AAD scheduling step).
 *
 * Final `h_commit_N` is the value anchored on-chain, emitted in
 * `RevealAuthorized`, signed by σ gates, keyed in shred/reveal/superseded
 * registries, and used in supersession pointers. NEVER use the
 * `commit_context_digest` form in any chain-facing context.
 *
 * Security-audit-2026-05-14 TS-CRYPTO-F-05 — closes the re-key-ceremony
 * preimage drift where the legacy implementation used
 * `keccak256(JSON.stringify(commit_AAD) ‖ envelope_hash)`. Callers MUST use
 * this helper for any final-h_commit computation; the JSON form will produce
 * an h_commit that fails the on-chain anchor lookup at reveal time.
 */
export function buildHCommitPreimage(
  input: CommitContextInput,
  ciphertextDigest: Bytes32,
): Bytes {
  validateCommitContextInput(input);
  if (ciphertextDigest.length !== 32) {
    throw new CommitContextValidationError(
      "ERR_COMMIT_CONTEXT_BYTES32_LENGTH",
      `ciphertextDigest must be 32 bytes, got ${ciphertextDigest.length}`,
    );
  }
  const out = new Uint8Array(H_COMMIT_PREIMAGE_BYTES_LOCAL);
  let off = 0;
  const writeBytes = (value: Bytes): void => {
    out.set(value, off);
    off += value.length;
  };

  writeBytes(tagToBytes(TAG_COMMIT_V3));
  writeBytes(input.authorizationId);
  writeBytes(input.pda_root);
  writeBytes(input.schema_digest);
  writeBytes(ciphertextDigest);
  writeBytes(input.aad_digest);
  writeBytes(input.composite_identity_digest);
  writeBytes(input.endpoint_attestation_digest);
  writeBytes(u64BE(input.retention_window));
  writeBytes(input.shred_authority_id);
  writeBytes(input.recipients_root);
  writeBytes(u32BE(input.reveal_challenge_window));
  writeBytes(u32BE(input.shred_challenge_window));
  out[off++] = input.g3_choice;
  out[off++] = input.phase;
  writeBytes(u16BE(input.commit_version));

  if (off !== H_COMMIT_PREIMAGE_BYTES_LOCAL) {
    throw new CommitContextValidationError(
      "ERR_COMMIT_CONTEXT_FIELD_RANGE",
      `h_commit preimage wrote ${off} bytes, expected ${H_COMMIT_PREIMAGE_BYTES_LOCAL}`,
    );
  }
  return out;
}

/**
 * Computes final `h_commit_N = keccak256(buildHCommitPreimage(input, ciphertextDigest))`.
 * See `buildHCommitPreimage` for spec reference and security context.
 */
export function computeHCommit(
  input: CommitContextInput,
  ciphertextDigest: Bytes32,
): Bytes32 {
  return keccak_256(buildHCommitPreimage(input, ciphertextDigest));
}

export function computeAttestationContextDigest(commit_AAD_attestation_N: CommitAADInput): Bytes32 {
  if (!isZero32(commit_AAD_attestation_N.endpoint_attestation_digest)) {
    throw new CommitContextValidationError(
      "ERR_ATTESTATION_AAD_ENDPOINT_NOT_ZERO",
      "commit_AAD_attestation_N.endpoint_attestation_digest must be ZERO32",
    );
  }
  const aadDigest = computeAADDigest(commit_AAD_attestation_N);
  const preimage = new Uint8Array(64);
  preimage.set(tagToBytes(TAG_ATTESTATION_CONTEXT_V3), 0);
  preimage.set(aadDigest, 32);
  return keccak_256(preimage);
}

export function zeroCommitContextInput(): CommitContextInput {
  const z32 = (): Bytes32 => new Uint8Array(32);
  return {
    authorizationId: z32(),
    pda_root: z32(),
    schema_digest: z32(),
    aad_digest: keccak_256(new Uint8Array([...(tagToBytes(TAG_AAD_V3)), ...new Uint8Array(523)])),
    composite_identity_digest: z32(),
    endpoint_attestation_digest: z32(),
    retention_window: 0n,
    shred_authority_id: z32(),
    recipients_root: z32(),
    reveal_challenge_window: 0,
    shred_challenge_window: 0,
    g3_choice: 0,
    phase: 1,
    commit_version: ACTIVE_COMMIT_VERSION,
  };
}
