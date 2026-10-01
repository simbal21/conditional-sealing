// CommitAAD SCALE codec per docs/specs/cryptography-spec.md §4.
//
// SCALE struct encoding is positional and fixed-width here: 16 bytes32 fields,
// three u8 fields, one u32 LE field, and two u16 LE fields = 523 bytes.

import { keccak_256 } from "@noble/hashes/sha3";
import { TAG_AAD_V3, type Hex32 } from "../tags.js";
import type { Bytes, Bytes32 } from "../types.js";

export const COMMIT_AAD_BYTES = 523;
export const COMMIT_AAD_DIGEST_PREIMAGE_BYTES = 32 + COMMIT_AAD_BYTES;
export const ACTIVE_COMMIT_VERSION = 0x0302 as const;

export interface CommitAADInput {
  authorizationId: Bytes32;
  pda_root: Bytes32;
  schema_digest: Bytes32;
  partner_id: Bytes32;
  commit_version: number;
  subject_commitment_v3: Bytes32;
  sigma_subject_digest: Bytes32;
  recipients_root: Bytes32;
  p15_attestations_root: Bytes32;
  endpoint_attestation_digest: Bytes32;
  conditional_recipients_policy_digest: Bytes32;
  sdMerkleRoot: Bytes32;
  g3_choice: number;
  phase: number;
  composite_identity_type: number;
  conditional_recipients_stanza_count: number;
  plugin_version_digest: Bytes32;
  g4_authority_ref: Bytes32;
  dsl_version_ref: Bytes32;
  oracle_references_root: Bytes32;
  superseded_commit_ref: Bytes32;
  commit_generation: number;
}

export const CommitAADError = {
  ERR_COMMIT_AAD_MISSING_FIELD: "ERR_COMMIT_AAD_MISSING_FIELD",
  ERR_COMMIT_AAD_BYTES32_LENGTH: "ERR_COMMIT_AAD_BYTES32_LENGTH",
  ERR_COMMIT_AAD_FIELD_RANGE: "ERR_COMMIT_AAD_FIELD_RANGE",
  ERR_COMMIT_AAD_DECODE_LENGTH: "ERR_COMMIT_AAD_DECODE_LENGTH",
} as const;

export type CommitAADErrorCode = keyof typeof CommitAADError;

export class CommitAADValidationError extends Error {
  constructor(
    public readonly code: CommitAADErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "CommitAADValidationError";
  }
}

const BYTES32_FIELDS = [
  "authorizationId",
  "pda_root",
  "schema_digest",
  "partner_id",
  "subject_commitment_v3",
  "sigma_subject_digest",
  "recipients_root",
  "p15_attestations_root",
  "endpoint_attestation_digest",
  "conditional_recipients_policy_digest",
  "sdMerkleRoot",
  "plugin_version_digest",
  "g4_authority_ref",
  "dsl_version_ref",
  "oracle_references_root",
  "superseded_commit_ref",
] as const satisfies readonly (keyof CommitAADInput)[];

function tagToBytes(tag: Hex32): Bytes {
  const hex = tag.slice(2);
  if (hex.length !== 64) throw new Error(`tag must be 32 bytes hex, got ${hex.length} hex chars`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function assertPresent(record: Record<string, unknown>, field: keyof CommitAADInput): void {
  if (!(field in record) || record[field] === undefined || record[field] === null) {
    throw new CommitAADValidationError("ERR_COMMIT_AAD_MISSING_FIELD", `${String(field)} is required`);
  }
}

function assertBytes32(record: Record<string, unknown>, field: (typeof BYTES32_FIELDS)[number]): void {
  assertPresent(record, field);
  const value = record[field];
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    const got = value instanceof Uint8Array ? value.length : typeof value;
    throw new CommitAADValidationError(
      "ERR_COMMIT_AAD_BYTES32_LENGTH",
      `${String(field)} must be 32 bytes, got ${got}`,
    );
  }
}

function assertU8(record: Record<string, unknown>, field: keyof CommitAADInput): number {
  assertPresent(record, field);
  const value = record[field];
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xff) {
    throw new CommitAADValidationError("ERR_COMMIT_AAD_FIELD_RANGE", `${String(field)} must be uint8`);
  }
  return value as number;
}

function assertU16(record: Record<string, unknown>, field: keyof CommitAADInput): number {
  assertPresent(record, field);
  const value = record[field];
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xffff) {
    throw new CommitAADValidationError("ERR_COMMIT_AAD_FIELD_RANGE", `${String(field)} must be uint16`);
  }
  return value as number;
}

function assertU32(record: Record<string, unknown>, field: keyof CommitAADInput): number {
  assertPresent(record, field);
  const value = record[field];
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > 0xffff_ffff) {
    throw new CommitAADValidationError("ERR_COMMIT_AAD_FIELD_RANGE", `${String(field)} must be uint32`);
  }
  return value as number;
}

export function validateCommitAAD(input: CommitAADInput): void {
  const record = input as unknown as Record<string, unknown>;
  for (const field of BYTES32_FIELDS) assertBytes32(record, field);

  const commitVersion = assertU16(record, "commit_version");
  const g3Choice = assertU8(record, "g3_choice");
  const phase = assertU8(record, "phase");
  const compositeIdentityType = assertU8(record, "composite_identity_type");
  assertU32(record, "conditional_recipients_stanza_count");
  assertU16(record, "commit_generation");

  if (commitVersion !== ACTIVE_COMMIT_VERSION) {
    throw new CommitAADValidationError(
      "ERR_COMMIT_AAD_FIELD_RANGE",
      `commit_version must be 0x0302 for this codec, got 0x${commitVersion.toString(16).padStart(4, "0")}`,
    );
  }
  if (g3Choice !== 0 && g3Choice !== 1) {
    throw new CommitAADValidationError("ERR_COMMIT_AAD_FIELD_RANGE", "g3_choice must be 0 or 1");
  }
  if (phase !== 1 && phase !== 2) {
    throw new CommitAADValidationError("ERR_COMMIT_AAD_FIELD_RANGE", "phase must be 1 or 2");
  }
  if (compositeIdentityType !== 0) {
    throw new CommitAADValidationError(
      "ERR_COMMIT_AAD_FIELD_RANGE",
      "composite_identity_type must be 0 for commit_version 0x0302",
    );
  }
}

function writeU16LE(out: Uint8Array, off: number, value: number): number {
  out[off] = value & 0xff;
  out[off + 1] = (value >>> 8) & 0xff;
  return off + 2;
}

function writeU32LE(out: Uint8Array, off: number, value: number): number {
  out[off] = value & 0xff;
  out[off + 1] = (value >>> 8) & 0xff;
  out[off + 2] = (value >>> 16) & 0xff;
  out[off + 3] = (value >>> 24) & 0xff;
  return off + 4;
}

function readU16LE(bytes: Uint8Array, off: number): number {
  return (bytes[off] ?? 0) | ((bytes[off + 1] ?? 0) << 8);
}

function readU32LE(bytes: Uint8Array, off: number): number {
  return (
    (bytes[off] ?? 0) |
    ((bytes[off + 1] ?? 0) << 8) |
    ((bytes[off + 2] ?? 0) << 16) |
    (((bytes[off + 3] ?? 0) << 24) >>> 0)
  ) >>> 0;
}

export function encodeCommitAAD(input: CommitAADInput): Bytes {
  validateCommitAAD(input);
  const out = new Uint8Array(COMMIT_AAD_BYTES);
  let off = 0;
  const writeBytes = (value: Bytes): void => {
    out.set(value, off);
    off += value.length;
  };

  writeBytes(input.authorizationId);
  writeBytes(input.pda_root);
  writeBytes(input.schema_digest);
  writeBytes(input.partner_id);
  off = writeU16LE(out, off, input.commit_version);

  writeBytes(input.subject_commitment_v3);
  writeBytes(input.sigma_subject_digest);
  writeBytes(input.recipients_root);
  writeBytes(input.p15_attestations_root);
  writeBytes(input.endpoint_attestation_digest);
  writeBytes(input.conditional_recipients_policy_digest);
  writeBytes(input.sdMerkleRoot);

  out[off++] = input.g3_choice;
  out[off++] = input.phase;
  out[off++] = input.composite_identity_type;
  off = writeU32LE(out, off, input.conditional_recipients_stanza_count);
  writeBytes(input.plugin_version_digest);
  writeBytes(input.g4_authority_ref);
  writeBytes(input.dsl_version_ref);
  writeBytes(input.oracle_references_root);

  writeBytes(input.superseded_commit_ref);
  off = writeU16LE(out, off, input.commit_generation);

  if (off !== COMMIT_AAD_BYTES) {
    throw new CommitAADValidationError(
      "ERR_COMMIT_AAD_DECODE_LENGTH",
      `CommitAAD encode wrote ${off} bytes, expected ${COMMIT_AAD_BYTES}`,
    );
  }
  return out;
}

export function decodeCommitAAD(bytes: Bytes): CommitAADInput {
  if (bytes.length !== COMMIT_AAD_BYTES) {
    throw new CommitAADValidationError(
      "ERR_COMMIT_AAD_DECODE_LENGTH",
      `CommitAAD must be ${COMMIT_AAD_BYTES} bytes, got ${bytes.length}`,
    );
  }
  let off = 0;
  const take32 = (): Bytes32 => {
    const value = bytes.slice(off, off + 32);
    off += 32;
    return value;
  };

  const out: CommitAADInput = {
    authorizationId: take32(),
    pda_root: take32(),
    schema_digest: take32(),
    partner_id: take32(),
    commit_version: readU16LE(bytes, off),
    subject_commitment_v3: new Uint8Array(32),
    sigma_subject_digest: new Uint8Array(32),
    recipients_root: new Uint8Array(32),
    p15_attestations_root: new Uint8Array(32),
    endpoint_attestation_digest: new Uint8Array(32),
    conditional_recipients_policy_digest: new Uint8Array(32),
    sdMerkleRoot: new Uint8Array(32),
    g3_choice: 0,
    phase: 0,
    composite_identity_type: 0,
    conditional_recipients_stanza_count: 0,
    plugin_version_digest: new Uint8Array(32),
    g4_authority_ref: new Uint8Array(32),
    dsl_version_ref: new Uint8Array(32),
    oracle_references_root: new Uint8Array(32),
    superseded_commit_ref: new Uint8Array(32),
    commit_generation: 0,
  };
  off += 2;

  out.subject_commitment_v3 = take32();
  out.sigma_subject_digest = take32();
  out.recipients_root = take32();
  out.p15_attestations_root = take32();
  out.endpoint_attestation_digest = take32();
  out.conditional_recipients_policy_digest = take32();
  out.sdMerkleRoot = take32();

  out.g3_choice = bytes[off++] ?? 0;
  out.phase = bytes[off++] ?? 0;
  out.composite_identity_type = bytes[off++] ?? 0;
  out.conditional_recipients_stanza_count = readU32LE(bytes, off);
  off += 4;
  out.plugin_version_digest = take32();
  out.g4_authority_ref = take32();
  out.dsl_version_ref = take32();
  out.oracle_references_root = take32();

  out.superseded_commit_ref = take32();
  out.commit_generation = readU16LE(bytes, off);
  off += 2;

  if (off !== COMMIT_AAD_BYTES) {
    throw new CommitAADValidationError(
      "ERR_COMMIT_AAD_DECODE_LENGTH",
      `CommitAAD decode consumed ${off} bytes, expected ${COMMIT_AAD_BYTES}`,
    );
  }
  validateCommitAAD(out);
  return out;
}

export function computeAADDigest(input: CommitAADInput): Bytes32 {
  const encoded = encodeCommitAAD(input);
  const preimage = new Uint8Array(COMMIT_AAD_DIGEST_PREIMAGE_BYTES);
  preimage.set(tagToBytes(TAG_AAD_V3), 0);
  preimage.set(encoded, 32);
  return keccak_256(preimage);
}

export function zeroCommitAADInput(): CommitAADInput {
  const z32 = (): Bytes32 => new Uint8Array(32);
  return {
    authorizationId: z32(),
    pda_root: z32(),
    schema_digest: z32(),
    partner_id: z32(),
    commit_version: ACTIVE_COMMIT_VERSION,
    subject_commitment_v3: z32(),
    sigma_subject_digest: z32(),
    recipients_root: z32(),
    p15_attestations_root: z32(),
    endpoint_attestation_digest: z32(),
    conditional_recipients_policy_digest: z32(),
    sdMerkleRoot: z32(),
    g3_choice: 0,
    phase: 1,
    composite_identity_type: 0,
    conditional_recipients_stanza_count: 0,
    plugin_version_digest: z32(),
    g4_authority_ref: z32(),
    dsl_version_ref: z32(),
    oracle_references_root: z32(),
    superseded_commit_ref: z32(),
    commit_generation: 0,
  };
}
