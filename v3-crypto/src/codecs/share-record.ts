// ShareRecord SCALE codec per docs/specs/cryptography-spec.md §6.3.2.
//
// Typed share record consumed by §6.3 Shamir.combine. The wrapped plaintext
// in §6.2 is the 32-byte `value`; the metadata (domain, role, logical_index,
// x) is bound in the §6.2 wrap AAD and reconstructed from stanza position +
// committed conditional_recipients_policy at reveal.
//
// SCALE encoding (positional struct, no length prefix for fixed-size fields):
//   share_domain:  1 byte   (u8)
//   share_role:    1 byte   (u8)
//   logical_index: 4 bytes  (u32 little-endian, SCALE-native)
//   x:             1 byte   (u8, non-zero)
//   value:         32 bytes (fixed-size [u8;32], no length prefix)
//
// Total: 39 bytes.
//
// Pulled to Phase A so Phase D (Shamir combine) and Phase E (per-stanza wrap
// AAD binding) consume the same codec — single source of truth for typed
// share metadata.

import type { Bytes, Bytes32 } from "../types.js";

export const SHARE_DOMAIN_TOP_LEVEL = 0x01 as const;
export const SHARE_DOMAIN_RECIPIENT_BRANCH = 0x02 as const;

export const SHARE_ROLE_LIT = 0x01 as const;
export const SHARE_ROLE_G3 = 0x02 as const;
export const SHARE_ROLE_G4 = 0x03 as const;
export const SHARE_ROLE_RECIPIENT_AGGREGATE = 0x04 as const;
export const SHARE_ROLE_CONDITIONAL_RECIPIENT = 0x05 as const;

export type ShareDomain = typeof SHARE_DOMAIN_TOP_LEVEL | typeof SHARE_DOMAIN_RECIPIENT_BRANCH;
export type ShareRole =
  | typeof SHARE_ROLE_LIT
  | typeof SHARE_ROLE_G3
  | typeof SHARE_ROLE_G4
  | typeof SHARE_ROLE_RECIPIENT_AGGREGATE
  | typeof SHARE_ROLE_CONDITIONAL_RECIPIENT;

/**
 * ShareRecord per §6.3.2.
 *
 * Domain/role consistency rules (validated by `validateShareRecord`):
 * - TOP_LEVEL admits {LIT, G3, G4, RECIPIENT_AGGREGATE}.
 * - RECIPIENT_BRANCH admits {CONDITIONAL_RECIPIENT}.
 * - x = 0 is reserved-invalid in every domain (§6.3.2 line 1914).
 */
export interface ShareRecord {
  share_domain: ShareDomain;
  share_role: ShareRole;
  /** Top-level index for TOP_LEVEL (0=Lit, 1=G3, 2=G4, 3=recipient_branch);
   *  zero-based recipient_index for RECIPIENT_BRANCH. */
  logical_index: number;
  /** Non-zero GF(2^8) coordinate. */
  x: number;
  /** Byte-sliced Shamir value, exactly 32 bytes. */
  value: Bytes32;
}

export const SHARE_RECORD_BYTES = 1 + 1 + 4 + 1 + 32; // 39

/** Validation error codes per §6.3.2 + §16. */
export const ShareRecordError = {
  ERR_SHAMIR_SHARE_INDEX_INVALID: "ERR_SHAMIR_SHARE_INDEX_INVALID",
  ERR_SHARE_RECORD_DOMAIN_ROLE_MISMATCH: "ERR_SHARE_RECORD_DOMAIN_ROLE_MISMATCH",
  ERR_SHARE_RECORD_VALUE_LENGTH: "ERR_SHARE_RECORD_VALUE_LENGTH",
  ERR_SHARE_RECORD_FIELD_RANGE: "ERR_SHARE_RECORD_FIELD_RANGE",
  ERR_SHARE_RECORD_DECODE_LENGTH: "ERR_SHARE_RECORD_DECODE_LENGTH",
} as const;

export class ShareRecordValidationError extends Error {
  constructor(
    public readonly code: keyof typeof ShareRecordError,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "ShareRecordValidationError";
  }
}

function isU8(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= 0xff;
}

function isU32(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff;
}

/**
 * Validate a ShareRecord against §6.3.2 invariants:
 * - x !== 0 (reserved-invalid)
 * - share_domain ∈ {0x01, 0x02}
 * - share_role ∈ {0x01..0x05}
 * - domain/role consistency: TOP_LEVEL ⊃ {LIT,G3,G4,RECIPIENT_AGGREGATE}; RECIPIENT_BRANCH ⊃ {CONDITIONAL_RECIPIENT}
 * - value.length === 32
 * - All numeric fields fit their declared widths
 */
export function validateShareRecord(record: ShareRecord): void {
  if (!isU8(record.share_domain) || (record.share_domain !== 0x01 && record.share_domain !== 0x02)) {
    throw new ShareRecordValidationError(
      "ERR_SHARE_RECORD_FIELD_RANGE",
      `share_domain must be 0x01 or 0x02, got ${record.share_domain}`,
    );
  }
  if (
    !isU8(record.share_role) ||
    record.share_role < 0x01 ||
    record.share_role > 0x05
  ) {
    throw new ShareRecordValidationError(
      "ERR_SHARE_RECORD_FIELD_RANGE",
      `share_role must be 0x01..0x05, got ${record.share_role}`,
    );
  }
  if (!isU32(record.logical_index)) {
    throw new ShareRecordValidationError(
      "ERR_SHARE_RECORD_FIELD_RANGE",
      `logical_index must be uint32, got ${record.logical_index}`,
    );
  }
  if (!isU8(record.x)) {
    throw new ShareRecordValidationError(
      "ERR_SHARE_RECORD_FIELD_RANGE",
      `x must be uint8, got ${record.x}`,
    );
  }
  if (record.x === 0) {
    throw new ShareRecordValidationError(
      "ERR_SHAMIR_SHARE_INDEX_INVALID",
      "x = 0 is reserved-invalid (§6.3.2)",
    );
  }
  if (record.value.length !== 32) {
    throw new ShareRecordValidationError(
      "ERR_SHARE_RECORD_VALUE_LENGTH",
      `value must be 32 bytes, got ${record.value.length}`,
    );
  }

  // Domain/role consistency
  const topLevelRoles = new Set<number>([
    SHARE_ROLE_LIT,
    SHARE_ROLE_G3,
    SHARE_ROLE_G4,
    SHARE_ROLE_RECIPIENT_AGGREGATE,
  ]);
  const recipientBranchRoles = new Set<number>([SHARE_ROLE_CONDITIONAL_RECIPIENT]);
  if (record.share_domain === SHARE_DOMAIN_TOP_LEVEL && !topLevelRoles.has(record.share_role)) {
    throw new ShareRecordValidationError(
      "ERR_SHARE_RECORD_DOMAIN_ROLE_MISMATCH",
      `TOP_LEVEL admits roles {LIT, G3, G4, RECIPIENT_AGGREGATE}; got role ${record.share_role}`,
    );
  }
  if (record.share_domain === SHARE_DOMAIN_RECIPIENT_BRANCH && !recipientBranchRoles.has(record.share_role)) {
    throw new ShareRecordValidationError(
      "ERR_SHARE_RECORD_DOMAIN_ROLE_MISMATCH",
      `RECIPIENT_BRANCH admits role {CONDITIONAL_RECIPIENT}; got role ${record.share_role}`,
    );
  }
}

/**
 * Encode a ShareRecord to its 39-byte SCALE serialization.
 * Validates first; throws on invariant breach.
 */
export function encodeShareRecord(record: ShareRecord): Bytes {
  validateShareRecord(record);
  const out = new Uint8Array(SHARE_RECORD_BYTES);
  out[0] = record.share_domain;
  out[1] = record.share_role;
  // u32 little-endian (SCALE-native)
  out[2] = record.logical_index & 0xff;
  out[3] = (record.logical_index >>> 8) & 0xff;
  out[4] = (record.logical_index >>> 16) & 0xff;
  out[5] = (record.logical_index >>> 24) & 0xff;
  out[6] = record.x;
  out.set(record.value, 7);
  return out;
}

/**
 * Decode a 39-byte SCALE serialization to a ShareRecord.
 * Validates after decode; throws on invariant breach or length mismatch.
 */
export function decodeShareRecord(bytes: Bytes): ShareRecord {
  if (bytes.length !== SHARE_RECORD_BYTES) {
    throw new ShareRecordValidationError(
      "ERR_SHARE_RECORD_DECODE_LENGTH",
      `ShareRecord must be ${SHARE_RECORD_BYTES} bytes, got ${bytes.length}`,
    );
  }
  const share_domain = bytes[0] as ShareDomain;
  const share_role = bytes[1] as ShareRole;
  const logical_index =
    (bytes[2] ?? 0) |
    ((bytes[3] ?? 0) << 8) |
    ((bytes[4] ?? 0) << 16) |
    (((bytes[5] ?? 0) << 24) >>> 0); // unsigned shift
  const x = bytes[6] ?? 0;
  const value = bytes.slice(7, 7 + 32);
  const record: ShareRecord = {
    share_domain,
    share_role,
    logical_index: logical_index >>> 0,
    x,
    value,
  };
  validateShareRecord(record);
  return record;
}
