// Byte-sliced Shamir reconstruction per docs/specs/cryptography-spec.md §6.3.
//
// The field is GF(2^8) with the AES irreducible polynomial
// x^8 + x^4 + x^3 + x + 1 (0x11b). Do not replace this with a generic
// Shamir library: Phase D requires typed access-structure reconstruction over
// 32 independent byte lanes.

import {
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_ROLE_CONDITIONAL_RECIPIENT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
  SHARE_ROLE_LIT,
  SHARE_ROLE_RECIPIENT_AGGREGATE,
  ShareRecordValidationError,
  validateShareRecord,
  type ShareRecord,
  type ShareRole,
} from "../codecs/share-record.js";
import type { Bytes32 } from "../types.js";

export const GF256_AES_POLYNOMIAL = 0x11b as const;

export type AccessStructureProfile =
  | { kind: "FIXED_ONLY" }
  | { kind: "RECIPIENT_1_OF_1" }
  | { kind: "RECIPIENT_K_OF_N"; n_conditional: number; k_conditional: number };

export const ShamirError = {
  ERR_SHAMIR_SHARE_INDEX_INVALID: "ERR_SHAMIR_SHARE_INDEX_INVALID",
  ERR_SHARE_RECORD_DOMAIN_ROLE_MISMATCH: "ERR_SHARE_RECORD_DOMAIN_ROLE_MISMATCH",
  ERR_SHARE_RECORD_VALUE_LENGTH: "ERR_SHARE_RECORD_VALUE_LENGTH",
  ERR_SHARE_RECORD_FIELD_RANGE: "ERR_SHARE_RECORD_FIELD_RANGE",
  ERR_SHARE_RECORD_DECODE_LENGTH: "ERR_SHARE_RECORD_DECODE_LENGTH",
  ERR_SHAMIR_THRESHOLD_NOT_MET: "ERR_SHAMIR_THRESHOLD_NOT_MET",
  ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT: "ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT",
  ERR_SHAMIR_COMBINE_FAIL: "ERR_SHAMIR_COMBINE_FAIL",
} as const;

export type ShamirErrorCode = keyof typeof ShamirError;
export type ShamirCombineResult =
  | { ok: true; dek: Uint8Array }
  | { ok: false; error: ShamirErrorCode };

export class ShamirCombinerError extends Error {
  constructor(
    public readonly code: ShamirErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "ShamirCombinerError";
  }
}

export interface ShamirByteShare {
  x: number;
  y: number;
}

const DEK_BYTES = 32;
const TOP_LEVEL_INDEX_BY_ROLE = new Map<ShareRole, number>([
  [SHARE_ROLE_LIT, 0],
  [SHARE_ROLE_G3, 1],
  [SHARE_ROLE_G4, 2],
  [SHARE_ROLE_RECIPIENT_AGGREGATE, 3],
]);
const MANDATORY_TOP_LEVEL_ROLES = [
  SHARE_ROLE_LIT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
] as const;

function assertByte(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new ShamirCombinerError("ERR_SHAMIR_SHARE_INDEX_INVALID", `${label} must be uint8`);
  }
  return value;
}

export function gfAdd(a: number, b: number): number {
  return assertByte(a, "a") ^ assertByte(b, "b");
}

export function gfMul(a: number, b: number): number {
  let aa = assertByte(a, "a");
  let bb = assertByte(b, "b");
  let product = 0;

  // Branchless implementation — removes data-dependent timing paths in the
  // inner loop. Previously: `if ((bb & 1) !== 0) product ^= aa;` produced a
  // bit-dependent timing variation; `if (carry) aa ^= GF256_AES_POLYNOMIAL & 0xff;`
  // the same. Each iteration now uses arithmetic masking so the operation count
  // is identical regardless of (a, b) bit pattern. JS engines are not formally
  // constant-time at the JIT level, but removing the source-level branches
  // closes the most exploitable observable side-channel and matches accepted
  // GF(2^8) constant-time patterns. Security-audit-2026-05-14 TS-CRYPTO-F-09.
  const polynomial = GF256_AES_POLYNOMIAL & 0xff;
  for (let i = 0; i < 8; i++) {
    // mask = 0xFF when (bb & 1) is 1, else 0x00 — branchless
    const bbBitMask = -(bb & 1) & 0xff;
    product ^= aa & bbBitMask;

    // mask = 0xFF when (aa & 0x80) is set, else 0x00 — branchless carry
    const carryMask = -((aa >> 7) & 1) & 0xff;
    aa = ((aa << 1) & 0xff) ^ (polynomial & carryMask);

    bb >>>= 1;
  }

  return product & 0xff;
}

function gfPow(a: number, exponent: number): number {
  let out = 1;
  let base = assertByte(a, "a");
  let exp = exponent;
  while (exp > 0) {
    if ((exp & 1) !== 0) out = gfMul(out, base);
    base = gfMul(base, base);
    exp >>>= 1;
  }
  return out;
}

export function gfInv(a: number): number {
  const value = assertByte(a, "a");
  if (value === 0) {
    throw new ShamirCombinerError("ERR_SHAMIR_SHARE_INDEX_INVALID", "cannot invert zero in GF(2^8)");
  }
  return gfPow(value, 254);
}

export function lagrangeAtZero(shares: { x: number; y: number }[]): number {
  if (shares.length === 0) {
    throw new ShamirCombinerError("ERR_SHAMIR_THRESHOLD_NOT_MET", "at least one share is required");
  }

  let secret = 0;
  const seen = new Set<number>();
  for (const share of shares) {
    const x = assertByte(share.x, "x");
    assertByte(share.y, "y");
    if (x === 0 || seen.has(x)) {
      throw new ShamirCombinerError("ERR_SHAMIR_SHARE_INDEX_INVALID", "duplicate or zero x-coordinate");
    }
    seen.add(x);
  }

  for (let i = 0; i < shares.length; i++) {
    const current = shares[i];
    if (current === undefined) throw new ShamirCombinerError("ERR_SHAMIR_COMBINE_FAIL", "share missing");
    let lambda = 1;
    for (let j = 0; j < shares.length; j++) {
      if (i === j) continue;
      const other = shares[j];
      if (other === undefined) throw new ShamirCombinerError("ERR_SHAMIR_COMBINE_FAIL", "share missing");
      const denominator = gfAdd(current.x, other.x);
      lambda = gfMul(lambda, gfMul(other.x, gfInv(denominator)));
    }
    secret = gfAdd(secret, gfMul(current.y, lambda));
  }

  return secret;
}

export function combineByteLane(shares: { x: number; y: number }[]): number {
  return lagrangeAtZero(shares);
}

function wrapShareRecordValidation(error: ShareRecordValidationError): ShamirCombinerError {
  if (error.code in ShamirError) {
    return new ShamirCombinerError(error.code as ShamirErrorCode, error.message);
  }
  return new ShamirCombinerError("ERR_SHAMIR_COMBINE_FAIL", error.message);
}

function validateProfile(profile: AccessStructureProfile): void {
  if (profile.kind !== "RECIPIENT_K_OF_N") return;
  const { n_conditional, k_conditional } = profile;
  if (
    !Number.isInteger(n_conditional) ||
    !Number.isInteger(k_conditional) ||
    n_conditional < 1 ||
    n_conditional > 0xff ||
    k_conditional < 1 ||
    k_conditional > n_conditional
  ) {
    throw new ShamirCombinerError(
      "ERR_SHAMIR_THRESHOLD_NOT_MET",
      "RECIPIENT_K_OF_N requires 1 <= k_conditional <= n_conditional <= 255",
    );
  }
}

function validateTypedRecords(records: ShareRecord[], profile: AccessStructureProfile): void {
  const seenDomainX = new Set<string>();
  for (const record of records) {
    try {
      validateShareRecord(record);
    } catch (error) {
      if (error instanceof ShareRecordValidationError) throw wrapShareRecordValidation(error);
      throw error;
    }

    const domainX = `${record.share_domain}:${record.x}`;
    if (seenDomainX.has(domainX)) {
      throw new ShamirCombinerError("ERR_SHAMIR_SHARE_INDEX_INVALID", "duplicate (share_domain, x)");
    }
    seenDomainX.add(domainX);

    if (record.share_domain === SHARE_DOMAIN_TOP_LEVEL) {
      const expectedIndex = TOP_LEVEL_INDEX_BY_ROLE.get(record.share_role);
      if (expectedIndex === undefined || record.logical_index !== expectedIndex || record.x !== expectedIndex + 1) {
        throw new ShamirCombinerError(
          "ERR_SHAMIR_SHARE_INDEX_INVALID",
          "TOP_LEVEL share x must equal top_level_index + 1",
        );
      }
      continue;
    }

    if (record.share_domain === SHARE_DOMAIN_RECIPIENT_BRANCH) {
      if (record.share_role !== SHARE_ROLE_CONDITIONAL_RECIPIENT || record.x !== record.logical_index + 1) {
        throw new ShamirCombinerError(
          "ERR_SHAMIR_SHARE_INDEX_INVALID",
          "RECIPIENT_BRANCH share x must equal recipient_index + 1",
        );
      }
      if (profile.kind === "RECIPIENT_K_OF_N" && record.logical_index >= profile.n_conditional) {
        throw new ShamirCombinerError("ERR_SHAMIR_SHARE_INDEX_INVALID", "recipient_index is outside policy n");
      }
    }
  }
}

function recordsByTopRole(records: ShareRecord[]): Map<ShareRole, ShareRecord> {
  const byRole = new Map<ShareRole, ShareRecord>();
  for (const record of records) {
    if (record.share_domain !== SHARE_DOMAIN_TOP_LEVEL) continue;
    if (byRole.has(record.share_role)) {
      throw new ShamirCombinerError("ERR_SHAMIR_SHARE_INDEX_INVALID", "duplicate top-level role");
    }
    byRole.set(record.share_role, record);
  }
  return byRole;
}

function recipientBranchRecords(records: ShareRecord[]): ShareRecord[] {
  return records
    .filter((record) => record.share_domain === SHARE_DOMAIN_RECIPIENT_BRANCH)
    .sort((a, b) => a.logical_index - b.logical_index);
}

function missingMandatoryTopRoles(topByRole: Map<ShareRole, ShareRecord>): ShareRole[] {
  return MANDATORY_TOP_LEVEL_ROLES.filter((role) => !topByRole.has(role));
}

function topThreshold(profile: AccessStructureProfile): number {
  return profile.kind === "FIXED_ONLY" ? 3 : 4;
}

function isSubstitutionAttempt(
  records: ShareRecord[],
  topByRole: Map<ShareRole, ShareRecord>,
  profile: AccessStructureProfile,
): boolean {
  if (topByRole.size >= topThreshold(profile)) return true;
  if (topByRole.has(SHARE_ROLE_RECIPIENT_AGGREGATE)) return true;
  const recipientCount = records.filter((record) => record.share_domain === SHARE_DOMAIN_RECIPIENT_BRANCH).length;
  if (profile.kind === "RECIPIENT_K_OF_N" && recipientCount >= profile.k_conditional) return true;
  return recipientCount > 0 && profile.kind !== "FIXED_ONLY";
}

function requiredTopRecord(topByRole: Map<ShareRole, ShareRecord>, role: ShareRole): ShareRecord {
  const record = topByRole.get(role);
  if (record === undefined) {
    throw new ShamirCombinerError("ERR_SHAMIR_THRESHOLD_NOT_MET", "required top-level share is absent");
  }
  return record;
}

function combineShareValues(records: ShareRecord[], threshold: number): Bytes32 {
  if (records.length < threshold) {
    throw new ShamirCombinerError("ERR_SHAMIR_THRESHOLD_NOT_MET", "not enough shares for branch threshold");
  }
  if (records.length !== threshold) {
    throw new ShamirCombinerError("ERR_SHAMIR_COMBINE_FAIL", "branch combine requires exact threshold records");
  }

  const out = new Uint8Array(DEK_BYTES);
  for (let lane = 0; lane < DEK_BYTES; lane++) {
    out[lane] = combineByteLane(
      records.map((record) => ({
        x: record.x,
        y: record.value[lane] ?? 0,
      })),
    );
  }
  return out;
}

function combineFixedOnly(topByRole: Map<ShareRole, ShareRecord>): Uint8Array {
  return combineShareValues(
    [
      requiredTopRecord(topByRole, SHARE_ROLE_LIT),
      requiredTopRecord(topByRole, SHARE_ROLE_G3),
      requiredTopRecord(topByRole, SHARE_ROLE_G4),
    ],
    3,
  );
}

function combineRecipient1Of1(topByRole: Map<ShareRole, ShareRecord>): Uint8Array {
  if (!topByRole.has(SHARE_ROLE_RECIPIENT_AGGREGATE)) {
    throw new ShamirCombinerError("ERR_SHAMIR_THRESHOLD_NOT_MET", "recipient top-level share is absent");
  }
  return combineShareValues(
    [
      requiredTopRecord(topByRole, SHARE_ROLE_LIT),
      requiredTopRecord(topByRole, SHARE_ROLE_G3),
      requiredTopRecord(topByRole, SHARE_ROLE_G4),
      requiredTopRecord(topByRole, SHARE_ROLE_RECIPIENT_AGGREGATE),
    ],
    4,
  );
}

function combineRecipientKOfN(records: ShareRecord[], topByRole: Map<ShareRole, ShareRecord>, profile: Extract<AccessStructureProfile, { kind: "RECIPIENT_K_OF_N" }>): Uint8Array {
  const recipientShares = recipientBranchRecords(records);
  if (recipientShares.length < profile.k_conditional) {
    throw new ShamirCombinerError("ERR_SHAMIR_THRESHOLD_NOT_MET", "recipient branch threshold is not met");
  }
  const selectedRecipientShares = recipientShares.slice(0, profile.k_conditional);
  const aggregate = combineShareValues(selectedRecipientShares, profile.k_conditional);
  const aggregateRecord: ShareRecord = {
    share_domain: SHARE_DOMAIN_TOP_LEVEL,
    share_role: SHARE_ROLE_RECIPIENT_AGGREGATE,
    logical_index: 3,
    x: 4,
    value: aggregate,
  };

  return combineShareValues(
    [
      requiredTopRecord(topByRole, SHARE_ROLE_LIT),
      requiredTopRecord(topByRole, SHARE_ROLE_G3),
      requiredTopRecord(topByRole, SHARE_ROLE_G4),
      aggregateRecord,
    ],
    4,
  );
}

function combine(records: ShareRecord[], profile: AccessStructureProfile): Uint8Array {
  validateProfile(profile);
  validateTypedRecords(records, profile);

  const topByRole = recordsByTopRole(records);
  const missing = missingMandatoryTopRoles(topByRole);
  if (missing.length > 0) {
    if (isSubstitutionAttempt(records, topByRole, profile)) {
      throw new ShamirCombinerError(
        "ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT",
        "mandatory top-level branch Lit/G3/G4 is absent",
      );
    }
    throw new ShamirCombinerError("ERR_SHAMIR_THRESHOLD_NOT_MET", "top-level threshold is not met");
  }

  switch (profile.kind) {
    case "FIXED_ONLY":
      return combineFixedOnly(topByRole);
    case "RECIPIENT_1_OF_1":
      return combineRecipient1Of1(topByRole);
    case "RECIPIENT_K_OF_N":
      return combineRecipientKOfN(records, topByRole, profile);
  }
}

export const Shamir = {
  combine,
} as const;

export function combineDek(records: ShareRecord[], profile: AccessStructureProfile): ShamirCombineResult {
  try {
    return { ok: true, dek: Shamir.combine(records, profile) };
  } catch (error) {
    if (error instanceof ShamirCombinerError) return { ok: false, error: error.code };
    if (error instanceof ShareRecordValidationError) return { ok: false, error: wrapShareRecordValidation(error).code };
    return { ok: false, error: "ERR_SHAMIR_COMBINE_FAIL" };
  }
}
