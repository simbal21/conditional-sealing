import {
  CUSTODY_ERROR_CODES,
  type CustodyErrorCode,
} from "../errors.js";
import type { DcipherCommitteeRecord } from "./committee-fetch.js";

export interface DcipherCommitKemBinding {
  readonly committeeId: string;
  readonly committeeEpoch: bigint;
  readonly kemPubkeyDigest: Uint8Array;
  readonly registryEntryId: string;
}

export interface DcipherDelegationRecord {
  readonly fromCommitteeId: string;
  readonly toCommitteeId: string;
  readonly kemPubkeyDigest: Uint8Array;
  readonly signedByRegistry: boolean;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
}

export type DcipherKemContinuityResult =
  | { readonly ok: true; readonly mode: "same-entry" | "delegation" }
  | {
      readonly ok: false;
      readonly code: CustodyErrorCode;
      readonly detail: string;
    };

export function verifyDcipherKemContinuity(input: {
  readonly commitBinding: DcipherCommitKemBinding;
  readonly authorizationCommittee: DcipherCommitteeRecord;
  readonly authorizationBlock: bigint;
  readonly delegation?: DcipherDelegationRecord;
}): DcipherKemContinuityResult {
  if (
    input.commitBinding.committeeId === input.authorizationCommittee.committeeId &&
    input.commitBinding.committeeEpoch === input.authorizationCommittee.committeeEpoch &&
    input.commitBinding.registryEntryId === input.authorizationCommittee.registryEntryId
  ) {
    return { ok: true, mode: "same-entry" };
  }

  const delegation = input.delegation;
  if (
    delegation !== undefined &&
    delegation.signedByRegistry &&
    delegation.fromCommitteeId === input.authorizationCommittee.committeeId &&
    delegation.toCommitteeId === input.commitBinding.committeeId &&
    bytesEqual(delegation.kemPubkeyDigest, input.commitBinding.kemPubkeyDigest) &&
    input.authorizationBlock >= delegation.effectiveBlock &&
    (delegation.tombstoneBlock === 0n || input.authorizationBlock < delegation.tombstoneBlock)
  ) {
    return { ok: true, mode: "delegation" };
  }

  return {
    ok: false,
    code: CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
    detail:
      "dcipher committee signing key is not linked to the commit-bound KEM key",
  };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
