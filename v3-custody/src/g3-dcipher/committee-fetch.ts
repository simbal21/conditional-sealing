import type { Hex32 } from "../m1-imports.js";
import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";

export interface DcipherCommitteeRecord {
  readonly committeeId: string;
  readonly committeeEpoch: bigint;
  readonly verificationPubkey: Uint8Array;
  readonly membershipDigest: Hex32;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
  readonly deprecationCode?: number;
  readonly registryEntryId: string;
}

export interface DcipherCommitteeFetchInput {
  readonly authorizationBlock: bigint;
  readonly expectedEpoch?: bigint;
  readonly registryEndpoint?: `https://${string}`;
}

export type DcipherCommitteeFetcher = (
  input: DcipherCommitteeFetchInput,
) => Promise<DcipherCommitteeRecord>;

export async function fetchDcipherCommitteeAtAuthorization(
  input: DcipherCommitteeFetchInput,
  fetcher?: DcipherCommitteeFetcher,
): Promise<DcipherCommitteeRecord> {
  if (fetcher === undefined) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_REGISTRY_UNAVAILABLE,
      "dcipher committee registry fetcher is not configured",
    );
  }
  const record = await fetcher(input);
  validateCommitteeRecord(record, input.authorizationBlock, input.expectedEpoch);
  return record;
}

export function validateCommitteeRecord(
  record: DcipherCommitteeRecord,
  authorizationBlock: bigint,
  expectedEpoch?: bigint,
): void {
  if (record.verificationPubkey.length === 0) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_REGISTRY_UNAVAILABLE,
      "dcipher committee pubkey missing",
    );
  }
  if (expectedEpoch !== undefined && record.committeeEpoch !== expectedEpoch) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_EPOCH_MISMATCH,
      "dcipher committee epoch mismatch",
      {
        metadata: {
          expectedEpoch,
          returnedEpoch: record.committeeEpoch,
        },
      },
    );
  }
  if (authorizationBlock < record.effectiveBlock) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_EPOCH_MISMATCH,
      "dcipher committee not effective at authorization block",
    );
  }
  if (record.tombstoneBlock !== 0n && authorizationBlock >= record.tombstoneBlock) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_DCIPHER_TOMBSTONED,
      "dcipher committee tombstoned at authorization block",
      { metadata: { tombstoneBlock: record.tombstoneBlock } },
    );
  }
}
