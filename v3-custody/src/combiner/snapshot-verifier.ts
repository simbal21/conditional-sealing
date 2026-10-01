import type {
  AuthorizationRegistrySnapshot,
  CommitRegistrySnapshot,
} from "../types/index.js";
import type { Hex32 } from "../m1-imports.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";

export interface SnapshotVerificationResult {
  readonly commitBlock: bigint;
  readonly authorizationBlock: bigint;
}

export function verifyRegistrySnapshots(input: {
  readonly commitSnapshot: CommitRegistrySnapshot;
  readonly authorizationSnapshot: AuthorizationRegistrySnapshot;
  readonly sigmaCommitBlock: bigint;
  readonly authorizationBlock: bigint;
  readonly blockHash: Hex32;
}): SnapshotVerificationResult {
  if (input.commitSnapshot.snapshot.blockNumber !== input.sigmaCommitBlock) {
    throw snapshotError("commit snapshot block does not match SigmaEvidenceBundle commitBlock");
  }
  if (input.authorizationSnapshot.snapshot.blockNumber !== input.authorizationBlock) {
    throw snapshotError("authorization snapshot block does not match combine input authorizationBlock");
  }
  if (input.authorizationSnapshot.snapshot.blockHash !== input.blockHash) {
    throw snapshotError("authorization snapshot block hash does not match RevealAuthorized block hash");
  }
  if (!input.authorizationSnapshot.canGatesSign) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATES_CANNOT_SIGN,
      "authorization snapshot reports gates cannot sign",
    );
  }
  if (
    input.authorizationSnapshot.refusalState.refused &&
    input.authorizationSnapshot.refusalState.reasonCode >= 0x01 &&
    input.authorizationSnapshot.refusalState.reasonCode <= 0x09
  ) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_REFUSED,
      "authorization snapshot contains a blocking G4 refusal",
      { subCodes: [`REASON_0x${input.authorizationSnapshot.refusalState.reasonCode.toString(16).padStart(2, "0")}`] },
    );
  }
  return {
    commitBlock: input.commitSnapshot.snapshot.blockNumber,
    authorizationBlock: input.authorizationSnapshot.snapshot.blockNumber,
  };
}

function snapshotError(message: string): CustodyError {
  return new CustodyError(
    CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
    message,
    { subCodes: ["ERR_REGISTRY_SNAPSHOT_MISMATCH"] },
  );
}
