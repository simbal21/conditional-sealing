import type { Hex32 } from "@cealis/v3-crypto";
import {
  CUSTODY_ERROR_CODES,
  CustodyError,
} from "../errors.js";
import type { LitAssignmentRecord } from "../types/registries.js";

export interface LitAssignmentReader {
  getLitAssignmentAt(
    authorizationId: Hex32,
    blockNumber: bigint,
  ): Promise<LitAssignmentRecord | null>;
}

export interface FetchLitAssignmentInput {
  readonly registryReader: LitAssignmentReader;
  readonly authorizationId: Hex32;
  readonly authorizationBlock: bigint;
  readonly assignedTeeIdFromQuote: Hex32;
  readonly expectedSourceGovernanceDigest?: Hex32;
}

export interface LitAssignmentEvidenceEdge {
  readonly authorizationId: Hex32;
  readonly assignmentBlock: bigint;
  readonly assignedTeeId: Hex32;
  readonly sourceGovernanceDigest: Hex32;
  readonly edge: string;
}

export interface VerifiedLitAssignment {
  readonly assignment: LitAssignmentRecord;
  readonly evidenceEdge: LitAssignmentEvidenceEdge;
}

export async function fetchAndVerifyLitAssignment(
  input: FetchLitAssignmentInput,
): Promise<VerifiedLitAssignment> {
  const assignment = await input.registryReader.getLitAssignmentAt(
    input.authorizationId,
    input.authorizationBlock,
  );
  if (assignment === null) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ASSIGNMENT_MISSING,
      "Lit assignment missing at authorization block",
      { metadata: { authorizationBlock: input.authorizationBlock.toString() } },
    );
  }
  if (assignment.assignmentBlock > input.authorizationBlock) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ASSIGNMENT_MISSING,
      "Lit assignment exists after authorization block",
      {
        metadata: {
          assignmentBlock: assignment.assignmentBlock.toString(),
          authorizationBlock: input.authorizationBlock.toString(),
        },
      },
    );
  }
  if (assignment.assignedTeeId !== input.assignedTeeIdFromQuote) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ASSIGNMENT_MISMATCH,
      "Lit DCAP quote TEE id does not match LitV3Assignment",
      {
        metadata: {
          assignmentBlock: assignment.assignmentBlock.toString(),
        },
      },
    );
  }
  if (
    input.expectedSourceGovernanceDigest !== undefined &&
    assignment.sourceGovernanceDigest !== input.expectedSourceGovernanceDigest
  ) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ASSIGNMENT_MISMATCH,
      "Lit source governance digest does not match expected bridge evidence",
      {
        metadata: {
          assignmentBlock: assignment.assignmentBlock.toString(),
        },
      },
    );
  }
  if (assignment.assignedTeePubkey.length !== 48) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_LIT_ASSIGNMENT_MISMATCH,
      "Lit assigned TEE pubkey is not the S2-3 pinned 48-byte BLS G1 pubkey",
      {
        metadata: {
          pubkeyLength: assignment.assignedTeePubkey.length,
        },
      },
    );
  }

  return {
    assignment,
    evidenceEdge: {
      authorizationId: input.authorizationId,
      assignmentBlock: assignment.assignmentBlock,
      assignedTeeId: assignment.assignedTeeId,
      sourceGovernanceDigest: assignment.sourceGovernanceDigest,
      edge: "authorizationId -> LitV3Assignment entry -> quote tee id -> sigma verification key",
    },
  };
}
