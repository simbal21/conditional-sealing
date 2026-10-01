import type { Hex32 } from "@cealis/v3-crypto";
import { CustodyError, CUSTODY_ERROR_CODES, type CustodyErrorCode } from "../errors.js";
import {
  ShredState,
  type ShredStateValue,
  isShredStateSignable,
} from "../types/registries.js";
import type { RefusalState } from "../types/refusal.js";
import { isBlocking } from "../refusal/codes.js";

export type PresignReadSource =
  | "authorization-block-historical"
  | "current-state-safety"
  | "local-finality"
  | "local-challenge-window";

export interface PresignChecklistStep {
  readonly step: 1 | 2 | 3 | 4 | 5;
  readonly name: string;
  readonly ok: boolean;
  readonly source: PresignReadSource;
  readonly detail: string;
}

export interface PresignChecklistTranscript {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly authorizationBlock: bigint;
  readonly blockHash: Hex32;
  readonly steps: readonly PresignChecklistStep[];
}

export interface PresignChecklistReader {
  canGatesSignAt(
    authorizationId: Hex32,
    hCommit: Hex32,
    blockNumber: bigint,
  ): Promise<{ readonly canSign: boolean; readonly reasons: readonly string[] }>;
  getCurrentShredState(hCommit: Hex32): Promise<ShredStateValue>;
  getRefusalStateAt(authorizationId: Hex32, blockNumber: bigint): Promise<RefusalState>;
  getCurrentRefusalState?(authorizationId: Hex32): Promise<RefusalState>;
}

export interface PresignChecklistInput {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly authorizationBlock: bigint;
  readonly blockHash: Hex32;
  readonly currentBlock: bigint;
  readonly finalityDepth: bigint;
  readonly challengeWindowClosed: boolean;
  readonly reader: PresignChecklistReader;
}

export async function runG4PresignChecklist(
  input: PresignChecklistInput,
): Promise<PresignChecklistTranscript> {
  const steps: PresignChecklistStep[] = [];

  const finalized = input.currentBlock >= input.authorizationBlock + input.finalityDepth;
  steps.push({
    step: 1,
    name: "RevealAuthorized finalized",
    ok: finalized,
    source: "local-finality",
    detail: finalized
      ? `currentBlock=${input.currentBlock.toString()} finalityDepth=${input.finalityDepth.toString()}`
      : `authorizationBlock=${input.authorizationBlock.toString()} currentBlock=${input.currentBlock.toString()} finalityDepth=${input.finalityDepth.toString()}`,
  });
  if (!finalized) {
    throwWithTranscript(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_FINALITY_PENDING,
      "RevealAuthorized not finalized at required depth",
      input,
      steps,
    );
  }

  steps.push({
    step: 2,
    name: "PDA challenge window closed",
    ok: input.challengeWindowClosed,
    source: "local-challenge-window",
    detail: input.challengeWindowClosed ? "closed" : "open",
  });
  if (!input.challengeWindowClosed) {
    throwWithTranscript(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_CHALLENGE_WINDOW_OPEN,
      "PDA challenge window is still open",
      input,
      steps,
    );
  }

  const canSign = await input.reader.canGatesSignAt(
    input.authorizationId,
    input.hCommit,
    input.authorizationBlock,
  );
  steps.push({
    step: 3,
    name: "AttestationGate.canGatesSign at authorization block",
    ok: canSign.canSign,
    source: "authorization-block-historical",
    detail: canSign.canSign ? "canSign=true" : canSign.reasons.join(";"),
  });
  if (!canSign.canSign) {
    throwWithTranscript(
      mapCanSignFailure(canSign.reasons),
      "AttestationGate cannot sign at authorization boundary",
      input,
      steps,
    );
  }

  const shredState = await input.reader.getCurrentShredState(input.hCommit);
  const shredOk = isShredStateSignable(shredState);
  steps.push({
    step: 4,
    name: "ShredRegistry current-state safety read",
    ok: shredOk,
    source: "current-state-safety",
    detail: `state=${shredStateLabel(shredState)}`,
  });
  if (!shredOk) {
    throwWithTranscript(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHRED_STATE_BLOCKED,
      "Shred state blocks gate signing",
      input,
      steps,
    );
  }

  const historicalRefusal = await input.reader.getRefusalStateAt(
    input.authorizationId,
    input.authorizationBlock,
  );
  const currentRefusal = input.reader.getCurrentRefusalState === undefined
    ? { refused: false, reasonCode: 0, encrypted: false }
    : await input.reader.getCurrentRefusalState(input.authorizationId);
  const noBlockingRefusal =
    !hasBlockingRefusal(historicalRefusal) && !hasBlockingRefusal(currentRefusal);
  steps.push({
    step: 5,
    name: "G4 refusal state historical and current reads",
    ok: noBlockingRefusal,
    source: "authorization-block-historical",
    detail: `historical=${describeRefusal(historicalRefusal)} current=${describeRefusal(currentRefusal)}`,
  });
  if (!noBlockingRefusal) {
    throwWithTranscript(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_REFUSED,
      "G4 blocking refusal active",
      input,
      steps,
    );
  }

  return buildTranscript(input, steps);
}

function hasBlockingRefusal(refusal: RefusalState): boolean {
  return refusal.refused && isBlocking(refusal.reasonCode);
}

function mapCanSignFailure(reasons: readonly string[]): CustodyErrorCode {
  if (reasons.some((reason) => reason.includes("G4_REFUSED"))) {
    return CUSTODY_ERROR_CODES.CUSTODY_ERR_G4_REFUSED;
  }
  if (reasons.some((reason) => reason.includes("SHRED_STATE"))) {
    return CUSTODY_ERROR_CODES.CUSTODY_ERR_SHRED_STATE_BLOCKED;
  }
  return CUSTODY_ERROR_CODES.CUSTODY_ERR_GATES_CANNOT_SIGN;
}

function throwWithTranscript(
  code: CustodyErrorCode,
  message: string,
  input: PresignChecklistInput,
  steps: readonly PresignChecklistStep[],
): never {
  throw new CustodyError(code, message, {
    metadata: {
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      authorizationBlock: input.authorizationBlock,
      checkedSteps: steps.length,
    },
  });
}

function buildTranscript(
  input: PresignChecklistInput,
  steps: readonly PresignChecklistStep[],
): PresignChecklistTranscript {
  return {
    authorizationId: input.authorizationId,
    hCommit: input.hCommit,
    authorizationBlock: input.authorizationBlock,
    blockHash: input.blockHash,
    steps,
  };
}

function describeRefusal(refusal: RefusalState): string {
  if (!refusal.refused) return "none";
  return `code=0x${refusal.reasonCode.toString(16).padStart(2, "0")}:encrypted=${refusal.encrypted}`;
}

function shredStateLabel(state: ShredStateValue): string {
  switch (state) {
    case ShredState.None:
      return "None";
    case ShredState.Requested:
      return "Requested";
    case ShredState.Authorized:
      return "Authorized";
    case ShredState.Finalized:
      return "Finalized";
    case ShredState.Blocked:
      return "Blocked";
    case ShredState.ChallengeOpen:
      return "ChallengeOpen";
    case ShredState.Shredded:
      return "Shredded";
  }
}
