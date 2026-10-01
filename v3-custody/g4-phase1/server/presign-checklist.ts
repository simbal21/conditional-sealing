export interface ServerPresignChecklistInput {
  readonly finalized: boolean;
  readonly challengeWindowClosed: boolean;
  readonly canGatesSign: boolean;
  readonly shredStateSignable: boolean;
  readonly blockingRefusalActive: boolean;
}

export function assertServerPresignChecklist(input: ServerPresignChecklistInput): void {
  if (!input.finalized) throw new Error("CUSTODY_ERR_FINALITY_PENDING");
  if (!input.challengeWindowClosed) throw new Error("CUSTODY_ERR_CHALLENGE_WINDOW_OPEN");
  if (!input.canGatesSign) throw new Error("CUSTODY_ERR_GATES_CANNOT_SIGN");
  if (!input.shredStateSignable) throw new Error("CUSTODY_ERR_SHRED_STATE_BLOCKED");
  if (input.blockingRefusalActive) throw new Error("CUSTODY_ERR_G4_REFUSED");
}
