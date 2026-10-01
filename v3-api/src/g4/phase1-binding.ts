import type { Hex32 } from "../h-commit/index.js";

export const PHASE_1_TRUST_STATEMENT = "phase_1_registered_binary" as const;

export interface Phase1Binding {
  readonly binary_hash: Hex32;
  readonly effective_block: number;
  readonly ed25519_signature: string;
  readonly phase_trust_statement: typeof PHASE_1_TRUST_STATEMENT;
}

export function buildPhase1Binding(input: {
  readonly binary_hash: Hex32;
  readonly effective_block: number;
  readonly ed25519_signature?: string;
}): Phase1Binding {
  return {
    binary_hash: input.binary_hash,
    effective_block: input.effective_block,
    ed25519_signature: input.ed25519_signature ?? "phase1-ed25519-signature-placeholder",
    phase_trust_statement: PHASE_1_TRUST_STATEMENT,
  };
}

