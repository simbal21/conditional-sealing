import { getConditionEngineAbi } from "../m2-imports.js";
import type { Hex32 } from "../h-commit/index.js";

export interface IngestionAnchorInput {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly pda_root: Hex32;
  readonly commit_block_hash: Hex32;
  readonly idempotency_key: string;
}

export interface IngestionAnchorResult {
  readonly commit_tx_hash: string;
  readonly commit_block: number;
  readonly commit_block_hash?: Hex32;
  readonly attempts: number;
}

export interface ChainAnchorClient {
  anchor(input: IngestionAnchorInput, attempt: number): Promise<IngestionAnchorResult>;
}

export function assertConditionEngineAbiLoadable(): void {
  const abi = getConditionEngineAbi();
  if (abi.length === 0) {
    throw new Error("ConditionEngine ABI did not load");
  }
}

export class SyntheticChainAnchorClient implements ChainAnchorClient {
  async anchor(input: IngestionAnchorInput, attempt: number): Promise<IngestionAnchorResult> {
    assertConditionEngineAbiLoadable();
    return {
      commit_tx_hash: `0x${input.h_commit.slice(2, 66)}`,
      commit_block: 1_000_000 + attempt,
      commit_block_hash: input.commit_block_hash,
      attempts: attempt,
    };
  }
}

