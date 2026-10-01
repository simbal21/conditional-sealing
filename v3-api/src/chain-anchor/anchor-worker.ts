import { throwProblem } from "../errors/index.js";
import type {
  ChainAnchorClient,
  IngestionAnchorInput,
  IngestionAnchorResult,
} from "./ingestion-anchor.js";
import {
  DEFAULT_CHAIN_ANCHOR_RETRY_POLICY,
  TerminalRetryError,
  type RetryPolicy,
  withRetry,
} from "./retry-policy.js";

export async function anchorIngestionWithRetry(input: {
  readonly client: ChainAnchorClient;
  readonly anchor: IngestionAnchorInput;
  readonly correlationId: string;
  readonly retryPolicy?: RetryPolicy;
}): Promise<IngestionAnchorResult> {
  try {
    return await withRetry(
      input.retryPolicy ?? DEFAULT_CHAIN_ANCHOR_RETRY_POLICY,
      (attempt) => input.client.anchor(input.anchor, attempt),
    );
  } catch (err) {
    // Discriminate terminal-short-circuit (e.g., execution reverted) from
    // genuine retry-budget exhaustion. Both surface as the same
    // CHAIN_ANCHOR_RETRY_EXHAUSTED code today (S2-5 §2.8 catalog has only
    // the one) but the detail string + retryable flag carry the correct
    // diagnostic. A terminal error is NOT retryable — surfacing
    // `retryable: true` for a reverted tx would mislead the caller into
    // re-submitting. Closes dw-quality-2 R2b-4 v0.1 SHOULD-FIX-2 follow-on.
    const isTerminal = err instanceof TerminalRetryError;
    throwProblem("CHAIN_ANCHOR_RETRY_EXHAUSTED", input.correlationId, {
      detail: isTerminal
        ? `Chain anchor terminal failure (not retryable): ${(err as TerminalRetryError).message}`
        : "Chain anchor retry budget exhausted for staged vault object",
      safe_refs: {
        authorizationId: input.anchor.authorizationId,
        h_commit: input.anchor.h_commit,
      },
      retryable: !isTerminal,
    });
  }
}

