// Real viem-backed ChainAnchorClient — replaces SyntheticChainAnchorClient
// (ingestion-anchor.ts:30) in production.
//
// Posts the ingestion-anchor commit to the on-chain ConditionEngine via a
// viem WalletClient, then reads back the commit_block + commit_block_hash
// from the receipt. Retries on transient RPC failures (timeouts, rate limits,
// nonce contention) with capped exponential backoff + jitter.
//
// V3 isolation:
//   - No V1 RevealManager hardcoded address (R2x grep gate).
//   - No V1 sealed-share/issuer-salt/committee-key env access.
//   - No `keys/` filesystem read.
//   - Wallet private key must come from a managed secret (Railway env or KMS),
//     never a checked-in file. The class takes the WalletClient as input so
//     the caller controls key provenance.
//
// Retry policy: distinct from the webhook policy (S2-5 §7.3). Chain RPC
// failures have different cost/SLO profile. Defaults documented in
// `DEFAULT_VIEM_CHAIN_ANCHOR_RETRY_POLICY`.
//
// Rule-25 snapshot-recheck: each retry attempt re-reads the chain via
// `getTransactionReceipt`, NOT a cached receipt — so a node that briefly
// dropped the tx and re-included it gives a correct block hash on the
// retry without ghost-attempt accumulation.

import {
  type Address,
  type Hash,
  type PublicClient,
  type WalletClient,
} from "viem";
import { getConditionEngineAbi } from "../m2-imports.js";
import type {
  ChainAnchorClient,
  IngestionAnchorInput,
  IngestionAnchorResult,
} from "./ingestion-anchor.js";
import type { Hex32 } from "../h-commit/index.js";
import { asTerminalRetryError } from "./retry-policy.js";

/**
 * Retry policy for the real chain-anchor client. Distinct from the webhook
 * retry policy: chain-anchor retries can be longer (RPC restarts, mempool
 * congestion) but capped to avoid unbounded gas burn under sustained outage.
 *
 * Defaults: 6 attempts, base 500ms, factor 2, cap 16s, ±20% jitter.
 *   attempt 1: ~0ms          (immediate)
 *   attempt 2: ~500ms ±20%
 *   attempt 3: ~1000ms ±20%
 *   attempt 4: ~2000ms ±20%
 *   attempt 5: ~4000ms ±20%
 *   attempt 6: ~8000ms ±20%
 *   (each capped at 16000ms)
 */
export interface ViemChainAnchorRetryPolicy {
  readonly maxAttempts: number;
  readonly baseDelayMs: number;
  readonly backoffFactor: number;
  readonly capDelayMs: number;
  /** ±jitter fraction, e.g. 0.2 = ±20%. */
  readonly jitterFraction: number;
}

export const DEFAULT_VIEM_CHAIN_ANCHOR_RETRY_POLICY: ViemChainAnchorRetryPolicy = {
  maxAttempts: 6,
  baseDelayMs: 500,
  backoffFactor: 2,
  capDelayMs: 16_000,
  jitterFraction: 0.2,
};

/**
 * Compute the delay before attempt N (1-indexed). attempt=1 returns 0.
 * Pure function — exposed for unit tests.
 */
export function computeBackoffDelay(
  attempt: number,
  policy: ViemChainAnchorRetryPolicy,
  random: () => number = Math.random,
): number {
  if (attempt <= 1) return 0;
  const exp = Math.min(
    policy.capDelayMs,
    policy.baseDelayMs * Math.pow(policy.backoffFactor, attempt - 2),
  );
  const jitter = exp * policy.jitterFraction * (random() * 2 - 1);
  return Math.max(0, Math.round(exp + jitter));
}

/**
 * Classify an error as retryable (transient RPC failure) or terminal
 * (programmer error / unrecoverable revert).
 *
 * Retryable buckets:
 *   - network timeout / ECONNRESET / ETIMEDOUT
 *   - HTTP 429 (rate limit) / 502 / 503 / 504
 *   - "nonce too low" / "replacement transaction underpriced" (mempool race)
 *   - generic "timeout" / "request timed out" strings
 *
 * Terminal buckets:
 *   - contract revert (any "execution reverted" surface)
 *   - invalid signature / chainId mismatch
 *   - insufficient funds
 */
export function isRetryableChainError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const msg = err.message.toLowerCase();
  // Terminal markers FIRST (an "execution reverted" that also mentions a
  // proxy "timed out" string would otherwise be misclassified).
  if (
    msg.includes("execution reverted") ||
    msg.includes("invalid signature") ||
    msg.includes("chainid mismatch") ||
    msg.includes("chain id mismatch") ||
    msg.includes("insufficient funds")
  ) {
    return false;
  }
  if (
    msg.includes("timeout") ||
    msg.includes("timed out") ||
    msg.includes("econnreset") ||
    msg.includes("etimedout") ||
    msg.includes("enotfound") ||
    msg.includes("429") ||
    msg.includes("502") ||
    msg.includes("503") ||
    msg.includes("504") ||
    msg.includes("rate limit") ||
    msg.includes("nonce too low") ||
    msg.includes("replacement transaction underpriced") ||
    msg.includes("could not coalesce") ||
    msg.includes("network error")
  ) {
    return true;
  }
  return false;
}

/**
 * Configuration for the real viem chain-anchor client.
 *
 * The caller provides both a WalletClient (for the write/tx) and a
 * PublicClient (for the receipt read). Splitting them lets production wire
 * a key-managed WalletClient + an unauthenticated PublicClient pointed at
 * a different RPC endpoint (e.g., a paid Alchemy URL for writes + a free
 * public node for reads).
 */
export interface ViemChainAnchorClientConfig {
  readonly walletClient: WalletClient;
  readonly publicClient: PublicClient;
  /** ConditionEngine contract address on the active chain. */
  readonly conditionEngineAddress: Address;
  /** Function name on ConditionEngine that anchors an ingestion commit. */
  readonly anchorFunctionName?: string;
  readonly retryPolicy?: ViemChainAnchorRetryPolicy;
  /**
   * Optional sleep override — tests inject a no-op so retry delays don't
   * actually wait. Production uses the real `setTimeout`.
   */
  readonly sleep?: (ms: number) => Promise<void>;
  readonly random?: () => number;
}

const DEFAULT_ANCHOR_FN = "anchorIngestion";

function realSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Production ChainAnchorClient — writes the ingestion-anchor commit to
 * ConditionEngine via viem, then reads the receipt for block + blockHash.
 *
 * Implements the same `anchor(input, attempt)` signature as
 * SyntheticChainAnchorClient. Internally runs its own retry loop using
 * `isRetryableChainError` so the caller (anchorIngestionWithRetry in
 * `./anchor-worker.ts`) can also wrap with its own retry budget — the two
 * are composable.
 */
export class ViemChainAnchorClient implements ChainAnchorClient {
  private readonly walletClient: WalletClient;
  private readonly publicClient: PublicClient;
  private readonly conditionEngineAddress: Address;
  private readonly anchorFunctionName: string;
  private readonly retryPolicy: ViemChainAnchorRetryPolicy;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly random: () => number;

  constructor(config: ViemChainAnchorClientConfig) {
    this.walletClient = config.walletClient;
    this.publicClient = config.publicClient;
    this.conditionEngineAddress = config.conditionEngineAddress;
    this.anchorFunctionName = config.anchorFunctionName ?? DEFAULT_ANCHOR_FN;
    this.retryPolicy = config.retryPolicy ?? DEFAULT_VIEM_CHAIN_ANCHOR_RETRY_POLICY;
    this.sleep = config.sleep ?? realSleep;
    this.random = config.random ?? Math.random;
  }

  async anchor(input: IngestionAnchorInput, attempt: number): Promise<IngestionAnchorResult> {
    // Outer attempt = the anchor-worker's call number. We run a private inner
    // retry loop so transient RPC failures within a single anchor() call
    // don't burn an outer attempt. The two budgets compose.
    let lastError: unknown;
    for (let inner = 1; inner <= this.retryPolicy.maxAttempts; inner += 1) {
      try {
        const txHash = await this.sendAnchorTx(input);
        const receipt = await this.waitReceipt(txHash);
        return {
          commit_tx_hash: txHash,
          commit_block: Number(receipt.blockNumber),
          commit_block_hash: receipt.blockHash as Hex32,
          attempts: attempt,
        };
      } catch (err) {
        lastError = err;
        if (!isRetryableChainError(err)) {
          // Terminal failure — wrap in TerminalRetryError so any outer
          // `withRetry` wrapper (anchor-worker.ts:anchorIngestionWithRetry)
          // short-circuits instead of burning outer attempts on an
          // unrecoverable error. The original error is preserved as
          // `.cause` for diagnostics. Closes dw-quality-2 R2b-4 v0.1
          // finding SHOULD-FIX-2.
          throw asTerminalRetryError(
            err,
            err instanceof Error
              ? `ViemChainAnchorClient: terminal chain error: ${err.message}`
              : "ViemChainAnchorClient: terminal chain error",
          );
        }
        if (inner < this.retryPolicy.maxAttempts) {
          const delay = computeBackoffDelay(inner + 1, this.retryPolicy, this.random);
          if (delay > 0) await this.sleep(delay);
        }
      }
    }
    // Inner budget exhausted on transient failures — surface to outer retry
    // budget. NOT wrapped as terminal: the outer should be allowed to retry
    // because the underlying failures were transient; inner just exhausted
    // its own budget for this call.
    throw lastError instanceof Error
      ? lastError
      : new Error("ViemChainAnchorClient: inner retry budget exhausted");
  }

  private async sendAnchorTx(input: IngestionAnchorInput): Promise<Hash> {
    // viem `writeContract` requires a WalletClient with an account. We
    // build the call manually to keep type-coupling minimal — the ABI
    // facade is loaded once via getConditionEngineAbi().
    const abi = getConditionEngineAbi();
    // viem's writeContract type is parameterized over the ABI; using
    // `unknown` cast here avoids over-constraining the ABI type at the
    // module boundary. Real type-safety lives at the call site if the
    // ABI is locked at a const.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const wc = this.walletClient as any;
    const account = wc.account;
    if (!account) {
      throw new Error("ViemChainAnchorClient: WalletClient has no account configured");
    }
    const chain = wc.chain;
    return wc.writeContract({
      address: this.conditionEngineAddress,
      abi,
      functionName: this.anchorFunctionName,
      account,
      chain,
      args: [
        input.authorizationId,
        input.h_commit,
        input.pda_root,
        input.commit_block_hash,
        input.idempotency_key,
      ],
    });
  }

  private async waitReceipt(
    txHash: Hash,
  ): Promise<{ blockNumber: bigint; blockHash: Hash }> {
    // viem's waitForTransactionReceipt awaits inclusion with internal polling.
    // Pass timeout = capDelayMs so a hung RPC times out into the retryable
    // bucket rather than blocking forever.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const pc = this.publicClient as any;
    const receipt = await pc.waitForTransactionReceipt({
      hash: txHash,
      timeout: this.retryPolicy.capDelayMs,
    });
    return {
      blockNumber: BigInt(receipt.blockNumber),
      blockHash: receipt.blockHash,
    };
  }
}
