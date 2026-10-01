// Retry policy used by `anchorIngestionWithRetry` (./anchor-worker.ts).
//
// R2b worker-4 upgrade: original Phase A version had `delayMs` only and no
// real backoff. This version adds exponential backoff + jitter while keeping
// the existing `RetryPolicy` shape backward-compatible (fields `maxAttempts`
// and `delayMs` retain their semantics; new optional fields opt-in to
// exponential behaviour).
//
// Existing callers (anchor-worker.ts, ingest/routes-create-mode-a.ts) keep
// working unchanged. New callers can pass `backoffFactor` + `capDelayMs` +
// `jitterFraction` to enable spec-compliant chain-anchor backoff.

export interface RetryPolicy {
  readonly maxAttempts: number;
  /** Base delay between attempts. With backoffFactor, this is delay before attempt 2. */
  readonly delayMs: number;
  /** Optional exponential factor (default 1 = fixed delay). */
  readonly backoffFactor?: number;
  /** Optional cap on individual delay (default no cap). */
  readonly capDelayMs?: number;
  /** Optional jitter as ±fraction (e.g., 0.2 = ±20%). Defaults to 0 (no jitter). */
  readonly jitterFraction?: number;
}

export const DEFAULT_CHAIN_ANCHOR_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 3,
  delayMs: 0,
};

/**
 * Exponential-backoff policy aligned with the spec-locked webhook intervals
 * (1s, 2s, 4s, 8s, 16s — types/webhook-events.ts:61). Five attempts, base
 * 1000ms, factor 2, cap 16s, ±20% jitter.
 */
export const EXPONENTIAL_CHAIN_ANCHOR_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 5,
  delayMs: 1000,
  backoffFactor: 2,
  capDelayMs: 16_000,
  jitterFraction: 0.2,
};

/**
 * Terminal-retry marker. When `withRetry`'s action throws an error that
 * `instanceof TerminalRetryError`, `withRetry` re-throws immediately WITHOUT
 * consuming further attempts.
 *
 * Why a marker class (not a per-error classifier callback): callers compose
 * retry budgets — `anchorIngestionWithRetry` wraps `withRetry` around
 * `ViemChainAnchorClient.anchor`, which itself runs an inner retry loop.
 * The inner loop already classifies retryable vs terminal (e.g., "execution
 * reverted" = terminal, "ETIMEDOUT" = transient). Before this marker, when
 * inner classified an error as terminal and threw, the outer `withRetry`
 * caught it and retried — burning attempts (and potentially gas via repeated
 * `writeContract`) on an error the inner had already declared unrecoverable.
 *
 * Inner now wraps its terminal errors in `TerminalRetryError`. `withRetry`
 * detects the marker and short-circuits, preserving the original cause for
 * the caller via `.cause` (Error.cause, ES2022).
 *
 * Closes dw-quality-2 R2b-4 v0.1 finding SHOULD-FIX-2 (outer retries terminal
 * errors).
 */
export class TerminalRetryError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "TerminalRetryError";
  }
}

/**
 * Convenience: wrap an error as terminal if it isn't already one. Preserves
 * the original error as `.cause` so callers can inspect via
 * `(err as TerminalRetryError).cause` without losing the original stack.
 */
export function asTerminalRetryError(err: unknown, message?: string): TerminalRetryError {
  if (err instanceof TerminalRetryError) return err;
  const baseMessage = err instanceof Error ? err.message : String(err);
  return new TerminalRetryError(message ?? baseMessage, { cause: err });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Test-only sleep override registry. When set, `withRetry` calls this instead
 * of the real `setTimeout`-backed sleep. Production code never touches it.
 * Cleared automatically when the call returns.
 *
 * The override is a module-level slot rather than a parameter so the public
 * `withRetry` signature stays backward-compatible (no breaking change for
 * existing callers).
 */
let sleepOverride: ((ms: number) => Promise<void>) | null = null;

export function __setRetrySleepOverride(fn: ((ms: number) => Promise<void>) | null): void {
  sleepOverride = fn;
}

/**
 * Compute the delay before attempt N (1-indexed). attempt=1 → 0 (no delay
 * before the first try). Pure function — exposed for tests.
 *
 * If `backoffFactor` is undefined or <=1, behaves as the original fixed-delay
 * policy. Otherwise computes `delayMs * factor^(attempt-2)`, capped at
 * `capDelayMs`, with `±jitterFraction` random jitter.
 */
export function computeRetryDelay(
  attempt: number,
  policy: RetryPolicy,
  random: () => number = Math.random,
): number {
  if (attempt <= 1) return 0;
  const factor = policy.backoffFactor ?? 1;
  if (factor <= 1) return policy.delayMs;
  const raw = policy.delayMs * Math.pow(factor, attempt - 2);
  const capped = policy.capDelayMs !== undefined ? Math.min(policy.capDelayMs, raw) : raw;
  const jitter = (policy.jitterFraction ?? 0) * capped * (random() * 2 - 1);
  return Math.max(0, Math.round(capped + jitter));
}

/**
 * Run `action` with retries per `policy`. Returns the first successful result.
 * On all attempts failing, throws the last error.
 *
 * Backward compatible: when policy has only `maxAttempts` + `delayMs`, behaves
 * identically to the original Phase A impl (fixed delay only between attempts
 * when `delayMs > 0`). The exponential path activates when `backoffFactor > 1`.
 *
 * Terminal short-circuit: if `action` throws a `TerminalRetryError` (or any
 * error instance whose constructor name is "TerminalRetryError" — duck-typed
 * to survive cross-realm boundaries), `withRetry` re-throws IMMEDIATELY
 * without consuming further attempts. This composes with inner retry loops:
 * the inner classifies retryable-vs-terminal once, the outer trusts the
 * classification. Without this, outer would re-attempt errors inner already
 * declared unrecoverable (e.g., `execution reverted` chain calls), burning
 * attempts and potentially gas. See `TerminalRetryError` for context.
 *
 * Tests can inject `random` for deterministic jitter.
 */
export async function withRetry<T>(
  policy: RetryPolicy,
  action: (attempt: number) => Promise<T>,
  random: () => number = Math.random,
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= policy.maxAttempts; attempt++) {
    try {
      return await action(attempt);
    } catch (error) {
      lastError = error;
      if (isTerminalRetryError(error)) {
        // Short-circuit: inner has classified this as unrecoverable. Do not
        // burn further attempts. Re-throw the marker so the caller can
        // inspect `.cause` for the original error.
        throw error;
      }
      if (attempt < policy.maxAttempts) {
        const delay = computeRetryDelay(attempt + 1, policy, random);
        if (delay > 0) await (sleepOverride ?? sleep)(delay);
      }
    }
  }
  throw lastError instanceof Error ? lastError : new Error("retry exhausted");
}

/**
 * Duck-typed instanceof check — survives the rare case where the marker
 * class is imported from a different bundle/realm and `instanceof` fails.
 * Belt-and-suspenders since cross-realm is unusual in this codebase, but
 * cheap to add and zero downside.
 */
function isTerminalRetryError(err: unknown): boolean {
  if (err instanceof TerminalRetryError) return true;
  return err instanceof Error && err.name === "TerminalRetryError";
}
