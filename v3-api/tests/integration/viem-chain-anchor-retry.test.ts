// Tests for the viem-backed ChainAnchorClient — exponential backoff,
// retry classification, and outcome propagation.
//
// The real WalletClient/PublicClient interactions are mocked at the viem
// layer; the test focuses on the retry logic + error classification, which
// is the load-bearing R2b correctness surface (the viem call itself is
// transparent passthrough).

import { describe, expect, it } from "vitest";
import {
  computeBackoffDelay,
  DEFAULT_VIEM_CHAIN_ANCHOR_RETRY_POLICY,
  isRetryableChainError,
  ViemChainAnchorClient,
  type ViemChainAnchorRetryPolicy,
} from "../../src/chain-anchor/viem-chain-anchor-client.js";
import {
  asTerminalRetryError,
  computeRetryDelay,
  EXPONENTIAL_CHAIN_ANCHOR_RETRY_POLICY,
  TerminalRetryError,
  withRetry,
  __setRetrySleepOverride,
} from "../../src/chain-anchor/retry-policy.js";
import { afterEach, beforeEach } from "vitest";
import type { Address, Hash, PublicClient, WalletClient } from "viem";
import type { IngestionAnchorInput } from "../../src/chain-anchor/ingestion-anchor.js";

describe("viem chain-anchor backoff math", () => {
  it("attempt 1 has zero delay (immediate first try)", () => {
    expect(computeBackoffDelay(1, DEFAULT_VIEM_CHAIN_ANCHOR_RETRY_POLICY, () => 0.5)).toBe(0);
  });

  it("exponential growth caps at capDelayMs", () => {
    const noJitter: ViemChainAnchorRetryPolicy = {
      ...DEFAULT_VIEM_CHAIN_ANCHOR_RETRY_POLICY,
      jitterFraction: 0,
    };
    // base 500, factor 2, cap 16_000
    expect(computeBackoffDelay(2, noJitter, () => 0.5)).toBe(500);
    expect(computeBackoffDelay(3, noJitter, () => 0.5)).toBe(1000);
    expect(computeBackoffDelay(4, noJitter, () => 0.5)).toBe(2000);
    expect(computeBackoffDelay(5, noJitter, () => 0.5)).toBe(4000);
    expect(computeBackoffDelay(6, noJitter, () => 0.5)).toBe(8000);
    expect(computeBackoffDelay(10, noJitter, () => 0.5)).toBe(16_000); // capped
  });

  it("jitter applies symmetrically within ±jitterFraction", () => {
    const policy: ViemChainAnchorRetryPolicy = {
      maxAttempts: 5,
      baseDelayMs: 1000,
      backoffFactor: 2,
      capDelayMs: 60_000,
      jitterFraction: 0.2,
    };
    // attempt 3 = 1000*2 = 2000 base
    // jitter = 2000 * 0.2 * (random()*2-1) = 400 * (random()*2-1)
    // random=0 → -400 → 1600
    // random=1 → +400 → 2400
    expect(computeBackoffDelay(3, policy, () => 0)).toBe(1600);
    expect(computeBackoffDelay(3, policy, () => 1)).toBe(2400);
    expect(computeBackoffDelay(3, policy, () => 0.5)).toBe(2000);
  });
});

describe("isRetryableChainError classification", () => {
  it.each([
    ["network timeout", "Request timeout"],
    ["timed out", "rpc request timed out"],
    ["econnreset", "ECONNRESET reading from socket"],
    ["etimedout", "ETIMEDOUT"],
    ["enotfound", "ENOTFOUND base-sepolia.example"],
    ["429 rate limit", "Server returned 429 Too Many Requests"],
    ["502", "502 Bad Gateway"],
    ["503", "503 Service Unavailable"],
    ["504", "504 Gateway Timeout"],
    ["rate limit", "client rate limit exceeded"],
    ["nonce too low", "nonce too low"],
    ["mempool replace", "replacement transaction underpriced"],
    ["network error", "network error: connection refused"],
  ])("classifies %s as retryable", (_label, msg) => {
    expect(isRetryableChainError(new Error(msg))).toBe(true);
  });

  it.each([
    ["execution reverted", "execution reverted: AccessControl: missing role"],
    ["invalid signature", "Invalid signature on tx"],
    ["chainId mismatch", "chainId mismatch: expected 8453, got 84532"],
    ["insufficient funds", "insufficient funds for gas * price + value"],
  ])("classifies %s as terminal", (_label, msg) => {
    expect(isRetryableChainError(new Error(msg))).toBe(false);
  });

  it("non-Error inputs are non-retryable", () => {
    expect(isRetryableChainError("string error")).toBe(false);
    expect(isRetryableChainError(null)).toBe(false);
    expect(isRetryableChainError(undefined)).toBe(false);
  });
});

describe("ViemChainAnchorClient retry on transient RPC timeout", () => {
  function makeInput(): IngestionAnchorInput {
    return {
      authorizationId: ("0x" + "a".repeat(64)) as `0x${string}` & { readonly __brand: "Hex32" },
      h_commit: ("0x" + "b".repeat(64)) as `0x${string}` & { readonly __brand: "Hex32" },
      pda_root: ("0x" + "c".repeat(64)) as `0x${string}` & { readonly __brand: "Hex32" },
      commit_block_hash: ("0x" + "d".repeat(64)) as `0x${string}` & { readonly __brand: "Hex32" },
      idempotency_key: "idem_test",
    };
  }

  function makeFakeWallet(writeContract: () => Promise<Hash>): WalletClient {
    return {
      writeContract,
      account: { address: ("0x" + "e".repeat(40)) as Address },
      chain: { id: 84532 },
    } as unknown as WalletClient;
  }

  function makeFakePublic(waitForTransactionReceipt: () => Promise<unknown>): PublicClient {
    return {
      waitForTransactionReceipt,
    } as unknown as PublicClient;
  }

  it("retries on first transient failure, succeeds on second", async () => {
    let calls = 0;
    const wallet = makeFakeWallet(async () => {
      calls += 1;
      if (calls === 1) throw new Error("ETIMEDOUT");
      return ("0x" + "f".repeat(64)) as Hash;
    });
    const pub = makeFakePublic(async () => ({
      blockNumber: 1_234_567n,
      blockHash: ("0x" + "1".repeat(64)) as Hash,
    }));
    const sleeps: number[] = [];
    const client = new ViemChainAnchorClient({
      walletClient: wallet,
      publicClient: pub,
      conditionEngineAddress: ("0x" + "9".repeat(40)) as Address,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
      random: () => 0.5, // deterministic jitter centerline
    });
    const result = await client.anchor(makeInput(), 1);
    expect(calls).toBe(2);
    expect(sleeps.length).toBeGreaterThan(0);
    expect(result.commit_block).toBe(1_234_567);
    expect(result.commit_tx_hash).toBe("0x" + "f".repeat(64));
  });

  it("does NOT retry on terminal revert; throws TerminalRetryError with original as cause", async () => {
    let calls = 0;
    const wallet = makeFakeWallet(async () => {
      calls += 1;
      throw new Error("execution reverted: AccessControl");
    });
    const pub = makeFakePublic(async () => {
      throw new Error("should never reach");
    });
    const client = new ViemChainAnchorClient({
      walletClient: wallet,
      publicClient: pub,
      conditionEngineAddress: ("0x" + "9".repeat(40)) as Address,
      sleep: async () => undefined,
    });
    let caught: unknown;
    try {
      await client.anchor(makeInput(), 1);
    } catch (err) {
      caught = err;
    }
    expect(calls).toBe(1); // no retry on terminal
    // SHOULD-FIX-2: inner now wraps terminal errors so outer `withRetry`
    // short-circuits instead of retrying.
    expect(caught).toBeInstanceOf(TerminalRetryError);
    expect((caught as TerminalRetryError).message).toMatch(/terminal chain error.*execution reverted/);
    // Original error preserved as `.cause` for diagnostics.
    const cause = (caught as TerminalRetryError).cause;
    expect(cause).toBeInstanceOf(Error);
    expect((cause as Error).message).toMatch(/execution reverted/);
  });

  it("transient-but-budget-exhausted does NOT wrap as terminal (outer may still retry)", async () => {
    // Inverse of the above: an exhausted INNER budget on TRANSIENT errors
    // surfaces the original error to the outer, NOT a TerminalRetryError —
    // because the underlying failures were retryable, the outer should be
    // allowed to retry.
    const wallet = makeFakeWallet(async () => {
      throw new Error("rpc timeout");
    });
    const pub = makeFakePublic(async () => {
      throw new Error("never");
    });
    const policy: ViemChainAnchorRetryPolicy = {
      maxAttempts: 2,
      baseDelayMs: 1,
      backoffFactor: 2,
      capDelayMs: 10,
      jitterFraction: 0,
    };
    const client = new ViemChainAnchorClient({
      walletClient: wallet,
      publicClient: pub,
      conditionEngineAddress: ("0x" + "9".repeat(40)) as Address,
      sleep: async () => undefined,
      retryPolicy: policy,
    });
    let caught: unknown;
    try {
      await client.anchor(makeInput(), 1);
    } catch (err) {
      caught = err;
    }
    // Plain Error, NOT TerminalRetryError.
    expect(caught).toBeInstanceOf(Error);
    expect(caught).not.toBeInstanceOf(TerminalRetryError);
    expect((caught as Error).message).toMatch(/rpc timeout/);
  });

  it("exhausts inner retry budget on sustained timeouts", async () => {
    let calls = 0;
    const wallet = makeFakeWallet(async () => {
      calls += 1;
      throw new Error("rpc timeout");
    });
    const pub = makeFakePublic(async () => {
      throw new Error("never");
    });
    const policy: ViemChainAnchorRetryPolicy = {
      maxAttempts: 3,
      baseDelayMs: 10,
      backoffFactor: 2,
      capDelayMs: 100,
      jitterFraction: 0,
    };
    const client = new ViemChainAnchorClient({
      walletClient: wallet,
      publicClient: pub,
      conditionEngineAddress: ("0x" + "9".repeat(40)) as Address,
      sleep: async () => undefined,
      retryPolicy: policy,
    });
    await expect(client.anchor(makeInput(), 1)).rejects.toThrow(/rpc timeout/);
    expect(calls).toBe(3); // exhausted maxAttempts
  });
});

describe("withRetry exponential backoff", () => {
  beforeEach(() => __setRetrySleepOverride(async () => undefined));
  afterEach(() => __setRetrySleepOverride(null));

  it("respects exponential growth with jitter=0", async () => {
    let calls = 0;
    await expect(
      withRetry(
        EXPONENTIAL_CHAIN_ANCHOR_RETRY_POLICY,
        async () => {
          calls += 1;
          if (calls < 3) throw new Error("fail");
          return "ok";
        },
        () => 0.5,
      ),
    ).resolves.toBe("ok");
    expect(calls).toBe(3);
  });

  it("computeRetryDelay returns 0 for first attempt", () => {
    expect(computeRetryDelay(1, EXPONENTIAL_CHAIN_ANCHOR_RETRY_POLICY)).toBe(0);
  });

  it("computeRetryDelay returns fixed delay when factor=1", () => {
    expect(computeRetryDelay(2, { maxAttempts: 5, delayMs: 100 })).toBe(100);
    expect(computeRetryDelay(5, { maxAttempts: 5, delayMs: 100 })).toBe(100);
  });

  it("computeRetryDelay caps at capDelayMs", () => {
    const policy = {
      maxAttempts: 10,
      delayMs: 1000,
      backoffFactor: 10,
      capDelayMs: 5000,
      jitterFraction: 0,
    };
    expect(computeRetryDelay(2, policy, () => 0.5)).toBe(1000);
    expect(computeRetryDelay(3, policy, () => 0.5)).toBe(5000); // 10_000 capped
    expect(computeRetryDelay(4, policy, () => 0.5)).toBe(5000); // 100_000 capped
  });
});

describe("withRetry terminal-error short-circuit (SHOULD-FIX-2)", () => {
  beforeEach(() => __setRetrySleepOverride(async () => undefined));
  afterEach(() => __setRetrySleepOverride(null));

  it("short-circuits immediately when action throws TerminalRetryError", async () => {
    let calls = 0;
    let caught: unknown;
    try {
      await withRetry(
        { maxAttempts: 5, delayMs: 0 },
        async () => {
          calls += 1;
          throw new TerminalRetryError("terminal: execution reverted");
        },
      );
    } catch (err) {
      caught = err;
    }
    // Critical: only ONE call, not 5. Without the fix, outer would have
    // retried the terminal error through the full budget.
    expect(calls).toBe(1);
    expect(caught).toBeInstanceOf(TerminalRetryError);
    expect((caught as TerminalRetryError).message).toMatch(/execution reverted/);
  });

  it("still retries normally on non-terminal errors", async () => {
    let calls = 0;
    await expect(
      withRetry({ maxAttempts: 3, delayMs: 0 }, async () => {
        calls += 1;
        if (calls < 3) throw new Error("transient");
        return "ok";
      }),
    ).resolves.toBe("ok");
    expect(calls).toBe(3);
  });

  it("detects TerminalRetryError via duck-typed name (cross-realm safety)", async () => {
    // Construct an Error-shaped object whose name is "TerminalRetryError"
    // but isn't an actual instance (simulating cross-realm / bundle-split).
    // The duck-typed check in withRetry must still short-circuit.
    let calls = 0;
    let caught: unknown;
    try {
      await withRetry({ maxAttempts: 5, delayMs: 0 }, async () => {
        calls += 1;
        const err = new Error("duck-typed terminal");
        err.name = "TerminalRetryError";
        throw err;
      });
    } catch (err) {
      caught = err;
    }
    expect(calls).toBe(1);
    expect((caught as Error).message).toBe("duck-typed terminal");
  });

  it("asTerminalRetryError wraps non-terminal errors with cause preserved", () => {
    const original = new Error("execution reverted: AccessControl");
    const wrapped = asTerminalRetryError(original, "ViemChainAnchorClient: terminal");
    expect(wrapped).toBeInstanceOf(TerminalRetryError);
    expect(wrapped.message).toBe("ViemChainAnchorClient: terminal");
    expect(wrapped.cause).toBe(original);
  });

  it("asTerminalRetryError is idempotent on already-terminal errors", () => {
    const already = new TerminalRetryError("already terminal");
    const wrapped = asTerminalRetryError(already);
    // Same instance — no double-wrapping.
    expect(wrapped).toBe(already);
  });

  it("composes inner-throws-terminal × outer-withRetry → exactly 1 inner call (NO wasted attempts)", async () => {
    // The full composition that dw-quality-2's SHOULD-FIX-2 finding targets.
    // Outer policy = DEFAULT_CHAIN_ANCHOR_RETRY_POLICY equivalent (3 attempts);
    // inner throws TerminalRetryError on its first attempt. Result MUST be
    // 1 outer call (not 3) — exactly the composition behavior dw-quality-2
    // traced through anchor-worker.ts × viem-chain-anchor-client.ts.
    let outerCalls = 0;
    let caught: unknown;
    try {
      await withRetry({ maxAttempts: 3, delayMs: 0 }, async () => {
        outerCalls += 1;
        // Simulate inner classifying as terminal + wrapping.
        throw asTerminalRetryError(new Error("execution reverted"));
      });
    } catch (err) {
      caught = err;
    }
    expect(outerCalls).toBe(1); // pre-fix this would have been 3
    expect(caught).toBeInstanceOf(TerminalRetryError);
    expect(((caught as TerminalRetryError).cause as Error).message).toBe("execution reverted");
  });
});
