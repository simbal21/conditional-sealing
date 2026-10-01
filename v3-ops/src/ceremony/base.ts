import type { Address, Hex } from "viem";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";
import {
  createLogger,
  defaultLogPath,
  type CeremonyLogger,
} from "../logging/index.js";
import {
  GovernancePath,
  type CeremonyContext,
  type CeremonyEventName,
} from "../types/index.js";
import {
  STANDARD_TIMELOCK_DELAY_SECONDS,
  EXPEDITED_DEPRECATION_DELAY_SECONDS,
  type TimelockOperation,
} from "../multisig/index.js";

/**
 * Abstract chain client used by every ceremony. Real implementations wrap
 * a viem `WalletClient` + `PublicClient`; tests use the in-memory mock
 * in `tests/_fixtures/mock-chain.ts`. Phase F Anvil integration tests
 * substitute a viem-backed client speaking to a forked Base Sepolia.
 */
export interface ChainClient {
  /** Read the current block number (used for queue + observation windows). */
  readBlockNumber(): Promise<bigint>;
  /** Read the current chain timestamp (unix seconds). */
  readBlockTimestamp(): Promise<bigint>;
  /** Submit a TimelockController.schedule(...) tx. Returns the op id. */
  scheduleTimelock(args: {
    readonly target: Address;
    readonly value: bigint;
    readonly data: Hex;
    readonly predecessor: Hex;
    readonly salt: Hex;
    readonly delaySeconds: bigint;
  }): Promise<{ opId: Hex; txHash: Hex; blockNumber: bigint }>;
  /** Submit a TimelockController.execute(...) tx after delay. */
  executeTimelock(args: {
    readonly target: Address;
    readonly value: bigint;
    readonly data: Hex;
    readonly predecessor: Hex;
    readonly salt: Hex;
  }): Promise<{ txHash: Hex; blockNumber: bigint; events: readonly { eventName: CeremonyEventName; entryId?: Hex }[] }>;
  /** Submit a Safe execTransaction(...) for a multisig action. */
  executeSafeMultisig(args: {
    readonly safeAddress: Address;
    readonly to: Address;
    readonly value: bigint;
    readonly data: Hex;
    readonly signatures: Hex;
  }): Promise<{ txHash: Hex; blockNumber: bigint; events: readonly { eventName: CeremonyEventName; entryId?: Hex }[] }>;
  /** Read a registry deprecation flag (if present). */
  readDeprecationFlag(args: {
    readonly registry: string;
    readonly entryRef: Hex;
  }): Promise<{ flagSet: boolean; reasonCode: number; disclosureCid: string | null } | null>;
  /** Cancel a queued timelock operation (abort path per §20). */
  cancelTimelock(opId: Hex): Promise<{ txHash: Hex }>;
}

/**
 * The 7 lifecycle stages every ceremony walks. Every stage either emits
 * one logger line OR throws a `CeremonyError`. No silent skips.
 */
export type CeremonyLifecycleStage =
  | "proposal"
  | "queue"
  | "observation"
  | "execute"
  | "verify"
  | "abort"
  | "complete";

export interface CeremonyOutcome {
  readonly ceremonyId: string;
  readonly slug: string;
  readonly success: boolean;
  readonly dryRun: boolean;
  readonly proposalHash: Hex;
  readonly governancePath: GovernancePath;
  readonly stagesReached: readonly CeremonyLifecycleStage[];
  readonly emittedEvents: readonly CeremonyEventName[];
  readonly logFile: string;
  readonly txHashes: readonly Hex[];
  readonly opId: Hex | null;
  readonly abortReason?: string;
}

/**
 * Common ceremony runtime — every ceremony script in `src/ceremony/`
 * extends this, providing a per-spec `proposal()` / `execute()` /
 * `verify()` implementation.
 *
 * Sub-classes are responsible for emitting allow-listed log fields only
 * (the wrapper rejects PII-leaking emissions). Sub-classes MUST NOT bypass
 * `logger.log` for free-text printf-style output.
 */
export interface CeremonyRunArgs {
  readonly context: CeremonyContext;
  readonly chain: ChainClient;
}

export abstract class Ceremony {
  abstract readonly slug: string;
  abstract readonly specSection: string;
  abstract readonly catalogRowNumber: number;
  abstract readonly governancePath: GovernancePath;

  protected logger: CeremonyLogger | null = null;
  protected stagesReached: CeremonyLifecycleStage[] = [];
  protected emittedEvents: CeremonyEventName[] = [];
  protected txHashes: Hex[] = [];
  protected opId: Hex | null = null;

  /** Build the on-chain calldata + deterministic proposal hash. */
  abstract proposal(args: CeremonyRunArgs): Promise<{
    proposalHash: Hex;
    target: Address;
    data: Hex;
    salt: Hex;
  }>;

  /** Queue the operation through TimelockController or Safe multisig. */
  abstract queue(args: CeremonyRunArgs, proposal: Awaited<ReturnType<this["proposal"]>>): Promise<void>;

  /** Execute after governance delay (if any) — apply the state change. */
  abstract execute(args: CeremonyRunArgs, proposal: Awaited<ReturnType<this["proposal"]>>): Promise<void>;

  /** Verify the post-execution state matches the proposal. */
  abstract verify(args: CeremonyRunArgs, proposal: Awaited<ReturnType<this["proposal"]>>): Promise<void>;

  async run(args: CeremonyRunArgs): Promise<CeremonyOutcome> {
    this.logger = createLogger({
      logFile: args.context.logFile,
      dryRun: args.context.dryRun,
    });
    this.stagesReached = [];
    this.emittedEvents = [];
    this.txHashes = [];
    this.opId = null;

    let proposal: {
      proposalHash: Hex;
      target: Address;
      data: Hex;
      salt: Hex;
    } | null = null;

    try {
      proposal = await this.proposal(args);
      this.stagesReached.push("proposal");
      await this.logger.log({
        ceremonyId: args.context.ceremonyId,
        level: "info",
        stage: "proposal",
        message: "proposal_built",
        fields: {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: proposal.proposalHash,
          specSection: this.specSection,
          governancePath: this.governancePath,
          dryRun: args.context.dryRun,
        },
      });

      await this.queue(args, proposal as never);
      this.stagesReached.push("queue");
      this.stagesReached.push("observation");

      await this.execute(args, proposal as never);
      this.stagesReached.push("execute");

      await this.verify(args, proposal as never);
      this.stagesReached.push("verify");
      this.stagesReached.push("complete");

      await this.logger.log({
        ceremonyId: args.context.ceremonyId,
        level: "audit",
        stage: "complete",
        message: "ceremony_completed",
        fields: {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          proposalHash: proposal.proposalHash,
          dryRun: args.context.dryRun,
        },
      });

      return {
        ceremonyId: args.context.ceremonyId,
        slug: this.slug,
        success: true,
        dryRun: args.context.dryRun,
        proposalHash: proposal.proposalHash,
        governancePath: this.governancePath,
        stagesReached: Object.freeze([...this.stagesReached]),
        emittedEvents: Object.freeze([...this.emittedEvents]),
        logFile: args.context.logFile,
        txHashes: Object.freeze([...this.txHashes]),
        opId: this.opId,
      };
    } catch (e) {
      const isCeremonyError = e instanceof CeremonyError;
      const code = isCeremonyError ? e.code : "UNKNOWN";
      this.stagesReached.push("abort");
      await this.logger.log({
        ceremonyId: args.context.ceremonyId,
        level: "error",
        stage: "abort",
        message: "ceremony_aborted",
        fields: {
          ceremonyId: args.context.ceremonyId,
          ceremonySlug: this.slug,
          errorCode: code,
          dryRun: args.context.dryRun,
        },
      });
      // Re-throw so callers (tests, CLI) can surface the exact error.
      throw e;
    }
  }

  /** Emit an event into the per-ceremony event log (allow-listed names only). */
  protected recordEvent(name: CeremonyEventName): void {
    this.emittedEvents.push(name);
  }

  protected recordTx(tx: Hex): void {
    this.txHashes.push(tx);
  }
}

/**
 * Helper for sub-classes: build a `CeremonyContext` with sensible defaults.
 */
export function makeContext(opts: {
  readonly ceremonyId: `0x${string}`;
  readonly proposalHash?: `0x${string}`;
  readonly commitBlock: bigint;
  readonly chainId: number;
  readonly dryRun: boolean;
  readonly slug: string;
  readonly logRoot?: string;
}): CeremonyContext {
  return Object.freeze({
    ceremonyId: opts.ceremonyId,
    proposalHash: opts.proposalHash ?? "0x" + "00".repeat(32) as `0x${string}`,
    commitBlock: opts.commitBlock,
    chainId: opts.chainId,
    dryRun: opts.dryRun,
    logFile: defaultLogPath(opts.slug, opts.logRoot),
  });
}

/**
 * Return the canonical timelock delay for a governance path. Throws
 * `CEREMONY_ERR_GOVERNANCE_TIMEOUT` if an unsupported path is requested.
 */
export function delayForPath(path: GovernancePath): bigint {
  switch (path) {
    case GovernancePath.TIMELOCK_7D_ADDITION:
    case GovernancePath.COOLDOWN_30D:
      return BigInt(STANDARD_TIMELOCK_DELAY_SECONDS);
    case GovernancePath.EXPEDITED_24H_DEPRECATION:
      return BigInt(EXPEDITED_DEPRECATION_DELAY_SECONDS);
    case GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION:
      return 0n;
    case GovernancePath.AUTO_CLEAR_72H:
      return BigInt(72 * 60 * 60);
    default:
      throw new CeremonyError(
        CeremonyErrorCode.GOVERNANCE_TIMEOUT,
        "proposal",
        { governancePath: path },
      );
  }
}

export type { TimelockOperation };
