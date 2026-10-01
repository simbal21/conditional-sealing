import type { Address, Hex } from "viem";
import { keccak_256 } from "@noble/hashes/sha3";
import type { ChainClient } from "../../src/ceremony/base.js";
import type { CeremonyEventName } from "../../src/types/ceremony.js";

interface QueuedOp {
  readonly opId: Hex;
  readonly target: Address;
  readonly value: bigint;
  readonly data: Hex;
  readonly predecessor: Hex;
  readonly salt: Hex;
  readonly delaySeconds: bigint;
  readonly queuedAt: bigint;
  cancelled: boolean;
  executed: boolean;
}

export interface MockChainOptions {
  readonly initialBlock?: bigint;
  readonly initialTimestamp?: bigint;
  readonly clockOverride?: () => bigint;
  readonly deprecationFlags?: ReadonlyMap<string, { reasonCode: number; disclosureCid: string | null }>;
}

/**
 * In-memory chain client used by ceremony unit tests. Records every
 * scheduled / executed / cancelled operation; tests assert on these
 * directly. Time advances manually via `advanceBlocks` / `advanceSeconds`.
 */
export class MockChain implements ChainClient {
  private block: bigint;
  private timestamp: bigint;
  private readonly clockOverride: (() => bigint) | undefined;
  private readonly queued = new Map<Hex, QueuedOp>();
  private readonly txLog: { txHash: Hex; description: string }[] = [];
  private nonce = 0;
  private deprecationFlags: Map<string, { reasonCode: number; disclosureCid: string | null }>;
  /** Pre-set events to be emitted on the next execute / multisig call. */
  pendingEvents: { eventName: CeremonyEventName; entryId?: Hex }[] = [];

  constructor(opts: MockChainOptions = {}) {
    this.block = opts.initialBlock ?? 1_000_000n;
    this.timestamp = opts.initialTimestamp ?? BigInt(Math.floor(Date.now() / 1000));
    this.clockOverride = opts.clockOverride;
    this.deprecationFlags = new Map(opts.deprecationFlags ?? new Map());
  }

  async readBlockNumber(): Promise<bigint> {
    return this.block;
  }

  async readBlockTimestamp(): Promise<bigint> {
    return this.clockOverride ? this.clockOverride() : this.timestamp;
  }

  advanceBlocks(n: bigint, secondsPerBlock = 2n): void {
    this.block += n;
    this.timestamp += n * secondsPerBlock;
  }

  advanceSeconds(s: bigint): void {
    this.timestamp += s;
    this.block += s / 2n;
  }

  setDeprecationFlag(key: string, flag: { reasonCode: number; disclosureCid: string | null }): void {
    this.deprecationFlags.set(key, flag);
  }

  async scheduleTimelock(args: {
    readonly target: Address;
    readonly value: bigint;
    readonly data: Hex;
    readonly predecessor: Hex;
    readonly salt: Hex;
    readonly delaySeconds: bigint;
  }): Promise<{ opId: Hex; txHash: Hex; blockNumber: bigint }> {
    const opIdBytes = keccak_256(
      new TextEncoder().encode(
        `${args.target}|${args.value}|${args.data}|${args.predecessor}|${args.salt}`,
      ),
    );
    let hex = "";
    for (const b of opIdBytes) hex += b.toString(16).padStart(2, "0");
    const opId = ("0x" + hex) as Hex;
    const queued: QueuedOp = {
      opId,
      target: args.target,
      value: args.value,
      data: args.data,
      predecessor: args.predecessor,
      salt: args.salt,
      delaySeconds: args.delaySeconds,
      queuedAt: this.timestamp,
      cancelled: false,
      executed: false,
    };
    this.queued.set(opId, queued);
    this.nonce += 1;
    const txHash = this.mintTx("scheduleTimelock");
    const blockNumber = this.block;
    return { opId, txHash, blockNumber };
  }

  async executeTimelock(args: {
    readonly target: Address;
    readonly value: bigint;
    readonly data: Hex;
    readonly predecessor: Hex;
    readonly salt: Hex;
  }): Promise<{
    txHash: Hex;
    blockNumber: bigint;
    events: readonly { eventName: CeremonyEventName; entryId?: Hex }[];
  }> {
    // Locate by recomputing the opId
    const opIdBytes = keccak_256(
      new TextEncoder().encode(
        `${args.target}|${args.value}|${args.data}|${args.predecessor}|${args.salt}`,
      ),
    );
    let hex = "";
    for (const b of opIdBytes) hex += b.toString(16).padStart(2, "0");
    const opId = ("0x" + hex) as Hex;
    const op = this.queued.get(opId);
    if (op === undefined) {
      throw new Error("MOCK_CHAIN_UNKNOWN_OP");
    }
    if (op.cancelled) {
      throw new Error("MOCK_CHAIN_OP_CANCELLED");
    }
    if (this.timestamp < op.queuedAt + op.delaySeconds) {
      throw new Error("MOCK_CHAIN_TIMELOCK_NOT_EXPIRED");
    }
    op.executed = true;
    const txHash = this.mintTx("executeTimelock");
    const events = this.pendingEvents.splice(0, this.pendingEvents.length);
    return { txHash, blockNumber: this.block, events };
  }

  async executeSafeMultisig(args: {
    readonly safeAddress: Address;
    readonly to: Address;
    readonly value: bigint;
    readonly data: Hex;
    readonly signatures: Hex;
  }): Promise<{
    txHash: Hex;
    blockNumber: bigint;
    events: readonly { eventName: CeremonyEventName; entryId?: Hex }[];
  }> {
    void args;
    const txHash = this.mintTx("executeSafeMultisig");
    const events = this.pendingEvents.splice(0, this.pendingEvents.length);
    return { txHash, blockNumber: this.block, events };
  }

  async readDeprecationFlag(args: {
    readonly registry: string;
    readonly entryRef: Hex;
  }): Promise<{ flagSet: boolean; reasonCode: number; disclosureCid: string | null } | null> {
    const key = `${args.registry}:${args.entryRef}`;
    const flag = this.deprecationFlags.get(key);
    if (flag === undefined) return null;
    return {
      flagSet: true,
      reasonCode: flag.reasonCode,
      disclosureCid: flag.disclosureCid,
    };
  }

  async cancelTimelock(opId: Hex): Promise<{ txHash: Hex }> {
    const op = this.queued.get(opId);
    if (op !== undefined) {
      op.cancelled = true;
    }
    return { txHash: this.mintTx("cancelTimelock") };
  }

  private mintTx(description: string): Hex {
    const seed = `tx-${this.nonce}-${this.block}-${this.timestamp}-${description}`;
    this.nonce += 1;
    const digest = keccak_256(new TextEncoder().encode(seed));
    let hex = "";
    for (const b of digest) hex += b.toString(16).padStart(2, "0");
    const txHash = ("0x" + hex) as Hex;
    this.txLog.push({ txHash, description });
    return txHash;
  }

  txCount(): number {
    return this.txLog.length;
  }

  getQueued(opId: Hex): QueuedOp | undefined {
    return this.queued.get(opId);
  }
}
