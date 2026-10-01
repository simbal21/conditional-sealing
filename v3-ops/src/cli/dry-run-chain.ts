import type { Address, Hex } from "viem";
import type { ChainClient } from "../ceremony/base.js";
import type { CeremonyEventName } from "../types/ceremony.js";

/**
 * In-memory chain client used by the M7 CLI dry-run path. Returns
 * synthetic-but-deterministic responses so a ceremony's full lifecycle
 * runs without touching a real RPC. Phase F Anvil-fork integration tests
 * use viem-backed clients; M8 wires the production client.
 *
 * For each `executeTimelock` / `executeSafeMultisig` call the chain
 * returns the events pre-loaded into `pendingEvents`. CLI handlers seed
 * these from the ceremony's `expectedEvents` so verify() passes in
 * dry-run.
 */
export class DryRunNoopChain implements ChainClient {
  pendingEvents: { eventName: CeremonyEventName; entryId?: Hex }[] = [];
  private block = 1_000_000n;
  private timestamp = BigInt(Math.floor(Date.now() / 1000));

  async readBlockNumber(): Promise<bigint> {
    return this.block;
  }
  async readBlockTimestamp(): Promise<bigint> {
    return this.timestamp;
  }
  async scheduleTimelock(args: {
    readonly target: Address;
    readonly value: bigint;
    readonly data: Hex;
    readonly predecessor: Hex;
    readonly salt: Hex;
    readonly delaySeconds: bigint;
  }): Promise<{ opId: Hex; txHash: Hex; blockNumber: bigint }> {
    void args;
    const opId = ("0x" + "ab".repeat(32)) as Hex;
    const txHash = ("0x" + "cd".repeat(32)) as Hex;
    return { opId, txHash, blockNumber: this.block };
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
    void args;
    const events = this.pendingEvents.splice(0, this.pendingEvents.length);
    return { txHash: ("0x" + "ef".repeat(32)) as Hex, blockNumber: this.block, events };
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
    const events = this.pendingEvents.splice(0, this.pendingEvents.length);
    return { txHash: ("0x" + "01".repeat(32)) as Hex, blockNumber: this.block, events };
  }
  async readDeprecationFlag(args: {
    readonly registry: string;
    readonly entryRef: Hex;
  }): Promise<{ flagSet: boolean; reasonCode: number; disclosureCid: string | null } | null> {
    void args;
    return null;
  }
  async cancelTimelock(opId: Hex): Promise<{ txHash: Hex }> {
    void opId;
    return { txHash: ("0x" + "02".repeat(32)) as Hex };
  }
}
