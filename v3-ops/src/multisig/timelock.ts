import type { Address, Hex } from "viem";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";

/**
 * Thin TimelockController helper. M2's `CealisTimelockController` enforces
 * a 7-day default delay per S2-6 §1.2.
 *
 * Phase A ships type-level + offline arithmetic helpers; Phase B/C/D wire
 * real viem calls when ceremony scripts queue / execute on chain.
 */

export const STANDARD_TIMELOCK_DELAY_SECONDS = 7 * 24 * 60 * 60;
export const EXPEDITED_DEPRECATION_DELAY_SECONDS = 24 * 60 * 60;

export interface TimelockOperation {
  readonly id: Hex;
  readonly target: Address;
  readonly value: bigint;
  readonly data: Hex;
  readonly predecessor: Hex;
  readonly salt: Hex;
  /** Block timestamp (unix seconds) when scheduled. */
  readonly queuedAt: bigint;
  /** Delay applied (e.g. 7d default). */
  readonly delaySeconds: bigint;
}

export function readyAt(op: TimelockOperation): bigint {
  return op.queuedAt + op.delaySeconds;
}

export function isReady(op: TimelockOperation, nowSeconds: bigint): boolean {
  return nowSeconds >= readyAt(op);
}

/**
 * Throw if the operation is not yet executable. Used by ceremony scripts'
 * `execute` step.
 */
export function assertReady(op: TimelockOperation, nowSeconds: bigint): void {
  if (!isReady(op, nowSeconds)) {
    throw new CeremonyError(
      CeremonyErrorCode.TIMELOCK_NOT_EXPIRED,
      "execute",
      {
        proposalHash: op.id,
        effectiveBlock: readyAt(op),
      },
    );
  }
}

/**
 * Cancellation primitive — TimelockController emits `Cancelled` per
 * S2-6 §20.1 abort discipline. Phase B/C/D wire the real abort call.
 */
export function buildCancelTx(opId: Hex): { selector: Hex; opId: Hex } {
  // OpenZeppelin TimelockController `cancel(bytes32)` 4-byte selector.
  const cancelSelector = "0xc4d252f5" as Hex;
  return { selector: cancelSelector, opId };
}
