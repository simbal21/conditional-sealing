import type { Address, Hex } from "viem";
import { MultisigActor, type MultisigConfig } from "../types/ceremony.js";
import { CeremonyError, CeremonyErrorCode } from "../errors/index.js";

/**
 * Thin wrapper around `@safe-global/protocol-kit` for constructing Safe
 * transactions for the two distinct multisig actors. Phase A ships the
 * type-level shape + transaction-data builder; Phase B/C/D wire the real
 * SDK when ceremony scripts need on-chain submission.
 *
 * Two-actor invariant per S2-6 §1.1: `CealisSecurityMultisig` and
 * `EmergencyGovernance` are SEPARATE Safe instances. The constructor
 * rejects identical addresses.
 */
export interface SafeTxData {
  readonly to: Address;
  readonly value: bigint;
  readonly data: Hex;
  readonly operation: 0 | 1; // 0 = call, 1 = delegatecall
}

/**
 * In-memory representation of a queued Safe proposal (pre-execTransaction).
 * Built off-chain, signatures collected via EIP-712 off-chain flow per
 * Safe canonical pattern, then submitted via `execTransaction`.
 */
export interface SafeProposal {
  readonly actor: MultisigActor;
  readonly safeAddress: Address;
  readonly txData: SafeTxData;
  readonly nonce: bigint;
  readonly safeTxHash: Hex;
  /** EIP-712 signatures collected from owners (concatenated). */
  readonly signatures: Hex;
  /** Count of owner signatures collected so far. */
  readonly signaturesCollected: number;
  /** Threshold required to execute (matches config.threshold). */
  readonly threshold: number;
}

/**
 * Validate that two multisig configs represent DISTINCT actors. Both
 * actors MUST have different Safe addresses; they MAY share owners.
 *
 * Throws `CEREMONY_ERR_QUORUM_MISSING` if the configs collapse to one
 * Safe — a configuration error that violates §1.1 line 81–86.
 */
export function assertDistinctMultisigs(
  security: MultisigConfig,
  emergency: MultisigConfig,
): void {
  if (security.actor !== MultisigActor.CEALIS_SECURITY) {
    throw new CeremonyError(
      CeremonyErrorCode.QUORUM_MISSING,
      "proposal",
      {
        registryName: security.actor,
      },
    );
  }
  if (emergency.actor !== MultisigActor.EMERGENCY_GOVERNANCE) {
    throw new CeremonyError(
      CeremonyErrorCode.QUORUM_MISSING,
      "proposal",
      {
        registryName: emergency.actor,
      },
    );
  }
  if (
    security.safeAddress.toLowerCase() ===
    emergency.safeAddress.toLowerCase()
  ) {
    throw new CeremonyError(
      CeremonyErrorCode.QUORUM_MISSING,
      "proposal",
      {
        actor: security.actor,
        safeAddress: security.safeAddress,
      },
    );
  }
}

/**
 * Build an unsigned Safe proposal. Real SDK call is deferred to Phase B/C/D
 * — this signature locks the shape ceremony scripts must accept.
 */
export function buildProposal(opts: {
  readonly config: MultisigConfig;
  readonly txData: SafeTxData;
  readonly nonce: bigint;
  readonly safeTxHash: Hex;
}): SafeProposal {
  return Object.freeze({
    actor: opts.config.actor,
    safeAddress: opts.config.safeAddress,
    txData: opts.txData,
    nonce: opts.nonce,
    safeTxHash: opts.safeTxHash,
    signatures: "0x" as Hex,
    signaturesCollected: 0,
    threshold: opts.config.threshold,
  });
}

/**
 * Check whether a proposal has gathered enough signatures to execute.
 */
export function hasQuorum(proposal: SafeProposal): boolean {
  return proposal.signaturesCollected >= proposal.threshold;
}
