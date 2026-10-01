// Gate-recipient pubkey types — byte-exact mirror of M2's
// `GateRecipientPubkeyRegistry.GateRecipientPubkeyEntry` struct +
// `GateKind` enum from `contracts/src/lib/Enums.sol`.
//
// Source of truth: `contracts/out/GateRecipientPubkeyRegistry.sol/
// GateRecipientPubkeyRegistry.json` ABI (`getPubkeyAt` return type).
// `getPubkeyAt` takes 4 params per App. A normative
// (`authorizationId, gateKind, conditionalRecipientIndex, blockNumber`)
// — see SPEC-COMPLIANCE-GUARD-M3 §10.
//
// Doctrine reminder: σ values are NOT key material; KEM material IS
// legitimate hybrid-KEM combiner input per RFC 9180 HPKE. `kemPubkey`
// here is the KEM pubkey portion of a per-gate per-commit binding —
// NOT a σ value.

import type { Hex32 } from "@cealis/v3-crypto";

/**
 * `GateKind` enum — verbatim from M2 `Enums.sol`. The numeric values
 * MUST match the on-chain enum exactly (uint8 layout).
 *
 * Note: there is NO "Subject" GateKind. `Subject` is a SHARE_ROLE_*
 * inside M1's share-record codec, not a gate.
 */
export const GateKind = {
  LitV3: 0,
  Dcipher: 1,
  Drand: 2,
  G4: 3,
  ConditionalRecipient: 4,
} as const;

export type GateKind = (typeof GateKind)[keyof typeof GateKind];

/** Convenience type-guard. */
export function isGateKind(value: number): value is GateKind {
  return value === 0 || value === 1 || value === 2 || value === 3 || value === 4;
}

/** Human-readable label for a `GateKind`. Used in error messages + logs. */
export function gateKindLabel(kind: GateKind): string {
  switch (kind) {
    case GateKind.LitV3:
      return "LitV3";
    case GateKind.Dcipher:
      return "Dcipher";
    case GateKind.Drand:
      return "Drand";
    case GateKind.G4:
      return "G4";
    case GateKind.ConditionalRecipient:
      return "ConditionalRecipient";
  }
}

/**
 * GateRecipientPubkeyEntry — byte-exact mirror of M2 ABI struct.
 *
 * From `getPubkeyAt(...)` tuple component layout:
 * ```
 * struct GateRecipientPubkeyEntry {
 *   bytes32 authorizationId;
 *   uint8   gateKind;
 *   uint16  conditionalRecipientIndex;
 *   bytes   kemPubkey;
 *   bytes32 attestationRef;
 *   uint64  effectiveBlock;
 *   uint64  tombstoneBlock;
 *   bool    perCommitEphemeral;
 * }
 * ```
 *
 * - `authorizationId` is a 32-byte authorization id (`0x` hex via viem).
 * - `gateKind` is `GateKind` (validated via `isGateKind` at the SDK
 *   boundary; stored as plain `number` to match ABI uint8).
 * - `conditionalRecipientIndex` is `0` for non-conditional gates; positive
 *   for conditional-recipient slots.
 * - `kemPubkey` is variable-length bytes — the KEM pubkey shape depends
 *   on gateKind (X25519 / BLS12-381 G1 / P-256 / hybrid).
 * - `attestationRef` is `bytes32` reference to an attestation digest
 *   (committee attestation, DCAP quote digest, etc.).
 * - `effectiveBlock` is the first block at which this entry is signable.
 * - `tombstoneBlock` is `0` if active, or the block at which the entry
 *   was tombstoned (no signatures accepted at or after this block).
 * - `perCommitEphemeral` is `true` for per-commit ephemeral KEM keys
 *   (Lit / G4 / Conditional) and `false` for long-lived committee keys
 *   (drand). Per internal design record `dek-lifecycle.md` line 35,
 *   the drand long-lived KEM is a documented structural weakness whose
 *   compromise leaks at most `TopShare(G3)`.
 */
export interface GateRecipientPubkeyEntry {
  readonly authorizationId: Hex32;
  readonly gateKind: GateKind;
  readonly conditionalRecipientIndex: number;
  readonly kemPubkey: Uint8Array;
  readonly attestationRef: Hex32;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
  readonly perCommitEphemeral: boolean;
}

/**
 * `effectiveBlock <= blockNumber < tombstoneBlock` (or `tombstoneBlock == 0`)
 * Returns true iff the entry is signable at the provided block.
 */
export function isGateRecipientPubkeySignableAt(
  entry: GateRecipientPubkeyEntry,
  blockNumber: bigint,
): boolean {
  if (blockNumber < entry.effectiveBlock) return false;
  if (entry.tombstoneBlock === 0n) return true;
  return blockNumber < entry.tombstoneBlock;
}
