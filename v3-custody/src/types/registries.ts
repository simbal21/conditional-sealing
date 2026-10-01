// V3 registry entry shapes — adapter-facing typed views over M2 ABI returns.
//
// Class split per internal design record `v3-registry-class-discipline.md`:
//
//   class-CRYPTO  (TAG-prefixed lookup-key discipline upstream):
//     - PluginHashRegistry   (TAG_PLUGIN_VERSION_V3)
//     - G4AuthorityRegistry  (TAG_G4_ATTESTATION_AUTHORITY_V3)
//     - OracleRegistry       (TAG_ORACLE_REGISTRY_V3)
//
//   class-CATALOG (raw 32-byte refs with upstream `TAG_AAD_V3` /
//                  `pda_root` wrapping):
//     - DSLVersionRegistry
//     - QTSPRegistry
//
// S2-3 §9.1: SDK consumers receive these as adapter-facing types after
// the chain reader decodes the raw ABI tuples. The raw `encodedEntry`
// bytes (from `getEntryAt`) are NOT exposed here; concrete decoders live
// in the chain reader.

import type { Hex32 } from "@cealis/v3-crypto";

/**
 * G4AuthorityEntry — Cealis governance entity authorized to publish G4
 * binary-hash-or-measurement attestations. Mirrors S2-3 §9.6 +
 * internal design record `v3-registry-class-discipline.md` class-CRYPTO
 * shape (TAG-prefixed lookup-key, sub-class enum, effective/tombstone blocks).
 */
export interface G4AuthorityEntry {
  readonly g4AuthorityRef: Hex32;
  /** Binary hash or hardware measurement (HW root-of-trust digest). */
  readonly binaryHashOrMeasurement: Hex32;
  readonly attestationFormat: number; // uint8 enum (Phase 1 Ed25519 attestation / Phase 2 DCAP)
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
  readonly deprecated: boolean;
}

/**
 * PluginHashRegistry entry — combiner self-verifies its own binary
 * hash against this entry before any σ handling per
 * SPEC-COMPLIANCE-GUARD-M3 §7. Read at `authorizationBlock`, NOT current
 * head, per PRO-499 R3 + S2-3 §9.3 + §9.6.
 */
export interface PluginEntry {
  readonly pluginVersionDigest: Hex32;
  readonly binaryHashOrMeasurement: Hex32;
  readonly governanceMetadata: Hex32;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
  readonly deprecated: boolean;
}

/**
 * Oracle registry entry — authorized oracle signing key(s) for
 * attestation-gate evaluation. Mirrors `OracleRegistry.getOracleAt(...)`.
 */
export interface OracleEntry {
  readonly oracleId: Hex32;
  readonly oraclePubkeyOrAddress: Uint8Array;
  readonly schemaIds: readonly Hex32[];
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
  readonly deprecated: boolean;
}

/**
 * DSL version registry entry — class-CATALOG. Raw ref form;
 * domain separation is provided by upstream `TAG_AAD_V3` wrapping
 * (NOT by an inner TAG_DSL_VERSION_V3 — none exists by design per
 * v3-registry-class-discipline.md).
 */
export interface DSLVersionEntry {
  readonly dslVersionRef: Hex32;
  readonly grammarHash: Hex32;
  readonly evaluatorBinaryHash: Hex32;
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
  readonly deprecated: boolean;
}

/**
 * QTSP registry entry — class-CATALOG (Qualified Trust Service
 * Provider directory per eIDAS). Currently a thin record; the registry
 * is informational and lookup-only.
 */
export interface QTSPEntry {
  readonly qtspProviderRef: Hex32;
  readonly providerName: string; // ASCII; on-chain stored as bytes
  readonly memberState: string; // ISO country code; on-chain stored as bytes2
  readonly effectiveBlock: bigint;
  readonly tombstoneBlock: bigint;
  readonly deprecated: boolean;
}

/**
 * Lit V3 assignment record — `LitV3Assignment.getAssignment(authorizationId)`
 * return tuple. Per S2-3 §3.3, the assignment carries the assigned TEE
 * identity which must be cross-vendor-disjoint from G4 Phase 2 TEE.
 */
export interface LitAssignmentRecord {
  readonly authorizationId: Hex32;
  readonly assignedTeeId: Hex32;
  readonly assignmentBlock: bigint;
  readonly assignedTeePubkey: Uint8Array;
  readonly sourceGovernanceDigest: Hex32;
}

/**
 * RegistrySnapshot — combiner uses this to bind every registry read
 * to a specific `blockNumber` per S2-3 §9.1 + PRO-499 R3.
 * Two snapshots are taken per reveal (S2-3 §2.5):
 *   - `commitBlock`   for stanza/wrap binding verification
 *   - `authorizationBlock` for σ authority + assignment + tombstone +
 *                          deprecation + refusal verification
 */
export interface RegistrySnapshot {
  readonly blockNumber: bigint;
  readonly chainId: number;
  readonly blockHash: Hex32;
  /** When was the snapshot taken (clock-only; not load-bearing). */
  readonly observedAt: bigint;
}

/**
 * Current shred state for a commit-hash. Mirrors
 * `ShredRegistry.currentShredState(hCommit)` returning `uint8`.
 * The enum values are M2's `ShredState` enum (verbatim, Enums.sol):
 *   0 None, 1 Requested, 2 Authorized, 3 Finalized, 4 Blocked,
 *   5 ChallengeOpen, 6 Shredded.
 */
export const ShredState = {
  None: 0,
  Requested: 1,
  Authorized: 2,
  Finalized: 3,
  Blocked: 4,
  ChallengeOpen: 5,
  Shredded: 6,
} as const;

export type ShredStateValue = (typeof ShredState)[keyof typeof ShredState];

/**
 * Returns true iff the current state allows gates to sign / shares to be
 * admitted. Per SPEC-COMPLIANCE-GUARD-M3 §15 step 4, this is the
 * current-state safety read taken immediately before σ admission.
 *
 * Signable when: state is `None` (no shred request pending) OR
 * `Requested` (request open but not yet authorized). `Authorized`,
 * `Finalized`, `Shredded` block. `Blocked` blocks (admin intervention).
 * `ChallengeOpen` blocks (race condition: post-challenge reveal in progress
 * mandates `NOT shred` per internal project constitution §0).
 */
export function isShredStateSignable(state: ShredStateValue): boolean {
  return state === ShredState.None || state === ShredState.Requested;
}
