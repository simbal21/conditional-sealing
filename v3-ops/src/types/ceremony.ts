import type { Address, Hex } from "viem";

/**
 * Common types shared across the 17-ceremony catalog. Per-ceremony scripts
 * import these from `@cealis/v3-ops/types`.
 */

/**
 * Governance paths recognized by S2-6 §13.6 (asymmetric registry
 * governance). Five distinct paths.
 */
export const GovernancePath = {
  TIMELOCK_7D_ADDITION: "timelock-7d-addition",
  EXPEDITED_24H_DEPRECATION: "expedited-24h-canonical-in-use-deprecation",
  INSTANT_NON_CANONICAL_DEPRECATION: "instant-non-canonical-deprecation",
  AUTO_CLEAR_72H: "permissionless-72h-auto-clear",
  COOLDOWN_30D: "30-day-post-auto-clear-cooldown",
} as const;

export type GovernancePath = (typeof GovernancePath)[keyof typeof GovernancePath];

export const GOVERNANCE_PATHS: readonly GovernancePath[] = Object.freeze([
  GovernancePath.TIMELOCK_7D_ADDITION,
  GovernancePath.EXPEDITED_24H_DEPRECATION,
  GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION,
  GovernancePath.AUTO_CLEAR_72H,
  GovernancePath.COOLDOWN_30D,
]);

/**
 * Multisig actor ids per S2-6 §1.1. Two DISTINCT Safe instances must be
 * configured: CealisSecurityMultisig and EmergencyGovernance. Foundation
 * test asserts distinctness.
 */
export const MultisigActor = {
  CEALIS_SECURITY: "CealisSecurityMultisig",
  EMERGENCY_GOVERNANCE: "EmergencyGovernance",
} as const;

export type MultisigActor = (typeof MultisigActor)[keyof typeof MultisigActor];

export interface MultisigConfig {
  readonly actor: MultisigActor;
  readonly safeAddress: Address;
  readonly threshold: number;
  readonly owners: readonly Address[];
  readonly chainId: number;
  readonly roleHash: Hex;
}

/**
 * Per-PDA / per-commit context a ceremony reads at runtime. `commit_block`
 * is REQUIRED for any registry lookup per §1.3 NORMATIVE.
 */
export interface CeremonyContext {
  readonly ceremonyId: `0x${string}`;
  readonly proposalHash: `0x${string}`;
  readonly commitBlock: bigint;
  readonly chainId: number;
  readonly dryRun: boolean;
  readonly logFile: string;
}

/**
 * Phase a G4 entry belongs to. Phase 1 = dev/scaffold sealed-code server,
 * Phase 2 = rented TEE with DCAP attestation (legal-effect & partner-ready).
 */
export const G4Phase = {
  PHASE_1: 1,
  PHASE_2: 2,
} as const;

export type G4Phase = (typeof G4Phase)[keyof typeof G4Phase];

/**
 * Ceremony catalog row per S2-6 §2 + §16.5. Used in
 * `src/catalog/ceremonies.ts` to build the 17-row CEREMONY_CATALOG.
 */
export interface CeremonyCatalogRow {
  /** Position in §2 catalog (1..16) or 17 for §16.5 Phase 2 transition */
  readonly number: number;
  /** Slug used by the CLI (`cealis-ops <slug>`) */
  readonly slug: string;
  /** Display name verbatim from §2 / §16.5 */
  readonly name: string;
  /** Allowed governance shapes (one or more) */
  readonly governance: readonly GovernancePath[];
  /** Registry / contract surfaces touched */
  readonly surfaces: readonly string[];
  /** Spec section anchor (e.g. "§3", "§16.5") */
  readonly specSection: string;
}

/**
 * Pause / shred / challenge / disclosure event names per S2-6 §18 logical
 * mapping (S2-2 owns exact ABI names). Free-text emission is forbidden;
 * pick one.
 */
export type CeremonyEventName =
  | "EntryAdded"
  | "EntryTombstoned"
  | "DeprecationFlagSet"
  | "DisclosurePublished"
  | "DeprecationAutoCleared"
  | "OracleAdded"
  | "OracleSchemaAdded"
  | "OracleAttestationAccepted"
  | "CommitSuperseded"
  | "DSLVersionUsed"
  | "ShredRequested"
  | "ShredFinalized"
  | "ChallengeOpened"
  | "ChallengeResolved"
  | "ChallengeExtended"
  | "ChallengeWithdrawn"
  | "VaultTransitionQueued"
  | "VaultTransitionFinalized"
  | "RefusalSignal"
  | "RefusalReasonPublic"
  | "RefusalReasonEncrypted"
  | "AdvisorySignal"
  | "SecurityCouncilSuspended"
  | "SecurityCouncilRestored"
  | "SecurityAuthoritySuspended"
  | "RoleGranted"
  | "RoleRevoked"
  | "GovernancePostureAnnounced"
  | "PauseActivated"
  | "PauseDeactivated"
  | "PauseAutoLifted"
  | "GateRecipientPubkeyPublished"
  | "LitAssignmentRecorded"
  | "RevealAuthorized"
  | "PDARegistered"
  | "PartnerRegistered";
