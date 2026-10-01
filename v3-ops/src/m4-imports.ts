/**
 * M4 configurator imports — PDA+ governance sub-class types. M7 §10A
 * pda-plus-governance-update consumes M4 types via this re-export layer.
 *
 * Phase A locks the surface; Phase C ceremony script wires real M4 reads.
 */
import type { Hex } from "viem";

/**
 * PDA+ governance sub-class per S2-4 §6.1-§6.7 + S2-6 §10A.1 table.
 */
export const PdaPlusSubClass = {
  /** Sub-class 1: TimelockController-7d additions */
  ADDITION_7D: 1,
  /** Sub-class 2: CealisSecurityMultisig deprecations */
  DEPRECATION_MULTISIG: 2,
  /** Sub-class 3: CealisSecurityMultisig with circuit breaker */
  EMERGENCY_CIRCUIT_BREAKER: 3,
  /** Sub-class 4: PDA+ conditional-rule constraint adjustment */
  CONSTRAINT_ADJUSTMENT: 4,
  /** Sub-class 5: PDA+ conditional-rule addition (codepath-bound) */
  RULE_ADDITION: 5,
} as const;

export type PdaPlusSubClass = (typeof PdaPlusSubClass)[keyof typeof PdaPlusSubClass];

export const PDA_PLUS_SUB_CLASSES: readonly PdaPlusSubClass[] = Object.freeze([
  PdaPlusSubClass.ADDITION_7D,
  PdaPlusSubClass.DEPRECATION_MULTISIG,
  PdaPlusSubClass.EMERGENCY_CIRCUIT_BREAKER,
  PdaPlusSubClass.CONSTRAINT_ADJUSTMENT,
  PdaPlusSubClass.RULE_ADDITION,
]);

/**
 * Minimal PDA+ governance proposal packet shape. Real M4 packet schema is
 * larger; M7 ceremony scripts compose this from M4 types.
 */
export interface PdaPlusProposalPacket {
  readonly subClass: PdaPlusSubClass;
  readonly addedContentRef: Hex;
  readonly affectedArchetypes: readonly string[];
  readonly validationStage: number;
  readonly sourceDigest: Hex;
  readonly auditDigest: Hex;
  readonly testDigest: Hex;
  readonly simulationVectorHash: Hex;
  readonly effectiveBlock: bigint;
  readonly inspectionRenderingHash: Hex;
}
