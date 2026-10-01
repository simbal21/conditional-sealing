// Refusal-code types — verbatim from S2-3 §7.7 + M2's
// `G4RefusalRegistry.sol`. 10 codes total (NOT 5 — V1 PoF's 5-code enum
// is forbidden in V3 per SPEC-COMPLIANCE-GUARD-M3 §2).
//
// Codes 0x01..0x09 are BLOCKING (refuse + halt the gate-signing path).
// Code 0x0A is ADVISORY (signal-only; does NOT block).
// Codes 0x02 and 0x03 use ENCRYPTED-REASON mode per §7.7: the reason
// is recorded as an encrypted blob on-chain and MUST NOT appear in
// logs/error messages in plaintext.
//
// Source verification: M2 contract constants:
//   REASON_LEGAL_COMPEL          == 0x01
//   REASON_ART_17_ERASURE        == 0x02  (encrypted reason mode)
//   REASON_ART_18_RESTRICTION    == 0x03  (encrypted reason mode)
//   REASON_INTEGRITY_FAIL        == 0x04
//   REASON_CHAIN_MISMATCH        == 0x05
//   REASON_PLUGIN_DEPRECATED     == 0x06
//   REASON_AUTHORITY_DEPRECATED  == 0x07
//   REASON_DSL_DEPRECATED        == 0x08
//   REASON_ORACLE_DEPRECATED     == 0x09
//   REASON_OPT_OUT_ACTIVE        == 0x0A  (advisory only)

import type { Hex32 } from "@cealis/v3-crypto";

/**
 * 10-code refusal enum — byte-exact mirror of M2
 * `G4RefusalRegistry` constants. Numeric values match the on-chain
 * `uint8 reasonCode` parameter.
 */
export const RefusalCode = {
  LegalCompel: 0x01,
  Art17Erasure: 0x02,
  Art18Restriction: 0x03,
  IntegrityFail: 0x04,
  ChainMismatch: 0x05,
  PluginDeprecated: 0x06,
  AuthorityDeprecated: 0x07,
  DslDeprecated: 0x08,
  OracleDeprecated: 0x09,
  OptOutActive: 0x0a,
} as const;

export type RefusalCodeValue = (typeof RefusalCode)[keyof typeof RefusalCode];

/**
 * `refusalState(authorizationId)` return tuple shape — mirrors the
 * `G4RefusalRegistry.refusalState(...)` view signature
 * `(bool refused, uint8 reasonCode, bool encrypted)`.
 */
export interface RefusalState {
  readonly refused: boolean;
  readonly reasonCode: number; // raw uint8 from chain; 0 if !refused
  readonly encrypted: boolean;
}

/**
 * `signalState(authorizationId)` return tuple shape — for advisory
 * code 0x0A. Mirrors `(bool signaled, uint8 reasonCode)`.
 */
export interface SignalState {
  readonly signaled: boolean;
  readonly reasonCode: number;
}

/**
 * `RefusalSignal` event payload shape per M2 ABI:
 *   `RefusalSignal(authorizationId:bytes32, hCommit:bytes32, reasonCode:uint8, blocking:bool)`
 */
export interface RefusalSignalEvent {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly reasonCode: number;
  readonly blocking: boolean;
}

/**
 * `AdvisorySignal` event payload shape per M2 ABI:
 *   `AdvisorySignal(authorizationId:bytes32, hCommit:bytes32, reasonCode:uint8)`
 */
export interface AdvisorySignalEvent {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly reasonCode: number;
}

/**
 * `RefusalReasonEncrypted` event for §7.7 encrypted-reason mode
 * (`reasonCode == 0x02` Art. 17 or `0x03` Art. 18).
 *   `RefusalReasonEncrypted(authorizationId:bytes32, encryptedReasonBlob:bytes)`
 *
 * NOTE: the plaintext reason MUST NOT be derived from this blob outside
 * the legally-authorized decryption boundary per SPEC-COMPLIANCE-GUARD-M3 §3.
 */
export interface RefusalReasonEncryptedEvent {
  readonly authorizationId: Hex32;
  readonly encryptedReasonBlob: Uint8Array;
}

/**
 * `RefusalReasonPublic` event for non-encrypted refusal disclosure.
 *   `RefusalReasonPublic(authorizationId:bytes32, reasonCode:uint8, proofRef:bytes32)`
 */
export interface RefusalReasonPublicEvent {
  readonly authorizationId: Hex32;
  readonly reasonCode: number;
  readonly proofRef: Hex32;
}
