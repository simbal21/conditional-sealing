// σ evidence bundle types — per S2-3 §9.1 normative shapes.
//
// SECURITY NOTE: per S2-3 §1.2/§1.4/§14.1 and SPEC-COMPLIANCE-GUARD-M3
// §17/§18, σ values in this bundle MUST be carried as opaque
// `SigmaBuffer` instances when crossing process / log / JSON
// boundaries. Codex combiner code MUST NOT `JSON.stringify` a bundle
// containing raw σ bytes; the bundle's σ fields are typed as
// `Uint8Array` for in-process use only and wrap-conversion to
// `SigmaBuffer` happens at boundary points.

import type { Hex32 } from "@cealis/v3-crypto";
import type {
  GateRecipientPubkeyEntry,
  GateKind,
} from "./gate-recipient.js";
import type { RefusalState } from "./refusal.js";
import type {
  G4AuthorityEntry,
  PluginEntry,
  LitAssignmentRecord,
  RegistrySnapshot,
  ShredStateValue,
} from "./registries.js";

/**
 * σ evidence per gate. Each entry includes the σ bytes (opaque
 * in-process), the gate-kind identifier, and the recovered
 * `GateRecipientPubkeyEntry` against which the σ was checked.
 */
export interface SigmaEvidence {
  readonly gateKind: GateKind;
  /** Conditional-recipient index for `GateKind.ConditionalRecipient`, else 0. */
  readonly conditionalRecipientIndex: number;
  /** Process-memory-only σ bytes. WRAP IN `SigmaBuffer` at SDK boundary. */
  readonly sigmaBytes: Uint8Array;
  /** Gate recipient pubkey entry against which σ was verified. */
  readonly gateRecipientPubkey: GateRecipientPubkeyEntry;
  /** Per-gate verification metadata (e.g. drand round, Lit assignment id). */
  readonly metadata: Readonly<Record<string, string | number | bigint | Hex32>>;
}

/**
 * Aggregate σ evidence for one reveal. Combiner consumes this.
 */
export interface SigmaEvidenceBundle {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly authorizationBlock: bigint;
  readonly commitBlock: bigint;
  readonly evidence: readonly SigmaEvidence[];
}

/**
 * Commit-block registry snapshot — values read at `commitBlock` for
 * stanza/wrap binding verification per S2-3 §2.5 + §9.1.
 */
export interface CommitRegistrySnapshot {
  readonly snapshot: RegistrySnapshot;
  /** Active plugin entry at commitBlock (for stanza-wrap reproducibility). */
  readonly plugin: PluginEntry;
  /**
   * Gate-recipient pubkeys for all gates participating in this commit,
   * keyed by `${gateKind}:${conditionalRecipientIndex}`.
   */
  readonly gateRecipientPubkeys: ReadonlyMap<string, GateRecipientPubkeyEntry>;
}

/**
 * Authorization-block registry snapshot — values read at
 * `authorizationBlock` for σ authority + assignment + tombstone +
 * deprecation + refusal verification per S2-3 §2.5 + §9.1.
 */
export interface AuthorizationRegistrySnapshot {
  readonly snapshot: RegistrySnapshot;
  /** Active G4 authority entry at authorizationBlock (if G4 participates). */
  readonly g4Authority?: G4AuthorityEntry;
  /** Active Lit V3 assignment record at authorizationBlock (if Lit participates). */
  readonly litAssignment?: LitAssignmentRecord;
  /** Current refusal state (refused / advisory-only / clean). */
  readonly refusalState: RefusalState;
  /** Current shred state for `hCommit`. */
  readonly currentShredState: ShredStateValue;
  /** Whether gates can sign at authorizationBlock (composite check). */
  readonly canGatesSign: boolean;
}

/**
 * DecryptResult — combiner's top-level return. Either successful
 * decryption (yields plaintext + RevealArtifactBundle digest) or a
 * structured failure carrying the operational error code and an
 * optional forensic sub-code chain.
 *
 * SECURITY NOTE: per S2-3 §9.7, NO partial plaintext is returned on
 * failure. The `plaintext` field is only present on `ok: true`.
 */
export type DecryptResult =
  | { readonly ok: true; readonly plaintext: Uint8Array; readonly artifactDigest: Hex32 }
  | {
      readonly ok: false;
      readonly code: string; // CUSTODY_ERR_*
      readonly subCodes: readonly string[]; // composite forensic sub-codes (S2-1 ERR_*, etc.)
      readonly metadata?: Readonly<Record<string, string | number | bigint | Hex32>>;
    };
