// Abstract `GateAdapter` interface — typed contract every gate adapter
// implements per S2-3 §1.1 + §12.1. Phase B (G3), Phase C (G2 Lit V3),
// and Phase D (G4 Phase 1 + Phase 2) all implement this shape.
//
// Locking the interface in Phase A prevents five silently-different
// implementations and gives the combiner a single dispatch surface.
// The two generic parameters allow per-adapter σ/KEM shape
// specialization while keeping the high-level lifecycle uniform.

import type { Hex32 } from "@cealis/v3-crypto";
import type { GateKind } from "../types/gate-recipient.js";

/**
 * Health-probe result — uniform across all adapters per S2-3 §12.1.
 *
 * - `ok`              healthy + ready to serve
 * - `degraded`        partially functional (e.g. drand: one endpoint
 *                     down, others still serving)
 * - `unavailable`     adapter cannot serve (e.g. dcipher SDK excluded
 *                     at build time, or vendor SDK unavailable). When
 *                     `unavailable`, no automatic retry; surface to
 *                     caller for adjacent-endpoint or alternative-path.
 */
export type HealthProbeStatus = "ok" | "degraded" | "unavailable";

export interface HealthProbeResult {
  readonly status: HealthProbeStatus;
  readonly gateKind: GateKind;
  /** Concise human-readable status detail. MUST NOT include σ / plaintext. */
  readonly detail: string;
  /** Adapter-specific structured detail (e.g. round number, epoch, endpoint id). */
  readonly metadata: Readonly<Record<string, string | number | bigint>>;
  /** Wall-clock time when the probe ran. */
  readonly observedAt: bigint;
}

/**
 * Successful σ verification result.
 */
export interface VerifySigmaOk {
  readonly ok: true;
}

/**
 * Failed σ verification result — carries a typed error code so the
 * combiner can map it to a `CUSTODY_ERR_*` operational class with the
 * code as forensic sub-code per S2-3 §13.2.
 */
export interface VerifySigmaFail {
  readonly ok: false;
  readonly code: string;
  /** Optional human-readable detail. MUST NOT include σ bytes or plaintext. */
  readonly detail?: string;
}

export type VerifySigmaResult = VerifySigmaOk | VerifySigmaFail;

/**
 * σ request parameters — common envelope passed to `requestSigma`.
 * Adapter-specific extra parameters are carried in `extras` (typed by
 * concrete adapter).
 */
export interface RequestSigmaInput<Extras = unknown> {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly authorizationBlock: bigint;
  readonly blockHash: Hex32;
  readonly extras: Extras;
}

/**
 * σ request result — carries the σ bytes (process-memory-only) plus
 * adapter-specific verification metadata (drand round, dcipher epoch,
 * Lit DCAP quote digest, G4 attestation ref, etc.).
 *
 * SECURITY: per S2-3 §1.4 + §18 of SPEC-COMPLIANCE-GUARD-M3, `sigma`
 * MUST be wrapped in `SigmaBuffer` from `src/redaction/sigma-buffer.ts`
 * at every boundary that crosses a log / IPC / persistence surface.
 * Concrete adapter implementations return `Uint8Array` here; the
 * combiner immediately wraps before logging.
 */
export interface RequestSigmaResult {
  readonly sigma: Uint8Array;
  readonly gateKind: GateKind;
  readonly metadata: Readonly<Record<string, string | number | bigint | Hex32>>;
}

/**
 * `prepareCommitBinding` input — adapter-specific binding step run at
 * commit time. Lit / G4 / Conditional produce a per-commit ephemeral
 * KEM pubkey; drand uses a long-lived committee key (see
 * SPEC-COMPLIANCE-GUARD-M3 §20). The adapter's `KemPubkey` type
 * encodes whichever shape applies.
 */
export interface PrepareCommitBindingInput<Extras = unknown> {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly commitBlock: bigint;
  readonly extras: Extras;
}

/**
 * Abstract per-gate adapter. Implementations live in:
 *   src/g2-lit/                 (Phase C)
 *   src/g3-drand/               (Phase B)
 *   src/g3-dcipher/             (Phase B)
 *   src/g4-phase1/              (Phase D)
 *   src/g4-phase2/              (Phase D)
 *   src/conditional-recipient/  (deferred to a future chunk — not in M3)
 */
export interface GateAdapter<
  Sigma = Uint8Array,
  KemPubkey = Uint8Array,
  RequestExtras = unknown,
  PrepareExtras = unknown,
> {
  /** Which gate this adapter implements. */
  readonly gateKind: GateKind;

  /**
   * Commit-time binding step: produces the KEM pubkey + attestation
   * payload that the chain reader will later observe in
   * `GateRecipientPubkeyRegistry`. For per-commit-ephemeral gates
   * (Lit / G4 / Conditional), this generates a fresh KEM pair. For
   * long-lived gates (drand), this returns the committee pubkey.
   */
  prepareCommitBinding(
    input: PrepareCommitBindingInput<PrepareExtras>,
  ): Promise<KemPubkey>;

  /**
   * Reveal-time σ request: contacts the gate's signing surface (Lit
   * Chipotle SDK / dcipher committee / drand round / G4 daemon) and
   * returns the σ bytes plus structured metadata. MUST NOT log σ
   * content; MUST NOT persist σ to disk / Redis / Kafka per S2-3 §1.2
   * + §1.4 + §9.7.
   */
  requestSigma(
    input: RequestSigmaInput<RequestExtras>,
  ): Promise<RequestSigmaResult & { sigma: Sigma }>;

  /**
   * Local-side σ verification. Returns typed result; combiner maps
   * `{ok: false, code}` to a `CUSTODY_ERR_*` class via §13.2 composite
   * rules. MUST be deterministic + side-effect-free + must not depend
   * on any state beyond the input parameters and previously-verified
   * registry-snapshot data.
   */
  verifySigma(
    input: RequestSigmaInput<RequestExtras> & { sigma: Sigma },
  ): Promise<VerifySigmaResult>;

  /**
   * Health probe per S2-3 §12.1. Returns adapter health without
   * triggering σ production. SHOULD be cheap (single connectivity
   * check + capability check), runnable on a periodic SRE cadence.
   */
  healthProbe(): Promise<HealthProbeResult>;
}

/**
 * Discriminated union of all M3 adapter kinds — for SDK-level dispatch
 * + factory selection.
 */
export type AdapterDiscriminator =
  | "g2-lit"
  | "g3-drand"
  | "g3-dcipher"
  | "g4-phase1"
  | "g4-phase2"
  | "conditional-recipient";

/**
 * Adapter factory function shape — Phase E combiner calls into a
 * registry of factory functions to obtain a concrete adapter for a
 * given commit. Phase B/C/D each register their factories at module
 * load.
 */
export type AdapterFactory<A extends GateAdapter = GateAdapter> = (
  config: Readonly<Record<string, unknown>>,
) => A;
