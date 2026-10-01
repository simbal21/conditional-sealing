// RevealCoordinator — FROZEN SEAM (R2a task #3, interface-only, NO impl).
//
// Closes C3a (Rule-25 snapshot-once) BY TYPE CONSTRUCTION, not by documentation.
//
// The C3a bug (../combiner-orchestrator/index.ts): `RevealPreconditions` is a frozen
// 4-boolean struct (l.41) passed as an input field (l.60) and asserted exactly ONCE
// at the top of processRevealAuthorizedEvent (l.94); ~140 lines of manifest build,
// G4-refusal handling, and per-recipient bundle assembly + persist + delivery then
// proceed with NO re-validation. A subject shred or Art.18 freeze between l.94 and
// the l.199 putBundle is not caught.
//
// This seam makes that pattern UNREPRESENTABLE:
//   - There is NO `RevealPreconditions`-shaped (or any boolean-snapshot) input on the
//     coordinator. An implementer cannot pass a precondition snapshot in — the type
//     simply does not exist here.
//   - Gate clearance is a PHASE-BRANDED opaque token `GateClearance<Phase>`. The only
//     constructor is the async `clearGatesAt(phase, reader)` factory, which awaits the
//     LIVE readers for that phase. Distinct phases are distinct, mutually
//     non-assignable token types.
//   - The deliver/persist step REQUIRES a `GateClearance<"pre-delivery">`. A clearance
//     obtained at entry is a `GateClearance<"entry">` (or "pre-manifest") and is NOT
//     assignable to the "pre-delivery" parameter. So a single up-front live read
//     cannot satisfy the deliver step — the implementer is forced by the type system
//     to call the live reader again at pre-delivery. Snapshot-once does not typecheck.
//
// ACCEPTANCE (greppable, dw-quality verifies by inspection): (1) zero
// `RevealPreconditions` (or any *Preconditions boolean struct) as a parameter/field
// on any coordinator/step type here; (2) `clearGatesAt` is async and consumes the
// `LiveStateReader`; (3) the deliver step's signature names `GateClearance<"pre-delivery">`;
// (4) `GateClearance` brand is private (un-forgeable outside this module);
// (5) RevealArtifactRepository re-exported AS-IS (frozen, unmodified); (6) no V1
// import / role name / TAG. The literal test: can a conformant implementation read
// shred/Art.18/chain/challenge state only once? If yes, this freeze FAILED.
//
// Isolation (SECURITY.md): no @cealis/shared, no ../../packages/* (V1),
// no V1-role names / V1 TAGs / V1 obligation lifecycle. Boundaries are
// backend-swappable (Rule 12 production-grade — no in-memory boundary ships).

import type { Hex32 } from "../types/reveal-artifact-bundle.js";
// Frozen-as-is seams CONSUMED here (type-only import, NOT re-exported). Re-exporting
// would double-export the same name via the src/index.ts barrel (TS2308). These
// stay canonical at their own modules; R2a does NOT modify them. Their LBU mock
// impls — InMemoryRevealArtifactRepository (bundle/persist.ts:49),
// SyntheticChainAnchorClient (chain-anchor/ingestion-anchor.ts:30) — are the
// mock→real R2b targets. ChainAnchorClient is the EXISTING canonical anchor seam
// (NOT redefined here — grep-existing-before-inventing).
import type { EventDrivenRevealResult } from "../combiner-orchestrator/index.js";
import type { ChainAnchorClient } from "../chain-anchor/ingestion-anchor.js";

// ── Live state (replaces the C3a boolean snapshots with live, per-read values) ──

export interface ShredStateLive {
  /** Live shred lifecycle for h_commit at read time. */
  readonly state: "none" | "requested" | "finalized";
  readonly post_challenge_reveal_in_progress: boolean;
  readonly read_at: string;
}

export interface Art18FreezeLive {
  /** Live Art.18 GDPR processing-restriction state for the subject at read time. */
  readonly frozen: boolean;
  readonly freeze_expires_at?: string;
  readonly read_at: string;
}

export interface ChainConfirmationLive {
  readonly reveal_authorized_present: boolean;
  readonly confirmations: number;
  readonly authorization_block: number;
  readonly read_at: string;
}

export interface ChallengeWindowLive {
  readonly closed: boolean;
  readonly window_expires_at: string;
  readonly read_at: string;
}

export interface RegistryDeprecationLive {
  readonly acceptable: boolean;
  readonly deprecated_refs: readonly string[];
  readonly read_at: string;
}

/**
 * Per-step live-source reader port. Every method hits the live source (chain / shred
 * registry / Art.18 registry) AT CALL TIME and stamps `read_at`. No method returns a
 * cached or snapshotted boolean. The coordinator is given THIS port — never a
 * precondition struct. (The *how* — RPC vs cache vs indexer — is the R2b
 * implementer's choice; the frozen contract is only THAT it reads live, per step.)
 */
export interface LiveStateReader {
  readShredState(hCommit: Hex32): Promise<ShredStateLive>;
  readArt18Freeze(subjectCommitment: Hex32): Promise<Art18FreezeLive>;
  readChainConfirmation(authorizationId: Hex32): Promise<ChainConfirmationLive>;
  readChallengeWindow(authorizationId: Hex32): Promise<ChallengeWindowLive>;
  readRegistryDeprecation(authorizationId: Hex32): Promise<RegistryDeprecationLive>;
}

// ── Phase-branded gate clearance (the type-level C3a closure) ──

declare const GATE_CLEARANCE_BRAND: unique symbol;

/** Reveal step phases at which gates must be (re-)cleared against LIVE state.
 *  Distinct phases produce distinct, mutually non-assignable clearance tokens. */
export type RevealPhase = "entry" | "pre-manifest" | "pre-delivery";

/**
 * Opaque, phase-branded proof that ALL gate conditions were checked against LIVE
 * state at `phase`. Cannot be constructed, narrowed, or cast outside this module
 * (private brand). The ONLY producer is `clearGatesAt` (async, consumes LiveStateReader).
 * A `GateClearance<"entry">` is NOT assignable to a `GateClearance<"pre-delivery">`
 * parameter — this is what makes snapshot-once untypeable.
 */
export interface GateClearance<P extends RevealPhase> {
  readonly [GATE_CLEARANCE_BRAND]: P;
  readonly phase: P;
  readonly cleared_at: string;
  readonly evidence: {
    readonly shred: ShredStateLive;
    readonly art18: Art18FreezeLive;
    readonly chain: ChainConfirmationLive;
    readonly challenge: ChallengeWindowLive;
    readonly registry: RegistryDeprecationLive;
  };
}

/**
 * The SOLE constructor of a GateClearance. Awaits every LiveStateReader port for the
 * given phase, then mints a clearance branded to that exact phase. R2b implements;
 * the signature is frozen. There is no synchronous / snapshot-fed alternative.
 */
export type ClearGatesAt = <P extends RevealPhase>(
  phase: P,
  reader: LiveStateReader,
  subject: { readonly authorizationId: Hex32; readonly h_commit: Hex32; readonly subjectCommitment: Hex32 },
) => Promise<GateClearance<P>>;

// ── Coordinator step contract ──

/** Input carries NO precondition booleans/snapshot. Live state is obtained only
 *  via the injected LiveStateReader, per step, through clearGatesAt. */
export interface RevealCoordinatorInput {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly subjectCommitment: Hex32;
  readonly partner_id: string;
  readonly pda_id: string;
}

export interface RevealCoordinatorPorts {
  readonly liveState: LiveStateReader;
  readonly clearGatesAt: ClearGatesAt;
  readonly anchor: ChainAnchorClient;
  // `deliveryQueue` is DELIBERATELY ABSENT here (dw-quality BINDING-4 BLOCKER-1 fix):
  // the enqueue/delivery capability is reachable ONLY as a parameter of
  // `persistAndDeliver`, which requires `GateClearance<"pre-delivery">`. Exposing it
  // on the shared ports would let an ungated method enqueue (the C3a re-encode).
}

/**
 * The reveal coordinator. `persistAndDeliver` is the SOLE method and the SOLE
 * delivery/enqueue path. It requires a fresh `GateClearance<"pre-delivery">` —
 * mintable ONLY by `await clearGatesAt("pre-delivery", liveReader, …)` (a live
 * read; module-private brand; mutually non-assignable across RevealPhase). There is
 * deliberately NO `runReveal` and no other/ungated method, and `deliveryQueue` is
 * NOT on `RevealCoordinatorPorts` — so there is NO type-valid path from
 * `RevealCoordinator` to delivery/enqueue without first awaiting the pre-delivery
 * clearance. The multi-step orchestration (read→manifest→assemble→clear→deliver) is
 * R2b IMPLEMENTATION detail, NOT a seam method; it physically cannot reach enqueue
 * except through this gated terminal. (R2b refactors ../combiner-orchestrator to
 * this seam — R2b/worker-1, NOT R2a. dw-quality adversarial-construction gate: no
 * type-valid snapshot-once delivery path is constructable against this signature.)
 */
export interface RevealCoordinator {
  persistAndDeliver(
    input: RevealCoordinatorInput,
    ports: RevealCoordinatorPorts,
    clearance: GateClearance<"pre-delivery">,
    deliveryQueue: RevealDeliveryQueue,
  ): Promise<EventDrivenRevealResult>;
}

// ── Backend-swappable boundary interfaces (Rule 12; impl-agnostic, R2b) ──
//
// ChainAnchorClient is the EXISTING canonical anchor seam
// (chain-anchor/ingestion-anchor.ts:19) — type-imported above and consumed by
// RevealCoordinatorPorts.anchor. It is NOT redefined here: redefining it duplicated
// the name and caused a src/index.ts TS2308 ambiguity (grep-existing-before-
// inventing). Its SyntheticChainAnchorClient impl (ingestion-anchor.ts:30) is the
// LBU mock→real R2b target. EventDrivenRevealResult is likewise type-imported (not
// re-exported — re-export would re-collide via the barrel).

/** Durable reveal/webhook delivery queue boundary (BullMQ/Redis in R2b; H5).
 *  Impl-agnostic, swappable, durable (survives restart) — no in-memory boundary. */
export interface RevealDeliveryQueue {
  enqueue(job: {
    readonly job_id: string;
    readonly authorizationId: Hex32;
    readonly recipient_ref: string;
    readonly payload: Readonly<Record<string, unknown>>;
  }): Promise<void>;
  deadLetter(jobId: string, reason: string): Promise<void>;
}

// ── Rule-47 pre-declared error-context surface ──

export type RevealCoordinatorStep =
  | "entry"
  | "clear-pre-manifest"
  | "build-manifest"
  | "g4-refusal"
  | "clear-pre-delivery"
  | "assemble-bundle"
  | "persist-bundle"
  | "enqueue-delivery";

export interface RevealCoordinatorErrorContext {
  readonly authorizationId?: Hex32;
  readonly h_commit?: Hex32;
  readonly subjectCommitment?: Hex32;
  readonly step?: RevealCoordinatorStep;
  readonly gatePhase?: RevealPhase;
  readonly liveReadAt?: string;
  readonly shredState?: ShredStateLive["state"];
  readonly postChallengeRevealInProgress?: boolean;
  readonly art18FreezeActive?: boolean;
  readonly chainConfirmations?: number;
  readonly challengeWindowClosed?: boolean;
  readonly registryDeprecationAcceptable?: boolean;
  readonly recipientRef?: string;
  readonly reasonCode?: RevealCoordinatorErrorReason;
}

export type RevealCoordinatorErrorReason =
  | "REVEAL_SHRED_BLOCKS"
  | "REVEAL_ART18_FROZEN"
  | "REVEAL_CHAIN_UNCONFIRMED"
  | "REVEAL_CHALLENGE_WINDOW_OPEN"
  | "REVEAL_REGISTRY_DEPRECATED"
  | "REVEAL_STALE_CLEARANCE"
  | "REVEAL_DELIVERY_ENQUEUE_FAILED";

export class RevealCoordinatorError extends Error {
  readonly context: RevealCoordinatorErrorContext;
  constructor(message: string, context: RevealCoordinatorErrorContext) {
    super(message);
    this.name = "RevealCoordinatorError";
    this.context = context;
  }
}
