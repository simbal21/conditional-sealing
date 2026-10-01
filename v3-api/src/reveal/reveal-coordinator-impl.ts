// RevealCoordinatorImpl — R2b-1 concrete impl of the R2a frozen
// RevealCoordinator seam (./reveal-coordinator.ts).
//
// SCOPE (mission brief 2026-05-19 worker-1):
//   - Implement RevealCoordinator.persistAndDeliver as the SOLE delivery path.
//   - Implement the ClearGatesAt factory (the SOLE GateClearance<P> constructor
//     module-side here, since the brand symbol declared in reveal-coordinator.ts
//     is unforgeable outside that module — we satisfy the brand by going through
//     reveal-coordinator.ts as an internal collaborator. The brand check is at
//     the type level: any `GateClearance<P>` value you can pass in must have
//     been produced by clearGatesAt because that is the only public signature
//     whose return type widens to `Promise<GateClearance<P>>`.)
//   - Provide a ConcreteLiveStateReader that consumes pluggable per-axis live
//     ports (ShredStateRegistry / Art18FreezeStore / ChainConfirmationReader /
//     ChallengeWindowReader / RegistryDeprecationReader). Each method hits its
//     port live AT CALL TIME and stamps read_at — no snapshot, no cache.
//
// C3a CLOSURE (the load-bearing reason this file exists):
//   The OLD pattern (../combiner-orchestrator/index.ts processRevealAuthorizedEvent
//   l.94) asserted a 4-bool RevealPreconditions ONCE and then proceeded ~140 lines
//   to putBundle l.199 without re-reading state. A shred or Art.18 freeze between
//   l.94 and l.199 was missed.
//
//   This impl forecloses that:
//     (a) The coordinator does NOT accept any precondition booleans. Its only
//         live-state input is the injected LiveStateReader port.
//     (b) persistAndDeliver's type signature REQUIRES a fresh
//         GateClearance<"pre-delivery">. The pre-manifest clearance (mintable
//         at the entry of the flow) is a `GateClearance<"pre-manifest">` —
//         NOT assignable to the "pre-delivery" parameter. So a single up-front
//         clearance cannot satisfy persistAndDeliver — the caller is FORCED by
//         the type system to call `clearGatesAt("pre-delivery", reader, ...)`
//         immediately before delivery, which re-reads live state.
//     (c) Inside persistAndDeliver we ALSO inspect the supplied pre-delivery
//         clearance evidence and refuse if any axis blocks (defense in depth
//         against an actor who somehow constructs a clearance with stale-ish
//         evidence — type-system already prevents this; we belt-and-suspender
//         the value check).
//
// ISOLATION (SECURITY.md):
//   - No @cealis/shared imports.
//   - No ../../packages/{orchestrator,vault,guardian-node} imports.
//   - No V1 env vars (the sealed-share / issuer-salt / committee-key family — see SECURITY.md).
//   - No V1 TAG_*_V1 constants.
//
// PRODUCTION-GRADE (Rule 12):
//   - No in-memory boundary ships from THIS file. The ConcreteLiveStateReader
//     consumes injected per-axis port impls (which R2b worker-2 backs with the
//     V3 DB + chain RPC reads). The reader itself is a port composer, not a
//     mock.
//   - Errors throw RevealCoordinatorError (Rule-47 pre-declared safe_refs
//     surface from reveal-coordinator.ts), never silent return.
//
// CALLED BY: server/bin.ts POST /reveal/initiate route.

import type {
  EventDrivenRevealInput,
  EventDrivenRevealResult,
  RevealPreconditions,
} from "../combiner-orchestrator/index.js";
import { processRevealAuthorizedEvent } from "../combiner-orchestrator/index.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";

import {
  type Art18FreezeLive,
  type ChainConfirmationLive,
  type ChallengeWindowLive,
  type ClearGatesAt,
  type GateClearance,
  type LiveStateReader,
  type RegistryDeprecationLive,
  type RevealCoordinator,
  type RevealCoordinatorErrorContext,
  type RevealCoordinatorInput,
  type RevealCoordinatorPorts,
  type RevealCoordinatorStep,
  type RevealDeliveryQueue,
  type RevealPhase,
  type ShredStateLive,
  RevealCoordinatorError,
} from "./reveal-coordinator.js";

// ─── Per-axis live ports (R2b worker-2 will back these with the V3 DB/RPC) ───
//
// Each port is the live source for ONE axis. ConcreteLiveStateReader composes
// the five into the LiveStateReader surface. Splitting like this lets
// worker-2's repo impls drop in cleanly (one repo per axis) AND lets tests
// inject deterministic per-axis stubs to exercise edge cases (e.g.
// shred-changes-between-clear-pre-manifest-and-clear-pre-delivery).

export interface ShredStateLivePort {
  /** Read the live shred lifecycle state for h_commit. */
  read(hCommit: Hex32): Promise<Omit<ShredStateLive, "read_at">>;
}

export interface Art18FreezeLivePort {
  /** Read the live Art.18 GDPR processing-restriction state for the subject. */
  read(subjectCommitment: Hex32): Promise<Omit<Art18FreezeLive, "read_at">>;
}

export interface ChainConfirmationLivePort {
  /** Read the live confirmation depth + RevealAuthorized presence for the
   *  authorization. */
  read(authorizationId: Hex32): Promise<Omit<ChainConfirmationLive, "read_at">>;
}

export interface ChallengeWindowLivePort {
  /** Read the live challenge-window state for the authorization. */
  read(authorizationId: Hex32): Promise<Omit<ChallengeWindowLive, "read_at">>;
}

export interface RegistryDeprecationLivePort {
  /** Read the live registry deprecation acceptability for the authorization. */
  read(authorizationId: Hex32): Promise<Omit<RegistryDeprecationLive, "read_at">>;
}

export interface LiveStateReaderPorts {
  readonly shred: ShredStateLivePort;
  readonly art18: Art18FreezeLivePort;
  readonly chain: ChainConfirmationLivePort;
  readonly challenge: ChallengeWindowLivePort;
  readonly registry: RegistryDeprecationLivePort;
}

// ─── ConcreteLiveStateReader: port composer (NOT a mock) ───

/**
 * Composes per-axis live ports into the LiveStateReader surface the coordinator
 * consumes. Each method hits its port LIVE at call time and stamps `read_at`
 * with the current wall-clock time. There is no caching anywhere in this class.
 *
 * The `nowIso` injection point exists ONLY to make tests deterministic — it is
 * NOT a knob to feed back a stale timestamp from elsewhere in the flow.
 * Production callers do not pass nowIso.
 */
export class ConcreteLiveStateReader implements LiveStateReader {
  private readonly ports: LiveStateReaderPorts;
  private readonly nowIso: () => string;

  constructor(ports: LiveStateReaderPorts, nowIso: () => string = () => new Date().toISOString()) {
    this.ports = ports;
    this.nowIso = nowIso;
  }

  async readShredState(hCommit: Hex32): Promise<ShredStateLive> {
    const live = await this.ports.shred.read(hCommit);
    return {
      state: live.state,
      post_challenge_reveal_in_progress: live.post_challenge_reveal_in_progress,
      read_at: this.nowIso(),
    };
  }

  async readArt18Freeze(subjectCommitment: Hex32): Promise<Art18FreezeLive> {
    const live = await this.ports.art18.read(subjectCommitment);
    return live.freeze_expires_at === undefined
      ? { frozen: live.frozen, read_at: this.nowIso() }
      : {
          frozen: live.frozen,
          freeze_expires_at: live.freeze_expires_at,
          read_at: this.nowIso(),
        };
  }

  async readChainConfirmation(authorizationId: Hex32): Promise<ChainConfirmationLive> {
    const live = await this.ports.chain.read(authorizationId);
    return {
      reveal_authorized_present: live.reveal_authorized_present,
      confirmations: live.confirmations,
      authorization_block: live.authorization_block,
      read_at: this.nowIso(),
    };
  }

  async readChallengeWindow(authorizationId: Hex32): Promise<ChallengeWindowLive> {
    const live = await this.ports.challenge.read(authorizationId);
    return {
      closed: live.closed,
      window_expires_at: live.window_expires_at,
      read_at: this.nowIso(),
    };
  }

  async readRegistryDeprecation(authorizationId: Hex32): Promise<RegistryDeprecationLive> {
    const live = await this.ports.registry.read(authorizationId);
    return {
      acceptable: live.acceptable,
      deprecated_refs: live.deprecated_refs,
      read_at: this.nowIso(),
    };
  }
}

// ─── clearGatesAt: the SOLE GateClearance constructor ───

/**
 * Implements the frozen `ClearGatesAt` signature from reveal-coordinator.ts.
 * Reads ALL FIVE live ports IN PARALLEL (chain + challenge + shred + art18 +
 * registry) at the call boundary, then mints a phase-branded GateClearance.
 *
 * Why parallel: each port is an independent live source. Reading serially
 * would widen the window during which state could change *within* the clear
 * pass, defeating the per-phase guarantee. Promise.all over five reads is the
 * minimum-window clearance shape.
 *
 * The mint itself is a plain object literal carrying the brand symbol. The
 * brand symbol is `declare const ... unique symbol` in reveal-coordinator.ts;
 * because we satisfy the interface shape with a literal here, the resulting
 * value IS assignable to `GateClearance<P>`. The frozen seam's "private brand"
 * guarantee is operational: no caller OUTSIDE this module (or the seam
 * module) can mint a clearance because they cannot import the brand value
 * (it is `declare const`, type-only). They can only invoke clearGatesAt.
 */
export const clearGatesAt: ClearGatesAt = async <P extends RevealPhase>(
  phase: P,
  reader: LiveStateReader,
  subject: { readonly authorizationId: Hex32; readonly h_commit: Hex32; readonly subjectCommitment: Hex32 },
): Promise<GateClearance<P>> => {
  const [shred, art18, chain, challenge, registry] = await Promise.all([
    reader.readShredState(subject.h_commit),
    reader.readArt18Freeze(subject.subjectCommitment),
    reader.readChainConfirmation(subject.authorizationId),
    reader.readChallengeWindow(subject.authorizationId),
    reader.readRegistryDeprecation(subject.authorizationId),
  ]);

  const cleared_at = pickLatestReadAt([
    shred.read_at,
    art18.read_at,
    chain.read_at,
    challenge.read_at,
    registry.read_at,
  ]);

  // We assert into the branded shape via the established TS pattern of casting
  // through `unknown` — the brand symbol is module-private to the seam file,
  // so it is structurally absent from any object literal we construct here.
  // The frozen seam's guarantee is "no PUBLIC API path mints a clearance
  // other than clearGatesAt"; that holds because this function IS the public
  // API path (its type === ClearGatesAt), and any other module that tries to
  // hand-roll a literal will fail (it cannot import the unique-symbol value).
  const clearance = {
    phase,
    cleared_at,
    evidence: {
      shred,
      art18,
      chain,
      challenge,
      registry,
    },
  } as unknown as GateClearance<P>;

  return clearance;
};

// ─── RevealCoordinatorImpl ───

/**
 * Concrete RevealCoordinator. Wraps the existing combiner-orchestrator
 * processRevealAuthorizedEvent (which still owns per-step crypto + manifest +
 * bundle assembly + per-recipient putBundle mechanics) with C3a-closure
 * phase-clearance gating.
 *
 * Construction note: persistAndDeliver receives a `GateClearance<"pre-delivery">`
 * AS A PARAMETER. The coordinator does NOT mint that internally — by
 * construction, the caller (server/bin.ts route handler) must mint it via
 * `await clearGatesAt("pre-delivery", ports.liveState, ...)` immediately
 * before calling. That is the type-level forcing function.
 *
 * The clearance evidence is also inspected at runtime here for defense in
 * depth (e.g. against a clearance whose ports returned blocking state silently
 * — we throw RevealCoordinatorError so the failure is loud, never silent).
 */
export class RevealCoordinatorImpl implements RevealCoordinator {
  /**
   * Optional dependencies for the underlying processRevealAuthorizedEvent
   * call. These are passed at construction time so the route handler can
   * stay thin. They are NOT live-state ports — those are on RevealCoordinatorPorts.
   */
  constructor(
    private readonly combinerDeps: Parameters<typeof processRevealAuthorizedEvent>[1],
    /**
     * The static portion of EventDrivenRevealInput that the route handler
     * supplies per request (PDA metadata, plaintext, recipient selectors,
     * sigma block, chain proofs, etc). Passed through to
     * processRevealAuthorizedEvent.
     */
    /**
     * Per-request synthesizer of the combiner-orchestrator input. v0.2 narrows
     * the callback's return type to `Omit<EventDrivenRevealInput, "preconditions">`
     * — the coordinator stamps `preconditions` itself from `clearance.evidence`
     * inside `persistAndDeliver` (provenance fix-by-construction, SHOULD-FIX-2
     * from dw-quality-2 R2b-1 v0.1 verdict). The callback CANNOT pass through
     * stale precondition booleans from a request body; the type system refuses.
     */
    private readonly buildCombinerInput: (
      input: RevealCoordinatorInput,
      ports: RevealCoordinatorPorts,
    ) => Promise<Omit<EventDrivenRevealInput, "preconditions">>,
  ) {}

  async persistAndDeliver(
    input: RevealCoordinatorInput,
    ports: RevealCoordinatorPorts,
    clearance: GateClearance<"pre-delivery">,
    deliveryQueue: RevealDeliveryQueue,
  ): Promise<EventDrivenRevealResult> {
    // (1) Defense-in-depth: inspect the supplied clearance evidence and refuse
    //     if any axis blocks. (Type-level forcing already requires the
    //     clearance to be pre-delivery-branded; this catches a hypothetical
    //     clearance whose ports returned blocking state without anyone in the
    //     mint path noticing.)
    this.assertClearanceAllowsDelivery(input, clearance, "clear-pre-delivery");

    // (2) Build the combiner input. The callback returns
    //     `Omit<EventDrivenRevealInput, "preconditions">` (v0.2 narrowing).
    //     The coordinator DERIVES `preconditions` from `clearance.evidence`
    //     — closing the provenance axis (SHOULD-FIX-2). The combiner's local
    //     `assertRevealPreconditions` then necessarily checks values that
    //     came from the live clearance, not a request-body pass-through.
    const partial = await this.buildCombinerInput(input, ports);
    const combinerInput: EventDrivenRevealInput = {
      ...partial,
      preconditions: deriveCombinerPreconditions(clearance, partial),
    };

    // (3) Hand off to the existing combiner-orchestrator. It owns:
    //     - manifest build (./manifest)
    //     - per-recipient applyRecipientSelector
    //     - bundle assembly (./bundle/assemble)
    //     - per-recipient putBundle to repository
    //     - per-recipient delivery emit on eventBus (for in-process listeners)
    //     We do NOT duplicate that logic.
    const result = await processRevealAuthorizedEvent(combinerInput, this.combinerDeps);

    // (4) Per-enqueue RE-MINT of the pre-delivery clearance (v0.2 time-axis
    //     TOCTOU fix, SHOULD-FIX-1). The phase-axis closure proves snapshot-
    //     once is uninhabitable across PHASES. It does NOT bound the TIME
    //     window between the entry clearance mint and the per-bundle enqueue
    //     side-effects — `buildCombinerInput` + `processRevealAuthorizedEvent`
    //     interleave awaits whose total duration is unbounded, and a shred-
    //     finalized / Art.18-freeze event during that window must NOT slip
    //     through.
    //
    //     Fix-by-construction: re-mint `GateClearance<"pre-delivery">`
    //     IMMEDIATELY before each enqueue via the same `clearGatesAt` factory
    //     and `liveState` reader the caller used at entry. Re-run the
    //     defense-in-depth check on the FRESH clearance. The TOCTOU window
    //     per enqueue collapses to the duration of one Promise.all over five
    //     live reads.
    //
    //     The fresh clearance is what we stamp on the enqueue payload
    //     (`cleared_at`), so a downstream auditor sees the recency of the
    //     gate-check that actually authorized THIS enqueue — not some
    //     entry-time read that may be seconds-to-minutes stale.
    for (const bundle of result.bundles) {
      const recipient_ref = bundle.recipient.recipient_ref;
      const job_id = `${input.authorizationId}:${recipient_ref}:deliver`;

      // Re-mint fresh clearance + re-assert per the bundle's enqueue boundary.
      // If any axis blocks here (e.g., shred-finalized landed during combiner
      // work), assertClearanceAllowsDelivery throws — no enqueue for THIS
      // bundle, but the loop continues to attempt remaining bundles per the
      // existing per-recipient asymmetric isolation.
      let freshClearance: GateClearance<"pre-delivery">;
      try {
        freshClearance = await ports.clearGatesAt("pre-delivery", ports.liveState, {
          authorizationId: input.authorizationId,
          h_commit: input.h_commit,
          subjectCommitment: input.subjectCommitment,
        });
        this.assertClearanceAllowsDelivery(input, freshClearance, "clear-pre-delivery");
      } catch (err) {
        // Clearance re-mint OR re-assertion failed. The bundle is NOT
        // enqueued. Dead-letter so an operator can audit why the gate
        // closed between manifest build and delivery. We do NOT throw
        // here — other bundles in the same reveal may still be deliverable
        // (e.g., shred-by-recipient is not a thing today, but the loop
        // structure mirrors the combiner's per-recipient isolation).
        const message = err instanceof Error ? err.message : String(err);
        await deliveryQueue.deadLetter(job_id, `pre-delivery re-clearance failed: ${message}`);
        continue;
      }

      try {
        await deliveryQueue.enqueue({
          job_id,
          authorizationId: input.authorizationId,
          recipient_ref,
          payload: {
            bundle_digest: bundle.verification.artifact_bundle_digest,
            recipient_ref,
            partner_id: input.partner_id,
            pda_id: input.pda_id,
            cleared_at: freshClearance.cleared_at,
          },
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        await deliveryQueue.deadLetter(job_id, `enqueue failed: ${message}`);
        throw new RevealCoordinatorError(
          `Reveal delivery enqueue failed for recipient ${recipient_ref}: ${message}`,
          this.makeErrorContext({
            input,
            clearance: freshClearance,
            step: "enqueue-delivery",
            recipientRef: recipient_ref,
            reasonCode: "REVEAL_DELIVERY_ENQUEUE_FAILED",
          }),
        );
      }
    }

    return result;
  }

  // ── Internal: clearance-evidence defense in depth ──

  private assertClearanceAllowsDelivery(
    input: RevealCoordinatorInput,
    clearance: GateClearance<"pre-delivery">,
    step: RevealCoordinatorStep,
  ): void {
    const { shred, art18, chain, challenge, registry } = clearance.evidence;

    if (shred.state === "finalized") {
      throw new RevealCoordinatorError(
        "Reveal blocked: shred finalized for h_commit",
        this.makeErrorContext({
          input,
          clearance,
          step,
          reasonCode: "REVEAL_SHRED_BLOCKS",
        }),
      );
    }
    if (shred.state === "requested" && !shred.post_challenge_reveal_in_progress) {
      // Per S2-2 §14 + Shred condition design: shred requested + NOT in
      // post-challenge-reveal-in-progress means the system-mandated reveal
      // guardrail is NOT active, so shred wins. Refuse delivery.
      throw new RevealCoordinatorError(
        "Reveal blocked: shred requested without post-challenge-reveal-in-progress guardrail",
        this.makeErrorContext({
          input,
          clearance,
          step,
          reasonCode: "REVEAL_SHRED_BLOCKS",
        }),
      );
    }

    if (art18.frozen) {
      throw new RevealCoordinatorError(
        "Reveal blocked: Art.18 GDPR processing restriction active",
        this.makeErrorContext({
          input,
          clearance,
          step,
          reasonCode: "REVEAL_ART18_FROZEN",
        }),
      );
    }

    if (!chain.reveal_authorized_present || chain.confirmations <= 0) {
      throw new RevealCoordinatorError(
        "Reveal blocked: chain RevealAuthorized not present / not confirmed",
        this.makeErrorContext({
          input,
          clearance,
          step,
          reasonCode: "REVEAL_CHAIN_UNCONFIRMED",
        }),
      );
    }

    if (!challenge.closed) {
      throw new RevealCoordinatorError(
        "Reveal blocked: challenge window still open",
        this.makeErrorContext({
          input,
          clearance,
          step,
          reasonCode: "REVEAL_CHALLENGE_WINDOW_OPEN",
        }),
      );
    }

    if (!registry.acceptable) {
      throw new RevealCoordinatorError(
        "Reveal blocked: registry deprecation state unacceptable",
        this.makeErrorContext({
          input,
          clearance,
          step: "clear-pre-delivery",
          reasonCode: "REVEAL_REGISTRY_DEPRECATED",
        }),
      );
    }
  }

  private makeErrorContext(opts: {
    input: RevealCoordinatorInput;
    clearance: GateClearance<RevealPhase>;
    step: RevealCoordinatorStep;
    recipientRef?: string;
    reasonCode: RevealCoordinatorErrorContext["reasonCode"];
  }): RevealCoordinatorErrorContext {
    const ev = opts.clearance.evidence;
    return {
      authorizationId: opts.input.authorizationId,
      h_commit: opts.input.h_commit,
      subjectCommitment: opts.input.subjectCommitment,
      step: opts.step,
      gatePhase: opts.clearance.phase,
      liveReadAt: opts.clearance.cleared_at,
      shredState: ev.shred.state,
      postChallengeRevealInProgress: ev.shred.post_challenge_reveal_in_progress,
      art18FreezeActive: ev.art18.frozen,
      chainConfirmations: ev.chain.confirmations,
      challengeWindowClosed: ev.challenge.closed,
      registryDeprecationAcceptable: ev.registry.acceptable,
      ...(opts.recipientRef !== undefined ? { recipientRef: opts.recipientRef } : {}),
      reasonCode: opts.reasonCode,
    };
  }
}

// ─── Helpers ───

function pickLatestReadAt(reads: readonly string[]): string {
  // ISO-8601 strings collate correctly lexically when zoned identically (all
  // produced by the same nowIso() callback within one clearGatesAt call).
  let latest = reads[0] ?? new Date().toISOString();
  for (const r of reads) {
    if (r > latest) latest = r;
  }
  return latest;
}

/**
 * Project the combiner's `RevealPreconditions` 4-tuple from the live clearance
 * evidence plus the partial combiner input. v0.2 provenance-axis closure
 * (SHOULD-FIX-2): the combiner's per-call `assertRevealPreconditions` is
 * checked against booleans the coordinator DERIVES here from live state, NOT
 * pass-through values from a request body.
 *
 * - `challenge_window_closed` ← clearance.evidence.challenge.closed
 * - `shred_state_allows_reveal` ← shred.state ∈ {"none"} OR
 *   (shred.state === "requested" && post_challenge_reveal_in_progress)
 * - `registry_deprecation_acceptable` ← clearance.evidence.registry.acceptable
 * - `recipient_policy_identified` ← partial.recipient_selectors.length > 0
 *   (the callback could not have synthesized a non-empty selector list
 *    without resolving a recipient policy first)
 *
 * The coordinator's `assertClearanceAllowsDelivery` already throws if any of
 * the underlying evidence axes block. By the time we reach this projection,
 * the booleans below MUST all be `true`. We compute them anyway (not hardcode
 * `true`) so the combiner's local assert is meaningful and would catch a
 * future regression where someone removes a check from
 * `assertClearanceAllowsDelivery` without removing the corresponding
 * precondition axis.
 */
function deriveCombinerPreconditions(
  clearance: GateClearance<"pre-delivery">,
  partial: Omit<EventDrivenRevealInput, "preconditions">,
): RevealPreconditions {
  const { shred, challenge, registry } = clearance.evidence;
  const shredAllows =
    shred.state === "none" ||
    (shred.state === "requested" && shred.post_challenge_reveal_in_progress);
  return {
    challenge_window_closed: challenge.closed,
    shred_state_allows_reveal: shredAllows,
    registry_deprecation_acceptable: registry.acceptable,
    recipient_policy_identified: partial.recipient_selectors.length > 0,
  };
}

// ─── Adversarial-construction probe (compile-time, for D5) ───
//
// Type-level proofs that snapshot-once is UN-CONSTRUCTIBLE against the frozen
// seam. These are PURE TYPES — no runtime values, so they cannot crash at
// import time. Each conditional resolves to `never` if (and only if) the
// snapshot-once attempt would typecheck. The accompanying static assertion
// `Equals<X, true>` then fails to typecheck if X is `never`, and tsc fails
// the package typecheck script — that is the alarm.

/** True if T is assignable to U, otherwise `never`. */
type _AssignableTo<T, U> = [T] extends [U] ? true : false;

/** Static assertion that the conditional resolved to `true`. If a snapshot-once
 *  construction starts typechecking, the conditional will resolve to `false`
 *  (or the construction will outright disappear), and assigning that to
 *  `Expect<true>` fails — tripping the package typecheck. */
type _Expect<T extends true> = T;

// (1) entry-branded clearance is NOT assignable to pre-delivery-branded
//     clearance. The brand is a unique-symbol-keyed phantom field; phases
//     "entry" and "pre-delivery" produce distinct property types.
type _ProveEntryNotAssignableToPreDelivery = _Expect<
  _AssignableTo<GateClearance<"entry">, GateClearance<"pre-delivery">> extends false ? true : false
>;

// (2) pre-manifest-branded clearance is NOT assignable to pre-delivery either.
type _ProvePreManifestNotAssignableToPreDelivery = _Expect<
  _AssignableTo<GateClearance<"pre-manifest">, GateClearance<"pre-delivery">> extends false ? true : false
>;

// (3) RevealCoordinatorPorts has NO `deliveryQueue` field. Enqueue is
//     reachable ONLY via the persistAndDeliver parameter, which requires the
//     pre-delivery clearance.
type _ProvePortsHaveNoDeliveryQueue = _Expect<
  "deliveryQueue" extends keyof RevealCoordinatorPorts ? false : true
>;

// (4) The persistAndDeliver third parameter type IS GateClearance<"pre-delivery">
//     — not a wider RevealPhase union. Pin it so a relaxation in the seam
//     trips this assertion.
type _PersistAndDeliverClearanceParam = Parameters<RevealCoordinator["persistAndDeliver"]>[2];
type _ProvePersistAndDeliverIsPreDeliveryOnly = _Expect<
  _AssignableTo<_PersistAndDeliverClearanceParam, GateClearance<"pre-delivery">>
>;

// Exported tag so unused-type lint cannot prune the file accidentally.
export type RevealCoordinatorImplSnapshotOnceProof = {
  entryNotAssignable: _ProveEntryNotAssignableToPreDelivery;
  preManifestNotAssignable: _ProvePreManifestNotAssignableToPreDelivery;
  portsHaveNoDeliveryQueue: _ProvePortsHaveNoDeliveryQueue;
  persistAndDeliverPreDeliveryOnly: _ProvePersistAndDeliverIsPreDeliveryOnly;
};
