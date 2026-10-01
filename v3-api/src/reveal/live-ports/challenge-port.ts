// ChallengeWindowLivePort — T3.4 (Phase 3 Wave 2).
//
// Real impl of `ChallengeWindowLivePort` (reveal-coordinator-impl.ts:107).
// Reads the live challenge-window state at call time, no cache, fail-closed —
// the C3a discipline (reveal-coordinator.ts §C3a). Backs the challenge axis of
// the `ConcreteLiveStateReader` the reveal-coordinator composes.
//
// DATA SOURCE (per PHASE-3-RUNTIME-PLAN §3):
//   Chain RPC + clock — `authorization_timestamp + challenge_window` from the
//   live RevealAuthorized event vs `now`. The window is CLOSED iff
//   `now >= authorization_timestamp + challenge_window_seconds` AND no
//   challenge is currently open on-chain.
//
// LATE-FILED CHALLENGE CATCH (the reason this reads LIVE, not from the
// reveal-GET path's precomputed `challenge_window_expired_at`): a challenge can
// be filed late in the window. The on-chain signal for an in-flight challenge
// is the ShredRegistry `ChallengeOpen` state (M2 enum 5) — when that is set,
// a post-challenge reveal is in progress, so the challenge window is NOT
// considered closed for plain delivery (the reveal proceeds only via the
// shred-guardrail path, which the shred port carries). This port therefore
// re-reads BOTH the timestamp/window AND the live shred state, and reports
// `closed=false` if a challenge is open even when the clock has elapsed.
//
// FAIL-CLOSED: absent authorization (no RevealAuthorized at read time) →
// `closed=false` (cannot prove the window elapsed) → the coordinator blocks. A
// throwing chain read propagates.
//
// ISOLATION (SECURITY.md): no @cealis/shared, no V1 package imports,
// no V1 env vars (the sealed-share / issuer-salt / committee-key family), no
// V1 TAG_*_V1 constants.

import type { ChallengeWindowLive } from "../reveal-coordinator.js";
import type { ChallengeWindowLivePort } from "../reveal-coordinator-impl.js";
import type { Hex32 } from "../../types/reveal-artifact-bundle.js";
import type { ChainStateReader } from "./chain-port.js";

/**
 * Reads the live challenge-window state for the authorization.
 *
 * `closed` is true iff the wall-clock has passed
 * `authorization_timestamp + challenge_window_seconds` AND the on-chain shred
 * state is not `ChallengeOpen` (no late-filed challenge in flight).
 *
 * `window_expires_at` is the ISO-8601 instant the window closes; when the
 * authorization is absent it is the read instant (the coordinator blocks on
 * `closed=false` regardless).
 */
export class ChallengeWindowLivePortImpl implements ChallengeWindowLivePort {
  private readonly reader: ChainStateReader;
  private readonly nowMs: () => number;

  /**
   * @param reader live chain-state boundary (chain-port.ts).
   * @param nowMs injectable clock for deterministic tests. Production omits it
   *   and uses `Date.now`. NOT a knob to feed a stale time from the flow — it
   *   is sampled fresh on every `read()`.
   */
  constructor(reader: ChainStateReader, nowMs: () => number = () => Date.now()) {
    this.reader = reader;
    this.nowMs = nowMs;
  }

  async read(authorizationId: Hex32): Promise<Omit<ChallengeWindowLive, "read_at">> {
    const auth = await this.reader.getAuthorizationState(authorizationId);
    const nowMs = this.nowMs();

    if (auth === null || !auth.reveal_authorized_present) {
      // Fail-closed: no on-chain authorization → cannot prove the window
      // elapsed → not closed.
      return { closed: false, window_expires_at: new Date(nowMs).toISOString() };
    }

    // Window expiry = authorization_timestamp (unix seconds) + challenge_window.
    const expiresMs = (Number(auth.authorization_timestamp) + auth.challenge_window_seconds) * 1000;
    const window_expires_at = new Date(expiresMs).toISOString();

    const clockElapsed = nowMs >= expiresMs;

    if (!clockElapsed) {
      return { closed: false, window_expires_at };
    }

    // Clock elapsed — but a late-filed challenge (on-chain ChallengeOpen)
    // keeps the window open for plain delivery. Re-read the live challenge
    // state via the chain reader (which resolves the authorization's bound
    // h_commit internally).
    const challengeOpen = await this.reader.isChallengeOpen(authorizationId);

    return { closed: !challengeOpen, window_expires_at };
  }
}
