// ShredStateLivePort — T3.4 (Phase 3 Wave 2).
//
// Real impl of `ShredStateLivePort` (reveal-coordinator-impl.ts:91). Reads the
// live on-chain ShredRegistry state at call time, no cache, fail-closed — the
// C3a discipline (reveal-coordinator.ts §C3a). Backs the shred axis of the
// `ConcreteLiveStateReader` the reveal-coordinator composes.
//
// DATA SOURCE (per PHASE-3-RUNTIME-PLAN §3):
//   Chain RPC — `ShredRegistry.currentShredState(hCommit)` via the shared
//   `ChainStateReader` boundary (chain-port.ts). The M2 enum is the verbatim
//   `ShredState` enum (Enums.sol): 0 None, 1 Requested, 2 Authorized,
//   3 Finalized, 4 Blocked, 5 ChallengeOpen, 6 Shredded.
//
// ENUM MAPPING — M2 7-value → coordinator 3-value lifecycle
// (`"none" | "requested" | "finalized"`) + the `post_challenge_reveal_in_progress`
// guardrail bool. The coordinator's `assertClearanceAllowsDelivery`
// (reveal-coordinator-impl.ts:427) consumes exactly:
//   - state === "finalized"                       → BLOCK (shred won)
//   - state === "requested" && !guardrail         → BLOCK (shred wins; no
//                                                    post-challenge reveal)
//   - otherwise                                   → allow
//
//   M2 → port:
//     None (0)         → "none",      guardrail=false   (no shred pending)
//     Requested (1)    → "requested", guardrail=false   (request open, no reveal race)
//     Authorized (2)   → "finalized", guardrail=false   (shred authorized → BLOCK; conservative)
//     Finalized (3)    → "finalized", guardrail=false   (shred finalized → BLOCK)
//     Blocked (4)      → "finalized", guardrail=false   (admin halt → BLOCK; conservative)
//     ChallengeOpen (5)→ "requested", guardrail=TRUE    (post-challenge reveal IN PROGRESS:
//                                                        the mandatory `NOT
//                                                        post_challenge_reveal_in_progress`
//                                                        shred guardrail is ACTIVE, so the
//                                                        reveal proceeds — internal constitution §0
//                                                        "post-challenge reveal mandates NOT shred")
//     Shredded (6)     → "finalized", guardrail=false   (data gone → BLOCK)
//
//   CONSERVATIVE/FAIL-CLOSED collapse: every M2 state that the on-chain
//   guardrail design treats as "shred has progressed past a recoverable point"
//   (Authorized / Finalized / Blocked / Shredded) maps to the coordinator's
//   most-restrictive bucket "finalized" so delivery is refused. Only None /
//   Requested / ChallengeOpen keep the reveal alive, exactly mirroring
//   `isShredStateSignable` (None|Requested) PLUS the ChallengeOpen carve-out
//   that the coordinator handles via the guardrail bool rather than the state.
//
// ISOLATION (SECURITY.md): no @cealis/shared, no V1 package imports,
// no V1 env vars (the sealed-share / issuer-salt / committee-key family), no
// V1 TAG_*_V1 constants.

import type { ShredStateLive } from "../reveal-coordinator.js";
import type { ShredStateLivePort } from "../reveal-coordinator-impl.js";
import type { Hex32 } from "../../types/reveal-artifact-bundle.js";
import type { ChainStateReader } from "./chain-port.js";

/**
 * M2 `ShredState` enum (Enums.sol), mirrored here as a local const so this
 * port does not type-couple to @cealis/v3-custody's runtime export. The
 * numeric values are the on-chain wire values — do NOT renumber.
 */
const M2_SHRED_STATE = {
  None: 0,
  Requested: 1,
  Authorized: 2,
  Finalized: 3,
  Blocked: 4,
  ChallengeOpen: 5,
  Shredded: 6,
} as const;

/**
 * Map the raw M2 uint8 shred state to the coordinator's
 * (lifecycle, guardrail) pair. Pure function — exported for the unit test so
 * every enum value's mapping is asserted explicitly.
 *
 * Throws on an out-of-range value (fail-closed: an undecodable chain return is
 * a hard error, not a silent "none").
 */
export function mapM2ShredState(raw: number): {
  state: ShredStateLive["state"];
  post_challenge_reveal_in_progress: boolean;
} {
  switch (raw) {
    case M2_SHRED_STATE.None:
      return { state: "none", post_challenge_reveal_in_progress: false };
    case M2_SHRED_STATE.Requested:
      return { state: "requested", post_challenge_reveal_in_progress: false };
    case M2_SHRED_STATE.ChallengeOpen:
      // Post-challenge reveal in progress: the mandatory guardrail is ACTIVE,
      // so the coordinator allows the reveal (state "requested" + guardrail
      // true is the ONLY combination that survives the requested-state check).
      return { state: "requested", post_challenge_reveal_in_progress: true };
    case M2_SHRED_STATE.Authorized:
    case M2_SHRED_STATE.Finalized:
    case M2_SHRED_STATE.Blocked:
    case M2_SHRED_STATE.Shredded:
      // Shred has progressed past a recoverable point — collapse to the
      // coordinator's most-restrictive bucket so delivery is refused.
      return { state: "finalized", post_challenge_reveal_in_progress: false };
    default:
      throw new Error(
        `ShredStateLivePort: chain returned out-of-range ShredState ${raw} (expected 0..6) — failing closed`,
      );
  }
}

/**
 * Reads the live shred lifecycle for `hCommit` from chain at call time.
 *
 * A throwing chain read propagates (fail-closed) — the port NEVER returns a
 * permissive "none" on RPC failure.
 */
export class ShredStateLivePortImpl implements ShredStateLivePort {
  private readonly reader: ChainStateReader;

  constructor(reader: ChainStateReader) {
    this.reader = reader;
  }

  async read(hCommit: Hex32): Promise<Omit<ShredStateLive, "read_at">> {
    const raw = await this.reader.getCurrentShredStateRaw(hCommit);
    return mapM2ShredState(raw);
  }
}
