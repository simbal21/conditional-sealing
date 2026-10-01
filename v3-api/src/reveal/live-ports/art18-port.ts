// Art18FreezeLivePort — T3.4 (Phase 3 Wave 2).
//
// Real impl of `Art18FreezeLivePort` (reveal-coordinator-impl.ts:96). Reads the
// live per-subject Art.18 GDPR processing-restriction (reveal freeze) at call
// time, no cache, fail-closed — the C3a discipline (reveal-coordinator.ts §C3a).
// Backs the Art.18 axis of the `ConcreteLiveStateReader` the reveal-coordinator
// composes.
//
// DATA SOURCE (per PHASE-3-RUNTIME-PLAN §3):
//   DB — a per-subject freeze record (`art18_freezes` table; OPERATOR-set,
//   90-day max). Art.18 is PER-SUBJECT (GDPR Art.18 right to restriction of
//   processing), so the natural home is the V3 DB keyed by subjectCommitment,
//   NOT on-chain (S2-2 §14 halt is a different, authorization-scoped axis).
//
//   AUTO-EXPIRY (90-day): every freeze carries a `freeze_expires_at`
//   (set = freeze_set_at + 90d at write time, OPERATOR may set sooner). The
//   port computes `frozen` AT READ TIME against `now`: a freeze whose
//   `freeze_expires_at <= now` is EXPIRED and reports `frozen=false`. The
//   expiry is enforced at the read, so a stale row never blocks a reveal past
//   its 90-day ceiling even if no sweeper has purged it yet.
//
//   `frozen=true` (active, non-expired freeze) blocks delivery — the
//   coordinator's `assertClearanceAllowsDelivery` throws REVEAL_ART18_FROZEN.
//
// FAIL-CLOSED: a throwing DB read propagates — the port NEVER reports
// `frozen=false` on a DB error. An unread freeze state is not provably absent,
// so it must not allow delivery. (The default impl re-throws; do not catch into
// a permissive result.)
//
// TABLE OWNERSHIP: the `art18_freezes` migration (0006) is owned by T0.1/T0.3,
// not this task. This port consumes the table through an injected
// `Art18FreezeStore` boundary so (a) typecheck passes without the table, (b)
// the composition root wires the postgres-js-backed store, (c) tests inject a
// fake store OR exercise the real `PostgresArt18FreezeStore` against an
// ephemeral table.
//
// ISOLATION (SECURITY.md): no @cealis/shared, no V1 package imports,
// no V1 env vars (the sealed-share / issuer-salt / committee-key family), no
// V1 TAG_*_V1 constants. The caller injects the postgres-js `Sql` client at the
// composition root — no connection is constructed from a file here.

import type { Sql } from "postgres";

import type { Art18FreezeLive } from "../reveal-coordinator.js";
import type { Art18FreezeLivePort } from "../reveal-coordinator-impl.js";
import type { Hex32 } from "../../types/reveal-artifact-bundle.js";

/** GDPR Art.18 reveal-freeze ceiling (Decision D13): 90 days. */
export const ART18_FREEZE_MAX_DAYS = 90;
export const ART18_FREEZE_MAX_MS = ART18_FREEZE_MAX_DAYS * 24 * 60 * 60 * 1000;

/**
 * The active-freeze record the store returns for a subject, or `null` when no
 * row exists. `freeze_expires_at` is an ISO-8601 instant; the port applies the
 * auto-expiry against `now`.
 */
export interface Art18FreezeRecord {
  readonly subject_commitment: Hex32;
  /** ISO-8601 instant the freeze auto-lifts (set_at + 90d, or OPERATOR-set sooner). */
  readonly freeze_expires_at: string;
}

/**
 * Live per-subject Art.18 freeze store boundary. `getActiveFreeze` returns the
 * single current freeze row for the subject (or null). The port owns the
 * expiry decision so the store stays a thin row-fetcher; this keeps the
 * auto-expiry logic testable in one place.
 */
export interface Art18FreezeStore {
  /** Fetch the current freeze row for the subject, or null when none exists. */
  getActiveFreeze(subjectCommitment: Hex32): Promise<Art18FreezeRecord | null>;
}

/**
 * Reads the live Art.18 freeze for a subject and applies the 90-day
 * auto-expiry at read time.
 *
 *   - no row                          → { frozen: false }
 *   - row, freeze_expires_at >  now   → { frozen: true, freeze_expires_at }
 *   - row, freeze_expires_at <= now   → { frozen: false }  (auto-expired)
 *
 * A throwing store read propagates (fail-closed).
 */
export class Art18FreezeLivePortImpl implements Art18FreezeLivePort {
  private readonly store: Art18FreezeStore;
  private readonly nowMs: () => number;

  /**
   * @param store live per-subject freeze store (DB-backed in production).
   * @param nowMs injectable clock for deterministic tests. Production omits it
   *   and uses `Date.now`. Sampled fresh on every `read()` — not a stale-time
   *   knob.
   */
  constructor(store: Art18FreezeStore, nowMs: () => number = () => Date.now()) {
    this.store = store;
    this.nowMs = nowMs;
  }

  async read(subjectCommitment: Hex32): Promise<Omit<Art18FreezeLive, "read_at">> {
    const record = await this.store.getActiveFreeze(subjectCommitment);
    if (record === null) {
      return { frozen: false };
    }

    const expiresMs = Date.parse(record.freeze_expires_at);
    const nowMs = this.nowMs();

    // Defensive: an unparseable expiry is fail-closed (treat as still frozen)
    // — an undecodable freeze must NOT silently lift.
    if (Number.isNaN(expiresMs)) {
      return { frozen: true, freeze_expires_at: record.freeze_expires_at };
    }

    if (expiresMs <= nowMs) {
      // Auto-expired past the 90-day ceiling (or the OPERATOR-set sooner
      // instant) — the freeze has lifted.
      return { frozen: false };
    }

    return { frozen: true, freeze_expires_at: record.freeze_expires_at };
  }
}

// ─── Postgres-backed Art18FreezeStore (production boundary impl) ───

export interface PostgresArt18FreezeStoreOptions {
  /** postgres-js Sql client bound to the V3 API DB. */
  readonly sql: Sql;
}

/**
 * Postgres-backed `Art18FreezeStore` over the `art18_freezes` table (migration
 * 0006, owned by T0.1/T0.3).
 *
 * Expected table shape (per PHASE-3-RUNTIME-PLAN §2 / §3):
 *   art18_freezes(
 *     subject_commitment  text primary key,   -- per-subject (Art.18 is per-subject)
 *     freeze_set_at       timestamptz not null,
 *     freeze_expires_at   timestamptz not null,  -- set_at + 90d max, OPERATOR may set sooner
 *     operator_ref        text not null,         -- who set the freeze (OPERATOR_ROLE)
 *     reason_ref          text,                  -- opaque ref; NO PII at rest
 *     lifted_at           timestamptz             -- non-null = manually lifted
 *   )
 *
 * `getActiveFreeze` returns the row only when it is not manually lifted; the
 * port applies the auto-expiry. NO PII is stored — `subject_commitment` is a
 * commitment hash, `reason_ref` an opaque pointer.
 */
export class PostgresArt18FreezeStore implements Art18FreezeStore {
  private readonly sql: Sql;

  constructor(options: PostgresArt18FreezeStoreOptions) {
    this.sql = options.sql;
  }

  async getActiveFreeze(subjectCommitment: Hex32): Promise<Art18FreezeRecord | null> {
    const rows = await this.sql<{ subject_commitment: string; freeze_expires_at: Date }[]>`
      SELECT subject_commitment, freeze_expires_at
      FROM art18_freezes
      WHERE subject_commitment = ${subjectCommitment}
        AND lifted_at IS NULL
      LIMIT 1
    `;
    const row = rows[0];
    if (!row) return null;
    return {
      subject_commitment: row.subject_commitment as Hex32,
      freeze_expires_at:
        row.freeze_expires_at instanceof Date
          ? row.freeze_expires_at.toISOString()
          : new Date(row.freeze_expires_at).toISOString(),
    };
  }
}
