// Art18FreezeLivePortImpl + PostgresArt18FreezeStore tests — T3.4.
//
// Proves (always, no infra): (a) no freeze row → frozen=false, (b) active
// non-expired freeze → frozen=true with expiry surfaced, (c) 90-day AUTO-EXPIRY
// at read time → an expired row reports frozen=false, (d) live re-read (clock
// sampled fresh), (e) fail-closed on a throwing store + on an unparseable
// expiry.
//
// Proves (opt-in via CEALIS_V3_DATABASE_URL / V3_TEST_PG_URL): the real
// PostgresArt18FreezeStore reads the per-subject row and respects lifted_at,
// against an ephemeral `art18_freezes` table (migration 0006 is owned by
// T0.1/T0.3, not this task, so the DB test self-provisions a scratch table).

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import postgres from "postgres";
import type { Sql } from "postgres";

import {
  Art18FreezeLivePortImpl,
  PostgresArt18FreezeStore,
  ART18_FREEZE_MAX_DAYS,
  ART18_FREEZE_MAX_MS,
  type Art18FreezeStore,
  type Art18FreezeRecord,
} from "../../../src/reveal/live-ports/art18-port.js";
import type { Hex32 } from "../../../src/types/reveal-artifact-bundle.js";

function hex(n: number): Hex32 {
  return `0x${n.toString(16).padStart(64, "0")}` as Hex32;
}

/** Fake store returning a fixed record (or null), with a settable thrower. */
function fakeStore(record: Art18FreezeRecord | null | (() => never)): Art18FreezeStore {
  return {
    getActiveFreeze: async () => {
      if (typeof record === "function") return record();
      return record;
    },
  };
}

describe("ART18 ceiling constants", () => {
  it("90-day max (Decision D13)", () => {
    expect(ART18_FREEZE_MAX_DAYS).toBe(90);
    expect(ART18_FREEZE_MAX_MS).toBe(90 * 24 * 60 * 60 * 1000);
  });
});

describe("Art18FreezeLivePortImpl — auto-expiry at read time", () => {
  const NOW = 1_778_000_000_000; // fixed clock (ms)

  it("no freeze row → frozen=false (no freeze_expires_at)", async () => {
    const port = new Art18FreezeLivePortImpl(fakeStore(null), () => NOW);
    const out = await port.read(hex(1));
    expect(out).toEqual({ frozen: false });
  });

  it("active non-expired freeze → frozen=true with expiry surfaced", async () => {
    const expiresAt = new Date(NOW + 10 * 24 * 60 * 60 * 1000).toISOString(); // +10d
    const port = new Art18FreezeLivePortImpl(
      fakeStore({ subject_commitment: hex(2), freeze_expires_at: expiresAt }),
      () => NOW,
    );

    const out = await port.read(hex(2));
    expect(out).toEqual({ frozen: true, freeze_expires_at: expiresAt });
  });

  it("freeze past 90-day ceiling auto-expires at read → frozen=false", async () => {
    // freeze_expires_at is in the past relative to `now` → auto-lifted, even
    // though no sweeper purged the row.
    const expiresAt = new Date(NOW - 1000).toISOString(); // 1s ago
    const port = new Art18FreezeLivePortImpl(
      fakeStore({ subject_commitment: hex(3), freeze_expires_at: expiresAt }),
      () => NOW,
    );

    const out = await port.read(hex(3));
    expect(out).toEqual({ frozen: false });
  });

  it("exactly-at-expiry instant counts as lifted (<= now)", async () => {
    const expiresAt = new Date(NOW).toISOString();
    const port = new Art18FreezeLivePortImpl(
      fakeStore({ subject_commitment: hex(4), freeze_expires_at: expiresAt }),
      () => NOW,
    );
    const out = await port.read(hex(4));
    expect(out.frozen).toBe(false);
  });

  it("reads LIVE: a freeze that lifts between two reads flips frozen→false (no cache)", async () => {
    const expiresAt = new Date(NOW + 5000).toISOString(); // +5s
    let now = NOW;
    const port = new Art18FreezeLivePortImpl(
      fakeStore({ subject_commitment: hex(5), freeze_expires_at: expiresAt }),
      () => now,
    );

    const before = await port.read(hex(5));
    now = NOW + 6000; // clock advances past expiry
    const after = await port.read(hex(5));

    expect(before.frozen).toBe(true);
    expect(after.frozen).toBe(false);
  });

  it("calls the store with the subjectCommitment on every read (live)", async () => {
    const store = fakeStore(null);
    const spy = vi.spyOn(store, "getActiveFreeze");
    const port = new Art18FreezeLivePortImpl(store, () => NOW);

    await port.read(hex(0xab));
    await port.read(hex(0xab));

    expect(spy).toHaveBeenCalledTimes(2);
    expect(spy).toHaveBeenCalledWith(hex(0xab));
  });

  it("fail-closed: unparseable expiry → treated as still frozen (never silently lifts)", async () => {
    const port = new Art18FreezeLivePortImpl(
      fakeStore({ subject_commitment: hex(6), freeze_expires_at: "not-a-date" }),
      () => NOW,
    );
    const out = await port.read(hex(6));
    expect(out.frozen).toBe(true);
  });

  it("fail-closed: a throwing store read propagates (never frozen=false on error)", async () => {
    const port = new Art18FreezeLivePortImpl(
      fakeStore(() => {
        throw new Error("DB connection lost");
      }),
      () => NOW,
    );
    await expect(port.read(hex(7))).rejects.toThrow("DB connection lost");
  });
});

// ─── Real Postgres store (opt-in) ───

const PG_URL = process.env["CEALIS_V3_DATABASE_URL"]?.trim() || process.env["V3_TEST_PG_URL"]?.trim();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = PG_URL ? describe : describe.skip;

describeIfPg("PostgresArt18FreezeStore (CEALIS_V3_DATABASE_URL / V3_TEST_PG_URL)", () => {
  let sql: Sql;
  let store: PostgresArt18FreezeStore;
  const subjActive = hex(0x1001);
  const subjLifted = hex(0x1002);
  const subjNone = hex(0x1003);

  beforeAll(async () => {
    sql = postgres(PG_URL as string, { max: 2, idle_timeout: 5, onnotice: () => {} });
    // Self-provision a scratch table matching the 0006 shape (T0.1/T0.3 owns
    // the real migration; this test does not depend on it landing first).
    await sql.unsafe(`
      CREATE TABLE IF NOT EXISTS art18_freezes (
        subject_commitment text PRIMARY KEY,
        freeze_set_at      timestamptz NOT NULL DEFAULT now(),
        freeze_expires_at  timestamptz NOT NULL,
        operator_ref       text NOT NULL,
        reason_ref         text,
        lifted_at          timestamptz
      );
    `);
    // Clean any prior rows from this test's subjects.
    await sql`DELETE FROM art18_freezes WHERE subject_commitment IN (${subjActive}, ${subjLifted}, ${subjNone})`;

    const expiresAt = new Date(Date.now() + ART18_FREEZE_MAX_MS).toISOString();
    await sql`
      INSERT INTO art18_freezes (subject_commitment, freeze_expires_at, operator_ref)
      VALUES (${subjActive}, ${expiresAt}, 'op-1')
    `;
    await sql`
      INSERT INTO art18_freezes (subject_commitment, freeze_expires_at, operator_ref, lifted_at)
      VALUES (${subjLifted}, ${expiresAt}, 'op-1', now())
    `;
    store = new PostgresArt18FreezeStore({ sql });
  });

  afterAll(async () => {
    if (sql) {
      await sql`DELETE FROM art18_freezes WHERE subject_commitment IN (${subjActive}, ${subjLifted}, ${subjNone})`;
      await sql.end({ timeout: 5 });
    }
  });

  it("returns the active (non-lifted) freeze row for a subject", async () => {
    const rec = await store.getActiveFreeze(subjActive);
    expect(rec).not.toBeNull();
    expect(rec?.subject_commitment).toBe(subjActive);
    // ISO-8601 round-trip.
    expect(typeof rec?.freeze_expires_at).toBe("string");
    expect(Number.isNaN(Date.parse(rec!.freeze_expires_at))).toBe(false);
  });

  it("ignores a manually-lifted freeze (lifted_at set) → null", async () => {
    const rec = await store.getActiveFreeze(subjLifted);
    expect(rec).toBeNull();
  });

  it("returns null for a subject with no freeze row", async () => {
    const rec = await store.getActiveFreeze(subjNone);
    expect(rec).toBeNull();
  });

  it("end-to-end: port over the real store reports frozen=true for the active subject", async () => {
    const port = new Art18FreezeLivePortImpl(store);
    const out = await port.read(subjActive);
    expect(out.frozen).toBe(true);
  });
});
