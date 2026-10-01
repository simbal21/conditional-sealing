// T3.5 tests — RevealAuthorized event listener as the production reveal driver.
//
// Coverage:
//   A. DRIVER DISCIPLINE (mockable — no Postgres / no RPC; always runs):
//      1. Cursor advance: each confirmed event drives the processor exactly once
//         and the cursor advances to its (block, logIndex).
//      2. Restart-resume: a fresh driver loaded from a persisted cursor skips
//         everything at-or-before that cursor — no re-process of old events.
//      3. No double-process: the same event re-delivered (re-watch / reorg
//         replay) within a run is de-duped against the in-run cursor.
//      4. Confirmation gating: an event whose block is within `confirmations`
//         of the head is NOT processed and does NOT advance the cursor; it
//         processes on a later fire once the head moves past it.
//      5. Fail-closed on error: a processor/resolver throw does NOT advance the
//         cursor (event replays); the batch stops rather than committing a gap.
//      6. Ordering: an out-of-order batch is processed in (block, logIndex)
//         order and the cursor ends at the max position.
//      7. start() is idempotent; stop() halts further processing.
//
//   B. DB CURSOR STORE (live-infra — env-gated, SKIPs without V3_TEST_PG_URL):
//      monotonic load/advance over `event_cursors`; a stale advance never
//      rewinds the high-water mark.
//
// The doubles cross NO vendor boundary and hold NO real key material.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres from "postgres";
import type { Sql } from "postgres";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Address } from "viem";

import {
  DbRevealEventCursorStore,
  InMemoryRevealEventCursorStore,
  RevealAuthorizedDriver,
  type ChainHeadReader,
  type RevealAuthorizedEvent,
  type RevealEventCursor,
  type RevealInputForDriver,
  type RevealInputResolver,
  type ViemRevealEventClient,
} from "../../src/combiner-orchestrator/event-listener.js";
import { buildDb } from "../../src/db/connection.js";
import type { Hex32 } from "../../src/types/reveal-artifact-bundle.js";

// ── shared fixtures ──────────────────────────────────────────────────────────

const CONDITION_ENGINE = "0xb09a8300423CA3BD0E028bAB6A6245A248520D02" as Address;
const CHAIN_ID = 84_532;

function hex32(byte: number): Hex32 {
  return ("0x" + byte.toString(16).padStart(2, "0").repeat(32).slice(0, 64)) as Hex32;
}

/** A raw viem-style log for `RevealAuthorized`, in the shape
 *  `normalizeRevealAuthorizedLog` consumes. */
function rawLog(args: {
  readonly authId: number;
  readonly block: bigint;
  readonly logIndex: number;
}): Record<string, unknown> {
  return {
    args: {
      authorizationId: hex32(args.authId),
      hCommit: hex32(args.authId + 0x40),
      pdaRoot: hex32(args.authId + 0x80),
      authorizationBlock: args.block,
      authorizationTimestamp: 1_778_489_600n,
      challengeWindow: 60,
      conditionRef: hex32(args.authId + 0xc0),
    },
    transactionHash: hex32(args.authId + 0x10),
    logIndex: args.logIndex,
    blockHash: hex32(args.authId + 0x20),
    blockNumber: args.block,
  };
}

/** A controllable viem-watch double: capture the `onLogs` callback so the test
 *  can fire batches, and record unwatch calls. */
function makeWatchClient(): ViemRevealEventClient & {
  fire(logs: readonly unknown[]): void;
  watchCount: number;
  unwatched: boolean;
} {
  let onLogs: ((logs: readonly unknown[]) => void) | undefined;
  const state = {
    watchCount: 0,
    unwatched: false,
    fire(logs: readonly unknown[]): void {
      if (!onLogs) throw new Error("watch not started");
      onLogs(logs);
    },
    watchContractEvent(args: { onLogs: (logs: readonly unknown[]) => void }): () => void {
      state.watchCount += 1;
      onLogs = args.onLogs;
      return () => {
        state.unwatched = true;
        onLogs = undefined;
      };
    },
  };
  return state as ViemRevealEventClient & {
    fire(logs: readonly unknown[]): void;
    watchCount: number;
    unwatched: boolean;
  };
}

/** A mutable head reader. */
function makeHeadReader(initial: bigint): ChainHeadReader & { head: bigint } {
  const state = {
    head: initial,
    async getBlockNumber(): Promise<bigint> {
      return state.head;
    },
  };
  return state;
}

/** The minimal processor input this test drives — only `event` matters; the
 *  resolver supplies an opaque marker the processor records. */
interface TestInput {
  readonly event: RevealAuthorizedEvent;
  readonly resolved_marker: string;
}

/** Resolver double — records which events it was asked to resolve; optionally
 *  throws for a chosen authorizationId (fail-closed test). */
function makeResolver(opts: { throwForAuthId?: Hex32 } = {}): RevealInputResolver<TestInput> & {
  resolvedAuthIds: Hex32[];
} {
  const resolvedAuthIds: Hex32[] = [];
  return {
    resolvedAuthIds,
    async resolve(event: RevealAuthorizedEvent): Promise<RevealInputForDriver<TestInput>> {
      resolvedAuthIds.push(event.authorizationId);
      if (opts.throwForAuthId !== undefined && event.authorizationId === opts.throwForAuthId) {
        throw new Error(`resolver refuses ${event.authorizationId}`);
      }
      return { resolved_marker: `marker-${event.authorizationId}` };
    },
  };
}

/** Processor double — records every event it processed (in order). */
function makeProcessor(opts: { throwForAuthId?: Hex32 } = {}): {
  process: (input: TestInput) => Promise<void>;
  processed: Hex32[];
} {
  const processed: Hex32[] = [];
  return {
    processed,
    async process(input: TestInput): Promise<void> {
      if (opts.throwForAuthId !== undefined && input.event.authorizationId === opts.throwForAuthId) {
        throw new Error(`processor refuses ${input.event.authorizationId}`);
      }
      processed.push(input.event.authorizationId);
    },
  };
}

interface DriverHarness {
  readonly driver: RevealAuthorizedDriver<TestInput, void>;
  readonly client: ReturnType<typeof makeWatchClient>;
  readonly head: ReturnType<typeof makeHeadReader>;
  readonly cursorStore: InMemoryRevealEventCursorStore;
  readonly resolver: ReturnType<typeof makeResolver>;
  readonly processor: ReturnType<typeof makeProcessor>;
  readonly errors: unknown[];
}

function makeDriver(opts: {
  headHeight?: bigint;
  confirmations?: bigint;
  initialCursor?: RevealEventCursor;
  resolverThrowForAuthId?: Hex32;
  processorThrowForAuthId?: Hex32;
} = {}): DriverHarness {
  const client = makeWatchClient();
  const head = makeHeadReader(opts.headHeight ?? 1_000n);
  const cursorStore = new InMemoryRevealEventCursorStore(opts.initialCursor);
  const resolver = makeResolver(
    opts.resolverThrowForAuthId !== undefined ? { throwForAuthId: opts.resolverThrowForAuthId } : {},
  );
  const processor = makeProcessor(
    opts.processorThrowForAuthId !== undefined ? { throwForAuthId: opts.processorThrowForAuthId } : {},
  );
  const errors: unknown[] = [];
  const driver = new RevealAuthorizedDriver<TestInput, void>({
    client,
    conditionEngineAddress: CONDITION_ENGINE,
    headReader: head,
    cursorStore,
    inputResolver: resolver,
    process: processor.process,
    confirmations: opts.confirmations ?? 0n,
    onError: (error) => {
      errors.push(error);
    },
  });
  return { driver, client, head, cursorStore, resolver, processor, errors };
}

// ── A. driver discipline (mockable) ──────────────────────────────────────────

describe("RevealAuthorizedDriver — production reveal driver discipline", () => {
  it("advances the cursor and processes each confirmed event exactly once", async () => {
    const h = makeDriver({ headHeight: 1_000n, confirmations: 0n });
    await h.driver.start();

    h.client.fire([
      rawLog({ authId: 1, block: 100n, logIndex: 0 }),
      rawLog({ authId: 2, block: 100n, logIndex: 1 }),
      rawLog({ authId: 3, block: 101n, logIndex: 0 }),
    ]);
    await h.driver.drain();

    expect(h.processor.processed).toEqual([hex32(1), hex32(2), hex32(3)]);
    await expect(h.cursorStore.load()).resolves.toEqual({
      lastProcessedBlock: 101n,
      lastProcessedLogIndex: 0,
    });
    expect(h.errors).toHaveLength(0);
  });

  it("resumes from a persisted cursor — skips events at-or-before it (no re-process on restart)", async () => {
    // Simulate a restart: the previous run committed up to (block 100, logIndex 1).
    const h = makeDriver({
      headHeight: 1_000n,
      confirmations: 0n,
      initialCursor: { lastProcessedBlock: 100n, lastProcessedLogIndex: 1 },
    });
    await h.driver.start();

    h.client.fire([
      rawLog({ authId: 1, block: 100n, logIndex: 0 }), // before cursor → skip
      rawLog({ authId: 2, block: 100n, logIndex: 1 }), // == cursor → skip
      rawLog({ authId: 3, block: 100n, logIndex: 2 }), // after cursor → process
      rawLog({ authId: 4, block: 101n, logIndex: 0 }), // after cursor → process
    ]);
    await h.driver.drain();

    expect(h.processor.processed).toEqual([hex32(3), hex32(4)]);
    await expect(h.cursorStore.load()).resolves.toEqual({
      lastProcessedBlock: 101n,
      lastProcessedLogIndex: 0,
    });
  });

  it("never double-processes a re-delivered event (reorg / re-watch replay)", async () => {
    const h = makeDriver({ headHeight: 1_000n, confirmations: 0n });
    await h.driver.start();

    h.client.fire([rawLog({ authId: 7, block: 200n, logIndex: 0 })]);
    await h.driver.drain();
    // The SAME event is delivered again (e.g. reorg replay or watcher re-fire).
    h.client.fire([
      rawLog({ authId: 7, block: 200n, logIndex: 0 }), // duplicate → de-dup
      rawLog({ authId: 8, block: 200n, logIndex: 1 }), // new → process
    ]);
    await h.driver.drain();

    expect(h.processor.processed).toEqual([hex32(7), hex32(8)]);
    await expect(h.cursorStore.load()).resolves.toEqual({
      lastProcessedBlock: 200n,
      lastProcessedLogIndex: 1,
    });
  });

  it("confirmation-gates: an under-confirmed event waits, then processes on a later fire", async () => {
    const h = makeDriver({ headHeight: 105n, confirmations: 10n });
    await h.driver.start();

    // block 100 needs head >= 110; head is 105 → not processed yet.
    h.client.fire([rawLog({ authId: 1, block: 100n, logIndex: 0 })]);
    await h.driver.drain();
    expect(h.processor.processed).toEqual([]);
    await expect(h.cursorStore.load()).resolves.toBeUndefined();

    // Head advances past the confirmation depth; a re-fire now processes it.
    h.head.head = 110n;
    h.client.fire([rawLog({ authId: 1, block: 100n, logIndex: 0 })]);
    await h.driver.drain();
    expect(h.processor.processed).toEqual([hex32(1)]);
    await expect(h.cursorStore.load()).resolves.toEqual({
      lastProcessedBlock: 100n,
      lastProcessedLogIndex: 0,
    });
  });

  it("stops the batch at an under-confirmed event without committing past the gap", async () => {
    const h = makeDriver({ headHeight: 110n, confirmations: 10n });
    await h.driver.start();

    h.client.fire([
      rawLog({ authId: 1, block: 100n, logIndex: 0 }), // head 110 >= 110 → process
      rawLog({ authId: 2, block: 101n, logIndex: 0 }), // needs >= 111 → gated, stop
      rawLog({ authId: 3, block: 100n, logIndex: 1 }), // would be confirmed but is after the gate in order
    ]);
    await h.driver.drain();

    // Ordered: (100,0) → (100,1) → (101,0). The (101,0) gate stops the batch
    // AFTER both block-100 events are committed.
    expect(h.processor.processed).toEqual([hex32(1), hex32(3)]);
    await expect(h.cursorStore.load()).resolves.toEqual({
      lastProcessedBlock: 100n,
      lastProcessedLogIndex: 1,
    });
  });

  it("fail-closed: a processor throw does NOT advance the cursor and stops the batch (event replays)", async () => {
    const h = makeDriver({
      headHeight: 1_000n,
      confirmations: 0n,
      processorThrowForAuthId: hex32(2),
    });
    await h.driver.start();

    h.client.fire([
      rawLog({ authId: 1, block: 300n, logIndex: 0 }), // ok → process + advance
      rawLog({ authId: 2, block: 300n, logIndex: 1 }), // throws → no advance, stop
      rawLog({ authId: 3, block: 300n, logIndex: 2 }), // never reached this batch
    ]);
    await h.driver.drain();

    expect(h.processor.processed).toEqual([hex32(1)]);
    // Cursor sits at the last SUCCESSFUL event — the failed one will replay.
    await expect(h.cursorStore.load()).resolves.toEqual({
      lastProcessedBlock: 300n,
      lastProcessedLogIndex: 0,
    });
    expect(h.errors).toHaveLength(1);

    // Replay (next fire / boot): the failed event + the unreached one process,
    // and the previously-committed event is NOT re-processed.
    h.client.fire([
      rawLog({ authId: 1, block: 300n, logIndex: 0 }), // committed → de-dup
      rawLog({ authId: 2, block: 300n, logIndex: 1 }), // retries → now ok? processor still throws
      rawLog({ authId: 3, block: 300n, logIndex: 2 }),
    ]);
    await h.driver.drain();
    // Processor still throws on authId 2 → it blocks again, 3 still unreached.
    expect(h.processor.processed).toEqual([hex32(1)]);
  });

  it("fail-closed also covers resolver failure (no cursor advance)", async () => {
    const h = makeDriver({
      headHeight: 1_000n,
      confirmations: 0n,
      resolverThrowForAuthId: hex32(5),
    });
    await h.driver.start();

    h.client.fire([rawLog({ authId: 5, block: 400n, logIndex: 0 })]);
    await h.driver.drain();

    expect(h.processor.processed).toEqual([]);
    await expect(h.cursorStore.load()).resolves.toBeUndefined();
    expect(h.errors).toHaveLength(1);
  });

  it("processes an out-of-order batch in (block, logIndex) order", async () => {
    const h = makeDriver({ headHeight: 1_000n, confirmations: 0n });
    await h.driver.start();

    h.client.fire([
      rawLog({ authId: 3, block: 101n, logIndex: 0 }),
      rawLog({ authId: 1, block: 100n, logIndex: 0 }),
      rawLog({ authId: 2, block: 100n, logIndex: 1 }),
    ]);
    await h.driver.drain();

    expect(h.processor.processed).toEqual([hex32(1), hex32(2), hex32(3)]);
    await expect(h.cursorStore.load()).resolves.toEqual({
      lastProcessedBlock: 101n,
      lastProcessedLogIndex: 0,
    });
  });

  it("start() is idempotent and stop() halts further processing", async () => {
    const h = makeDriver({ headHeight: 1_000n, confirmations: 0n });
    const stop1 = await h.driver.start();
    const stop2 = await h.driver.start();
    expect(stop1).toBe(stop2);
    expect(h.client.watchCount).toBe(1); // only one watch established

    h.driver.stop();
    expect(h.client.unwatched).toBe(true);
  });

  it("serializes overlapping batches so two fires cannot double-advance", async () => {
    const h = makeDriver({ headHeight: 1_000n, confirmations: 0n });
    await h.driver.start();

    // Two fires back-to-back without awaiting between them — the internal queue
    // must serialize so the second batch sees the first batch's cursor.
    h.client.fire([rawLog({ authId: 1, block: 500n, logIndex: 0 })]);
    h.client.fire([
      rawLog({ authId: 1, block: 500n, logIndex: 0 }), // duplicate of batch-1's event
      rawLog({ authId: 2, block: 500n, logIndex: 1 }),
    ]);
    await h.driver.drain();

    expect(h.processor.processed).toEqual([hex32(1), hex32(2)]);
  });
});

// ── B. DB cursor store (live-infra — env-gated) ──────────────────────────────

const TEST_PG_URL = process.env["V3_TEST_PG_URL"] ?? process.env["CEALIS_V3_DATABASE_URL"];

const __dirname_ = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(__dirname_, "..", "..", "src", "db", "migrations");
const CURSOR_LOCK_KEY = 5_204_482;

describe.skipIf(!TEST_PG_URL)("DbRevealEventCursorStore — live Postgres (env-gated)", () => {
  let sql: Sql;
  let store: DbRevealEventCursorStore;
  // Per-process unique address so parallel test files don't collide on the
  // (chain_id, contract_address, event_name) PK.
  const testAddress = ("0x" +
    `${process.pid.toString(16)}${Math.random().toString(16).slice(2)}`.padEnd(40, "0").slice(0, 40)) as Address;

  beforeAll(async () => {
    sql = postgres(TEST_PG_URL as string, {
      max: 4,
      idle_timeout: 5,
      onnotice: () => {
        /* suppress CREATE TABLE IF NOT EXISTS notices */
      },
    });
    // Apply 0002 (holds `event_cursors`); serialize via advisory lock so
    // parallel workers don't race the CREATE statements.
    const ddl = readFileSync(join(MIGRATIONS_DIR, "0002_reveals.sql"), "utf-8");
    await sql`SELECT pg_advisory_lock(${CURSOR_LOCK_KEY})`;
    try {
      await sql.unsafe(ddl);
    } finally {
      await sql`SELECT pg_advisory_unlock(${CURSOR_LOCK_KEY})`;
    }
    store = new DbRevealEventCursorStore({ db: buildDb(sql), chainId: CHAIN_ID, contractAddress: testAddress });
  });

  afterAll(async () => {
    await sql`DELETE FROM event_cursors WHERE contract_address = ${testAddress.toLowerCase()}`;
    await sql.end({ timeout: 5 });
  });

  it("returns undefined before any advance", async () => {
    await expect(store.load()).resolves.toBeUndefined();
  });

  it("persists and reloads an advanced cursor", async () => {
    await store.advance({ lastProcessedBlock: 100n, lastProcessedLogIndex: 3 });
    await expect(store.load()).resolves.toEqual({ lastProcessedBlock: 100n, lastProcessedLogIndex: 3 });
  });

  it("advances monotonically and never rewinds on a stale advance", async () => {
    await store.advance({ lastProcessedBlock: 200n, lastProcessedLogIndex: 0 });
    await expect(store.load()).resolves.toEqual({ lastProcessedBlock: 200n, lastProcessedLogIndex: 0 });

    // Stale (earlier block) advance → no-op.
    await store.advance({ lastProcessedBlock: 150n, lastProcessedLogIndex: 9 });
    await expect(store.load()).resolves.toEqual({ lastProcessedBlock: 200n, lastProcessedLogIndex: 0 });

    // Same block, earlier logIndex → no-op.
    await store.advance({ lastProcessedBlock: 200n, lastProcessedLogIndex: 0 });
    await expect(store.load()).resolves.toEqual({ lastProcessedBlock: 200n, lastProcessedLogIndex: 0 });

    // Same block, later logIndex → advances.
    await store.advance({ lastProcessedBlock: 200n, lastProcessedLogIndex: 5 });
    await expect(store.load()).resolves.toEqual({ lastProcessedBlock: 200n, lastProcessedLogIndex: 5 });
  });
});
