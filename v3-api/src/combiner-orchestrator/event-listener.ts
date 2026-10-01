import type { Address, Hex } from "viem";
import { and, eq, gt, or, sql, type SQL } from "drizzle-orm";
import { getConditionEngineAbi } from "../m2-imports.js";
import type { V3Database } from "../db/connection.js";
import { eventCursorsTable } from "../db/schema-extensions/reveals.js";
import type { Hex32 } from "../types/reveal-artifact-bundle.js";

export interface RevealAuthorizedEvent {
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly pda_root: Hex32;
  readonly authorization_block: bigint;
  readonly authorization_timestamp: bigint;
  readonly challenge_window: number;
  readonly conditionRef: Hex32;
  readonly transaction_hash?: Hex;
  readonly log_index?: number;
  readonly block_hash?: Hex32;
  readonly block_number?: bigint;
}

export interface ViemRevealEventClient {
  watchContractEvent(args: {
    readonly address: Address;
    readonly abi: unknown;
    readonly eventName: "RevealAuthorized";
    readonly onLogs: (logs: readonly unknown[]) => void;
  }): () => void;
}

export interface RevealAuthorizedListenerOptions {
  readonly client: ViemRevealEventClient;
  readonly conditionEngineAddress: Address;
  readonly onRevealAuthorized: (event: RevealAuthorizedEvent) => Promise<void> | void;
  readonly onError?: (error: unknown) => Promise<void> | void;
}

export function createRevealAuthorizedListener(options: RevealAuthorizedListenerOptions): {
  readonly start: () => () => void;
} {
  return {
    start: () =>
      options.client.watchContractEvent({
        address: options.conditionEngineAddress,
        abi: getConditionEngineAbi(),
        eventName: "RevealAuthorized",
        onLogs: (logs) => {
          void handleLogs(logs, options);
        },
      }),
  };
}

export async function handleRevealAuthorizedLog(
  log: unknown,
  onRevealAuthorized: (event: RevealAuthorizedEvent) => Promise<void> | void,
): Promise<void> {
  await onRevealAuthorized(normalizeRevealAuthorizedLog(log));
}

// ─────────────────────────────────────────────────────────────────────────────
// T3.5 — RevealAuthorized event listener as the PRODUCTION reveal driver.
//
// `createRevealAuthorizedListener` above is the raw viem-watch → normalize seam.
// This section wraps it into the production driver: the thing the Wave-5
// composition root starts at boot to translate every on-chain `RevealAuthorized`
// into a `processRevealAuthorizedEvent` (T3.3) run, exactly once, surviving
// restarts.
//
// THREE DISCIPLINES (Rule 25 — snapshot/never-re-check is the failure mode):
//
//   1. CONFIRMATION GATING. A freshly-watched log can sit on a block that a
//      reorg later orphans. The driver does NOT process a log until the chain
//      head is `confirmations` blocks past the log's block. `confirmations` is
//      PDA/env-configurable (Base finality default), never hardcoded into the
//      flow. The head is read LIVE per batch from the injected head-reader.
//
//   2. CURSOR PERSIST + RESUME (no missed / no double events). The driver
//      persists a `(chainId, contractAddress, "RevealAuthorized")` cursor of the
//      last (block, logIndex) it COMMITTED. On every candidate event it skips
//      anything at-or-before the cursor (de-dup across restart / re-watch /
//      reorg replay). The cursor advances ONLY AFTER a successful
//      `processRevealAuthorizedEvent` — a crash between fire and persist replays
//      the event on the next boot rather than dropping it (at-least-once into
//      the idempotent processor, never at-most-once that could silently lose a
//      reveal).
//
//   3. EVENT-DRIVEN vs REQUEST-DRIVEN. The `/internal/reveal/initiate` route is
//      the request-driven test/ceremony entry; THIS listener is the production
//      driver. Both route into the same `processRevealAuthorizedEvent`.
//
// The chain-watch client, the ConditionEngine address, the head-reader, and the
// input-resolver are ALL injected ports — the real viem `PublicClient`, the
// deployed address, and the PDA-config/σ/vault resolution are vendor/manifest-
// gated and wired at Wave 5. The listener itself crosses no vendor boundary.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The cursor a `RevealAuthorized` driver persists so it never re-processes (no
 * double) and never skips (no missed) an event across restarts. Keyed by the
 * `(chainId, contractAddress, eventName)` tuple in `event_cursors`.
 */
export interface RevealEventCursor {
  readonly lastProcessedBlock: bigint;
  readonly lastProcessedLogIndex: number;
}

/**
 * Persistence port for the reveal-event cursor. The production impl is
 * `DbRevealEventCursorStore` over the `event_cursors` table; tests inject an
 * in-memory double. The store is responsible for nothing but durable
 * load/advance of the `(block, logIndex)` high-water mark — the ordering /
 * de-dup discipline lives in the driver.
 */
export interface RevealEventCursorStore {
  /** Load the persisted cursor, or `undefined` if none committed yet. */
  load(): Promise<RevealEventCursor | undefined>;
  /**
   * Durably advance the cursor to `cursor` — called ONLY after the event at
   * that position was fully processed. Monotonic: an `advance` to a position
   * at-or-before the stored one is a no-op (guards out-of-order callbacks).
   */
  advance(cursor: RevealEventCursor): Promise<void>;
}

/**
 * Postgres-backed cursor store over `event_cursors` (migration 0002). One row
 * per `(chain_id, contract_address, event_name)`; the driver owns exactly the
 * `RevealAuthorized` row for its configured ConditionEngine. Upsert via the
 * primary key gives a single durable high-water mark; the monotonic guard lives
 * in the `WHERE` so a stale/out-of-order advance cannot rewind the cursor.
 *
 * V3 isolation: no @cealis/shared, no V1 env. The caller injects the Drizzle
 * client (composition root); the contract address is normalized lowercase so a
 * checksummed-vs-lowercase address mismatch can't fork the cursor row.
 */
export class DbRevealEventCursorStore implements RevealEventCursorStore {
  private readonly db: V3Database;
  private readonly chainId: number;
  private readonly contractAddress: string;
  private static readonly EVENT_NAME = "RevealAuthorized";

  constructor(args: { readonly db: V3Database; readonly chainId: number; readonly contractAddress: Address }) {
    this.db = args.db;
    this.chainId = args.chainId;
    this.contractAddress = args.contractAddress.toLowerCase();
  }

  async load(): Promise<RevealEventCursor | undefined> {
    const rows = await this.db
      .select({
        lastProcessedBlock: eventCursorsTable.lastProcessedBlock,
        lastProcessedLogIndex: eventCursorsTable.lastProcessedLogIndex,
      })
      .from(eventCursorsTable)
      .where(
        and(
          eq(eventCursorsTable.chainId, this.chainId),
          eq(eventCursorsTable.contractAddress, this.contractAddress),
          eq(eventCursorsTable.eventName, DbRevealEventCursorStore.EVENT_NAME),
        ),
      )
      .limit(1);
    const row = rows[0];
    if (row === undefined) return undefined;
    return {
      lastProcessedBlock: row.lastProcessedBlock,
      lastProcessedLogIndex: row.lastProcessedLogIndex,
    };
  }

  async advance(cursor: RevealEventCursor): Promise<void> {
    // Upsert the single row; the DO-UPDATE WHERE makes the advance MONOTONIC —
    // a row already at-or-ahead of `cursor` is never rewound (out-of-order or
    // duplicate advance is a no-op). The block-then-logIndex compare matches the
    // driver's ordering.
    await this.db
      .insert(eventCursorsTable)
      .values({
        chainId: this.chainId,
        contractAddress: this.contractAddress,
        eventName: DbRevealEventCursorStore.EVENT_NAME,
        lastProcessedBlock: cursor.lastProcessedBlock,
        lastProcessedLogIndex: cursor.lastProcessedLogIndex,
        updatedAt: new Date(),
      })
      .onConflictDoUpdate({
        target: [
          eventCursorsTable.chainId,
          eventCursorsTable.contractAddress,
          eventCursorsTable.eventName,
        ],
        set: {
          lastProcessedBlock: cursor.lastProcessedBlock,
          lastProcessedLogIndex: cursor.lastProcessedLogIndex,
          updatedAt: new Date(),
        },
        setWhere: cursorAheadPredicate(cursor),
      });
  }
}

/**
 * The monotonic-guard predicate for the DB store's `DO UPDATE ... WHERE`: update
 * the row only when the incoming `(block, logIndex)` is strictly AFTER the stored
 * row, so a stale / duplicate / out-of-order advance can never rewind the cursor.
 */
function cursorAheadPredicate(cursor: RevealEventCursor): SQL {
  return or(
    gt(sql`${cursor.lastProcessedBlock}`, eventCursorsTable.lastProcessedBlock),
    and(
      eq(eventCursorsTable.lastProcessedBlock, cursor.lastProcessedBlock),
      gt(sql`${cursor.lastProcessedLogIndex}`, eventCursorsTable.lastProcessedLogIndex),
    ),
  ) as SQL;
}

/**
 * In-memory cursor store — for tests and for a transient/no-DB boot. NOT a
 * production path (a process restart loses the high-water mark and would replay
 * every event into the idempotent processor). Wave 5 wires the DB store.
 */
export class InMemoryRevealEventCursorStore implements RevealEventCursorStore {
  private cursor: RevealEventCursor | undefined;

  constructor(initial?: RevealEventCursor) {
    this.cursor = initial;
  }

  async load(): Promise<RevealEventCursor | undefined> {
    return this.cursor;
  }

  async advance(cursor: RevealEventCursor): Promise<void> {
    if (this.cursor === undefined || isStrictlyAfter(cursor, this.cursor)) {
      this.cursor = cursor;
    }
  }
}

/**
 * Resolves the rich `EventDrivenRevealInput` (T3.3) for a bare on-chain
 * `RevealAuthorized` event. This is the seam between "an event fired" and "the
 * combiner runs": the resolver reads the PDA config (g3_choice / g4_phase /
 * trust_tier / shred_authority …), builds the `combiner_input` reference
 * (σ-gathering request + vault ref + access-structure profile + registry
 * snapshots + canonical pin), and the recipient selectors — all PDA-driven,
 * nothing hardcoded (PLATFORM PRINCIPLE).
 *
 * It is an injected port so this listener owns ONLY the watch + cursor + drive
 * discipline; the PDA/σ/vault wiring is the Wave-5 composition root's. Tests
 * inject a deterministic resolver.
 *
 * `RevealInputForDriver` is `EventDrivenRevealInput` minus `event` (the driver
 * supplies the normalized event) — so the resolver cannot contradict the
 * on-chain event the cursor commits against.
 */
export type RevealInputForDriver<TInput> = Omit<TInput, "event">;

export interface RevealInputResolver<TInput> {
  resolve(event: RevealAuthorizedEvent): Promise<RevealInputForDriver<TInput>>;
}

/** Reads the current chain head height — injected (real viem `PublicClient`
 *  `getBlockNumber` in prod; deterministic in tests). Used for confirmation
 *  gating: an event is processed only once `head >= block + confirmations`. */
export interface ChainHeadReader {
  getBlockNumber(): Promise<bigint>;
}

export interface RevealAuthorizedDriverOptions<TInput, TResult> {
  /** Raw chain-watch port (real viem `PublicClient.watchContractEvent` shape). */
  readonly client: ViemRevealEventClient;
  /** Deployed ConditionEngine address (manifest-gated). */
  readonly conditionEngineAddress: Address;
  /** Live chain-head reader for confirmation gating. */
  readonly headReader: ChainHeadReader;
  /** Durable cursor store (DB-backed in prod). */
  readonly cursorStore: RevealEventCursorStore;
  /** Resolves the full processor input from the bare event. */
  readonly inputResolver: RevealInputResolver<TInput>;
  /** The reveal processor (T3.3 `processRevealAuthorizedEvent`, partially
   *  applied with its deps at Wave 5). Receives the full input. */
  readonly process: (input: TInput) => Promise<TResult>;
  /** Confirmation depth before an event is processed. PDA/env-configurable;
   *  Base finality is ~32. Never hardcoded into the flow. */
  readonly confirmations: bigint;
  /** Optional per-event error sink (logging / alerting). A throwing handler
   *  does NOT advance the cursor (the event replays on the next fire / boot). */
  readonly onError?: (error: unknown, event?: RevealAuthorizedEvent) => Promise<void> | void;
}

/**
 * The production reveal driver. Construct at Wave 5, call `start()` at boot,
 * `stop()` on shutdown.
 *
 * On `start()` it loads the persisted cursor (resume point) and begins watching
 * `RevealAuthorized`. Each batch of logs is processed SERIALLY in (block,
 * logIndex) order so the cursor advances monotonically and a mid-batch failure
 * leaves the remaining events for a later fire/boot rather than committing past
 * a gap.
 */
export class RevealAuthorizedDriver<TInput, TResult> {
  private readonly options: RevealAuthorizedDriverOptions<TInput, TResult>;
  private cursor: RevealEventCursor | undefined;
  private unwatch: (() => void) | undefined;
  /** Serializes overlapping `watchContractEvent` callbacks so two batches
   *  cannot interleave and double-advance / re-process the same event. */
  private queue: Promise<void> = Promise.resolve();

  constructor(options: RevealAuthorizedDriverOptions<TInput, TResult>) {
    this.options = options;
  }

  /** Load the resume cursor, then begin watching. Returns a stop fn (also on
   *  `this.stop`). Idempotent: a second `start()` while already watching is a
   *  no-op returning the live stop fn. */
  async start(): Promise<() => void> {
    if (this.unwatch !== undefined) return this.unwatch;
    this.cursor = await this.options.cursorStore.load();
    // Watch the RAW log batch (carrying block / logIndex) rather than the
    // per-event normalized callback of `createRevealAuthorizedListener` — the
    // cursor needs the ordering positions, which that factory drops. Same ABI /
    // event / address; this driver just keeps the batch.
    this.unwatch = this.options.client.watchContractEvent({
      address: this.options.conditionEngineAddress,
      abi: getConditionEngineAbi(),
      eventName: "RevealAuthorized",
      onLogs: (logs) => {
        this.enqueue(logs);
      },
    });
    return this.unwatch;
  }

  /** Stop watching. Drains no in-flight batch synchronously; await `drain()` if
   *  a clean shutdown must finish the current batch first. */
  stop(): void {
    if (this.unwatch !== undefined) {
      this.unwatch();
      this.unwatch = undefined;
    }
  }

  /** Resolve once the currently-queued batches have settled (for clean
   *  shutdown / test synchronization). */
  async drain(): Promise<void> {
    await this.queue;
  }

  /** Chain each batch onto the serial queue so callbacks never interleave. */
  private enqueue(logs: readonly unknown[]): void {
    this.queue = this.queue.then(() => this.processBatch(logs)).catch(async (error) => {
      await this.options.onError?.(error);
    });
  }

  private async processBatch(logs: readonly unknown[]): Promise<void> {
    const events = this.orderAndDedupe(logs);
    if (events.length === 0) return;
    const head = await this.options.headReader.getBlockNumber();
    for (const event of events) {
      const block = event.block_number;
      if (block === undefined) {
        // A pending log without a block can't be confirmation-gated or
        // cursor-committed. Skip it; the confirmed version arrives later.
        continue;
      }
      // CONFIRMATION GATING — not finalized enough yet; leave for a later fire
      // once the head advances. Cursor is NOT advanced (no skip).
      if (head < block + this.options.confirmations) {
        break; // events are ordered; nothing after this is more-confirmed
      }
      const position: RevealEventCursor = {
        lastProcessedBlock: block,
        lastProcessedLogIndex: event.log_index ?? 0,
      };
      try {
        const input = await this.options.inputResolver.resolve(event);
        await this.options.process({ ...(input as TInput), event });
      } catch (error) {
        await this.options.onError?.(error, event);
        // Fail-CLOSED on the cursor: do NOT advance past a failed event. It
        // replays on the next fire / boot (at-least-once into the idempotent
        // processor). Stop the batch so we never commit past a gap.
        break;
      }
      // Advance ONLY after successful processing.
      await this.options.cursorStore.advance(position);
      this.cursor = position;
    }
  }

  /**
   * Normalize the raw log batch into ordered `RevealAuthorizedEvent`s, dropping
   * any at-or-before the resume cursor (de-dup across restart / re-watch / reorg
   * replay). Logs missing a block number are kept (pending) but sort last and
   * are skipped by confirmation gating.
   */
  private orderAndDedupe(logs: readonly unknown[]): RevealAuthorizedEvent[] {
    const normalized = logs.map((log) => normalizeRevealAuthorizedLog(log));
    normalized.sort(compareEventPosition);
    const cursor = this.cursor;
    if (cursor === undefined) return normalized;
    return normalized.filter((event) => isStrictlyAfter(eventPosition(event), cursor));
  }
}

/** Internal: the `(block, logIndex)` position of a normalized event. A pending
 *  log (no block) sorts last and is never committed. */
function eventPosition(event: RevealAuthorizedEvent): RevealEventCursor {
  return {
    lastProcessedBlock: event.block_number ?? -1n,
    lastProcessedLogIndex: event.log_index ?? 0,
  };
}

function compareEventPosition(a: RevealAuthorizedEvent, b: RevealAuthorizedEvent): number {
  const ab = a.block_number ?? maxBlockSentinel;
  const bb = b.block_number ?? maxBlockSentinel;
  if (ab !== bb) return ab < bb ? -1 : 1;
  return (a.log_index ?? 0) - (b.log_index ?? 0);
}

/** Pending (no-block) logs sort AFTER every real block. */
const maxBlockSentinel = 2n ** 63n;

/** `a` is strictly after `b` in (block, logIndex) order. */
function isStrictlyAfter(a: RevealEventCursor, b: RevealEventCursor): boolean {
  if (a.lastProcessedBlock !== b.lastProcessedBlock) {
    return a.lastProcessedBlock > b.lastProcessedBlock;
  }
  return a.lastProcessedLogIndex > b.lastProcessedLogIndex;
}

async function handleLogs(
  logs: readonly unknown[],
  options: RevealAuthorizedListenerOptions,
): Promise<void> {
  for (const log of logs) {
    try {
      await handleRevealAuthorizedLog(log, options.onRevealAuthorized);
    } catch (error) {
      await options.onError?.(error);
    }
  }
}

export function normalizeRevealAuthorizedLog(log: unknown): RevealAuthorizedEvent {
  const record = assertRecord(log, "RevealAuthorized log");
  const args = assertRecord(record.args, "RevealAuthorized args");
  const authorizationId = asHex32(args.authorizationId, "authorizationId");
  const hCommit = asHex32(args.hCommit, "hCommit");
  const pdaRoot = asHex32(args.pdaRoot, "pdaRoot");
  return {
    authorizationId,
    h_commit: hCommit,
    pda_root: pdaRoot,
    authorization_block: asBigInt(args.authorizationBlock, "authorizationBlock"),
    authorization_timestamp: asBigInt(args.authorizationTimestamp, "authorizationTimestamp"),
    challenge_window: Number(asBigInt(args.challengeWindow, "challengeWindow")),
    conditionRef: asHex32(args.conditionRef, "conditionRef"),
    ...(typeof record.transactionHash === "string" ? { transaction_hash: record.transactionHash as Hex } : {}),
    ...(typeof record.logIndex === "number" ? { log_index: record.logIndex } : {}),
    ...(typeof record.blockHash === "string" ? { block_hash: record.blockHash as Hex32 } : {}),
    ...(typeof record.blockNumber === "bigint" ? { block_number: record.blockNumber } : {}),
  };
}

function assertRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    throw new Error(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function asHex32(value: unknown, label: string): Hex32 {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be bytes32 hex.`);
  }
  return value as Hex32;
}

function asBigInt(value: unknown, label: string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isInteger(value)) return BigInt(value);
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  throw new Error(`${label} must be bigint-compatible.`);
}
