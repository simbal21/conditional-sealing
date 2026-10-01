// T3.5 — boot helper for the RevealAuthorized event listener (production reveal
// driver). The Wave-5 composition root calls `startRevealEventListener` after it
// has constructed the chain client, the cursor store, the input resolver, and
// the partially-applied reveal processor; it returns a handle the boot path
// keeps and the shutdown path stops.
//
// WHY A SEPARATE START HELPER
// ---------------------------
// `combiner-orchestrator/event-listener.ts` owns the watch + cursor + drive
// DISCIPLINE (confirmation gating, persist/resume, no missed/double). This file
// owns only the BOOT SHAPE: assemble those injected ports into a started driver
// and hand back a `{ stop, drain }`. Keeping it here (not in `bin.ts`) means the
// composition root (`server/composition-root.ts`, Wave 5) wires it without this
// file pulling the whole dependency graph — and tests can start the listener
// with doubles, no Postgres / no RPC.
//
// EXTERNAL-GATE BOUNDARY (build TO, do NOT cross — Phase-3 plan §6)
// ----------------------------------------------------------------
// The real viem `PublicClient` (Base Sepolia / anvil), the deployed
// ConditionEngine address, the live head reader, and the PDA/σ/vault input
// resolver are all INJECTED here — they are vendor/manifest-gated and supplied
// by Wave 5. This helper crosses no vendor boundary; it never reads a chain RPC
// URL or a managed key from env itself.
//
// V3 isolation: no @cealis/shared import, no V1 env vars, no `keys/` read.

import type { Address } from "viem";

import {
  DbRevealEventCursorStore,
  RevealAuthorizedDriver,
  type ChainHeadReader,
  type RevealAuthorizedEvent,
  type RevealEventCursorStore,
  type RevealInputForDriver,
  type RevealInputResolver,
  type ViemRevealEventClient,
} from "../combiner-orchestrator/event-listener.js";
import type { V3Database } from "../db/connection.js";

/**
 * Default confirmation depth before an on-chain `RevealAuthorized` is processed.
 * Base finality is ~32 blocks. This is the BOOT default; a deployment may
 * override per-env (anvil dev can use a small depth, Base Sepolia uses the
 * finality depth). It is NOT a per-flow / per-PDA hardcode of the reveal
 * behaviour — only the reorg-safety margin for accepting the event.
 */
export const DEFAULT_REVEAL_CONFIRMATIONS = 32n;

/**
 * Everything the boot path injects to start the production reveal driver. The
 * processor is `processRevealAuthorizedEvent` (T3.3) already partially-applied
 * with its deps (repository, σ-gatherer, vault, …) at Wave 5 — so this helper
 * stays agnostic of the reveal deps bag.
 */
export interface StartRevealEventListenerDeps<TInput extends { event: RevealAuthorizedEvent }, TResult> {
  /** Raw chain-watch port (real viem `PublicClient.watchContractEvent` shape). */
  readonly client: ViemRevealEventClient;
  /** Deployed ConditionEngine address (manifest-gated). */
  readonly conditionEngineAddress: Address;
  /** Live chain-head reader for confirmation gating (real `PublicClient`). */
  readonly headReader: ChainHeadReader;
  /** Durable cursor store. Build the DB-backed one via
   *  `dbRevealEventCursorStore` (below) at Wave 5. */
  readonly cursorStore: RevealEventCursorStore;
  /** Resolves the rich processor input from the bare event (PDA / σ / vault). */
  readonly inputResolver: RevealInputResolver<TInput>;
  /** The reveal processor (T3.3 `processRevealAuthorizedEvent`, deps applied). */
  readonly process: (input: TInput) => Promise<TResult>;
  /** Confirmation depth; defaults to {@link DEFAULT_REVEAL_CONFIRMATIONS}. */
  readonly confirmations?: bigint;
  /** Error sink for per-event failures (logging / alerting). A thrown error
   *  does NOT advance the cursor — the event replays on the next fire / boot. */
  readonly onError?: (error: unknown, event?: RevealAuthorizedEvent) => Promise<void> | void;
}

/**
 * A started reveal-event listener handle. The composition root holds it for the
 * process lifetime; the shutdown path calls `stop()` (and optionally awaits
 * `drain()` to finish the in-flight batch before exit).
 */
export interface RevealEventListenerHandle {
  /** Stop watching the chain. Does not drain in-flight work — await `drain`. */
  stop(): void;
  /** Resolve once the currently-queued event batches have settled. */
  drain(): Promise<void>;
}

/**
 * Construct the DB-backed cursor store over `event_cursors`. The composition
 * root passes the V3 Drizzle client + the chain id / ConditionEngine address it
 * is watching; the store owns exactly the `RevealAuthorized` cursor row for that
 * `(chainId, address)`.
 */
export function dbRevealEventCursorStore(args: {
  readonly db: V3Database;
  readonly chainId: number;
  readonly conditionEngineAddress: Address;
}): RevealEventCursorStore {
  return new DbRevealEventCursorStore({
    db: args.db,
    chainId: args.chainId,
    contractAddress: args.conditionEngineAddress,
  });
}

/**
 * Build, start, and return the production reveal driver. The driver loads its
 * resume cursor from the store, begins watching `RevealAuthorized`, and drives
 * every confirmed event through the injected processor exactly once (Rule 25).
 *
 * Returns a `{ stop, drain }` handle for the composition root.
 */
export async function startRevealEventListener<
  TInput extends { event: RevealAuthorizedEvent },
  TResult,
>(deps: StartRevealEventListenerDeps<TInput, TResult>): Promise<RevealEventListenerHandle> {
  const driver = new RevealAuthorizedDriver<TInput, TResult>({
    client: deps.client,
    conditionEngineAddress: deps.conditionEngineAddress,
    headReader: deps.headReader,
    cursorStore: deps.cursorStore,
    inputResolver: deps.inputResolver,
    process: deps.process,
    confirmations: deps.confirmations ?? DEFAULT_REVEAL_CONFIRMATIONS,
    ...(deps.onError ? { onError: deps.onError } : {}),
  });

  await driver.start();

  return {
    stop: () => driver.stop(),
    drain: () => driver.drain(),
  };
}

// Re-export the resolver/input types so the Wave-5 composition root can type its
// concrete resolver against this boot module without reaching into the
// combiner-orchestrator internals.
export type { RevealInputForDriver, RevealInputResolver };
