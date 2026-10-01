// IngestContextRegistry (GAP-B) — the per-request seam that lets the real
// `RealVaultWriter` run through the `/v1/ingestions` API route.
//
// THE SEAM PROBLEM
// ----------------
// The ingest route (`routes-create-mode-a.ts`, createModeAIngestion) computes the
// full `HCommitArtifacts` from the PDA inspection + the request candidate, then
// calls `vault.write({ h_commit, plaintext, payload_classification })` — passing
// ONLY the h_commit. But the `RealVaultWriter` (vault-writer-impl.ts) needs the
// FULL per-ingest context the narrow `write()` call does not carry: the
// `HCommitArtifacts` the sealer binds, the PDA-selected `AccessStructureProfile`,
// the retention floor, the shred authority, and the vault ref. The
// `IngestContextResolver` is the injected port that maps the in-flight h_commit to
// that context.
//
// THE SOLUTION
// ------------
// A short-lived, in-process registry keyed by h_commit. The route REGISTERS the
// computed context just before calling `vault.write` (the route already computed
// the same `HCommitArtifacts`, so registering it is free — no re-derivation, no
// drift). The resolver READS it back inside `vault.write`. The entry is consumed
// (removed) on read so the registry never grows. This keeps the narrow `write()`
// call shape untouched (it stays a Wave-5 frozen seam) while threading PDA config
// into the runtime — the same h_commit the route bound is the one the sealer binds.
//
// A single process owns both the route and the writer (the composition root wires
// the same registry instance into the route hook + the resolver), so the registry
// is the natural in-process handoff. It is NOT a durable store: an ingest that
// crashes between register and write leaves a stale entry that the periodic sweep
// (or a TTL on read) reaps; the ingest itself failed and replays cleanly.
//
// V3 isolation (SECURITY.md): no @cealis/shared, no V1 packages, no
// V1 env vars. Pure in-process state.

import type { Hex32 } from "../h-commit/index.js";
import type {
  IngestContextResolver,
  IngestWriteContext,
} from "./vault-writer-impl.js";

interface Entry {
  readonly context: IngestWriteContext;
  readonly registeredAt: number;
}

/**
 * In-process registry mapping an in-flight ingest's h_commit to the full
 * `IngestWriteContext` the `RealVaultWriter` needs. The route registers; the
 * resolver consumes.
 */
export class IngestContextRegistry {
  private readonly entries = new Map<string, Entry>();
  /** Entries older than this (ms) are stale (a crashed ingest); swept on access. */
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(options: { readonly ttlMs?: number; readonly now?: () => number } = {}) {
    this.ttlMs = options.ttlMs ?? 60_000;
    this.now = options.now ?? Date.now;
  }

  /** Register the full ingest context for an in-flight h_commit (route hook). */
  register(hCommit: Hex32, context: IngestWriteContext): void {
    this.sweep();
    this.entries.set(hCommit.toLowerCase(), { context, registeredAt: this.now() });
  }

  /** Build the `IngestContextResolver` the `RealVaultWriter` consumes. Reads +
   *  consumes the registered entry. Throws (fail-loud) when no entry exists — a
   *  live ingest must always register before `vault.write`. */
  resolver(): IngestContextResolver {
    return {
      resolve: (input) => {
        const key = input.h_commit.toLowerCase();
        const entry = this.entries.get(key);
        if (entry === undefined) {
          throw new Error(
            `IngestContextRegistry: no registered context for h_commit ${input.h_commit}. The ingest ` +
              "route must register the resolved PDA context (registerIngestContext) before calling " +
              "vault.write — this is the per-request ingest-context seam.",
          );
        }
        // Consume on read — the registry never grows past in-flight ingests.
        this.entries.delete(key);
        return entry.context;
      },
    };
  }

  /** Remove entries older than the TTL (a crashed ingest never reached write). */
  private sweep(): void {
    if (this.entries.size === 0) return;
    const cutoff = this.now() - this.ttlMs;
    for (const [key, entry] of this.entries) {
      if (entry.registeredAt < cutoff) this.entries.delete(key);
    }
  }

  /** Current registered-entry count (test / observability). */
  size(): number {
    return this.entries.size;
  }
}
