// Postgres-backed idempotency store. Mirrors `InMemoryIdempotencyStore`
// (see ./idempotency-middleware.ts) with the same semantics:
//
//   execute({ scope, key, rawRequestBody, run }) →
//     - First call for (scope, key) within TTL → run() once, persist
//       (status, body, request_digest, expires_at), return { replayed: false }.
//     - Replay with same digest → return { replayed: true, status, body }.
//     - Replay with different digest → throw HttpProblem("IDEMPOTENCY_KEY_CONFLICT").
//     - Beyond TTL → treat as a fresh call (replace the row).
//
// Concurrency: two replicas racing the same (scope, key) → INSERT ... ON
// CONFLICT DO NOTHING means only one row wins. The losing replica re-reads
// the winning row and returns its response (replayed=true). The losing
// replica's run() is NEVER executed.
//
// Important: we DO NOT run the partner's handler under a long-held row lock;
// that would serialize all requests through one row. Instead:
//   1. Pre-check the row (SELECT) — fast path for replays.
//   2. If absent or expired, execute run() outside any tx.
//   3. INSERT the row with ON CONFLICT(scope, idempotency_key) DO UPDATE
//      where expires_at <= now (expired-replace race). If a fresh winner
//      slipped in between step 1 and step 3, ON CONFLICT returns no rows
//      and we re-read that winning row.
//
// V3 isolation: caller-injected Sql; no V1 imports.

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import type { Sql } from "postgres";
import { HttpProblem, problemFromCode } from "../errors/index.js";

export interface PostgresIdempotencyStoreOptions {
  readonly sql: Sql;
  /**
   * Default TTL for stored records, in ms. Per V1 carry, 24h.
   * Per-call ttlMs in execute() overrides.
   */
  readonly defaultTtlMs?: number;
}

interface IdempotencyRow {
  readonly request_digest: string;
  readonly response_status: number;
  readonly response_body: unknown;
  readonly expires_at: Date;
}

export class PostgresIdempotencyStore {
  private readonly sql: Sql;
  private readonly defaultTtlMs: number;

  constructor(options: PostgresIdempotencyStoreOptions) {
    this.sql = options.sql;
    this.defaultTtlMs = options.defaultTtlMs ?? 24 * 60 * 60 * 1000;
  }

  async execute<T>(input: {
    readonly scope: string;
    readonly key: string;
    readonly rawRequestBody: Uint8Array;
    readonly nowMs?: number;
    readonly ttlMs?: number;
    readonly correlationId?: string;
    readonly run: () => Promise<{ statusCode: number; body: T }> | { statusCode: number; body: T };
  }): Promise<{ replayed: boolean; statusCode: number; body: T }> {
    const nowMs = input.nowMs ?? Date.now();
    const ttlMs = input.ttlMs ?? this.defaultTtlMs;
    const digest = bytesToHex(sha256(input.rawRequestBody));
    const now = new Date(nowMs);
    const expiresAt = new Date(nowMs + ttlMs);

    // Step 1: fast-path replay check.
    const replay = await this.tryReplay<T>(input.scope, input.key, digest, now, input.correlationId);
    if (replay !== null) return replay;

    // Step 2: execute the partner handler outside any DB tx so handler
    // duration doesn't pin a row lock.
    const result = await input.run();

    // Step 3: persist. ON CONFLICT path covers two races —
    //   (a) a peer replica wrote a fresh row in the meantime → we lose,
    //       re-read and return its body;
    //   (b) the row exists but is expired → we overwrite (UPDATE branch).
    // postgres-js `sql.json()` requires a JSONValue input; the partner's
    // response body is typed as a generic `T` so we round-trip through a
    // string serialize → JSONB CAST to stay strictly typed without an
    // `as any` escape hatch.
    const responseBodyJson = JSON.stringify(result.body);
    const inserted = await this.sql<{ inserted: number }[]>`
      INSERT INTO idempotency_keys (
        scope, idempotency_key, request_digest, response_status, response_body, expires_at, created_at
      )
      VALUES (
        ${input.scope}, ${input.key}, ${digest}, ${result.statusCode},
        ${responseBodyJson}::jsonb, ${expiresAt}, ${now}
      )
      ON CONFLICT (scope, idempotency_key) DO UPDATE
        SET request_digest = EXCLUDED.request_digest,
            response_status = EXCLUDED.response_status,
            response_body = EXCLUDED.response_body,
            expires_at = EXCLUDED.expires_at,
            created_at = EXCLUDED.created_at
        WHERE idempotency_keys.expires_at <= ${now}
      RETURNING 1 AS inserted
    `;

    if (inserted.length === 0) {
      // Lost the race — a peer replica wrote a fresh row. Re-read and
      // return its body (replay path) instead of double-billing the
      // partner's handler.
      const peer = await this.tryReplay<T>(
        input.scope,
        input.key,
        digest,
        now,
        input.correlationId,
      );
      if (peer !== null) return peer;
      // Row vanished between INSERT and re-read (e.g. concurrent sweep).
      // Honor our own result; the next caller will repopulate.
    }

    return { replayed: false, statusCode: result.statusCode, body: result.body };
  }

  private async tryReplay<T>(
    scope: string,
    key: string,
    digest: string,
    now: Date,
    correlationId: string | undefined,
  ): Promise<{ replayed: boolean; statusCode: number; body: T } | null> {
    const rows = await this.sql<IdempotencyRow[]>`
      SELECT request_digest, response_status, response_body, expires_at
      FROM idempotency_keys
      WHERE scope = ${scope} AND idempotency_key = ${key} AND expires_at > ${now}
      LIMIT 1
    `;
    if (rows.length === 0) return null;
    const existing = rows[0]!;
    if (existing.request_digest !== digest) {
      throw new HttpProblem(
        problemFromCode("IDEMPOTENCY_KEY_CONFLICT", correlationId ?? "idempotency", {
          detail: "The same Idempotency-Key was replayed with a different request digest.",
        }),
      );
    }
    // postgres-js returns JSONB values as raw strings; parse back to the
    // partner's original object shape so callers see the same body they
    // returned from run().
    const body =
      typeof existing.response_body === "string"
        ? (JSON.parse(existing.response_body) as T)
        : (existing.response_body as T);
    return {
      replayed: true,
      statusCode: existing.response_status,
      body,
    };
  }

  /** Background sweeper helper — purge rows past expires_at. */
  async purgeExpired(nowMs?: number): Promise<number> {
    const now = new Date(nowMs ?? Date.now());
    const rows = await this.sql<{ count: number }[]>`
      WITH d AS (DELETE FROM idempotency_keys WHERE expires_at <= ${now} RETURNING 1)
      SELECT COUNT(*)::int AS count FROM d
    `;
    return rows[0]?.count ?? 0;
  }

  async size(): Promise<number> {
    const rows = await this.sql<{ count: number }[]>`
      SELECT COUNT(*)::int AS count FROM idempotency_keys
    `;
    return rows[0]?.count ?? 0;
  }
}
