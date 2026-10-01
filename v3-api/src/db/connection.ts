// V3 API Postgres connection — postgres-js client + Drizzle wrapper.
//
// Phase 3 (T0.1): `getDb()` returns a typed Drizzle client over the V3 DB
// (`cealis_v3_dev` local; a separate Railway Postgres in production). Repos +
// stores + workers consume this at the composition root.
//
// V3 isolation (SECURITY.md): a NEW database, never the V1
// `cealis_dev`, no FK across. No @cealis/shared import. No V1 env vars (the
// sealed-share / issuer-salt / committee-key family — see SECURITY.md): the
// connection string is read from the V3-scoped env var only.
//
// Env: `CEALIS_V3_DATABASE_URL` (canonical). `V3_TEST_PG_URL` is honored as a
// fallback so the opt-in Postgres test harness and the runtime share one
// resolver in CI.

import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import type { Sql } from "postgres";

import * as authSchema from "./schema-extensions/auth.js";
import * as ingestionsSchema from "./schema-extensions/ingestions.js";
import * as revealsSchema from "./schema-extensions/reveals.js";
import * as vaultSchema from "./schema-extensions/vault-blobs.js";

/**
 * The full Drizzle schema the V3 API runtime queries. Composed from the real
 * column-typed *-extensions (NOT the Phase-A placeholder `schema.ts`, which
 * only carries the locked API table-name catalog).
 */
export const v3Schema = {
  ...ingestionsSchema,
  ...revealsSchema,
  ...authSchema,
  ...vaultSchema,
} as const;

export type V3Schema = typeof v3Schema;

/** Drizzle client type for the V3 API DB. */
export type V3Database = ReturnType<typeof buildDb>;

export interface GetDbOptions {
  /**
   * Override the connection string. Defaults to `CEALIS_V3_DATABASE_URL`
   * (then `V3_TEST_PG_URL`) from the environment.
   */
  readonly connectionString?: string;
  /** Max pool connections. postgres-js default is 10. */
  readonly max?: number;
  /** Idle-connection timeout (seconds). */
  readonly idleTimeoutSeconds?: number;
}

/**
 * Resolve the V3 DB connection string from the environment.
 *
 * Canonical `CEALIS_V3_DATABASE_URL`; falls back to `V3_TEST_PG_URL` so the
 * Postgres test harness and the runtime share a single resolver. Returns
 * `undefined` when neither is set — callers decide whether that is fatal
 * (runtime boot) or a skip (tests).
 */
export function resolveV3DatabaseUrl(): string | undefined {
  const url = process.env["CEALIS_V3_DATABASE_URL"]?.trim();
  if (url) return url;
  const testUrl = process.env["V3_TEST_PG_URL"]?.trim();
  if (testUrl) return testUrl;
  return undefined;
}

/** Build a Drizzle client over an already-constructed postgres-js Sql client. */
export function buildDb(sql: Sql) {
  return drizzle(sql, { schema: v3Schema });
}

/**
 * A V3 DB handle: the Drizzle client for queries, the raw `sql` client for
 * migrations / advisory locks / `octet_length`-style checks, and a `close()`.
 */
export interface V3DbHandle {
  readonly db: V3Database;
  readonly sql: Sql;
  close(): Promise<void>;
}

/**
 * Open a V3 DB connection. Throws if no connection string is resolvable —
 * the runtime boot path treats a missing `CEALIS_V3_DATABASE_URL` as fatal
 * (there is no in-memory fallback in Phase 3).
 */
export function getDb(options: GetDbOptions = {}): V3DbHandle {
  const connectionString = options.connectionString ?? resolveV3DatabaseUrl();
  if (!connectionString) {
    throw new Error(
      "CEALIS_V3_DATABASE_URL is not set — the V3 API runtime requires a Postgres connection " +
        "(there is no in-memory fallback in Phase 3).",
    );
  }

  const sql = postgres(connectionString, {
    max: options.max ?? 10,
    idle_timeout: options.idleTimeoutSeconds ?? 30,
    onnotice: () => {
      /* suppress NOTICE noise from CREATE TABLE IF NOT EXISTS during migrate */
    },
  });

  const db = buildDb(sql);

  return {
    db,
    sql,
    close: async () => {
      await sql.end({ timeout: 5 });
    },
  };
}
