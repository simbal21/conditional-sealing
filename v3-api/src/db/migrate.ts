// V3 API Drizzle migration runner.
//
// Phase 3 (T0.1): apply `migrations/0001..NNNN.sql` in lexical (== numeric)
// order against the V3 DB. The bin can call `runMigrations()` at boot, or a
// `scripts/migrate.ts` can invoke it. Each migration is idempotent (CREATE
// TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS / CREATE OR REPLACE
// FUNCTION), so re-running is a no-op.
//
// Concurrency: a session-scoped advisory lock serializes the apply so parallel
// boots / parallel vitest workers don't race the `CREATE OR REPLACE FUNCTION` +
// `CREATE TRIGGER` bodies in pg_type (same pattern as the test harness).
//
// V3 isolation: no @cealis/shared import, no V1 env vars. The caller injects
// the postgres-js `Sql` client (composition root) OR lets the runner open one
// from `CEALIS_V3_DATABASE_URL`.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { Sql } from "postgres";

import { getDb, type V3DbHandle } from "./connection.js";

const thisDir = dirname(fileURLToPath(import.meta.url));

/** Absolute path to the migrations directory (resolved relative to this file). */
export const MIGRATIONS_DIR = join(thisDir, "migrations");

/** Advisory-lock id used to serialize concurrent migration applies. */
const MIGRATION_LOCK_KEY = 5_204_481; // arbitrary, stable across processes

/**
 * Discover migration files in numeric order. Files are named `NNNN_*.sql`;
 * lexical sort on the zero-padded prefix is numeric order.
 */
export function listMigrationFiles(dir: string = MIGRATIONS_DIR): string[] {
  return readdirSync(dir)
    .filter((f) => /^\d{4}_.*\.sql$/.test(f))
    .sort();
}

export interface RunMigrationsResult {
  /** Migration file names applied, in order. */
  readonly applied: string[];
}

/**
 * Apply all migrations against an already-open `Sql` client. Used when the
 * composition root or a test harness owns the connection lifecycle.
 */
export async function applyMigrations(sql: Sql, dir: string = MIGRATIONS_DIR): Promise<RunMigrationsResult> {
  const files = listMigrationFiles(dir);
  const applied: string[] = [];

  await sql`SELECT pg_advisory_lock(${MIGRATION_LOCK_KEY})`;
  try {
    for (const file of files) {
      const ddl = readFileSync(join(dir, file), "utf-8");
      await sql.unsafe(ddl);
      applied.push(file);
    }
  } finally {
    await sql`SELECT pg_advisory_unlock(${MIGRATION_LOCK_KEY})`;
  }

  return { applied };
}

/**
 * Open a V3 DB connection from the environment, apply all migrations, and close
 * it. This is the boot-path entry (`bin` / `scripts/migrate.ts`). Throws if no
 * `CEALIS_V3_DATABASE_URL` is resolvable.
 */
export async function runMigrations(dir: string = MIGRATIONS_DIR): Promise<RunMigrationsResult> {
  const handle: V3DbHandle = getDb();
  try {
    return await applyMigrations(handle.sql, dir);
  } finally {
    await handle.close();
  }
}
