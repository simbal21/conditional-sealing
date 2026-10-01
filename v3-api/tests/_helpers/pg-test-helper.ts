// Postgres test harness for R2b LBU store tests.
//
// Strategy: opt-in via `V3_TEST_PG_URL`. When unset, every Postgres store
// test SKIPs cleanly — CI without a PG instance still passes. When set,
// tests run against a real Postgres and assert real behavior (race-safe
// upsert, expired-window replace, append-only triggers, etc.).
//
// Each describe block creates schema fresh from migration SQL and tears
// down afterwards via TRUNCATE — no cross-test bleed.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import postgres from "postgres";
import type { Sql } from "postgres";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const MIGRATIONS_DIR = join(__dirname, "..", "..", "src", "db", "migrations");

export const TEST_PG_URL = process.env["V3_TEST_PG_URL"];

export interface PgTestContext {
  readonly sql: Sql;
  /** Random per-suite prefix; combine with test-specific keys to avoid
   *  cross-file collisions when vitest runs files in parallel. */
  readonly prefix: string;
  reset(): Promise<void>;
  end(): Promise<void>;
}

/**
 * Build a test SQL client + apply both auth-related migrations.
 *
 * Returns `null` when `V3_TEST_PG_URL` is unset (caller should skip).
 */
export async function createPgTestContext(): Promise<PgTestContext | null> {
  if (!TEST_PG_URL) return null;

  const sql = postgres(TEST_PG_URL, {
    max: 4,
    idle_timeout: 5,
    onnotice: () => {
      /* suppress NOTICE noise from CREATE TABLE IF NOT EXISTS */
    },
  });

  // Apply migrations 0003 (auth) and 0004 (replay + rate-limit). Each is
  // idempotent via IF NOT EXISTS for tables, but CREATE OR REPLACE FUNCTION
  // + CREATE TRIGGER bodies race in `pg_type` when parallel vitest workers
  // apply concurrently. Serialize the apply with a session-scoped advisory
  // lock — released automatically when the connection closes.
  const m3 = readFileSync(join(MIGRATIONS_DIR, "0003_auth_webhooks.sql"), "utf-8");
  const m4 = readFileSync(join(MIGRATIONS_DIR, "0004_auth_replay_and_ratelimit.sql"), "utf-8");
  const LOCK_KEY = 8675309; // arbitrary advisory-lock id (Jenny)
  await sql`SELECT pg_advisory_lock(${LOCK_KEY})`;
  try {
    await sql.unsafe(m3);
    await sql.unsafe(m4);
  } finally {
    await sql`SELECT pg_advisory_unlock(${LOCK_KEY})`;
  }

  const reset = async (): Promise<void> => {
    // Per-suite truncate is intentionally NOT used — multiple test files
    // run in parallel against the same DB and would clobber each other's
    // rows mid-test. Each suite owns its own random key/scope prefix and
    // cleans up only rows under that prefix.
  };

  // Per-process random prefix — every test file gets its own namespace.
  const prefix = `t-${process.pid}-${Math.random().toString(36).slice(2, 8)}-`;

  const end = async (): Promise<void> => {
    // Clean up only this suite's rows.
    await sql`DELETE FROM idempotency_keys WHERE scope LIKE ${prefix + "%"} OR idempotency_key LIKE ${prefix + "%"}`;
    await sql`DELETE FROM nonces WHERE key_id LIKE ${prefix + "%"} OR nonce LIKE ${prefix + "%"}`;
    await sql`DELETE FROM rate_limit_buckets WHERE bucket_key LIKE ${prefix + "%"}`;
    await sql.end({ timeout: 5 });
  };

  return { sql, prefix, reset, end };
}
