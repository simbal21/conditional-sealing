// T0.1 — DB connection + migration runner tests.
//
// Two layers:
//   1. ALWAYS-ON unit tests (no DB): migration discovery is ordered + complete,
//      getDb()/runMigrations() fail loudly without a connection string, and the
//      runtime-storage schema catalog matches the schema-extension definitions.
//   2. OPT-IN live-DB tests (real Postgres): the full migration set applies,
//      the new Phase-3 tables exist with the right shape, the wrapped-share
//      length CHECK + no-PII discipline hold, and the append-only
//      vault_audit_log trigger raises on UPDATE/DELETE.
//
// Live tests SKIP cleanly when neither CEALIS_V3_DATABASE_URL nor V3_TEST_PG_URL
// is set — CI without a Postgres instance still passes (per task: "Do NOT
// require a live DB to typecheck — guard live-DB tests so they skip when
// DATABASE_URL is unset").

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { eq, getTableColumns, getTableName } from "drizzle-orm";
import postgres from "postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  MIGRATIONS_DIR,
  applyMigrations,
  buildDb,
  getDb,
  listMigrationFiles,
  resolveV3DatabaseUrl,
  runMigrations,
} from "../../src/db/index.js";
import {
  V3_RUNTIME_STORAGE_TABLE_NAMES,
  V3_RUNTIME_STORAGE_TABLE_COUNT,
  V3_API_TABLE_NAMES,
} from "../../src/db/schema.js";
import { vaultAuditLogAuth } from "../../src/db/schema-extensions/auth.js";
import {
  dekShareRecordsTable,
  vaultBlobsTable,
} from "../../src/db/schema-extensions/vault-blobs.js";

const LIVE_URL = resolveV3DatabaseUrl();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = LIVE_URL ? describe : describe.skip;

// ---------------------------------------------------------------------------
// 1. Always-on unit tests (no DB required).
// ---------------------------------------------------------------------------

describe("migration discovery (no DB)", () => {
  it("lists migrations in zero-padded numeric order", () => {
    const files = listMigrationFiles();
    expect(files.length).toBeGreaterThanOrEqual(6);
    const sorted = [...files].sort();
    expect(files).toEqual(sorted);
    expect(files[0]).toBe("0001_ingestions.sql");
  });

  it("includes the two Phase-3 runtime-storage migrations", () => {
    const files = listMigrationFiles();
    expect(files).toContain("0005_vault_blobs.sql");
    expect(files).toContain("0006_dek_share_records.sql");
  });

  it("every discovered migration file exists on disk and is non-empty", () => {
    for (const f of listMigrationFiles()) {
      const p = join(MIGRATIONS_DIR, f);
      expect(existsSync(p)).toBe(true);
      expect(readFileSync(p, "utf-8").trim().length).toBeGreaterThan(0);
    }
  });

  it("the dek-share migration persists ONLY WRAPPED material (non-custody invariant)", () => {
    const ddl = readFileSync(join(MIGRATIONS_DIR, "0006_dek_share_records.sql"), "utf-8").toLowerCase();
    // Shares are wrapped per-gate; the schema must not invite a plaintext-DEK or
    // raw-share column.
    expect(ddl).not.toMatch(/\bplaintext_dek\b/);
    expect(ddl).not.toMatch(/\bdek_plaintext\b/);
    // No `share_bytes BYTEA` COLUMN declaration (the retired raw-39-byte column).
    // The token may appear in the evolution-note comment; we forbid only a column.
    expect(ddl).not.toMatch(/share_bytes\s+bytea/);
    // The 1168-byte wrapped-stanza length CHECK must be present — a raw 32/39-byte
    // share write fails it loud (the non-custody guardrail). 1168 = 32 + 1088 + 48.
    expect(ddl).toMatch(/octet_length\(wrapped_payload\)\s*=\s*1168/);
    // The public-digest columns are 32-byte fixed (not key material).
    expect(ddl).toMatch(/octet_length\(plugin_version_digest\)\s*=\s*32/);
  });
});

describe("connection + migrate guards (no DB)", () => {
  it("getDb() throws a clear error when no connection string is resolvable", () => {
    expect(() => getDb({ connectionString: "" })).toThrowError(/CEALIS_V3_DATABASE_URL/);
  });

  it("buildDb() returns a Drizzle client without connecting", () => {
    // A bare postgres-js client is fine to construct without connecting; we
    // never issue a query here, just assert buildDb() wires up cleanly.
    const sql = postgres("postgres://unused:unused@127.0.0.1:1/none", { max: 1 });
    try {
      const db = buildDb(sql);
      expect(db).toBeDefined();
      expect(typeof db.select).toBe("function");
      // The runtime-storage tables resolve to their real Postgres names.
      expect(getTableName(vaultBlobsTable)).toBe("vault_blobs");
      expect(getTableName(dekShareRecordsTable)).toBe("dek_share_records");
    } finally {
      // Never connected; end() is a no-op cleanup.
      void sql.end({ timeout: 1 });
    }
  });
});

describe("runtime-storage catalog matches the schema extensions (no DB)", () => {
  it("catalog count + names are stable and separate from the locked API catalog", () => {
    expect(V3_RUNTIME_STORAGE_TABLE_COUNT).toBe(2);
    expect([...V3_RUNTIME_STORAGE_TABLE_NAMES]).toEqual(["vault_blobs", "dek_share_records"]);
    // Runtime-storage tables must NOT leak into the frozen API catalog (17).
    expect(V3_API_TABLE_NAMES.length).toBe(17);
    for (const name of V3_RUNTIME_STORAGE_TABLE_NAMES) {
      expect(V3_API_TABLE_NAMES as readonly string[]).not.toContain(name);
    }
  });

  it("vault_blobs has no key/DEK/plaintext column (no PII at rest beyond ciphertext)", () => {
    const cols = Object.keys(getTableColumns(vaultBlobsTable));
    expect(cols).toContain("ciphertext");
    expect(cols).toContain("commit_aad_bytes");
    for (const forbidden of ["dek", "plaintext", "key", "share"]) {
      for (const c of cols) {
        expect(c.includes(forbidden)).toBe(false);
      }
    }
  });

  it("dek_share_records exposes the WRAPPED-stanza routing columns and no plaintext-dek/raw-share column", () => {
    const cols = Object.keys(getTableColumns(dekShareRecordsTable));
    for (const required of [
      "h_commit",
      "stanza_index",
      "gate_kind",
      "role",
      "domain",
      "binding_tag",
      "wrapped_payload",
    ]) {
      expect(cols).toContain(required);
    }
    // The retired raw-share column must be gone; nothing exposes plaintext DEK.
    expect(cols).not.toContain("share_bytes");
    expect(cols).not.toContain("plaintext_dek");
    expect(cols).not.toContain("dek");
  });
});

// ---------------------------------------------------------------------------
// 2. Opt-in live-DB tests (real Postgres).
// ---------------------------------------------------------------------------

describeIfPg("migrations apply against real Postgres (CEALIS_V3_DATABASE_URL / V3_TEST_PG_URL)", () => {
  // Suite-scoped namespace so parallel test files don't clobber each other's
  // rows on a shared DB.
  const P = `t-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
  // Connection is opened lazily in beforeAll — never at describe-collection
  // time, so the no-DB run can skip cleanly without getDb() throwing.
  let handle: ReturnType<typeof getDb>;
  let sql: ReturnType<typeof getDb>["sql"];
  let db: ReturnType<typeof getDb>["db"];

  beforeAll(async () => {
    handle = getDb({ connectionString: LIVE_URL, max: 4, idleTimeoutSeconds: 5 });
    sql = handle.sql;
    db = handle.db;
    // Idempotent: every migration is CREATE ... IF NOT EXISTS.
    const result = await applyMigrations(sql);
    expect(result.applied).toContain("0005_vault_blobs.sql");
    expect(result.applied).toContain("0006_dek_share_records.sql");
  });

  afterAll(async () => {
    // Clean up only this suite's mutable rows, then close. NOTE: we do NOT
    // delete from vault_audit_log — it is append-only by DB trigger (the very
    // invariant this suite asserts). Scratch audit rows are left in place; on a
    // real DB they age out via the SECURITY-DEFINER purge path, never a DELETE.
    await sql`DELETE FROM dek_share_records WHERE h_commit LIKE ${"%" + P + "%"}`;
    await sql`DELETE FROM vault_blobs WHERE vault_ref LIKE ${P + "%"}`;
    await handle.close();
  });

  it("runMigrations() is idempotent (re-apply is a no-op, never throws)", async () => {
    // runMigrations opens its own env-derived connection; only meaningful when
    // CEALIS_V3_DATABASE_URL is the live URL. If only V3_TEST_PG_URL is set,
    // resolveV3DatabaseUrl() still returns it, so this path is exercised.
    const result = await runMigrations();
    expect(result.applied.length).toBeGreaterThanOrEqual(6);
  });

  it("vault_blobs + dek_share_records tables exist after migration", async () => {
    const rows = await sql<{ table_name: string }[]>`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name IN ('vault_blobs', 'dek_share_records')
      ORDER BY table_name
    `;
    expect(rows.map((r) => r.table_name)).toEqual(["dek_share_records", "vault_blobs"]);
  });

  it("ciphertext + commit binding round-trip as bytea (no PII at rest beyond ciphertext)", async () => {
    // Write/read via the Drizzle client so jsonb + bytea serialization goes
    // through Drizzle's own (single-realm) codecs — avoids the postgres-js
    // `sql.json()`/Buffer instanceof-across-realms breakage under Vitest.
    const vaultRef = `${P}-vault-1`;
    const ciphertext = Buffer.from("01020304deadbeef", "hex");
    const aad = Buffer.from("aabbccdd", "hex");
    const digest = `0x${"cd".repeat(32)}`;
    await db.insert(vaultBlobsTable).values({
      vault_ref: vaultRef,
      ciphertext,
      commit_aad_bytes: aad,
      commit_version_onwire: 0x0301,
      commit_aad_digest: digest,
      payload_classification: { classes: ["pii"] },
      retention_policy_id: "default-3y",
      retention_expires_at: new Date(Date.now() + 365 * 24 * 3600 * 1000),
      byte_len: ciphertext.length,
    });
    const back = await db
      .select({
        ciphertext: vaultBlobsTable.ciphertext,
        commit_aad_bytes: vaultBlobsTable.commit_aad_bytes,
        payload_classification: vaultBlobsTable.payload_classification,
      })
      .from(vaultBlobsTable)
      .where(eq(vaultBlobsTable.vault_ref, vaultRef));
    expect(back).toHaveLength(1);
    expect(Buffer.from(back[0]!.ciphertext).toString("hex")).toBe(ciphertext.toString("hex"));
    expect(Buffer.from(back[0]!.commit_aad_bytes).toString("hex")).toBe(aad.toString("hex"));
    // jsonb round-trips as the object, not a JSON-string scalar.
    expect(back[0]!.payload_classification).toEqual({ classes: ["pii"] });
  });

  it("dek_share_records enforces the 1168-byte WRAPPED-payload CHECK (rejects a raw share)", async () => {
    const validHCommit = `0x${"12".repeat(32)}`;
    const d32 = Buffer.alloc(32, 3); // the public digests are 32 bytes
    const good = Buffer.alloc(1168, 7); // a real §6.2 wrapped stanza is 1168 bytes
    // A valid WRAPPED stanza inserts.
    await sql`
      INSERT INTO dek_share_records (
        h_commit, stanza_index, gate_kind, conditional_recipient_index,
        role, domain, logical_index, x, binding_tag, wrapped_payload,
        plugin_version_digest, commit_context_digest_n, commit_context_digest_0
      )
      VALUES (
        ${validHCommit}, ${0}, ${0}, ${0}, ${1}, ${1}, ${0}, ${1},
        ${`0x${"ab".repeat(32)}`}, ${good}, ${d32}, ${d32}, ${d32}
      )
    `;
    const inserted = await sql<{ n: number }[]>`
      SELECT count(*)::int AS n FROM dek_share_records WHERE h_commit = ${validHCommit}
    `;
    expect(inserted[0]!.n).toBe(1);
    // NON-CUSTODY GUARDRAIL: a raw 32-byte (or 39-byte) reconstructable share is
    // REJECTED by the octet_length CHECK — the schema structurally refuses to hold
    // anything but a full wrapped stanza.
    for (const rawLen of [32, 39]) {
      const bad = Buffer.alloc(rawLen, 9);
      await expect(
        sql`
          INSERT INTO dek_share_records (
            h_commit, stanza_index, gate_kind, conditional_recipient_index,
            role, domain, logical_index, x, binding_tag, wrapped_payload,
            plugin_version_digest, commit_context_digest_n, commit_context_digest_0
          )
          VALUES (
            ${validHCommit}, ${rawLen}, ${0}, ${0}, ${1}, ${1}, ${0}, ${1},
            ${`0x${"ab".repeat(32)}`}, ${bad}, ${d32}, ${d32}, ${d32}
          )
        `,
      ).rejects.toThrow();
    }
    // Cleanup this test's share rows.
    await sql`DELETE FROM dek_share_records WHERE h_commit = ${validHCommit}`;
  });

  it("vault_audit_log is append-only: UPDATE and DELETE raise the trigger", async () => {
    // The append-only invariant is legally load-bearing (chain-of-custody,
    // §371a ZPO). A shred writes an audit row; the row can never be mutated.
    // Insert via Drizzle (realm-safe jsonb); assert the trigger via raw SQL
    // UPDATE/DELETE (no object params, so the realm issue doesn't apply).
    const auditId = crypto.randomUUID();
    await db.insert(vaultAuditLogAuth).values({
      audit_id: auditId,
      actor_ref: `${P}-actor`,
      action: "shred",
      h_commit: `0x${"ee".repeat(32)}`,
      safe_refs: { reason: "art-17" },
      purge_after: new Date(Date.now() + 12 * 30 * 24 * 3600 * 1000),
    });
    await expect(
      sql`UPDATE vault_audit_log SET action = ${"tamper"} WHERE audit_id = ${auditId}`,
    ).rejects.toThrow(/append-only/i);
    await expect(
      sql`DELETE FROM vault_audit_log WHERE audit_id = ${auditId}`,
    ).rejects.toThrow(/append-only/i);
    // The row is still there + unchanged.
    const rows = await sql<{ action: string }[]>`
      SELECT action FROM vault_audit_log WHERE audit_id = ${auditId}
    `;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.action).toBe("shred");
  });
});
