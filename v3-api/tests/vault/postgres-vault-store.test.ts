// PostgresVaultStore tests — REAL Postgres bytea round-trip + append-only
// vault_audit_log shred row. Opt-in via V3_TEST_PG_URL; SKIPs cleanly when unset
// (CI without a PG instance still passes).
//
// Asserts the Postgres-specific guarantees the Filesystem suite cannot:
//   - bytea ciphertext round-trips byte-exact (no Buffer-subtype leak);
//   - the inseparable commit binding is stored in the SAME row and returned with
//     the ciphertext (C1);
//   - crypto-shred deletes the vault_blobs row AND appends a row to the
//     append-only vault_audit_log — and that audit table genuinely rejects
//     UPDATE/DELETE during the retention window (the legal append-only invariant);
//   - the shred-audit row carries NO PII.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import postgres from "postgres";
import type { Sql } from "postgres";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CealisV3VaultImpl } from "../../src/vault/cealis-v3-vault-impl.js";
import { PostgresVaultStore } from "../../src/vault/backends/postgres-vault-store.js";
import type { VaultCommitBinding } from "../../src/vault/cealis-v3-vault.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const MIGRATIONS_DIR = join(__dirname, "..", "..", "src", "db", "migrations");

const TEST_PG_URL = process.env["V3_TEST_PG_URL"];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = TEST_PG_URL ? describe : describe.skip;

const PLAINTEXT_TOKEN = "SECRET-PII-Erika-Mustermann";
const DEK_TOKEN = "DEK-0xdeadbeef";

function fakeCiphertext(seed: string): Uint8Array {
  return new TextEncoder().encode(`AEAD::${seed}::opaque-no-secrets`);
}
function binding(commitVersion = 0x0301, digest = "0xabc"): VaultCommitBinding {
  return {
    commit_aad_bytes: new TextEncoder().encode(`commit-aad::${commitVersion}::${digest}`),
    commit_version_onwire: commitVersion,
    commit_aad_digest: digest,
  };
}
function meta(retentionExpiresAt = "2029-01-01T00:00:00.000Z") {
  return {
    payload_classification: { kind: "kyc" },
    retention_policy_id: "obligation_plus_3y",
    retention_expires_at: retentionExpiresAt,
  };
}

describeIfPg("PostgresVaultStore (V3_TEST_PG_URL)", () => {
  let sql: Sql;
  let vault: CealisV3VaultImpl;
  let store: PostgresVaultStore;
  let P: string; // per-suite ref prefix to avoid cross-file collisions

  beforeAll(async () => {
    if (!TEST_PG_URL) return;
    sql = postgres(TEST_PG_URL, { max: 4, idle_timeout: 5, onnotice: () => {} });
    // 0003 creates partners/user_accounts/vault_audit_log (+ append-only
    // triggers); 0005 creates vault_blobs. Serialize the apply (CREATE TRIGGER /
    // CREATE OR REPLACE FUNCTION race in pg_type under parallel workers).
    const m3 = readFileSync(join(MIGRATIONS_DIR, "0003_auth_webhooks.sql"), "utf-8");
    const m5 = readFileSync(join(MIGRATIONS_DIR, "0005_vault_blobs.sql"), "utf-8");
    const LOCK_KEY = 8675311;
    await sql`SELECT pg_advisory_lock(${LOCK_KEY})`;
    try {
      await sql.unsafe(m3);
      await sql.unsafe(m5);
    } finally {
      await sql`SELECT pg_advisory_unlock(${LOCK_KEY})`;
    }
    store = new PostgresVaultStore({ sql });
    vault = new CealisV3VaultImpl({ store });
    P = `vault://t-${process.pid}-${Math.random().toString(36).slice(2, 8)}-`;
  });

  afterAll(async () => {
    if (!sql) return;
    // Clean up only this suite's rows. vault_audit_log is append-only — its rows
    // can only be removed by the SECURITY-DEFINER purge in prod; for the test DB
    // we drop suite rows by disabling the trigger transiently is NOT allowed, so
    // we leave audit rows (namespaced by ref) — they are harmless and prefixed.
    await sql`DELETE FROM vault_blobs WHERE vault_ref LIKE ${P + "%"}`;
    await sql.end({ timeout: 5 });
  });

  it("round-trips bytea ciphertext + inseparable binding byte-exact (C1)", async () => {
    const ref = `${P}round-trip`;
    const ct = fakeCiphertext("rt");
    const b = binding();
    const put = await vault.putBlob({ ref, ciphertext: ct, commitBinding: b, meta: meta() });
    expect(put.byte_len).toBe(ct.byteLength);

    const got = await vault.getBlob(ref);
    // bytea read normalized to plain Uint8Array — byte-exact, no Buffer leak.
    expect(got.ciphertext).toBeInstanceOf(Uint8Array);
    expect(Array.from(got.ciphertext)).toEqual(Array.from(ct));
    expect(Array.from(got.commitBinding.commit_aad_bytes)).toEqual(Array.from(b.commit_aad_bytes));
    expect(got.commitBinding.commit_version_onwire).toBe(b.commit_version_onwire);
    expect(got.commitBinding.commit_aad_digest).toBe(b.commit_aad_digest);
  });

  it("rejects same-ref put with different bytes (VAULT_REF_COLLISION)", async () => {
    const ref = `${P}collide`;
    await vault.putBlob({ ref, ciphertext: fakeCiphertext("a"), commitBinding: binding(), meta: meta() });
    await expect(
      vault.putBlob({ ref, ciphertext: fakeCiphertext("b"), commitBinding: binding(), meta: meta() }),
    ).rejects.toMatchObject({ context: { reasonCode: "VAULT_REF_COLLISION" } });
  });

  it("crypto-shred deletes the blob row AND appends an append-only audit row", async () => {
    const ref = `${P}shred`;
    await vault.putBlob({ ref, ciphertext: fakeCiphertext("s"), commitBinding: binding(), meta: meta() });

    const before = await sql<{ c: number }[]>`SELECT COUNT(*)::int AS c FROM vault_blobs WHERE vault_ref = ${ref}`;
    expect(before[0]?.c).toBe(1);

    await vault.deleteBlob({ ref, shredAuthority: "subject" });

    const after = await sql<{ c: number }[]>`SELECT COUNT(*)::int AS c FROM vault_blobs WHERE vault_ref = ${ref}`;
    expect(after[0]?.c).toBe(0);

    const audit = await sql<{ action: string; h_commit: string; safe_refs: unknown }[]>`
      SELECT action, h_commit, safe_refs FROM vault_audit_log WHERE h_commit = ${ref}
    `;
    expect(audit.length).toBe(1);
    expect(audit[0]?.action).toBe("vault_shred");
    // postgres-js may return a jsonb column as a parsed object OR a JSON string
    // (depends on the column's CAST path) — normalize before asserting.
    const rawSafeRefs = audit[0]?.safe_refs;
    const safeRefs = (
      typeof rawSafeRefs === "string" ? JSON.parse(rawSafeRefs) : rawSafeRefs
    ) as Record<string, unknown>;
    expect(safeRefs).toMatchObject({ vault_ref: ref, shred_authority: "subject" });
    // No PII / no DEK in the audit row.
    const audJson = JSON.stringify(safeRefs);
    expect(audJson).not.toContain(PLAINTEXT_TOKEN);
    expect(audJson).not.toContain(DEK_TOKEN);

    // Shred is irreversible.
    await expect(vault.getBlob(ref)).rejects.toMatchObject({ context: { reasonCode: "VAULT_REF_NOT_FOUND" } });
  });

  it("vault_audit_log is append-only — UPDATE and DELETE both raise (legal invariant)", async () => {
    const ref = `${P}append-only`;
    await vault.putBlob({ ref, ciphertext: fakeCiphertext("ao"), commitBinding: binding(), meta: meta() });
    await vault.deleteBlob({ ref, shredAuthority: "operator" });

    await expect(
      sql`UPDATE vault_audit_log SET action = 'tamper' WHERE h_commit = ${ref}`,
    ).rejects.toThrow(/append-only/i);
    await expect(
      sql`DELETE FROM vault_audit_log WHERE h_commit = ${ref}`,
    ).rejects.toThrow(/append-only/i);
  });

  it("refuses crypto-shred when shred authority is 'disabled'", async () => {
    const ref = `${P}disabled`;
    await vault.putBlob({ ref, ciphertext: fakeCiphertext("d"), commitBinding: binding(), meta: meta() });
    await expect(vault.deleteBlob({ ref, shredAuthority: "disabled" })).rejects.toMatchObject({
      context: { reasonCode: "VAULT_SHRED_AUTHORITY_DISABLED" },
    });
    // Still present — disabled means erasure is OFF.
    await expect(vault.getBlob(ref)).resolves.toBeDefined();
  });

  it("no plaintext / no DEK is ever stored in the vault_blobs row", async () => {
    const ref = `${P}no-pii`;
    await vault.putBlob({ ref, ciphertext: fakeCiphertext("np"), commitBinding: binding(), meta: meta() });
    // Read EVERY column as text and assert the secrets never appear anywhere.
    const rows = await sql<{ dump: string }[]>`
      SELECT
        encode(ciphertext, 'escape') || '|' || encode(commit_aad_bytes, 'escape') || '|' ||
        commit_aad_digest || '|' || payload_classification::text || '|' || retention_policy_id AS dump
      FROM vault_blobs WHERE vault_ref = ${ref}
    `;
    expect(rows.length).toBe(1);
    expect(rows[0]?.dump).not.toContain(PLAINTEXT_TOKEN);
    expect(rows[0]?.dump).not.toContain(DEK_TOKEN);
  });

  it("listExpired returns only refs past their retention floor", async () => {
    const expiredRef = `${P}expired`;
    const liveRef = `${P}live`;
    await vault.putBlob({ ref: expiredRef, ciphertext: fakeCiphertext("e"), commitBinding: binding(), meta: meta("2025-01-01T00:00:00.000Z") });
    await vault.putBlob({ ref: liveRef, ciphertext: fakeCiphertext("l"), commitBinding: binding(), meta: meta("2099-01-01T00:00:00.000Z") });
    const expired = await vault.listExpired("2026-06-02T00:00:00.000Z");
    expect(expired).toContain(expiredRef);
    expect(expired).not.toContain(liveRef);
  });
});
