// RetentionWorker tests (Phase 3 T4.3).
//
// Two layers:
//   (A) ALWAYS-ON unit suite — drives the worker against a REAL
//       FilesystemVaultStore-backed vault (Rule 12: not an in-memory shortcut)
//       for the vault-ciphertext class, plus injected fake purge ports for the
//       audit-log / webhook / ephemeral classes. Asserts: expired blobs are
//       crypto-shred, in-window blobs are kept, `disabled` shred authority is
//       SKIPPED (not force-purged), each class purges past its own window,
//       per-item failures don't abort the sweep, and start/stop lifecycle.
//   (B) V3_TEST_PG_URL-gated suite — drives the REAL append-only `vault_audit_log`
//       through the SECURITY-DEFINER purge port, proving the purge respects the
//       12-month window AND that a raw DELETE is rejected by the append-only
//       trigger (the worker never issues one). SKIPs cleanly when unset.

import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import postgres from "postgres";
import type { Sql } from "postgres";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  CealisV3VaultImpl,
  FilesystemVaultStore,
  type CealisV3Vault,
  type ShredAuthority,
  type VaultCommitBinding,
  type VaultRef,
} from "../../src/vault/index.js";
import {
  CompositeExpiringRowPurge,
  PostgresAuditLogPurgePort,
  RetentionWorker,
  type AuditLogPurgePort,
  type ExpiringRowPurgePort,
  type RetentionClass,
  type ShredAuthorityResolver,
} from "../../src/vault/retention-worker.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function fakeCiphertext(seed: string): Uint8Array {
  return new TextEncoder().encode(`AEAD::${seed}::opaque-ciphertext-no-secrets`);
}

function binding(commitVersion = 0x0301, digest = "0xabc123"): VaultCommitBinding {
  return {
    commit_aad_bytes: new TextEncoder().encode(`commit-aad::${commitVersion}::${digest}`),
    commit_version_onwire: commitVersion,
    commit_aad_digest: digest,
  };
}

function meta(retentionExpiresAt: string) {
  return {
    payload_classification: { kind: "kyc" },
    retention_policy_id: "obligation_plus_3y",
    retention_expires_at: retentionExpiresAt,
  };
}

/** A `ShredAuthorityResolver` driven by an explicit per-ref map (PDA config
 *  stand-in). Unmapped refs default to `subject`. */
class MapShredAuthorityResolver implements ShredAuthorityResolver {
  constructor(private readonly map: Map<VaultRef, ShredAuthority> = new Map()) {}
  set(ref: VaultRef, authority: ShredAuthority): this {
    this.map.set(ref, authority);
    return this;
  }
  async resolve(ref: VaultRef): Promise<ShredAuthority> {
    return this.map.get(ref) ?? "subject";
  }
}

/** A counting fake purge port — records every `asOf` it was called with and
 *  returns a fixed purged count. */
class FakePurgePort implements AuditLogPurgePort, ExpiringRowPurgePort {
  readonly calls: Date[] = [];
  constructor(private readonly purged: number) {}
  async purgeExpired(asOf: Date): Promise<number> {
    this.calls.push(asOf);
    return this.purged;
  }
}

class ThrowingPurgePort implements ExpiringRowPurgePort {
  async purgeExpired(): Promise<number> {
    throw new Error("backend unavailable");
  }
}

const FIXED_NOW = new Date("2026-06-02T12:00:00.000Z");

// ---------------------------------------------------------------------------
// (A) Always-on unit suite
// ---------------------------------------------------------------------------

describe("RetentionWorker (real FilesystemVaultStore + fake ports)", () => {
  let dir: string;
  let vault: CealisV3Vault;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cealis-retention-test-"));
    vault = new CealisV3VaultImpl({
      store: new FilesystemVaultStore({ rootDir: dir }),
      now: () => FIXED_NOW,
    });
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  function buildWorker(overrides: {
    resolver?: ShredAuthorityResolver;
    auditLogPurge?: AuditLogPurgePort;
    webhookMetadataPurge?: ExpiringRowPurgePort;
    ephemeralAuthPurge?: ExpiringRowPurgePort;
    onError?: (c: RetentionClass, e: unknown) => void;
  } = {}) {
    return new RetentionWorker({
      vault,
      shredAuthorityResolver: overrides.resolver ?? new MapShredAuthorityResolver(),
      auditLogPurge: overrides.auditLogPurge ?? new FakePurgePort(0),
      webhookMetadataPurge: overrides.webhookMetadataPurge ?? new FakePurgePort(0),
      ephemeralAuthPurge: overrides.ephemeralAuthPurge ?? new FakePurgePort(0),
      now: () => FIXED_NOW,
      onError: overrides.onError,
    });
  }

  /** Run a slow sweep and return the (always-present) vault-ciphertext result. */
  async function slowVaultSweep(worker: RetentionWorker) {
    const slow = await worker.runSlowSweep();
    const vaultSweep = slow.find((r) => r.retentionClass === "vault_ciphertext");
    expect(vaultSweep).toBeDefined();
    return vaultSweep!;
  }

  it("crypto-shreds vault ciphertext past its retention floor and KEEPS in-window blobs", async () => {
    const expiredRef = "vault://0xexpired";
    const liveRef = "vault://0xlive";
    await vault.putBlob({ ref: expiredRef, ciphertext: fakeCiphertext("e"), commitBinding: binding(), meta: meta("2025-01-01T00:00:00.000Z") });
    await vault.putBlob({ ref: liveRef, ciphertext: fakeCiphertext("l"), commitBinding: binding(), meta: meta("2099-01-01T00:00:00.000Z") });

    const worker = buildWorker();
    const vaultSweep = await slowVaultSweep(worker);

    expect(vaultSweep.retentionClass).toBe("vault_ciphertext");
    expect(vaultSweep.purged).toBe(1);
    expect(vaultSweep.skipped).toBe(0);
    expect(vaultSweep.failed).toBe(0);

    // Expired blob is gone (irreversible crypto-shred); in-window blob remains.
    await expect(vault.getBlob(expiredRef)).rejects.toMatchObject({ context: { reasonCode: "VAULT_REF_NOT_FOUND" } });
    await expect(vault.getBlob(liveRef)).resolves.toBeDefined();
  });

  it("SKIPS an expired blob whose PDA shred authority is 'disabled' (feature, not bug)", async () => {
    const disabledRef = "vault://0xdisabled-expired";
    const subjectRef = "vault://0xsubject-expired";
    await vault.putBlob({ ref: disabledRef, ciphertext: fakeCiphertext("d"), commitBinding: binding(), meta: meta("2025-01-01T00:00:00.000Z") });
    await vault.putBlob({ ref: subjectRef, ciphertext: fakeCiphertext("s"), commitBinding: binding(), meta: meta("2025-01-01T00:00:00.000Z") });

    const resolver = new MapShredAuthorityResolver()
      .set(disabledRef, "disabled")
      .set(subjectRef, "subject");
    const worker = buildWorker({ resolver });
    const vaultSweep = await slowVaultSweep(worker);

    expect(vaultSweep.purged).toBe(1); // only the subject-authority blob
    expect(vaultSweep.skipped).toBe(1); // disabled is preserved past expiry

    // The disabled blob MUST still be retrievable — erasure is OFF for it even
    // though its retention floor passed (testament / archival / evidence).
    await expect(vault.getBlob(disabledRef)).resolves.toBeDefined();
    await expect(vault.getBlob(subjectRef)).rejects.toMatchObject({ context: { reasonCode: "VAULT_REF_NOT_FOUND" } });
  });

  it("drives the crypto-shred with the PDA-resolved authority (operator / timelock honored)", async () => {
    const ref = "vault://0xoperator";
    await vault.putBlob({ ref, ciphertext: fakeCiphertext("o"), commitBinding: binding(), meta: meta("2025-01-01T00:00:00.000Z") });
    const resolver = new MapShredAuthorityResolver().set(ref, "operator");
    const deleteSpy = vi.spyOn(vault, "deleteBlob");

    const worker = buildWorker({ resolver });
    await worker.runSlowSweep();

    expect(deleteSpy).toHaveBeenCalledWith({ ref, shredAuthority: "operator" });
  });

  it("a single blob shred failure does not abort the batch (counts failed, continues)", async () => {
    const okRef = "vault://0xok";
    const badRef = "vault://0xbad";
    await vault.putBlob({ ref: okRef, ciphertext: fakeCiphertext("ok"), commitBinding: binding(), meta: meta("2025-01-01T00:00:00.000Z") });
    await vault.putBlob({ ref: badRef, ciphertext: fakeCiphertext("bad"), commitBinding: binding(), meta: meta("2025-01-01T00:00:00.000Z") });

    // Make exactly the bad ref throw a non-disabled error on delete.
    const realDelete = vault.deleteBlob.bind(vault);
    vi.spyOn(vault, "deleteBlob").mockImplementation(async (input) => {
      if (input.ref === badRef) throw new Error("transient store failure");
      return realDelete(input);
    });
    const errors: RetentionClass[] = [];
    const worker = buildWorker({ onError: (c) => errors.push(c) });
    const vaultSweep = await slowVaultSweep(worker);

    expect(vaultSweep.purged).toBe(1);
    expect(vaultSweep.failed).toBe(1);
    expect(errors).toContain("vault_ciphertext");
  });

  it("a vault.listExpired failure is surfaced and reported as a zero sweep (never throws)", async () => {
    vi.spyOn(vault, "listExpired").mockRejectedValueOnce(new Error("vault down"));
    const errors: RetentionClass[] = [];
    const worker = buildWorker({ onError: (c) => errors.push(c) });
    const vaultSweep = await slowVaultSweep(worker);
    expect(vaultSweep.purged).toBe(0);
    expect(vaultSweep.failed).toBe(1);
    expect(errors).toContain("vault_ciphertext");
  });

  it("purges the audit-log + webhook + ephemeral classes via their injected ports", async () => {
    const auditPort = new FakePurgePort(3);
    const webhookPort = new FakePurgePort(5);
    const ephemeralPort = new FakePurgePort(7);
    const worker = buildWorker({
      auditLogPurge: auditPort,
      webhookMetadataPurge: webhookPort,
      ephemeralAuthPurge: ephemeralPort,
    });

    const slow = await worker.runSlowSweep();
    const auditSweep = slow.find((r) => r.retentionClass === "vault_audit_log");
    const webhookSweep = slow.find((r) => r.retentionClass === "webhook_metadata");
    expect(auditSweep?.purged).toBe(3);
    expect(webhookSweep?.purged).toBe(5);
    // Each slow port called once, with the worker's clock.
    expect(auditPort.calls).toEqual([FIXED_NOW]);
    expect(webhookPort.calls).toEqual([FIXED_NOW]);

    const ephemeralSweep = await worker.runEphemeralSweep();
    expect(ephemeralSweep.retentionClass).toBe("ephemeral_auth");
    expect(ephemeralSweep.purged).toBe(7);
    expect(ephemeralPort.calls).toEqual([FIXED_NOW]);
  });

  it("a purge-port failure is isolated per class (other classes still purge)", async () => {
    const errors: RetentionClass[] = [];
    const worker = buildWorker({
      webhookMetadataPurge: new ThrowingPurgePort(),
      auditLogPurge: new FakePurgePort(2),
      onError: (c) => errors.push(c),
    });
    const slow = await worker.runSlowSweep();
    const webhookSweep = slow.find((r) => r.retentionClass === "webhook_metadata");
    const auditSweep = slow.find((r) => r.retentionClass === "vault_audit_log");
    expect(webhookSweep?.failed).toBe(1);
    expect(auditSweep?.purged).toBe(2); // unaffected
    expect(errors).toEqual(["webhook_metadata"]);
  });

  it("start() runs an eager first sweep + arms timers; stop() is idempotent", async () => {
    vi.useFakeTimers();
    try {
      const auditPort = new FakePurgePort(1);
      const ephemeralPort = new FakePurgePort(1);
      const worker = new RetentionWorker({
        vault,
        shredAuthorityResolver: new MapShredAuthorityResolver(),
        auditLogPurge: auditPort,
        webhookMetadataPurge: new FakePurgePort(0),
        ephemeralAuthPurge: ephemeralPort,
        now: () => FIXED_NOW,
        policy: {
          vaultAuditLogRetentionDays: 365,
          webhookMetadataRetentionDays: 90,
          slowSweepIntervalMs: 1000,
          ephemeralSweepIntervalMs: 500,
        },
      });

      expect(worker.isRunning).toBe(false);
      worker.start();
      expect(worker.isRunning).toBe(true);
      // Eager first sweep fired immediately (microtask flush).
      await vi.advanceTimersByTimeAsync(0);
      expect(auditPort.calls.length).toBe(1);
      expect(ephemeralPort.calls.length).toBe(1);

      // One slow interval (1000ms) + two ephemeral intervals (500ms each).
      await vi.advanceTimersByTimeAsync(1000);
      expect(auditPort.calls.length).toBe(2); // 1 eager + 1 interval
      expect(ephemeralPort.calls.length).toBe(3); // 1 eager + 2 intervals

      // Second start() is a no-op (already running).
      worker.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(auditPort.calls.length).toBe(2);

      await worker.stop();
      expect(worker.isRunning).toBe(false);
      await vi.advanceTimersByTimeAsync(5000);
      expect(auditPort.calls.length).toBe(2); // no further sweeps after stop
      // Second stop() is idempotent.
      await expect(worker.stop()).resolves.toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });

  it("the CompositeExpiringRowPurge sums its sub-ports (multi-table ephemeral sweep)", async () => {
    const composite = new CompositeExpiringRowPurge([
      new FakePurgePort(2),
      new FakePurgePort(3),
      new FakePurgePort(0),
    ]);
    expect(await composite.purgeExpired(FIXED_NOW)).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// (B) V3_TEST_PG_URL-gated suite — real append-only audit-log purge path
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const MIGRATIONS_DIR = join(__dirname, "..", "..", "src", "db", "migrations");
const TEST_PG_URL = process.env["V3_TEST_PG_URL"];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describeIfPg: any = TEST_PG_URL ? describe : describe.skip;

describeIfPg("RetentionWorker audit-log purge (V3_TEST_PG_URL, real append-only)", () => {
  let sql: Sql;
  let P: string;

  beforeAll(async () => {
    if (!TEST_PG_URL) return;
    sql = postgres(TEST_PG_URL, { max: 4, idle_timeout: 5, onnotice: () => {} });
    // 0003 creates vault_audit_log + the append-only triggers. Serialize the
    // apply (CREATE TRIGGER race under parallel workers).
    const m3 = readFileSync(join(MIGRATIONS_DIR, "0003_auth_webhooks.sql"), "utf-8");
    const LOCK_KEY = 8675313;
    await sql`SELECT pg_advisory_lock(${LOCK_KEY})`;
    try {
      await sql.unsafe(m3);
      // Provision the SECURITY-DEFINER purge function from the REAL migration
      // (0009) — the ONLY legal path past the append-only trigger and the
      // companion to the 0003 trigger. This verifies the shipped migration
      // actually creates `purge_old_audit_logs(...)` with the signature the
      // worker's PostgresAuditLogPurgePort calls, exercising the real purge
      // path end-to-end (closes the prior migration gap).
      const m9 = readFileSync(join(MIGRATIONS_DIR, "0009_audit_log_purge_fn.sql"), "utf-8");
      await sql.unsafe(m9);
    } finally {
      await sql`SELECT pg_advisory_unlock(${LOCK_KEY})`;
    }
    P = `0xret${process.pid.toString(16).padStart(4, "0")}${Math.random().toString(16).slice(2, 8)}`;
  });

  afterAll(async () => {
    if (!sql) return;
    // vault_audit_log is append-only — the only legal removal is the purge
    // function. Use it to clean this suite's rows (set purge_after in the past).
    await sql`SELECT purge_old_audit_logs(now() + interval '100 years', 0)`.catch(() => undefined);
    await sql.end({ timeout: 5 });
  });

  /** Insert an audit row with an explicit purge_after (no PII). */
  async function insertAuditRow(hCommit: string, purgeAfter: Date): Promise<void> {
    await sql`
      INSERT INTO vault_audit_log (audit_id, actor_ref, action, h_commit, pda_id, safe_refs, created_at, purge_after)
      VALUES (gen_random_uuid(), 'vault:subject', 'vault_shred', ${hCommit}, ${null},
              ${JSON.stringify({ vault_ref: hCommit })}::jsonb, ${new Date()}, ${purgeAfter})
    `;
  }

  it("a raw DELETE on vault_audit_log is REJECTED by the append-only trigger", async () => {
    const ref = `${P}-raw-delete`;
    await insertAuditRow(ref, new Date("2024-01-01T00:00:00.000Z"));
    await expect(sql`DELETE FROM vault_audit_log WHERE h_commit = ${ref}`).rejects.toThrow(/append-only/i);
  });

  it("purges audit rows past the 12-month window AND keeps in-window rows (via SECURITY-DEFINER fn)", async () => {
    const expiredRef = `${P}-expired`;
    const liveRef = `${P}-live`;
    // purge_after in the past → eligible; in the far future → retained.
    await insertAuditRow(expiredRef, new Date("2024-01-01T00:00:00.000Z"));
    await insertAuditRow(liveRef, new Date("2099-01-01T00:00:00.000Z"));

    const port = new PostgresAuditLogPurgePort({ sql });
    const purged = await port.purgeExpired(new Date("2026-06-02T12:00:00.000Z"));
    expect(purged).toBeGreaterThanOrEqual(1);

    const expiredCount = await sql<{ c: number }[]>`SELECT COUNT(*)::int AS c FROM vault_audit_log WHERE h_commit = ${expiredRef}`;
    const liveCount = await sql<{ c: number }[]>`SELECT COUNT(*)::int AS c FROM vault_audit_log WHERE h_commit = ${liveRef}`;
    expect(expiredCount[0]?.c).toBe(0); // expired row purged
    expect(liveCount[0]?.c).toBe(1); // in-window row kept
  });

  it("the worker drives the real audit-log purge through runSlowSweep", async () => {
    const ref = `${P}-worker-sweep`;
    await insertAuditRow(ref, new Date("2024-01-01T00:00:00.000Z"));

    // A vault stub that has nothing to shred — we only exercise the audit class here.
    const noopVault = {
      listExpired: async () => [] as VaultRef[],
      deleteBlob: async (i: { ref: VaultRef }) => ({ ref: i.ref, shredded_at: new Date().toISOString() }),
    } as unknown as CealisV3Vault;

    const worker = new RetentionWorker({
      vault: noopVault,
      shredAuthorityResolver: { resolve: async () => "subject" as ShredAuthority },
      auditLogPurge: new PostgresAuditLogPurgePort({ sql }),
      webhookMetadataPurge: { purgeExpired: async () => 0 },
      ephemeralAuthPurge: { purgeExpired: async () => 0 },
    });
    const slow = await worker.runSlowSweep();
    const auditSweep = slow.find((r) => r.retentionClass === "vault_audit_log");
    expect(auditSweep?.purged).toBeGreaterThanOrEqual(1);

    const after = await sql<{ c: number }[]>`SELECT COUNT(*)::int AS c FROM vault_audit_log WHERE h_commit = ${ref}`;
    expect(after[0]?.c).toBe(0);
  });
});

// The SECURITY-DEFINER `purge_old_audit_logs(...)` function is now provisioned
// by the real migration `src/db/migrations/0009_audit_log_purge_fn.sql`
// (applied in beforeAll above), so the test no longer carries an inline copy.
