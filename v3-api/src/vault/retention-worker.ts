// RetentionWorker (Phase 3 T4.3) — the periodic GDPR retention purge.
//
// Enforces the D3 retention table (internal legal-constraints rules): each
// data class has its OWN period and its OWN legal purge path. NOTHING is
// hardcoded to a single flow — every period is sourced from the injected
// `RetentionPolicy` (which a PDA / env supplies at the composition root), and
// every purge target is an injected port so the worker is testable without live
// Postgres/Redis (PLATFORM PRINCIPLE + Rule 12).
//
// The five data classes this worker drives (D3):
//   1. Vault ciphertext + wrapped DEK shares  — obligation duration + 3y
//      (§195 BGB). Past `retention_expires_at` → crypto-shred cascade
//      (`vault.deleteBlob`: vault blob deletion + append-only shred-audit row;
//      DEK-share destruction is the ShredExecutor's part of the same cascade,
//      wired at T4.2 — the vault never holds a DEK). A blob whose PDA shred
//      authority is `disabled` is SKIPPED, not force-purged: erasure is
//      deliberately off for testament / archival / evidence (a feature, not a
//      bug). `retention_expires_at` is the per-blob floor, populated at ingest.
//   2. Vault access / audit logs              — 12 months rolling. Purged ONLY
//      via the `purge_old_audit_logs()` SECURITY-DEFINER function — the
//      `vault_audit_log` append-only trigger rejects any raw UPDATE/DELETE, so
//      this function is THE ONLY legal purge path. The worker NEVER issues a
//      raw DELETE against the audit log.
//   3. Webhook delivery metadata              — 90 days rolling. Past
//      `expires_at` → plain DELETE (`webhook_deliveries` is not append-only).
//   4. Ephemeral auth state (sessions /        — short TTL, swept frequently.
//      idempotency keys / nonces / rate-limit    Past `expires_at` / `reset_at`
//      buckets)                                  → plain DELETE.
//
// On-chain commitments are PERMANENT (D3) — never purged here; the on-chain
// commitment merely becomes an orphan once the blob + shares are crypto-shred.
//
// Lifecycle: `start()` arms a per-class interval timer (each class on its own
// cadence — vault/audit/webhook on the slow tick, ephemeral on the hourly
// tick), runs an immediate first sweep, and returns. `stop()` clears the timers
// and is idempotent. A failing sweep NEVER crashes the worker — each class is
// isolated and its error is surfaced to the injected `onError` sink.
//
// Rule-47 error context: every purge result carries counts + the data class so
// the composition root has full lineage without a debugger.
//
// V3 isolation (SECURITY.md + R2x grep gate): no `@cealis/shared`,
// no `../../packages/*` (V1), no V1 env-var names (the sealed-share /
// issuer-salt / committee-key family — see SECURITY.md). The audit-log purge
// function name and the Postgres `Sql` client are injected at Wave 5.

import type { Sql } from "postgres";
import type { CealisV3Vault, ShredAuthority, VaultError, VaultRef } from "./cealis-v3-vault.js";

/** The retention data classes this worker purges (D3). */
export type RetentionClass =
  | "vault_ciphertext"
  | "vault_audit_log"
  | "webhook_metadata"
  | "ephemeral_auth";

/**
 * Per-class retention configuration — PDA / env-sourced, NEVER hardcoded.
 *
 * Periods here are the *floors / windows* the worker enforces. The vault
 * ciphertext floor is NOT a single global number: it is per-blob
 * (`retention_expires_at`, populated at ingest from the PDA's retention floor),
 * so the worker drives the vault by `listExpired(now)`, not by subtracting a
 * fixed window. The audit-log / webhook / ephemeral windows ARE rolling
 * durations and are surfaced here so a PDA / deployment can tighten them.
 */
export interface RetentionPolicy {
  /**
   * Vault access / audit-log retention window (days). D3 default = 365
   * (12 months). The `purge_old_audit_logs()` function decides the cutoff via
   * the rows' own `purge_after`; this value is passed so the function (or a
   * deployment that overrides it) uses the policy window, not a hardcoded one.
   */
  readonly vaultAuditLogRetentionDays: number;
  /** Webhook delivery metadata retention window (days). D3 default = 90. */
  readonly webhookMetadataRetentionDays: number;
  /**
   * Sweep cadence (ms) for the slow classes (vault ciphertext, audit log,
   * webhook metadata). D3 framing = daily. Injected so tests run fast.
   */
  readonly slowSweepIntervalMs: number;
  /**
   * Sweep cadence (ms) for the ephemeral auth classes (sessions / idempotency
   * keys / nonces / rate-limit buckets). D3 framing = hourly. Injected so tests
   * run fast.
   */
  readonly ephemeralSweepIntervalMs: number;
}

/** D3 defaults (internal legal-constraints rules). A PDA / deployment may
 *  tighten any of these at the composition root; the worker never assumes them
 *  beyond this fallback. */
export const DEFAULT_RETENTION_POLICY: RetentionPolicy = {
  vaultAuditLogRetentionDays: 365, // 12 months rolling — "Legitimate Interest"
  webhookMetadataRetentionDays: 90, // 90 days rolling — "Debugging + Security"
  slowSweepIntervalMs: 24 * 60 * 60 * 1000, // daily
  ephemeralSweepIntervalMs: 60 * 60 * 1000, // hourly
};

/**
 * Resolves a blob's PDA-configured shred authority before the worker drives a
 * crypto-shred. The authority is PDA config (subject / joint / operator /
 * timelock / disabled) and is NOT recoverable from the frozen `CealisV3Vault`
 * surface (its `getRetentionStatus` returns a display string, not the typed
 * authority). So the worker resolves it through THIS injected port — the same
 * PDA-config seam the rest of the runtime reads (PLATFORM PRINCIPLE: the worker
 * obeys the PDA, it does not pick an authority).
 *
 * Returning `"disabled"` (or the port deciding erasure is off) causes the blob
 * to be skipped — retention expiry never overrides a deliberately-disabled
 * shred authority (testament / archival / evidence).
 */
export interface ShredAuthorityResolver {
  resolve(ref: VaultRef): Promise<ShredAuthority>;
}

/** Audit-log purge port — the ONLY legal path past the append-only trigger.
 *  Production wires it to the `purge_old_audit_logs()` SECURITY-DEFINER SQL
 *  function; tests inject a fake. The worker never issues a raw DELETE on
 *  `vault_audit_log`. */
export interface AuditLogPurgePort {
  /** Purge audit rows whose `purge_after <= asOf`. Returns the count removed. */
  purgeExpired(asOf: Date): Promise<number>;
}

/** Generic expiring-row purge port for webhook metadata + ephemeral auth state.
 *  Each is a plain DELETE on a non-append-only table; production wires the
 *  Postgres-backed impl, tests inject a fake. */
export interface ExpiringRowPurgePort {
  /** Purge rows expired as of `asOf`; returns the count removed. */
  purgeExpired(asOf: Date): Promise<number>;
}

/** Outcome of one class sweep (Rule-47 lineage). */
export interface RetentionSweepResult {
  readonly retentionClass: RetentionClass;
  /** Rows / blobs purged in this sweep. */
  readonly purged: number;
  /** Expired-but-skipped (e.g. vault blob with `shredding_authority=disabled`). */
  readonly skipped: number;
  /** Per-item failures that did NOT abort the sweep. */
  readonly failed: number;
  readonly asOf: string;
}

export interface RetentionWorkerConfig {
  /** The opaque-ciphertext vault (drives vault-ciphertext crypto-shred). */
  readonly vault: CealisV3Vault;
  /** PDA-config seam for per-blob shred authority. */
  readonly shredAuthorityResolver: ShredAuthorityResolver;
  /** Audit-log purge via the SECURITY-DEFINER function (the only legal path). */
  readonly auditLogPurge: AuditLogPurgePort;
  /** Webhook delivery-metadata purge (90d). */
  readonly webhookMetadataPurge: ExpiringRowPurgePort;
  /** Ephemeral auth-state purge (sessions / idempotency / nonces / buckets). */
  readonly ephemeralAuthPurge: ExpiringRowPurgePort;
  /** Retention policy — PDA / env-sourced. Defaults to D3. */
  readonly policy?: RetentionPolicy;
  /** Wall-clock source (injectable for deterministic tests). */
  readonly now?: () => Date;
  /** Per-class error sink. A class sweep failure is surfaced here, never thrown
   *  (a failing sweep must not crash the worker process). */
  readonly onError?: (retentionClass: RetentionClass, error: unknown) => void;
  /** Per-class completion sink (observability). */
  readonly onSweep?: (result: RetentionSweepResult) => void;
}

/**
 * The running retention worker. `start()` arms the timers + runs an immediate
 * first sweep; `stop()` clears them (idempotent). Wave 5 keeps the handle to
 * stop on SIGTERM.
 */
export class RetentionWorker {
  private readonly vault: CealisV3Vault;
  private readonly shredAuthorityResolver: ShredAuthorityResolver;
  private readonly auditLogPurge: AuditLogPurgePort;
  private readonly webhookMetadataPurge: ExpiringRowPurgePort;
  private readonly ephemeralAuthPurge: ExpiringRowPurgePort;
  private readonly policy: RetentionPolicy;
  private readonly now: () => Date;
  private readonly onError?: (retentionClass: RetentionClass, error: unknown) => void;
  private readonly onSweep?: (result: RetentionSweepResult) => void;

  private slowTimer?: ReturnType<typeof setInterval>;
  private ephemeralTimer?: ReturnType<typeof setInterval>;
  private running = false;

  constructor(config: RetentionWorkerConfig) {
    this.vault = config.vault;
    this.shredAuthorityResolver = config.shredAuthorityResolver;
    this.auditLogPurge = config.auditLogPurge;
    this.webhookMetadataPurge = config.webhookMetadataPurge;
    this.ephemeralAuthPurge = config.ephemeralAuthPurge;
    this.policy = config.policy ?? DEFAULT_RETENTION_POLICY;
    this.now = config.now ?? (() => new Date());
    this.onError = config.onError;
    this.onSweep = config.onSweep;
  }

  /** True between `start()` and `stop()`. */
  get isRunning(): boolean {
    return this.running;
  }

  /**
   * Arm the per-class timers + run an immediate first sweep. Idempotent: a
   * second `start()` while already running is a no-op. The first sweep runs
   * eagerly (so a freshly-booted process purges immediately, not after one full
   * interval); subsequent sweeps fire on the policy cadence.
   */
  start(): void {
    if (this.running) return;
    this.running = true;

    // Eager first sweep — fire-and-forget; errors land in `onError`, never throw.
    void this.runSlowSweep();
    void this.runEphemeralSweep();

    this.slowTimer = setInterval(() => {
      void this.runSlowSweep();
    }, this.policy.slowSweepIntervalMs);
    this.ephemeralTimer = setInterval(() => {
      void this.runEphemeralSweep();
    }, this.policy.ephemeralSweepIntervalMs);

    // Don't keep the event loop alive solely for the sweep timers — the API
    // process owns liveness, not this worker.
    this.slowTimer.unref?.();
    this.ephemeralTimer.unref?.();
  }

  /** Clear the timers. Idempotent — a second `stop()` is a no-op. In-flight
   *  sweeps are allowed to finish (they hold no locks; each purge is atomic). */
  async stop(): Promise<void> {
    if (!this.running) return;
    this.running = false;
    if (this.slowTimer) {
      clearInterval(this.slowTimer);
      this.slowTimer = undefined;
    }
    if (this.ephemeralTimer) {
      clearInterval(this.ephemeralTimer);
      this.ephemeralTimer = undefined;
    }
  }

  /** Run all slow-cadence classes once (vault ciphertext, audit log, webhook
   *  metadata). Exposed for the eager first sweep + tests; each class is
   *  isolated so one failure does not block the others. */
  async runSlowSweep(): Promise<readonly RetentionSweepResult[]> {
    const asOf = this.now();
    const results = await Promise.all([
      this.sweepVaultCiphertext(asOf),
      this.sweepVaultAuditLog(asOf),
      this.sweepWebhookMetadata(asOf),
    ]);
    return results;
  }

  /** Run the ephemeral-auth class once (sessions / idempotency / nonces /
   *  buckets). Exposed for the eager first sweep + tests. */
  async runEphemeralSweep(): Promise<RetentionSweepResult> {
    const asOf = this.now();
    return this.sweepEphemeralAuth(asOf);
  }

  /**
   * Vault ciphertext + wrapped DEK shares (obligation + 3y §195 BGB). Drives
   * the crypto-shred cascade for every blob past its per-blob retention floor.
   * A blob whose PDA shred authority is `disabled` is SKIPPED — erasure is
   * deliberately off for that use case. A per-blob shred failure is counted and
   * the sweep continues (no single blob aborts the batch).
   */
  private async sweepVaultCiphertext(asOf: Date): Promise<RetentionSweepResult> {
    const asOfIso = asOf.toISOString();
    try {
      const expired = await this.vault.listExpired(asOfIso);
      let purged = 0;
      let skipped = 0;
      let failed = 0;
      for (const ref of expired) {
        try {
          const authority = await this.shredAuthorityResolver.resolve(ref);
          if (authority === "disabled") {
            // Retention expiry NEVER overrides a deliberately-disabled shred
            // authority (testament / archival / evidence) — feature, not bug.
            skipped += 1;
            continue;
          }
          await this.vault.deleteBlob({ ref, shredAuthority: authority });
          purged += 1;
        } catch (err) {
          // A vault that itself reports the authority disabled (defence in
          // depth) is a skip, not a failure.
          if (isShredAuthorityDisabled(err)) {
            skipped += 1;
          } else {
            failed += 1;
            this.onError?.("vault_ciphertext", err);
          }
        }
      }
      return this.report({ retentionClass: "vault_ciphertext", purged, skipped, failed, asOf: asOfIso });
    } catch (err) {
      // listExpired itself failed — surface, report a zero sweep, do not throw.
      this.onError?.("vault_ciphertext", err);
      return this.report({ retentionClass: "vault_ciphertext", purged: 0, skipped: 0, failed: 1, asOf: asOfIso });
    }
  }

  /**
   * Vault access / audit logs (12 months rolling). Purged ONLY via the
   * SECURITY-DEFINER `purge_old_audit_logs()` function — the append-only
   * trigger rejects raw UPDATE/DELETE, so this is the only legal purge path.
   * The function uses each row's own `purge_after`; the policy window is the
   * cutoff frame.
   */
  private async sweepVaultAuditLog(asOf: Date): Promise<RetentionSweepResult> {
    const asOfIso = asOf.toISOString();
    try {
      const purged = await this.auditLogPurge.purgeExpired(asOf);
      return this.report({ retentionClass: "vault_audit_log", purged, skipped: 0, failed: 0, asOf: asOfIso });
    } catch (err) {
      this.onError?.("vault_audit_log", err);
      return this.report({ retentionClass: "vault_audit_log", purged: 0, skipped: 0, failed: 1, asOf: asOfIso });
    }
  }

  /** Webhook delivery metadata (90 days rolling). Plain DELETE past expiry. */
  private async sweepWebhookMetadata(asOf: Date): Promise<RetentionSweepResult> {
    const asOfIso = asOf.toISOString();
    try {
      const purged = await this.webhookMetadataPurge.purgeExpired(asOf);
      return this.report({ retentionClass: "webhook_metadata", purged, skipped: 0, failed: 0, asOf: asOfIso });
    } catch (err) {
      this.onError?.("webhook_metadata", err);
      return this.report({ retentionClass: "webhook_metadata", purged: 0, skipped: 0, failed: 1, asOf: asOfIso });
    }
  }

  /** Ephemeral auth state (sessions / idempotency keys / nonces / rate-limit
   *  buckets). Plain DELETE past expiry. */
  private async sweepEphemeralAuth(asOf: Date): Promise<RetentionSweepResult> {
    const asOfIso = asOf.toISOString();
    try {
      const purged = await this.ephemeralAuthPurge.purgeExpired(asOf);
      return this.report({ retentionClass: "ephemeral_auth", purged, skipped: 0, failed: 0, asOf: asOfIso });
    } catch (err) {
      this.onError?.("ephemeral_auth", err);
      return this.report({ retentionClass: "ephemeral_auth", purged: 0, skipped: 0, failed: 1, asOf: asOfIso });
    }
  }

  private report(result: RetentionSweepResult): RetentionSweepResult {
    this.onSweep?.(result);
    return result;
  }
}

/** True if the error is the vault's `VAULT_SHRED_AUTHORITY_DISABLED` refusal. */
function isShredAuthorityDisabled(err: unknown): boolean {
  const e = err as Partial<VaultError> | undefined;
  return !!e && typeof e === "object" && e.context?.reasonCode === "VAULT_SHRED_AUTHORITY_DISABLED";
}

/**
 * Production `AuditLogPurgePort` over the SECURITY-DEFINER `purge_old_audit_logs()`
 * SQL function — the ONLY legal way past the `vault_audit_log` append-only
 * trigger. The function is provisioned by a DB migration (the trigger lives in
 * 0003; the SECURITY-DEFINER purge function is its companion). If the function
 * is ABSENT, this port FAILS LOUD (Rule 19 — never a silent fake-success):
 * the worker MUST NOT fall back to a raw DELETE (the trigger would reject it,
 * and bypassing the trigger any other way would violate the legal append-only
 * invariant). Surfacing the missing function is the correct behaviour — it is a
 * migration-gap signal, not something this worker may paper over.
 *
 * The function name is injectable (default `purge_old_audit_logs`) and the
 * retention-day window is passed so a deployment can tighten it.
 */
export class PostgresAuditLogPurgePort implements AuditLogPurgePort {
  private readonly sql: Sql;
  private readonly functionName: string;
  private readonly retentionDays: number;

  constructor(options: { readonly sql: Sql; readonly functionName?: string; readonly retentionDays?: number }) {
    this.sql = options.sql;
    this.functionName = options.functionName ?? "purge_old_audit_logs";
    this.retentionDays = options.retentionDays ?? DEFAULT_RETENTION_POLICY.vaultAuditLogRetentionDays;
  }

  async purgeExpired(asOf: Date): Promise<number> {
    // Call the SECURITY-DEFINER function. `${this.sql(name)}` safely quotes the
    // identifier. The function returns the count of purged rows. A missing
    // function surfaces as a Postgres "function does not exist" error — caught
    // by the worker's per-class isolation, reported via onError, NEVER silently
    // swallowed and NEVER replaced by a raw DELETE.
    const rows = await this.sql<{ purged: number | string }[]>`
      SELECT ${this.sql(this.functionName)}(${asOf}, ${this.retentionDays}) AS purged
    `;
    const raw = rows[0]?.purged;
    return typeof raw === "string" ? Number.parseInt(raw, 10) || 0 : raw ?? 0;
  }
}

/**
 * Production `ExpiringRowPurgePort` — a plain `DELETE … WHERE <expiryColumn> <= asOf`
 * against a non-append-only table. Used for webhook metadata (`webhook_deliveries`,
 * `expires_at`) and each ephemeral-auth table (`user_sessions.expires_at`,
 * `idempotency_keys.expires_at`, `nonces.expires_at`, `rate_limit_buckets.reset_at`).
 *
 * The table name + expiry column are injected — NOTHING hardcoded; a deployment
 * composes one port per table (or wraps several in a `CompositeExpiringRowPurge`).
 * Identifiers are quoted via `this.sql(name)`; the cutoff is a bound param.
 */
export class PostgresExpiringRowPurgePort implements ExpiringRowPurgePort {
  private readonly sql: Sql;
  private readonly table: string;
  private readonly expiryColumn: string;

  constructor(options: { readonly sql: Sql; readonly table: string; readonly expiryColumn: string }) {
    this.sql = options.sql;
    this.table = options.table;
    this.expiryColumn = options.expiryColumn;
  }

  async purgeExpired(asOf: Date): Promise<number> {
    const deleted = await this.sql<{ purged: number | string }[]>`
      WITH d AS (
        DELETE FROM ${this.sql(this.table)}
        WHERE ${this.sql(this.expiryColumn)} <= ${asOf}
        RETURNING 1
      )
      SELECT COUNT(*)::int AS purged FROM d
    `;
    const raw = deleted[0]?.purged;
    return typeof raw === "string" ? Number.parseInt(raw, 10) || 0 : raw ?? 0;
  }
}

/**
 * Fan a single `purgeExpired(asOf)` across several `ExpiringRowPurgePort`s,
 * summing the counts. Used to drive the four ephemeral-auth tables under one
 * port (sessions / idempotency / nonces / buckets). A per-port failure aborts
 * the composite (the worker's class isolation catches it) so a partial sweep is
 * never silently reported as complete.
 */
export class CompositeExpiringRowPurge implements ExpiringRowPurgePort {
  private readonly ports: readonly ExpiringRowPurgePort[];

  constructor(ports: readonly ExpiringRowPurgePort[]) {
    this.ports = ports;
  }

  async purgeExpired(asOf: Date): Promise<number> {
    let total = 0;
    for (const port of this.ports) {
      total += await port.purgeExpired(asOf);
    }
    return total;
  }
}
