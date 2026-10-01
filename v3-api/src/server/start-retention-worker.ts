// Boot helper (Phase 3 T4.3) — assembles + lifecycles the GDPR retention worker
// so Wave 5 (composition-root / bin.ts) can wire it without re-deriving the
// construction. This file owns NO retention logic: it is the start/stop seam
// over the already-built `RetentionWorker` (../vault/retention-worker.ts).
//
// INJECTED PORTS (infra-gated, wired at Wave 5 — never constructed here):
//   - `vault` (CealisV3Vault): from T0.3 — drives the vault-ciphertext
//     crypto-shred cascade (`listExpired` → `deleteBlob`).
//   - `sql` (postgres-js `Sql`): from `getDb()` (T0.1) — backs the audit-log
//     SECURITY-DEFINER purge + the webhook/ephemeral plain-DELETE purges. This
//     helper does NOT open a connection: passing the `Sql` client is the
//     composition root's job (Rule 12: no in-process default).
//   - `shredAuthorityResolver`: the PDA-config seam for per-blob shred authority
//     (PLATFORM PRINCIPLE — the worker obeys the PDA, never picks an authority).
//
// Default port construction (overridable for tests): the audit-log purge is
// bound to the `purge_old_audit_logs()` SECURITY-DEFINER function (the ONLY
// legal path past the append-only trigger — see retention-worker.ts), webhook
// metadata to `webhook_deliveries.expires_at`, and the four ephemeral-auth
// tables to a composite plain-DELETE purge. Every table name + column is
// explicit, NOTHING hardcoded into the worker itself.
//
// V3 isolation (SECURITY.md + R2x grep gate): no `@cealis/shared`,
// no `../../packages/*` (V1), no V1 env-var names (the sealed-share /
// issuer-salt / committee-key family — see SECURITY.md). Table names below are
// the V3 namespace (cealis_v3_dev) — NOT V1's `cealis_dev`.

import type { Sql } from "postgres";

import type { CealisV3Vault } from "../vault/cealis-v3-vault.js";
import {
  CompositeExpiringRowPurge,
  PostgresAuditLogPurgePort,
  PostgresExpiringRowPurgePort,
  RetentionWorker,
  type AuditLogPurgePort,
  type ExpiringRowPurgePort,
  type RetentionClass,
  type RetentionPolicy,
  type RetentionSweepResult,
  type ShredAuthorityResolver,
} from "../vault/retention-worker.js";

/**
 * Configuration for the retention worker service. The vault + DB client +
 * PDA-config resolver are INJECTED — this helper builds no infrastructure of
 * its own; it only composes the default purge ports over the injected `Sql`.
 */
export interface RetentionWorkerServiceConfig {
  /** The opaque-ciphertext vault (T0.3). */
  readonly vault: CealisV3Vault;
  /** postgres-js client over the V3 DB (T0.1) — backs every SQL-side purge. */
  readonly sql: Sql;
  /** PDA-config seam for per-blob shred authority. */
  readonly shredAuthorityResolver: ShredAuthorityResolver;
  /** Retention policy (periods + cadences) — PDA / env-sourced. Defaults to D3. */
  readonly policy?: RetentionPolicy;
  /** Wall-clock source (injectable for deterministic tests). */
  readonly now?: () => Date;
  /** Per-class error sink (a sweep failure is surfaced here, never thrown). */
  readonly onError?: (retentionClass: RetentionClass, error: unknown) => void;
  /** Per-class completion sink (observability). */
  readonly onSweep?: (result: RetentionSweepResult) => void;
  /**
   * Override the audit-log purge port. When absent, a
   * `PostgresAuditLogPurgePort` over `purge_old_audit_logs()` is built. Tests
   * inject a fake to avoid provisioning the SECURITY-DEFINER function.
   */
  readonly auditLogPurge?: AuditLogPurgePort;
  /** Override the webhook-metadata purge port (defaults to `webhook_deliveries.expires_at`). */
  readonly webhookMetadataPurge?: ExpiringRowPurgePort;
  /** Override the ephemeral-auth purge port (defaults to the 4-table composite). */
  readonly ephemeralAuthPurge?: ExpiringRowPurgePort;
}

/**
 * The running retention worker service. Wave 5 keeps the handle to call
 * `stop()` on graceful shutdown (SIGTERM). `started` is observable so the
 * composition root can assert boot completed before flipping readiness.
 */
export interface RetentionWorkerService {
  /** The live worker (exposed for observability / tests). */
  readonly worker: RetentionWorker;
  /** True once `start()` has run. */
  readonly started: boolean;
  /** Graceful shutdown — clears the sweep timers. Idempotent. */
  stop(): Promise<void>;
}

/**
 * The four ephemeral-auth tables + their expiry columns. Each is swept on the
 * hourly cadence. Explicit list — NOTHING hardcoded into the worker; the seam
 * is composed here so a deployment can add/remove a table without touching the
 * worker.
 */
const EPHEMERAL_AUTH_TABLES: ReadonlyArray<{ readonly table: string; readonly expiryColumn: string }> = [
  { table: "user_sessions", expiryColumn: "expires_at" }, // 7-day session TTL
  { table: "idempotency_keys", expiryColumn: "expires_at" }, // retryable-op dedup TTL
  { table: "nonces", expiryColumn: "expires_at" }, // HMAC replay window
  { table: "rate_limit_buckets", expiryColumn: "reset_at" }, // fixed-window buckets
];

/**
 * Construct + start the retention worker service.
 *
 * Construction order:
 *   1. Build the default purge ports over the injected `Sql` (unless overridden):
 *      audit-log → `purge_old_audit_logs()` SECURITY-DEFINER function; webhook
 *      metadata → `webhook_deliveries.expires_at`; ephemeral → composite over
 *      the four short-TTL tables.
 *   2. Construct the `RetentionWorker` with the vault + ports + policy.
 *   3. `start()` it (arms the per-class timers + runs an eager first sweep).
 *
 * The worker begins sweeping immediately; `started` flips true once armed.
 */
export function startRetentionWorkerService(
  config: RetentionWorkerServiceConfig,
): RetentionWorkerService {
  const auditLogPurge =
    config.auditLogPurge ??
    new PostgresAuditLogPurgePort({
      sql: config.sql,
      retentionDays: config.policy?.vaultAuditLogRetentionDays,
    });

  const webhookMetadataPurge =
    config.webhookMetadataPurge ??
    new PostgresExpiringRowPurgePort({
      sql: config.sql,
      table: "webhook_deliveries",
      expiryColumn: "expires_at",
    });

  const ephemeralAuthPurge =
    config.ephemeralAuthPurge ??
    new CompositeExpiringRowPurge(
      EPHEMERAL_AUTH_TABLES.map(
        ({ table, expiryColumn }) =>
          new PostgresExpiringRowPurgePort({ sql: config.sql, table, expiryColumn }),
      ),
    );

  const worker = new RetentionWorker({
    vault: config.vault,
    shredAuthorityResolver: config.shredAuthorityResolver,
    auditLogPurge,
    webhookMetadataPurge,
    ephemeralAuthPurge,
    policy: config.policy,
    now: config.now,
    onError: config.onError,
    onSweep: config.onSweep,
  });

  worker.start();

  let stopped = false;
  return {
    worker,
    started: true,
    async stop(): Promise<void> {
      if (stopped) return;
      stopped = true;
      await worker.stop();
    },
  };
}
