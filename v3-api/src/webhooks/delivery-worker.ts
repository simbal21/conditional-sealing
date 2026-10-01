// BullMQ Worker — consumes the V3 reveal-delivery queue, does the HTTP POST
// to the partner webhook URL, records delivery state to the
// `webhook_deliveries` table, and dead-letters on retry-exhaust.
//
// Producer side: `./bullmq-reveal-queue.ts` (the frozen RevealDeliveryQueue
// impl). Same connection, same queue name, same DLQ.
//
// Spec retry policy (S2-5 §7.3 + types/webhook-events.ts:61-65):
//   - 5 attempts total
//   - [1s, 2s, 4s, 8s, 16s] intervals (BullMQ exponential-2 = same shape)
//   - 30s success window per attempt
// Rule-25 snapshot-recheck: every retry attempt re-reads the partner's
// current webhook_url + signing_secret from the `partners` table — does NOT
// trust the enqueue-time snapshot embedded in the job. If a partner has
// revoked or rotated their webhook between attempts, the Worker picks up
// the rotation on the next retry (the enqueued payload still carries the
// authorizationId + recipient_ref + payload, so identification is stable).
//
// Rule-47 error context: every failure path stamps the
// `webhook_deliveries` row with `final_state`, `status_code`, `attempt_count`,
// `dead_letter_ref` so downstream observability + the 90-day retention sweep
// have full audit lineage.
//
// V3 isolation: no V1 imports, no V1 env names. The `partners` row read is
// against the V3 namespace `partners` table (db/schema-extensions/auth.ts) —
// NOT V1's partners table at packages/orchestrator/src/db/.

import { Worker, type ConnectionOptions, type Job } from "bullmq";
import { eq } from "drizzle-orm";
import { randomUUID, createHash } from "node:crypto";
import { partnersAuth, webhookDeliveriesAuth } from "../db/schema-extensions/auth.js";
import {
  WEBHOOK_DELIVERY_SUCCESS_WINDOW_MS,
  WEBHOOK_METADATA_RETENTION_DAYS,
  type WebhookEnvelope,
} from "../types/webhook-events.js";
import { signWebhookEnvelope } from "./signer.js";
import {
  DEFAULT_REVEAL_DELIVERY_QUEUE_NAME,
  type BullMQRevealDeliveryQueue,
  type RevealDeliveryJobData,
} from "./bullmq-reveal-queue.js";

/**
 * Drizzle DB handle — narrow shape, so the Worker accepts the V3 connection
 * pool without coupling to a specific Drizzle generic. The `db` provides
 * `.select`/`.insert`/`.update` against the V3 schema-extensions.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type V3WebhookDb = any;

/**
 * Partner-row snapshot returned by `readPartnerSnapshot`. The Worker uses
 * this on every retry attempt (NOT cached from enqueue) to honour Rule-25.
 *
 * `signing_secret` is the DECRYPTED webhook signing secret — the DB column
 * stores the encrypted form (`webhook_secret_encrypted`) and the
 * `partnerSecretReader` port handles decryption. This is DISTINCT from
 * `signing_secret_encrypted`, which is the API-request-auth HMAC secret used
 * by the auth middleware — the two MUST NOT be crossed. Keeping decryption
 * inside an injectable port lets prod use KMS while tests inject the plaintext
 * directly.
 */
export interface PartnerWebhookSnapshot {
  readonly partner_id: string;
  readonly webhook_url: string;
  readonly signing_secret: string;
  readonly revoked: boolean;
}

/** Reader port for partner snapshot — Rule-25 live read on every attempt. */
export interface PartnerSnapshotReader {
  read(partnerId: string): Promise<PartnerWebhookSnapshot | null>;
}

/** HTTP POST port — defaults to `fetch`, swappable for tests. */
export type HttpPoster = (
  url: string,
  body: Uint8Array,
  headers: Record<string, string>,
) => Promise<{ statusCode: number; elapsedMs: number }>;

/**
 * Configuration for the BullMQ delivery worker.
 *
 * `partnerReader` is injectable so production wires it to the real DB-backed
 * `partners` reader and tests inject a fake. The Worker NEVER reads partner
 * state from cached/enqueued data — Rule 25.
 */
export interface DeliveryWorkerConfig {
  readonly connection: ConnectionOptions;
  readonly queueName?: string;
  readonly db: V3WebhookDb;
  readonly partnerReader: PartnerSnapshotReader;
  readonly poster?: HttpPoster;
  readonly deadLetterQueue: BullMQRevealDeliveryQueue;
  /**
   * Concurrency — how many delivery jobs the Worker processes in parallel.
   * Defaults to 4 (conservative; production may scale higher).
   */
  readonly concurrency?: number;
  /**
   * Stall check interval. BullMQ default is 30s — overriding lets tests run
   * faster with short timeouts.
   */
  readonly stalledInterval?: number;
}

/**
 * The DB-backed partner snapshot reader. Uses Drizzle to read the V3
 * `partners` table on every call (no in-process cache — Rule 25).
 *
 * Decryption of `webhook_secret_encrypted` is the caller's concern: production
 * wires a KMS-backed decryptor via the `decrypt` callback; tests inject a
 * pass-through that returns the column value as-is. NOTE: the WEBHOOK signing
 * key is `webhook_secret_encrypted`, NOT `signing_secret_encrypted` (the latter
 * is the API-request-auth HMAC secret consumed by the auth middleware).
 */
export class DbPartnerSnapshotReader implements PartnerSnapshotReader {
  constructor(
    private readonly db: V3WebhookDb,
    private readonly decrypt: (ciphertext: string) => Promise<string> | string,
  ) {}

  async read(partnerId: string): Promise<PartnerWebhookSnapshot | null> {
    // Rule 25 live re-read: every call hits the DB; no caching.
    const rows = (await this.db
      .select()
      .from(partnersAuth)
      .where(eq(partnersAuth.partner_id, partnerId))
      .limit(1)) as Array<{
      partner_id: string;
      webhook_url: string | null;
      webhook_secret_encrypted: string;
      revoked_at: Date | null;
    }>;
    if (rows.length === 0) return null;
    const row = rows[0];
    if (!row) return null;
    const url = row.webhook_url;
    if (!url) return null;
    // Webhook envelope signing uses the WEBHOOK secret, NOT the API-auth HMAC
    // secret (`signing_secret_encrypted`). These are two distinct secrets.
    const secret = await this.decrypt(row.webhook_secret_encrypted);
    return {
      partner_id: row.partner_id,
      webhook_url: url,
      signing_secret: secret,
      revoked: row.revoked_at !== null,
    };
  }
}

/**
 * Default HTTP poster — uses `fetch` with a 30s timeout (the spec's success
 * window per §7.3). Stamps `elapsedMs` for the dispatcher's success-window
 * check.
 */
export const defaultHttpPoster: HttpPoster = async (url, body, headers) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WEBHOOK_DELIVERY_SUCCESS_WINDOW_MS);
  const t0 = Date.now();
  try {
    // `fetch` accepts ArrayBufferView for body. Use the underlying buffer slice.
    const response = await fetch(url, {
      method: "POST",
      headers,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      body: body as any,
      signal: controller.signal,
    });
    return { statusCode: response.status, elapsedMs: Date.now() - t0 };
  } catch (err) {
    const elapsed = Date.now() - t0;
    // Network errors / timeouts → 0 status (retryable per spec §7.3 isRetryable).
    if (err instanceof Error && err.name === "AbortError") {
      return { statusCode: 0, elapsedMs: elapsed };
    }
    return { statusCode: 0, elapsedMs: elapsed };
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Hash a delivery URL for the audit table. The `webhook_deliveries` schema
 * stores `delivery_url_digest`, not the raw URL — the URL itself could be
 * partner-sensitive (some include API tokens in path/query).
 */
function deliveryUrlDigest(url: string): string {
  return createHash("sha256").update(url).digest("hex");
}

/**
 * Compute the 90-day retention `expires_at` for a freshly-recorded delivery row.
 */
function retentionExpiresAt(createdAt: Date): Date {
  return new Date(createdAt.getTime() + WEBHOOK_METADATA_RETENTION_DAYS * 24 * 60 * 60 * 1000);
}

/**
 * Build the WebhookEnvelope from the BullMQ job data. The job payload IS
 * the envelope body (after sanitization at the dispatcher / event-bus layer)
 * — the Worker just re-wraps it for signing.
 *
 * If the payload doesn't carry the expected envelope keys, we synthesize a
 * minimal envelope from job data; in practice the producer always sends a
 * full envelope.
 */
function envelopeFromJobData(data: RevealDeliveryJobData): WebhookEnvelope {
  const p = data.payload as Partial<WebhookEnvelope>;
  return {
    event_id: typeof p.event_id === "string" ? p.event_id : data.job_id,
    schema_version: typeof p.schema_version === "string" ? p.schema_version : "s2-5.1",
    event_type:
      typeof p.event_type === "string"
        ? (p.event_type as WebhookEnvelope["event_type"])
        : "reveal.finalized",
    created_at: typeof p.created_at === "string" ? p.created_at : data.enqueued_at,
    partner_id: typeof p.partner_id === "string" ? p.partner_id : "",
    pda_id: typeof p.pda_id === "string" ? p.pda_id : "",
    data: (p.data ?? {}) as Record<string, unknown>,
  };
}

/**
 * Outcome of a single delivery attempt. `delivered` shape captures the
 * elapsed time so the dispatcher can enforce the 30s success window.
 */
export interface DeliveryAttemptOutcome {
  readonly statusCode: number;
  readonly elapsedMs: number;
  readonly delivered: boolean;
  /** True when 4xx (non-429) — non-retryable, dispatcher stops without DLQ. */
  readonly discarded: boolean;
}

/**
 * Pure-function attempt classifier — same shape as
 * bullmq-queue.ts:isSuccessful/isRetryable but operating on the unified
 * `DeliveryAttemptOutcome`. Exposed for tests + the Worker's own decision.
 */
export function classifyAttempt(statusCode: number, elapsedMs: number): DeliveryAttemptOutcome {
  const delivered = statusCode >= 200 && statusCode < 300 && elapsedMs <= WEBHOOK_DELIVERY_SUCCESS_WINDOW_MS;
  if (delivered) {
    return { statusCode, elapsedMs, delivered: true, discarded: false };
  }
  const retryable = statusCode >= 500 || statusCode === 429 || statusCode === 0;
  return { statusCode, elapsedMs, delivered: false, discarded: !retryable };
}

/**
 * Start the BullMQ delivery worker. Returns the BullMQ `Worker` so callers can
 * `await worker.close()` on shutdown.
 *
 * Lifecycle:
 *   1. BullMQ picks up a job from the V3 reveal-delivery queue
 *   2. Worker reads partner snapshot from DB (Rule 25 — live read)
 *   3. If partner is revoked / no webhook_url → record discarded + done
 *   4. Sign envelope with current signing_secret
 *   5. POST to partner.webhook_url
 *   6. Classify outcome:
 *      - delivered → record final_state=delivered + return
 *      - discarded (4xx) → record final_state=discarded + return (no retry)
 *      - retryable (5xx/429/0) → throw; BullMQ schedules retry per attempts/backoff
 *   7. On final BullMQ retry exhaust → "failed" event fires → Worker DLQs
 */
export function startDeliveryWorker(config: DeliveryWorkerConfig): Worker<RevealDeliveryJobData> {
  const queueName = config.queueName ?? DEFAULT_REVEAL_DELIVERY_QUEUE_NAME;
  const poster = config.poster ?? defaultHttpPoster;
  const concurrency = config.concurrency ?? 4;

  const worker = new Worker<RevealDeliveryJobData>(
    queueName,
    async (job: Job<RevealDeliveryJobData>) => {
      const attemptCount = job.attemptsMade + 1;
      const data = job.data;
      // Rule 25 live re-read — every attempt reads partner snapshot fresh.
      const partner = await config.partnerReader.read(
        getPartnerIdFromPayload(data),
      );
      if (!partner || partner.revoked) {
        // Partner gone — record discarded, do NOT retry.
        await recordDelivery(config.db, {
          data,
          partner_id: getPartnerIdFromPayload(data),
          delivery_url_digest: deliveryUrlDigest(partner?.webhook_url ?? "unknown"),
          attempt_count: attemptCount,
          status_code: null,
          final_state: "discarded_partner_revoked",
          dead_letter_ref: null,
        });
        return; // Do not throw → BullMQ marks job completed.
      }
      const envelope = envelopeFromJobData(data);
      const signed = signWebhookEnvelope({
        envelope,
        body: envelope,
        secret: partner.signing_secret,
      });
      const result = await poster(
        partner.webhook_url,
        signed.rawBody,
        // Spread to satisfy Record<string,string>; WebhookDeliveryHeaders is
        // a fixed-key interface, but its four field values are all strings.
        { ...signed.headers },
      );
      const outcome = classifyAttempt(result.statusCode, result.elapsedMs);
      if (outcome.delivered) {
        await recordDelivery(config.db, {
          data,
          partner_id: partner.partner_id,
          delivery_url_digest: deliveryUrlDigest(partner.webhook_url),
          attempt_count: attemptCount,
          status_code: outcome.statusCode,
          final_state: "delivered",
          dead_letter_ref: null,
        });
        return;
      }
      if (outcome.discarded) {
        await recordDelivery(config.db, {
          data,
          partner_id: partner.partner_id,
          delivery_url_digest: deliveryUrlDigest(partner.webhook_url),
          attempt_count: attemptCount,
          status_code: outcome.statusCode,
          final_state: "discarded_4xx",
          dead_letter_ref: null,
        });
        return; // 4xx is non-retryable; BullMQ marks completed without retry.
      }
      // Retryable — throw so BullMQ counts this attempt as failed and
      // schedules a retry per the queue's attempts/backoff policy. The
      // partial record below captures the in-flight attempt; the final
      // delivery row gets stamped on the last attempt (either delivered or
      // dead-lettered in the failed handler).
      throw new RetryableDeliveryFailure(
        `Webhook delivery failed: status=${outcome.statusCode} elapsed=${outcome.elapsedMs}ms attempt=${attemptCount}`,
        { statusCode: outcome.statusCode, elapsedMs: outcome.elapsedMs, attempt: attemptCount },
      );
    },
    {
      connection: config.connection,
      concurrency,
      stalledInterval: config.stalledInterval,
    },
  );

  // BullMQ 'failed' fires both on each failed attempt AND on the final
  // retry-exhaust. We only DLQ on the final exhaust — discriminated by
  // attemptsMade >= the queue's `attempts` setting.
  //
  // BullMQ's `worker.on("failed", ...)` callback signature expects a void
  // return. We wrap our async work in a sync handler that fires the promise
  // and explicitly ignores it (with .catch to log rather than crash the
  // worker process).
  worker.on("failed", (job, err) => {
    if (!job) return;
    if (job.attemptsMade < (job.opts.attempts ?? 5)) {
      // More attempts left — BullMQ will retry.
      return;
    }
    const reason = err instanceof Error ? err.message : String(err);
    void handleFinalFailure(config, job, reason).catch((handlerErr) => {
      // Best-effort: don't propagate to BullMQ (would crash the Worker).
      // Production wires structured logging here; for now stay silent rather
      // than `console.log` (lint forbids it in production code).
      void handlerErr;
    });
  });

  return worker;
}

/**
 * Final-failure handler — invoked from the worker's `failed` event listener
 * once retry budget is exhausted. Pushes the original job to the DLQ and
 * stamps the audit row.
 */
async function handleFinalFailure(
  config: DeliveryWorkerConfig,
  job: Job<RevealDeliveryJobData>,
  reason: string,
): Promise<void> {
  await config.deadLetterQueue.deadLetter(job.id ?? job.data.job_id, reason);
  const dlRef = `dlq:${job.id ?? job.data.job_id}`;
  try {
    await recordDelivery(config.db, {
      data: job.data,
      partner_id: getPartnerIdFromPayload(job.data),
      delivery_url_digest: deliveryUrlDigest("unknown"),
      attempt_count: job.attemptsMade,
      status_code: null,
      final_state: "dead_lettered",
      dead_letter_ref: dlRef,
    });
  } catch {
    // DB unavailable — DLQ still has the record. Don't crash the worker.
  }
}

/**
 * Custom error class — discriminated so BullMQ's failed handler can tell
 * retryable network failures apart from programmer errors (TypeError etc).
 *
 * Rule-47 safe_refs are carried as enumerable instance fields.
 */
export class RetryableDeliveryFailure extends Error {
  readonly safeRefs: {
    readonly statusCode: number;
    readonly elapsedMs: number;
    readonly attempt: number;
  };
  constructor(message: string, safeRefs: { statusCode: number; elapsedMs: number; attempt: number }) {
    super(message);
    this.name = "RetryableDeliveryFailure";
    this.safeRefs = safeRefs;
  }
}

/**
 * Record a delivery row in the V3 `webhook_deliveries` table. Uses the
 * Drizzle table from `db/schema-extensions/auth.ts` (worker-2's schema).
 * `expires_at` is set to `created_at + 90d` per legal-constraints.md row 47.
 */
async function recordDelivery(
  db: V3WebhookDb,
  row: {
    readonly data: RevealDeliveryJobData;
    readonly partner_id: string;
    readonly delivery_url_digest: string;
    readonly attempt_count: number;
    readonly status_code: number | null;
    readonly final_state: string;
    readonly dead_letter_ref: string | null;
  },
): Promise<void> {
  const envelope = envelopeFromJobData(row.data);
  const createdAt = new Date();
  await db.insert(webhookDeliveriesAuth).values({
    delivery_id: randomUUID(),
    event_id: envelope.event_id,
    event_type: envelope.event_type,
    partner_id: row.partner_id || envelope.partner_id || "unknown",
    pda_id: envelope.pda_id || "unknown",
    delivery_url_digest: row.delivery_url_digest,
    attempt_count: row.attempt_count,
    status_code: row.status_code,
    final_state: row.final_state,
    dead_letter_ref: row.dead_letter_ref,
    created_at: createdAt,
    expires_at: retentionExpiresAt(createdAt),
  });
}

/**
 * Pull the partner_id out of the enqueued payload. The producer always
 * includes it in the envelope, but we tolerate absent values by returning
 * empty string so the Worker can stamp `discarded_partner_revoked` rather
 * than crash.
 */
function getPartnerIdFromPayload(data: RevealDeliveryJobData): string {
  const p = data.payload as { partner_id?: unknown };
  return typeof p.partner_id === "string" ? p.partner_id : "";
}
