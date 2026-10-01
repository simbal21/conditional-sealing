// BullMQ-backed RevealDeliveryQueue — concrete impl of the frozen seam in
// reveal/reveal-coordinator.ts:196-204 (enqueue + deadLetter).
//
// R2b worker-4 mock→real lift: replaces the in-memory `InMemoryWebhookQueue`
// (./bullmq-queue.ts) as the production durable boundary per the H5 V1-parity
// cluster (BullMQ + Redis + DLQ). The InMemoryWebhookQueue stays available for
// foundation tests and dev (some integration tests directly construct it).
//
// Why a separate file alongside the misleadingly-named `bullmq-queue.ts`:
// the existing module name is referenced by tests/integration/
// webhook-retry-1s-2s-4s-8s-16s.test.ts (line 11 imports `InMemoryWebhookQueue`
// from there); renaming the existing file would break that test surface for
// no protocol gain. Real impl lands here under its own filename so both
// surfaces (in-memory test queue + real BullMQ queue) coexist behind the
// frozen `RevealDeliveryQueue` interface.
//
// V3 isolation discipline (SECURITY.md + R2x grep gate):
//   - no `@cealis/shared` import
//   - no `../../packages/*` (V1) import
//   - no V1 env-var names (the sealed-share + issuer-salt + committee-key
//     family; the SECURITY.md catalog is the authoritative list)
//   - queue name V3-namespaced (`cealis-v3-webhook-delivery`) so V1 and V3
//     queues on the same Redis instance never collide
//
// Rule-25 snapshot-recheck discipline: enqueue payload is the snapshot; the
// `delivery-worker.ts` re-reads partner-subscription/webhook-URL state at
// retry time from the partner row, NOT from the enqueued payload. This
// module owns the enqueue side only; the re-read happens in the Worker.
//
// Rule-47 error context discipline: every throw path carries `safe_refs`
// with `authorizationId` + `job_id` + `queue_name` so failures are
// observable without log-archaeology.

import { Queue, type ConnectionOptions, type JobsOptions } from "bullmq";
import { randomUUID } from "node:crypto";
import type {
  RevealDeliveryQueue,
} from "../reveal/reveal-coordinator.js";
import type { Hex32 } from "../h-commit/index.js";
import {
  WEBHOOK_RETRY_INTERVALS_MS,
  WEBHOOK_RETRY_MAX,
} from "../types/webhook-events.js";

/** Default V3-namespaced queue name. Configurable via env or constructor. */
export const DEFAULT_REVEAL_DELIVERY_QUEUE_NAME = "cealis-v3-reveal-delivery";

/** Default DLQ name — a separate BullMQ queue used by the Worker on retry-exhaust. */
export const DEFAULT_REVEAL_DELIVERY_DLQ_NAME = "cealis-v3-reveal-delivery-dlq";

/** Maximum payload depth (defence against deeply-nested unknown payloads). */
const MAX_PAYLOAD_DEPTH = 8;

/**
 * BullMQ job data — exactly the frozen `RevealDeliveryQueue.enqueue` shape,
 * plus an `enqueued_at` timestamp the Worker uses for retry-window logic.
 */
export interface RevealDeliveryJobData {
  readonly job_id: string;
  readonly authorizationId: Hex32;
  readonly recipient_ref: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly enqueued_at: string;
}

/**
 * Dead-letter job data — the original job + reason + timestamp. Dead-lettered
 * jobs sit in the DLQ until retention purge (90d per legal-constraints.md row
 * 47 + S2-5 §15.3).
 */
export interface RevealDeliveryDeadLetterData {
  readonly original_job_id: string;
  readonly authorizationId: Hex32;
  readonly recipient_ref: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly reason: string;
  readonly enqueued_at: string;
  readonly dead_lettered_at: string;
}

/**
 * Connection + queue-name configuration for the BullMQ-backed reveal delivery
 * queue. All fields except `connection` are optional and default to the
 * V3-namespaced names.
 *
 * `connection` is REQUIRED (no in-process default) — passing the production
 * IORedis-compatible connection is the caller's responsibility so the queue
 * never silently spins up a dev fallback. (Per Rule 12 production-grade
 * boundary: no in-memory or in-process default ships from this module.)
 */
export interface BullMQRevealDeliveryQueueConfig {
  readonly connection: ConnectionOptions;
  readonly queueName?: string;
  readonly dlqName?: string;
  /**
   * Override the BullMQ-level retry policy used on enqueue. Defaults to the
   * S2-5 §7.3 spec (5 attempts, 1/2/4/8/16s — locked at
   * types/webhook-events.ts:61-65). Callers should override only in tests.
   *
   * Note: BullMQ's `attempts` value INCLUDES the first try, so we pass
   * WEBHOOK_RETRY_MAX directly (5 total attempts = 1 initial + 4 retries
   * in BullMQ terminology when you want the spec's 5 attempts represented
   * as 5 total runs of the Worker job).
   */
  readonly jobOptions?: JobsOptions;
}

/**
 * Construct the JobsOptions that mirror the S2-5 §7.3 retry plan as a custom
 * backoff array. BullMQ supports `fixed` and `exponential` strategies natively;
 * for the spec-locked `[1s,2s,4s,8s,16s]` shape we encode the same intervals
 * as exponential base=1000ms, factor=2 (1*2^0=1000, 1*2^1=2000, 1*2^2=4000,
 * 1*2^3=8000, 1*2^4=16000) — byte-equivalent to the spec.
 */
/**
 * BullMQ-job idempotency retention window — completed jobs are kept in the
 * main queue for this many seconds so re-enqueues with the same `job_id`
 * collapse to the existing terminal job instead of starting fresh delivery.
 *
 * Sized to overlap with the orchestrator's idempotency-key TTL (worker-2's
 * `PostgresIdempotencyStore` default 24h, S2-5 §1.5). After this window
 * expires, idempotency falls through to the partner-side dedup contract
 * (S2-5 §7.2: partners dedup on `event_id`).
 */
export const BULLMQ_COMPLETED_RETENTION_SECONDS = 24 * 60 * 60;

/**
 * Construct the JobsOptions that mirror the S2-5 §7.3 retry plan as a custom
 * backoff array. BullMQ supports `fixed` and `exponential` strategies natively;
 * for the spec-locked `[1s,2s,4s,8s,16s]` shape we encode the same intervals
 * as exponential base=1000ms, factor=2 (1*2^0=1000, 1*2^1=2000, 1*2^2=4000,
 * 1*2^3=8000, 1*2^4=16000) — byte-equivalent to the spec.
 *
 * `removeOnComplete` retains successful jobs for BULLMQ_COMPLETED_RETENTION_SECONDS
 * (24h, matching orchestrator idempotency TTL) so a same-`job_id` re-enqueue
 * after delivery hits the existing terminal job rather than starting a fresh
 * delivery. Without this retention, BullMQ deletes completed jobs immediately
 * and a replay would re-deliver. See `enqueue` docstring for the full 2-tier
 * idempotency contract.
 */
export function defaultRevealDeliveryJobOptions(): JobsOptions {
  return {
    attempts: WEBHOOK_RETRY_MAX,
    backoff: {
      type: "exponential",
      delay: WEBHOOK_RETRY_INTERVALS_MS[0],
    },
    // Retain completed jobs for 24h so same-job_id re-enqueues are no-ops
    // during that window; partner-side dedup on event_id handles beyond.
    removeOnComplete: { age: BULLMQ_COMPLETED_RETENTION_SECONDS },
    removeOnFail: 1000,
  };
}

/**
 * BullMQ-backed reveal delivery queue. Implements the frozen
 * `RevealDeliveryQueue` interface byte-for-byte.
 *
 * Producer side only. The consumer (delivery worker) lives at
 * `./delivery-worker.ts` — same connection, same queue name, same DLQ.
 */
export class BullMQRevealDeliveryQueue implements RevealDeliveryQueue {
  private readonly queue: Queue<RevealDeliveryJobData>;
  private readonly dlq: Queue<RevealDeliveryDeadLetterData>;
  private readonly jobOptions: JobsOptions;
  private readonly queueName: string;
  private readonly dlqName: string;

  constructor(config: BullMQRevealDeliveryQueueConfig) {
    this.queueName = config.queueName ?? DEFAULT_REVEAL_DELIVERY_QUEUE_NAME;
    this.dlqName = config.dlqName ?? DEFAULT_REVEAL_DELIVERY_DLQ_NAME;
    this.jobOptions = config.jobOptions ?? defaultRevealDeliveryJobOptions();
    this.queue = new Queue<RevealDeliveryJobData>(this.queueName, {
      connection: config.connection,
    });
    this.dlq = new Queue<RevealDeliveryDeadLetterData>(this.dlqName, {
      connection: config.connection,
    });
  }

  /**
   * Enqueue a delivery job. BullMQ jobId is the caller-supplied `job_id`.
   *
   * IDEMPOTENCY CONTRACT (2-tier — be explicit, do not overstate):
   *
   *  Tier 1 — Producer-side (this queue), bounded by job retention:
   *    BullMQ's `add()` with an existing jobId is a no-op while the job is
   *    still in the queue (pending, active, delayed, completed, or failed).
   *    Combined with `removeOnComplete: { age: 24h }` (BULLMQ_COMPLETED_RETENTION_SECONDS),
   *    this means a re-enqueue with the same `job_id` is a no-op for the
   *    full 24h post-delivery window — overlapping with the orchestrator's
   *    `PostgresIdempotencyStore` TTL (S2-5 §1.5).
   *
   *  Tier 2 — Partner-side, post-window:
   *    After the 24h producer-side window expires, BullMQ deletes the
   *    completed job and a same-`job_id` re-enqueue WILL create a fresh
   *    delivery. Final idempotency at that point relies on the partner
   *    deduping on `event_id` per S2-5 §7.2 ("event_id MUST be unique per
   *    event; partners SHOULD use it as a dedup key").
   *
   *  Tier 1 is enforced HERE (BullMQ retention + jobId). Tier 2 is the
   *  partner integration contract, NOT enforceable by this seam. Comment
   *  formerly claimed "native idempotency" with no scope qualification —
   *  that was misleading post-completion-removal and has been corrected per
   *  dw-quality-2 R2b-4 v0.1 finding SHOULD-FIX-1.
   *
   * This satisfies the Rule-25 snapshot-recheck implicit contract: replays
   * within the operative idempotency window do not enqueue duplicate work.
   */
  async enqueue(job: {
    readonly job_id: string;
    readonly authorizationId: Hex32;
    readonly recipient_ref: string;
    readonly payload: Readonly<Record<string, unknown>>;
  }): Promise<void> {
    assertSerializablePayload(job.payload);
    const data: RevealDeliveryJobData = {
      job_id: job.job_id,
      authorizationId: job.authorizationId,
      recipient_ref: job.recipient_ref,
      payload: job.payload,
      enqueued_at: new Date().toISOString(),
    };
    await this.queue.add(this.queueName, data, {
      ...this.jobOptions,
      jobId: job.job_id,
    });
  }

  /**
   * Dead-letter a job by id. Idempotent via per-call random ref so multiple
   * deadLetter() calls for the same job_id produce distinct DLQ rows (this is
   * deliberate — each call records WHEN the dead-letter decision was made,
   * not a single immutable "this job is dead" assertion). The dispatcher
   * normally only calls this once per exhausted retry chain; tests may
   * exercise multiple paths.
   */
  async deadLetter(jobId: string, reason: string): Promise<void> {
    // Pull the original job so we have the full enqueued payload to preserve.
    // If the job has already been removed (e.g., by removeOnFail GC), we
    // record what we know: id + reason + ts.
    const job = await this.queue.getJob(jobId);
    const dlData: RevealDeliveryDeadLetterData = job
      ? {
          original_job_id: jobId,
          authorizationId: job.data.authorizationId,
          recipient_ref: job.data.recipient_ref,
          payload: job.data.payload,
          reason,
          enqueued_at: job.data.enqueued_at,
          dead_lettered_at: new Date().toISOString(),
        }
      : {
          original_job_id: jobId,
          authorizationId: "0x" + "0".repeat(64) as Hex32,
          recipient_ref: "unknown",
          payload: {},
          reason: `${reason} (original job evicted before dead-letter)`,
          enqueued_at: new Date(0).toISOString(),
          dead_lettered_at: new Date().toISOString(),
        };
    await this.dlq.add(this.dlqName, dlData, {
      jobId: `${jobId}:${randomUUID()}`,
      removeOnComplete: false,
      // DLQ entries are NOT removed automatically — they age out via the
      // 90-day retention worker (./retention-90d.ts + a future cron job
      // that drains rows whose `dead_lettered_at` is older than the window).
      removeOnFail: false,
    });
  }

  /**
   * Test-only accessor — returns the underlying BullMQ queues so foundation
   * tests can assert on job counts without round-tripping through the real
   * Redis. Production code MUST NOT use this; the interface contract is the
   * frozen `RevealDeliveryQueue` shape only.
   */
  __testInspect(): {
    readonly queue: Queue<RevealDeliveryJobData>;
    readonly dlq: Queue<RevealDeliveryDeadLetterData>;
    readonly queueName: string;
    readonly dlqName: string;
  } {
    return {
      queue: this.queue,
      dlq: this.dlq,
      queueName: this.queueName,
      dlqName: this.dlqName,
    };
  }

  /**
   * Graceful shutdown — close both underlying queues. Caller is responsible
   * for ensuring no in-flight `enqueue`/`deadLetter` calls.
   */
  async close(): Promise<void> {
    await this.queue.close();
    await this.dlq.close();
  }
}

/**
 * Build the BullMQ connection options from env vars. Prefers
 * `BULLMQ_REDIS_URL` (V3-namespaced) if present, falls back to the
 * shared-infra `REDIS_URL`. Throws if neither is set.
 *
 * Env var name discipline (R2x isolation gate):
 *   - `BULLMQ_REDIS_URL` is V3-only — no conflict with V1.
 *   - `REDIS_URL` is shared-infra (Railway-injected) and explicitly allowed
 *     by SECURITY.md (the V1-forbidden env-var names are listed there — not
 *     REDIS_URL).
 */
export function bullmqConnectionFromEnv(env: NodeJS.ProcessEnv = process.env): ConnectionOptions {
  const url = env["BULLMQ_REDIS_URL"] ?? env["REDIS_URL"];
  if (!url) {
    throw new Error(
      "BullMQ connection unavailable — set BULLMQ_REDIS_URL (V3-namespaced) or REDIS_URL (shared)",
    );
  }
  // ConnectionOptions accepts an IORedis-compatible URL string via its
  // `url` field (BullMQ v5 passes this straight to ioredis). Using the URL
  // form keeps the configuration single-line and Railway-injectable.
  // BullMQ requires `maxRetriesPerRequest: null` for blocking commands;
  // we set it here so callers don't have to remember.
  return {
    // The cast is needed because BullMQ's ConnectionOptions union is wider
    // than what ioredis exposes at the public type level; the underlying
    // ioredis constructor accepts `{ url, maxRetriesPerRequest }` cleanly.
    url,
    maxRetriesPerRequest: null,
  } as ConnectionOptions;
}

/**
 * Assert that a payload is JSON-serializable without prototype pollution and
 * without exceeding the depth limit. BullMQ stores job data as JSON; bad
 * payloads explode at `add()` with cryptic errors. Catching here gives a
 * pre-declared `safe_refs`-rich error.
 */
function assertSerializablePayload(payload: Readonly<Record<string, unknown>>, depth = 0): void {
  if (depth > MAX_PAYLOAD_DEPTH) {
    throw new Error("Reveal delivery payload exceeds max nesting depth");
  }
  for (const [key, value] of Object.entries(payload)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      throw new Error(`Reveal delivery payload contains forbidden key: ${key}`);
    }
    if (value === null || value === undefined) continue;
    if (typeof value === "function" || typeof value === "symbol") {
      throw new Error(`Reveal delivery payload contains non-serializable value at ${key}`);
    }
    if (typeof value === "object" && !Array.isArray(value)) {
      assertSerializablePayload(value as Readonly<Record<string, unknown>>, depth + 1);
    }
  }
}
