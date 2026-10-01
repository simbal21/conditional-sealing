// Boot helper (Phase 3 T4.1) — assembles + lifecycles the real BullMQ/Redis
// reveal-delivery queue + worker so Wave 5 (composition-root / bin.ts) can wire
// it without re-deriving the construction. This file owns NO business logic: it
// is the start/stop seam over the two already-built modules:
//   - producer  : ./../webhooks/bullmq-reveal-queue.ts  (BullMQRevealDeliveryQueue)
//   - consumer  : ./../webhooks/delivery-worker.ts       (startDeliveryWorker)
//
// INJECTED PORTS (infra-gated, wired at Wave 5 — never constructed here):
//   - `connection` (BullMQ/Redis `ConnectionOptions`): the caller builds this
//     from `bullmqConnectionFromEnv(process.env)` (BULLMQ_REDIS_URL / REDIS_URL).
//     This boot helper does NOT read env or spin up a dev Redis — passing the
//     connection is the composition root's job (Rule 12: no in-process default).
//   - `db` (V3 Drizzle handle): from `getDb()` (T0.1). The worker writes
//     `webhook_deliveries` rows; the producer never touches the DB.
//   - `partnerSecretDecryptor`: KMS-backed in prod, plaintext pass-through in
//     tests. Decryption stays in an injected port so prod uses KMS without this
//     file importing a key client.
//
// Rule-25 snapshot-recheck lives in the Worker (delivery-worker.ts re-reads the
// partner row per attempt). This helper only constructs the wiring.
//
// V3 isolation (SECURITY.md + R2x grep gate): no `@cealis/shared`
// import, no `../../packages/*` (V1) import, no V1 env-var names (the
// sealed-share / issuer-salt / committee-key family — see SECURITY.md). The
// Redis connection + queue names are V3-namespaced upstream.

import type { ConnectionOptions } from "bullmq";
import type { Worker } from "bullmq";

import {
  BullMQRevealDeliveryQueue,
  type BullMQRevealDeliveryQueueConfig,
  type RevealDeliveryJobData,
} from "../webhooks/bullmq-reveal-queue.js";
import {
  DbPartnerSnapshotReader,
  startDeliveryWorker,
  type HttpPoster,
  type PartnerSnapshotReader,
  type V3WebhookDb,
} from "../webhooks/delivery-worker.js";

/**
 * Decryptor port for the partner webhook signing secret. Production wires a
 * KMS-backed decryptor; tests inject a pass-through that returns the column
 * value as-is. Mirrors `DbPartnerSnapshotReader`'s `decrypt` callback contract.
 */
export type PartnerSecretDecryptor = (ciphertext: string) => Promise<string> | string;

/**
 * Configuration for the reveal-delivery worker service. Every external piece
 * (Redis connection, DB, secret decryptor) is INJECTED — this helper builds no
 * infrastructure of its own.
 */
export interface DeliveryWorkerServiceConfig {
  /** BullMQ/Redis connection (built by the caller from env at Wave 5). */
  readonly connection: ConnectionOptions;
  /** V3 Drizzle DB handle (the Worker stamps `webhook_deliveries`). */
  readonly db: V3WebhookDb;
  /**
   * Decryptor for the partner webhook signing secret. Used to construct the
   * default `DbPartnerSnapshotReader`. Ignored when `partnerReader` is supplied.
   */
  readonly partnerSecretDecryptor?: PartnerSecretDecryptor;
  /**
   * Override the partner-snapshot reader entirely. When absent, a
   * `DbPartnerSnapshotReader(db, partnerSecretDecryptor)` is built. Tests inject
   * a fake reader here; prod relies on the default DB-backed reader.
   */
  readonly partnerReader?: PartnerSnapshotReader;
  /** Override the HTTP poster (defaults to `fetch` inside the Worker). Tests inject a fake. */
  readonly poster?: HttpPoster;
  /** Override the queue name (defaults to the V3-namespaced constant). */
  readonly queueName?: string;
  /** Override the DLQ name (defaults to the V3-namespaced constant). */
  readonly dlqName?: string;
  /** Worker concurrency (defaults to 4 inside the Worker). */
  readonly concurrency?: number;
  /** BullMQ stall-check interval (ms) — tests shorten it. */
  readonly stalledInterval?: number;
  /** Override the queue's BullMQ job options (tests only). */
  readonly jobOptions?: BullMQRevealDeliveryQueueConfig["jobOptions"];
}

/**
 * The running reveal-delivery worker service. Holds the producer queue (which
 * is ALSO the DLQ owner) and the consumer Worker. Wave 5 keeps a handle to call
 * `stop()` on graceful shutdown (SIGTERM) and uses `queue` as the coordinator's
 * `deliveryQueue` port (the enqueue side).
 *
 * `started` is observable so the composition root can assert the boot completed
 * before flipping the readiness probe.
 */
export interface DeliveryWorkerService {
  /** The producer queue — pass this as the coordinator's `deliveryQueue` port. */
  readonly queue: BullMQRevealDeliveryQueue;
  /** The live BullMQ Worker (exposed for observability / tests). */
  readonly worker: Worker<RevealDeliveryJobData>;
  /** True once `start()` has run and both ends are constructed. */
  readonly started: boolean;
  /**
   * Graceful shutdown — closes the Worker first (drains in-flight jobs), then
   * the producer queue + DLQ. Idempotent: a second `stop()` is a no-op.
   */
  stop(): Promise<void>;
}

/**
 * Construct + start the reveal-delivery worker service.
 *
 * Construction order:
 *   1. Build the producer `BullMQRevealDeliveryQueue` (queue + DLQ on the
 *      injected connection). This is BOTH the coordinator's enqueue port AND
 *      the Worker's `deadLetterQueue`.
 *   2. Build the partner-snapshot reader (injected fake, or DB-backed default).
 *   3. Start the consumer Worker bound to the same queue name + connection.
 *
 * The Worker begins consuming immediately on construction (BullMQ semantics);
 * `started` flips true once both ends exist.
 */
export function startDeliveryWorkerService(
  config: DeliveryWorkerServiceConfig,
): DeliveryWorkerService {
  const queue = new BullMQRevealDeliveryQueue({
    connection: config.connection,
    queueName: config.queueName,
    dlqName: config.dlqName,
    jobOptions: config.jobOptions,
  });

  const partnerReader =
    config.partnerReader ??
    new DbPartnerSnapshotReader(
      config.db,
      config.partnerSecretDecryptor ?? defaultPlaintextDecryptor,
    );

  const worker = startDeliveryWorker({
    connection: config.connection,
    queueName: config.queueName,
    db: config.db,
    partnerReader,
    poster: config.poster,
    deadLetterQueue: queue,
    concurrency: config.concurrency,
    stalledInterval: config.stalledInterval,
  });

  let stopped = false;
  const service: DeliveryWorkerService = {
    queue,
    worker,
    started: true,
    async stop(): Promise<void> {
      if (stopped) return;
      stopped = true;
      // Close the consumer first so no new attempt starts mid-shutdown, then
      // the producer + DLQ. `BullMQRevealDeliveryQueue.close()` closes both
      // underlying queues.
      await worker.close();
      await queue.close();
    },
  };
  return service;
}

/**
 * Default decryptor used when the production KMS decryptor is not injected and
 * no `partnerReader` override is supplied. It is a PLAINTEXT pass-through and is
 * therefore only safe for environments where `webhook_secret_encrypted` already
 * holds plaintext (local dev / integration fixtures). Production MUST inject a
 * real `partnerSecretDecryptor` (KMS) — the composition root is responsible for
 * that. Kept here so the helper has a non-throwing default for the local stack
 * while staying explicit that it does no real decryption.
 */
export const defaultPlaintextDecryptor: PartnerSecretDecryptor = (ciphertext) => ciphertext;
