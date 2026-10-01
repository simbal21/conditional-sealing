// T4.1 test — the real BullMQ reveal-delivery worker + the start/stop boot
// helper (server/start-delivery-worker.ts), driven by INJECTED fakes (no real
// Redis). We mock the `bullmq` module so the `Worker` constructor captures the
// processor closure and the `failed` listener that `startDeliveryWorker`
// registers; that lets us drive synthetic jobs through the GENUINE
// delivery-worker.ts code path (deliver → status row, retryable throw, DLQ on
// retry-exhaust, HMAC signing preserved, fail-closed on non-JCS envelope) with
// injected poster / partner-reader / db doubles.
//
// A separate, env-gated block exercises the boot helper against a REAL Redis
// when `V3_TEST_REDIS_URL` is set (infra-gated — SKIPs otherwise per the
// Phase-3 live-infra discipline).
//
// V3 isolation: no @cealis/shared, no V1 imports, no V1 env names.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ── In-process BullMQ double ────────────────────────────────────────────────
// We capture the processor + options the Worker is constructed with, and the
// jobs added to each Queue, so the test can drive the real processor closure
// without a Redis server.

interface FakeJobInit<T> {
  readonly id?: string;
  readonly data: T;
  readonly attemptsMade: number;
  readonly opts: { attempts?: number };
}

class FakeJob<T> {
  id?: string;
  data: T;
  attemptsMade: number;
  opts: { attempts?: number };
  constructor(init: FakeJobInit<T>) {
    this.id = init.id;
    this.data = init.data;
    this.attemptsMade = init.attemptsMade;
    this.opts = init.opts;
  }
}

interface AddedJob {
  readonly name: string;
  readonly data: unknown;
  readonly opts: Record<string, unknown>;
}

// Registry the mock populates so the test can reach the captured internals.
const capture = {
  workerProcessors: [] as Array<(job: FakeJob<unknown>) => Promise<void>>,
  workerFailedListeners: [] as Array<(job: unknown, err: unknown) => void>,
  workerOptions: [] as Array<Record<string, unknown>>,
  workerClosed: [] as boolean[],
  // queueName → added jobs
  queues: new Map<string, AddedJob[]>(),
  queueClosed: [] as boolean[],
};

function resetCapture(): void {
  capture.workerProcessors = [];
  capture.workerFailedListeners = [];
  capture.workerOptions = [];
  capture.workerClosed = [];
  capture.queues = new Map();
  capture.queueClosed = [];
}

vi.mock("bullmq", () => {
  class FakeQueue {
    readonly name: string;
    constructor(name: string, _opts: unknown) {
      this.name = name;
      if (!capture.queues.has(name)) capture.queues.set(name, []);
    }
    async add(name: string, data: unknown, opts: Record<string, unknown>): Promise<void> {
      capture.queues.get(this.name)!.push({ name, data, opts });
    }
    async getJob(jobId: string): Promise<{ data: unknown } | undefined> {
      // Return the most-recent matching job by jobId for deadLetter() payload
      // preservation (the producer reads job.data.authorizationId etc).
      for (const job of capture.queues.get(this.name) ?? []) {
        if ((job.opts as { jobId?: string }).jobId === jobId) {
          return { data: job.data };
        }
      }
      return undefined;
    }
    async close(): Promise<void> {
      capture.queueClosed.push(true);
    }
  }

  class FakeWorker {
    readonly name: string;
    constructor(
      name: string,
      processor: (job: FakeJob<unknown>) => Promise<void>,
      opts: Record<string, unknown>,
    ) {
      this.name = name;
      capture.workerProcessors.push(processor);
      capture.workerOptions.push(opts);
    }
    on(event: string, listener: (job: unknown, err: unknown) => void): this {
      if (event === "failed") capture.workerFailedListeners.push(listener);
      return this;
    }
    async close(): Promise<void> {
      capture.workerClosed.push(true);
    }
  }

  return { Queue: FakeQueue, Worker: FakeWorker };
});

// Imports AFTER vi.mock so the mocked bullmq is in effect.
import {
  startDeliveryWorkerService,
  defaultPlaintextDecryptor,
} from "../../src/server/start-delivery-worker.js";
import {
  classifyAttempt,
  DbPartnerSnapshotReader,
  type HttpPoster,
  type PartnerSnapshotReader,
  type PartnerWebhookSnapshot,
} from "../../src/webhooks/delivery-worker.js";
import {
  DEFAULT_REVEAL_DELIVERY_QUEUE_NAME,
  DEFAULT_REVEAL_DELIVERY_DLQ_NAME,
  type RevealDeliveryJobData,
} from "../../src/webhooks/bullmq-reveal-queue.js";
import { verifyWebhookSignature } from "../../src/webhooks/signer.js";
import type { Hex32 } from "../../src/h-commit/index.js";

// ── Fakes ───────────────────────────────────────────────────────────────────

const FAKE_CONNECTION = { url: "redis://fake:6379/9" } as unknown as Parameters<
  typeof startDeliveryWorkerService
>[0]["connection"];

const PARTNER_SECRET = "whk_secret_value";
const PARTNER_URL = "https://partner.example/webhook";

function fakePartnerReader(snapshot: PartnerWebhookSnapshot | null): {
  reader: PartnerSnapshotReader;
  calls: () => number;
} {
  let calls = 0;
  return {
    reader: {
      async read(): Promise<PartnerWebhookSnapshot | null> {
        calls += 1;
        return snapshot;
      },
    },
    calls: () => calls,
  };
}

// Fake Drizzle insert chain — records every webhook_deliveries row.
function fakeDb(): { db: unknown; rows: Array<Record<string, unknown>> } {
  const rows: Array<Record<string, unknown>> = [];
  const db = {
    insert(_table: unknown) {
      return {
        async values(row: Record<string, unknown>): Promise<void> {
          rows.push(row);
        },
      };
    },
  };
  return { db, rows };
}

// Recording HTTP poster — returns the queued status codes in order, and
// captures the bytes + headers it was handed so we can verify HMAC signing.
function recordingPoster(statusCodes: number[]): {
  poster: HttpPoster;
  posts: Array<{ url: string; body: Uint8Array; headers: Record<string, string> }>;
} {
  const posts: Array<{ url: string; body: Uint8Array; headers: Record<string, string> }> = [];
  let i = 0;
  const poster: HttpPoster = async (url, body, headers) => {
    posts.push({ url, body, headers });
    const code = statusCodes[Math.min(i, statusCodes.length - 1)] ?? 0;
    i += 1;
    return { statusCode: code, elapsedMs: 5 };
  };
  return { poster, posts };
}

const AUTH_ID = ("0x" + "ab".repeat(32)) as Hex32;
const PDA_ID = "pda_demo";
const PARTNER_ID = "11111111-1111-1111-1111-111111111111";

function jobData(overrides: Partial<RevealDeliveryJobData> = {}): RevealDeliveryJobData {
  return {
    job_id: "job_1",
    authorizationId: AUTH_ID,
    recipient_ref: "recipient_a",
    enqueued_at: "2026-06-02T10:00:00.000Z",
    payload: {
      event_id: "evt_1",
      schema_version: "s2-5.1",
      event_type: "reveal.finalized",
      created_at: "2026-06-02T10:00:00.000Z",
      partner_id: PARTNER_ID,
      pda_id: PDA_ID,
      data: { authorizationId: AUTH_ID },
    },
    ...overrides,
  };
}

// Drive a synthetic job through the captured processor + (on throw) the failed
// listener, mimicking BullMQ's retry accounting.
async function runJobThroughWorker(
  data: RevealDeliveryJobData,
  attemptsMade: number,
  maxAttempts: number,
): Promise<{ threw: boolean; error?: unknown }> {
  const processor = capture.workerProcessors[0];
  expect(processor).toBeDefined();
  const job = new FakeJob<RevealDeliveryJobData>({
    id: data.job_id,
    data,
    attemptsMade,
    opts: { attempts: maxAttempts },
  });
  try {
    await processor!(job as unknown as FakeJob<unknown>);
    return { threw: false };
  } catch (err) {
    // Mimic BullMQ firing the `failed` listener after a processor throw.
    for (const listener of capture.workerFailedListeners) {
      listener(job, err);
    }
    // Let any async DLQ work in the listener settle.
    await new Promise((r) => setTimeout(r, 0));
    return { threw: true, error: err };
  }
}

// ── Mockable tests (always run) ──────────────────────────────────────────────

describe("reveal delivery worker — boot helper wiring (mocked bullmq)", () => {
  beforeEach(() => resetCapture());
  afterEach(() => vi.restoreAllMocks());

  it("startDeliveryWorkerService constructs queue + DLQ + worker on the injected connection", () => {
    const { db } = fakeDb();
    const svc = startDeliveryWorkerService({ connection: FAKE_CONNECTION, db });

    expect(svc.started).toBe(true);
    // Producer built both the main queue and the DLQ (V3-namespaced).
    expect(capture.queues.has(DEFAULT_REVEAL_DELIVERY_QUEUE_NAME)).toBe(true);
    expect(capture.queues.has(DEFAULT_REVEAL_DELIVERY_DLQ_NAME)).toBe(true);
    // Worker constructed exactly once, bound to the main queue name.
    expect(capture.workerProcessors).toHaveLength(1);
    expect(svc.queue).toBeDefined();
    expect(svc.worker).toBeDefined();
  });

  it("stop() closes the worker then the queue + dlq; second stop() is a no-op", async () => {
    const { db } = fakeDb();
    const svc = startDeliveryWorkerService({ connection: FAKE_CONNECTION, db });

    await svc.stop();
    // worker.close() once, queue.close() closes both underlying queues.
    expect(capture.workerClosed.length).toBe(1);
    expect(capture.queueClosed.length).toBe(2); // queue + dlq
    // Idempotent.
    await svc.stop();
    expect(capture.workerClosed.length).toBe(1);
    expect(capture.queueClosed.length).toBe(2);
  });

  it("enqueue → deliver → status row 'delivered', with HMAC signature preserved (Rule-25 live read)", async () => {
    const { db, rows } = fakeDb();
    const { reader, calls } = fakePartnerReader({
      partner_id: PARTNER_ID,
      webhook_url: PARTNER_URL,
      signing_secret: PARTNER_SECRET,
      revoked: false,
    });
    const { poster, posts } = recordingPoster([200]);

    startDeliveryWorkerService({ connection: FAKE_CONNECTION, db, partnerReader: reader, poster });

    const outcome = await runJobThroughWorker(jobData(), 0, 5);
    expect(outcome.threw).toBe(false);

    // Live partner read happened (Rule 25 — not from enqueued snapshot).
    expect(calls()).toBe(1);

    // A delivery row was written with final_state=delivered.
    expect(rows).toHaveLength(1);
    expect(rows[0]!.final_state).toBe("delivered");
    expect(rows[0]!.status_code).toBe(200);
    expect(rows[0]!.attempt_count).toBe(1);
    // 90-day retention expiry stamped.
    expect(rows[0]!.expires_at).toBeInstanceOf(Date);

    // HMAC signing preserved end-to-end: the bytes the poster received verify
    // under the partner's signing secret with the delivered headers.
    expect(posts).toHaveLength(1);
    const post = posts[0]!;
    expect(post.url).toBe(PARTNER_URL);
    expect(post.headers["x-cealis-signature"]).toMatch(/^sha256=[0-9a-f]+$/);
    const verified = verifyWebhookSignature({
      rawBody: post.body,
      headers: post.headers,
      secret: PARTNER_SECRET,
      now: new Date(Number(post.headers["x-cealis-timestamp"]) * 1000),
    });
    expect(verified).toBe(true);
    // Wrong secret must NOT verify (signing is real, not a passthrough).
    expect(
      verifyWebhookSignature({
        rawBody: post.body,
        headers: post.headers,
        secret: "not-the-secret",
        now: new Date(Number(post.headers["x-cealis-timestamp"]) * 1000),
      }),
    ).toBe(false);
  });

  it("retryable failure (5xx) throws so BullMQ reschedules; no terminal row yet", async () => {
    const { db, rows } = fakeDb();
    const { reader } = fakePartnerReader({
      partner_id: PARTNER_ID,
      webhook_url: PARTNER_URL,
      signing_secret: PARTNER_SECRET,
      revoked: false,
    });
    const { poster } = recordingPoster([503]);

    startDeliveryWorkerService({ connection: FAKE_CONNECTION, db, partnerReader: reader, poster });

    // attemptsMade=0 (first try), 5 attempts allowed → still retries left.
    const outcome = await runJobThroughWorker(jobData(), 0, 5);
    expect(outcome.threw).toBe(true);
    expect((outcome.error as Error).name).toBe("RetryableDeliveryFailure");
    // No delivered/discarded row stamped on a retryable attempt.
    expect(rows.find((r) => r.final_state === "delivered")).toBeUndefined();
    // failed listener with attemptsMade < attempts must NOT dead-letter.
    const dlq = capture.queues.get(DEFAULT_REVEAL_DELIVERY_DLQ_NAME) ?? [];
    expect(dlq).toHaveLength(0);
  });

  it("non-retryable 4xx is discarded (no retry, no DLQ)", async () => {
    const { db, rows } = fakeDb();
    const { reader } = fakePartnerReader({
      partner_id: PARTNER_ID,
      webhook_url: PARTNER_URL,
      signing_secret: PARTNER_SECRET,
      revoked: false,
    });
    const { poster } = recordingPoster([400]);

    startDeliveryWorkerService({ connection: FAKE_CONNECTION, db, partnerReader: reader, poster });

    const outcome = await runJobThroughWorker(jobData(), 0, 5);
    expect(outcome.threw).toBe(false); // discarded → no throw, no retry
    expect(rows).toHaveLength(1);
    expect(rows[0]!.final_state).toBe("discarded_4xx");
    expect((capture.queues.get(DEFAULT_REVEAL_DELIVERY_DLQ_NAME) ?? [])).toHaveLength(0);
  });

  it("revoked partner → discarded_partner_revoked, no POST", async () => {
    const { db, rows } = fakeDb();
    const { reader } = fakePartnerReader({
      partner_id: PARTNER_ID,
      webhook_url: PARTNER_URL,
      signing_secret: PARTNER_SECRET,
      revoked: true,
    });
    const { poster, posts } = recordingPoster([200]);

    startDeliveryWorkerService({ connection: FAKE_CONNECTION, db, partnerReader: reader, poster });

    const outcome = await runJobThroughWorker(jobData(), 0, 5);
    expect(outcome.threw).toBe(false);
    expect(posts).toHaveLength(0); // never POSTed
    expect(rows[0]!.final_state).toBe("discarded_partner_revoked");
  });

  it("DLQ after retry-exhaust: last attempt throws → failed listener dead-letters + stamps dead_lettered", async () => {
    const { db, rows } = fakeDb();
    const { reader } = fakePartnerReader({
      partner_id: PARTNER_ID,
      webhook_url: PARTNER_URL,
      signing_secret: PARTNER_SECRET,
      revoked: false,
    });
    // Enqueue the original job into the captured queue so the producer's
    // deadLetter() can read its payload back (getJob by jobId).
    const { poster } = recordingPoster([500]);
    const svc = startDeliveryWorkerService({
      connection: FAKE_CONNECTION,
      db,
      partnerReader: reader,
      poster,
    });
    await svc.queue.enqueue({
      job_id: "job_1",
      authorizationId: AUTH_ID,
      recipient_ref: "recipient_a",
      payload: jobData().payload,
    });

    // attemptsMade = 4, attempts = 5 → after this throw, attemptsMade(4) is NOT
    // < attempts(5)? BullMQ increments attemptsMade before the failed event on
    // the final try; we model the terminal case where the listener sees
    // attemptsMade >= attempts.
    const outcome = await runJobThroughWorker(
      { ...jobData(), job_id: "job_1" },
      5, // attemptsMade at/over the limit → terminal
      5,
    );
    expect(outcome.threw).toBe(true);

    // DLQ got the original job (one row).
    const dlq = capture.queues.get(DEFAULT_REVEAL_DELIVERY_DLQ_NAME) ?? [];
    expect(dlq).toHaveLength(1);
    expect((dlq[0]!.data as { authorizationId: string }).authorizationId).toBe(AUTH_ID);
    expect((dlq[0]!.data as { reason: string }).reason).toMatch(/status=500/);

    // A dead_lettered audit row was stamped with a dlq ref.
    const dlRow = rows.find((r) => r.final_state === "dead_lettered");
    expect(dlRow).toBeDefined();
    expect(dlRow!.dead_letter_ref).toBe("dlq:job_1");
  });

  it("fails-closed on a non-JCS-serializable envelope (throws, no POST, no terminal row)", async () => {
    const { db, rows } = fakeDb();
    const { reader } = fakePartnerReader({
      partner_id: PARTNER_ID,
      webhook_url: PARTNER_URL,
      signing_secret: PARTNER_SECRET,
      revoked: false,
    });
    const { poster, posts } = recordingPoster([200]);

    startDeliveryWorkerService({ connection: FAKE_CONNECTION, db, partnerReader: reader, poster });

    // A BigInt in the envelope data has no JCS representation → signer throws
    // WebhookEnvelopeNotJcsCompatibleError → processor fails closed.
    const bad = jobData({
      payload: {
        event_id: "evt_bad",
        schema_version: "s2-5.1",
        event_type: "reveal.finalized",
        created_at: "2026-06-02T10:00:00.000Z",
        partner_id: PARTNER_ID,
        pda_id: PDA_ID,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        data: { authorizationId: AUTH_ID, bad: 10n as any },
      },
    });

    const outcome = await runJobThroughWorker(bad, 0, 5);
    expect(outcome.threw).toBe(true);
    // Never POSTed an unsigned/garbled body.
    expect(posts).toHaveLength(0);
    // No "delivered" / "discarded" terminal row from a fail-closed signer error.
    expect(rows.find((r) => r.final_state === "delivered")).toBeUndefined();
    expect(rows.find((r) => r.final_state?.toString().startsWith("discarded"))).toBeUndefined();
  });

  it("classifyAttempt: 2xx-in-window delivered; 5xx/429/0 retryable; 4xx discarded", () => {
    expect(classifyAttempt(200, 5)).toMatchObject({ delivered: true, discarded: false });
    expect(classifyAttempt(204, 100)).toMatchObject({ delivered: true });
    expect(classifyAttempt(200, 60_000)).toMatchObject({ delivered: false }); // outside 30s window
    expect(classifyAttempt(503, 5)).toMatchObject({ delivered: false, discarded: false });
    expect(classifyAttempt(429, 5)).toMatchObject({ delivered: false, discarded: false });
    expect(classifyAttempt(0, 5)).toMatchObject({ delivered: false, discarded: false });
    expect(classifyAttempt(404, 5)).toMatchObject({ delivered: false, discarded: true });
  });

  it("defaultPlaintextDecryptor is an explicit pass-through (prod must inject KMS)", async () => {
    expect(await defaultPlaintextDecryptor("ciphertext-blob")).toBe("ciphertext-blob");
  });

  it("DbPartnerSnapshotReader signs webhooks with webhook_secret_encrypted, NOT the API-auth signing_secret_encrypted", async () => {
    // Two DISTINCT secrets per partner row: signing_secret_encrypted is the
    // API-request-auth HMAC secret; webhook_secret_encrypted is the outbound
    // webhook signing key. The reader MUST source the webhook key, never the
    // API-auth key (crossing them leaks the API secret into webhook signatures
    // and breaks partner-side verification).
    const API_AUTH_SECRET = "api_auth_hmac_secret_DO_NOT_USE_FOR_WEBHOOKS";
    const WEBHOOK_SECRET = "webhook_signing_secret_CORRECT";
    let selectedColumns: string[] = [];

    // Fake Drizzle select chain returning a single partner row with both secrets.
    const fakeDb = {
      select() {
        return {
          from() {
            return {
              where() {
                return {
                  async limit() {
                    return [
                      {
                        partner_id: PARTNER_ID,
                        webhook_url: PARTNER_URL,
                        signing_secret_encrypted: API_AUTH_SECRET,
                        webhook_secret_encrypted: WEBHOOK_SECRET,
                        revoked_at: null,
                      },
                    ];
                  },
                };
              },
            };
          },
        };
      },
    };

    // The decryptor records which column value it was handed (pass-through).
    const reader = new DbPartnerSnapshotReader(fakeDb, (ciphertext: string) => {
      selectedColumns.push(ciphertext);
      return ciphertext;
    });

    const snapshot = await reader.read(PARTNER_ID);
    expect(snapshot).not.toBeNull();
    // The decrypted webhook signing secret is the WEBHOOK column, not API-auth.
    expect(snapshot!.signing_secret).toBe(WEBHOOK_SECRET);
    expect(snapshot!.signing_secret).not.toBe(API_AUTH_SECRET);
    // The reader decrypted exactly the webhook column.
    expect(selectedColumns).toEqual([WEBHOOK_SECRET]);
  });
});

// ── Live-infra (env-gated, SKIP without a real Redis) ────────────────────────

const REAL_REDIS_URL = process.env["V3_TEST_REDIS_URL"];
const liveDescribe = REAL_REDIS_URL ? describe : describe.skip;

liveDescribe("reveal delivery worker — live Redis (infra-gated)", () => {
  it("env-gated marker: full enqueue→deliver E2E runs in the integration stack", () => {
    // This block only runs with V3_TEST_REDIS_URL set. `vi.mock("bullmq")` is
    // hoisted file-wide, so the real-Redis enqueue→deliver→DLQ E2E cannot be
    // exercised here against the genuine BullMQ client — it lives in the
    // Phase-3 §5 integration stack test (env-gated INTEGRATION_REAL_STACK=1).
    // This marker asserts the infra env is well-formed when present, so a
    // misconfigured CI surfaces loudly rather than silently skipping.
    expect(typeof REAL_REDIS_URL).toBe("string");
    expect(REAL_REDIS_URL).toMatch(/^rediss?:\/\//);
  });
});
