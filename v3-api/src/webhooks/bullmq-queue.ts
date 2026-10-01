import { randomUUID } from "node:crypto";
import type { WebhookEnvelope } from "../types/webhook-events.js";
import {
  WEBHOOK_DELIVERY_SUCCESS_WINDOW_MS,
  WEBHOOK_RETRY_INTERVALS_MS,
  WEBHOOK_RETRY_MAX,
} from "../types/webhook-events.js";
import type { DeadLetterRecord, InMemoryDeadLetterStore } from "./dead-letter.js";

export interface WebhookDeliveryJob {
  readonly job_id: string;
  readonly envelope: WebhookEnvelope;
  readonly delivery_url: string;
  readonly signing_secret_ref: string;
}

export interface WebhookAttemptResult {
  readonly statusCode: number;
  readonly elapsedMs?: number;
}

export interface WebhookRetryTrace {
  readonly attempts: number;
  readonly plannedIntervalsMs: readonly number[];
  readonly finalState: "delivered" | "dead_letter" | "discarded";
  readonly statusCode?: number;
  readonly deadLetter?: DeadLetterRecord;
}

export class InMemoryWebhookQueue {
  private readonly jobs: WebhookDeliveryJob[] = [];

  enqueue(job: Omit<WebhookDeliveryJob, "job_id"> & { readonly job_id?: string }): WebhookDeliveryJob {
    const stored: WebhookDeliveryJob = { ...job, job_id: job.job_id ?? randomUUID() };
    this.jobs.push(stored);
    return stored;
  }

  list(): readonly WebhookDeliveryJob[] {
    return this.jobs;
  }
}

export function retryDelayForAttempt(attemptIndex: number): number {
  const value = WEBHOOK_RETRY_INTERVALS_MS[attemptIndex];
  if (value === undefined) return WEBHOOK_RETRY_INTERVALS_MS[WEBHOOK_RETRY_INTERVALS_MS.length - 1] ?? 16000;
  return value;
}

export async function runWebhookRetryPlan(input: {
  readonly envelope: WebhookEnvelope;
  readonly send: (attempt: number) => Promise<WebhookAttemptResult> | WebhookAttemptResult;
  readonly deadLetters: InMemoryDeadLetterStore;
}): Promise<WebhookRetryTrace> {
  const plannedIntervalsMs: number[] = [];
  let lastStatus: number | undefined;
  for (let attempt = 1; attempt <= WEBHOOK_RETRY_MAX; attempt += 1) {
    const result = await input.send(attempt);
    lastStatus = result.statusCode;
    if (isSuccessful(result)) {
      return {
        attempts: attempt,
        plannedIntervalsMs,
        finalState: "delivered",
        statusCode: result.statusCode,
      };
    }
    if (!isRetryable(result.statusCode)) {
      return {
        attempts: attempt,
        plannedIntervalsMs,
        finalState: "discarded",
        statusCode: result.statusCode,
      };
    }
    plannedIntervalsMs.push(retryDelayForAttempt(attempt - 1));
  }
  const deadLetter: DeadLetterRecord = {
    dead_letter_ref: `dead_${input.envelope.event_id}`,
    envelope: input.envelope,
    partner_id: input.envelope.partner_id,
    attempts: WEBHOOK_RETRY_MAX,
    status_code: lastStatus,
    created_at: new Date().toISOString(),
  };
  input.deadLetters.add(deadLetter);
  return {
    attempts: WEBHOOK_RETRY_MAX,
    plannedIntervalsMs,
    finalState: "dead_letter",
    statusCode: lastStatus,
    deadLetter,
  };
}

function isSuccessful(result: WebhookAttemptResult): boolean {
  return result.statusCode >= 200 && result.statusCode < 300 && (result.elapsedMs ?? 0) <= WEBHOOK_DELIVERY_SUCCESS_WINDOW_MS;
}

function isRetryable(statusCode: number): boolean {
  return statusCode >= 500 || statusCode === 429 || statusCode === 0;
}
