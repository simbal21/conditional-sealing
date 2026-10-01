import type { WebhookEnvelope } from "../types/webhook-events.js";
import { signWebhookEnvelope, type SignedWebhookBody } from "./signer.js";
import { runWebhookRetryPlan, type WebhookAttemptResult, type WebhookRetryTrace } from "./bullmq-queue.js";
import type { InMemoryDeadLetterStore } from "./dead-letter.js";

export interface WebhookDispatchTarget {
  readonly delivery_url: string;
  readonly signing_secret: Uint8Array | string;
}

export interface WebhookSenderResponse {
  readonly statusCode: number;
  readonly elapsedMs?: number;
}

export type WebhookSender = (
  target: WebhookDispatchTarget,
  signed: SignedWebhookBody,
  attempt: number,
) => Promise<WebhookSenderResponse> | WebhookSenderResponse;

export async function dispatchWebhookWithRetry(input: {
  readonly envelope: WebhookEnvelope;
  readonly target: WebhookDispatchTarget;
  readonly sender: WebhookSender;
  readonly deadLetters: InMemoryDeadLetterStore;
}): Promise<WebhookRetryTrace> {
  return runWebhookRetryPlan({
    envelope: input.envelope,
    deadLetters: input.deadLetters,
    send: async (attempt: number): Promise<WebhookAttemptResult> => {
      const signed = signWebhookEnvelope({
        envelope: input.envelope,
        body: input.envelope,
        secret: input.target.signing_secret,
      });
      return input.sender(input.target, signed, attempt);
    },
  });
}
