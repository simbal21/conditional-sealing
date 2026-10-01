import type { WebhookEnvelope } from "../types/webhook-events.js";

export interface DeadLetterRecord {
  readonly dead_letter_ref: string;
  readonly envelope: WebhookEnvelope;
  readonly partner_id: string;
  readonly attempts: number;
  readonly status_code?: number;
  readonly created_at: string;
}

export class InMemoryDeadLetterStore {
  private readonly records: DeadLetterRecord[] = [];

  add(record: DeadLetterRecord): void {
    this.records.push(record);
  }

  list(): readonly DeadLetterRecord[] {
    return this.records;
  }
}
