import { WEBHOOK_METADATA_RETENTION_DAYS } from "../types/webhook-events.js";
import type { DeadLetterRecord } from "./dead-letter.js";

export function webhookMetadataCutoff(now = new Date()): Date {
  return new Date(now.getTime() - WEBHOOK_METADATA_RETENTION_DAYS * 24 * 60 * 60 * 1000);
}

export function isWebhookMetadataRetained(createdAt: string, now = new Date()): boolean {
  return new Date(createdAt).getTime() >= webhookMetadataCutoff(now).getTime();
}

export function filterRetainedDeadLetters(records: readonly DeadLetterRecord[], now = new Date()): readonly DeadLetterRecord[] {
  return records.filter((record) => isWebhookMetadataRetained(record.created_at, now));
}
