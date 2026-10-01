import { describe, expect, it } from "vitest";
import { TIER_BEHAVIOR_MATRIX, OPERATIONAL_CLASSES } from "../../src/types/tier-behavior.js";
import { buildRetentionStatus } from "../../src/vault/index.js";
import { filterRetainedDeadLetters, isWebhookMetadataRetained, webhookMetadataCutoff } from "../../src/webhooks/index.js";
import type { DeadLetterRecord } from "../../src/webhooks/index.js";

describe("retention floors", () => {
  it("keeps §15.1 retention periods and §12 retention_floor behavior visible at runtime", () => {
    const status = buildRetentionStatus({
      h_commit: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      retention_expires_at: "2029-01-01T00:00:00.000Z",
    });

    expect(status.retention_policy_id).toBe("obligation_plus_3y");
    expect(status.retention_floor_statement).toBe(TIER_BEHAVIOR_MATRIX.retention_floor.b2b_partner);
    expect(status.vault_access_log_retention).toBe("P12M");
    expect(status.webhook_metadata_retention).toBe("P90D");
    expect(new Date(status.retention_expires_at).getTime()).toBeGreaterThanOrEqual(
      Date.parse("2026-01-01T00:00:00.000Z") + 3 * 365 * 24 * 60 * 60 * 1000,
    );

    for (const operationalClass of OPERATIONAL_CLASSES) {
      expect(TIER_BEHAVIOR_MATRIX.retention_floor[operationalClass].length, operationalClass).toBeGreaterThan(0);
    }
  });

  it("keeps webhook metadata on a 90-day rolling floor", () => {
    const now = new Date("2026-05-11T00:00:00.000Z");
    const cutoff = webhookMetadataCutoff(now);
    expect(cutoff.toISOString()).toBe("2026-02-10T00:00:00.000Z");
    expect(isWebhookMetadataRetained("2026-02-10T00:00:00.000Z", now)).toBe(true);
    expect(isWebhookMetadataRetained("2026-02-09T23:59:59.999Z", now)).toBe(false);

    const records: DeadLetterRecord[] = [
      deadLetter("retained", "2026-02-10T00:00:00.000Z"),
      deadLetter("expired", "2026-02-09T23:59:59.999Z"),
    ];
    expect(filterRetainedDeadLetters(records, now).map((record) => record.envelope.event_id)).toEqual(["retained"]);
  });
});

function deadLetter(eventId: string, createdAt: string): DeadLetterRecord {
  return {
    dead_letter_ref: `dead-letter://${eventId}`,
    envelope: {
      event_id: eventId,
      schema_version: "s2-5.1",
      event_type: "reveal.finalized",
      created_at: createdAt,
      partner_id: "partner_demo",
      pda_id: "pda_demo",
      data: { authorizationId: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
    },
    partner_id: "partner_demo",
    attempts: 5,
    status_code: 500,
    created_at: createdAt,
  };
}
