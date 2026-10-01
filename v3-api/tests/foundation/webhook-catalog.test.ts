import { describe, it, expect } from "vitest";
import {
  WEBHOOK_EVENT_TYPES,
  WEBHOOK_EVENT_COUNT,
  WEBHOOK_RETRY_INTERVALS_MS,
  WEBHOOK_RETRY_MAX,
  WEBHOOK_METADATA_RETENTION_DAYS,
  WEBHOOK_REPLAY_WINDOW_SECONDS,
  buildEventKey,
} from "../../src/types/webhook-events.js";

describe("Webhook event taxonomy (S2-5 §7.1 — 18 verbatim)", () => {
  it("locks exactly 18 webhook event types", () => {
    expect(WEBHOOK_EVENT_TYPES.length).toBe(18);
    expect(WEBHOOK_EVENT_COUNT).toBe(18);
  });

  it("contains all 18 verbatim event types", () => {
    const expected = [
      "commit.finalized",
      "commit.failed",
      "sd.completed",
      "sd.partial_failure",
      "reveal.authorized",
      "challenge.opened",
      "challenge.resolved",
      "reveal.ready_for_gate_signing",
      "reveal.finalized",
      "reveal.failed",
      "g4.refused",
      "shred.authorized",
      "shred.challenge_opened",
      "shred.finalized",
      "halt.triggered",
      "registry.deprecated",
      "vault.retention_expiring",
      "vault.shredded",
    ];
    for (const t of expected) {
      expect(WEBHOOK_EVENT_TYPES).toContain(t);
    }
  });

  it("retry policy intervals = [1s, 2s, 4s, 8s, 16s] verbatim", () => {
    expect(Array.from(WEBHOOK_RETRY_INTERVALS_MS)).toEqual([1000, 2000, 4000, 8000, 16000]);
    expect(WEBHOOK_RETRY_MAX).toBe(5);
  });

  it("retention + replay window constants match spec", () => {
    expect(WEBHOOK_METADATA_RETENTION_DAYS).toBe(90);
    expect(WEBHOOK_REPLAY_WINDOW_SECONDS).toBe(300);
  });

  it("buildEventKey concatenates event_id + ':' + (h_commit || authorizationId) per §7.4", () => {
    expect(
      buildEventKey("evt_123", { h_commit: "0xaa", authorizationId: "0xbb" }),
    ).toBe("evt_123:0xaa");
    expect(buildEventKey("evt_123", { authorizationId: "0xbb" })).toBe("evt_123:0xbb");
    expect(() => buildEventKey("evt_123", {})).toThrow();
  });
});
