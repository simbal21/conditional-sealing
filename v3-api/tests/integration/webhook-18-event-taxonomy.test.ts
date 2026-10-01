import { describe, expect, it } from "vitest";
import { RefusalCode, WEBHOOK_EVENT_TYPES } from "../../src/types/index.js";
import {
  InMemoryWebhookEventBus,
  buildG4RefusedData,
  signWebhookEnvelope,
  verifyWebhookSignature,
} from "../../src/webhooks/index.js";

describe("18-event webhook taxonomy", () => {
  it("emits every locked event with envelope shape and signatures", async () => {
    const bus = new InMemoryWebhookEventBus();
    const seen: string[] = [];
    bus.subscribe((event) => seen.push(event.event_type));
    for (const eventType of WEBHOOK_EVENT_TYPES) {
      const data =
        eventType === "g4.refused"
          ? buildG4RefusedData({
              authorizationId: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
              reason_code: RefusalCode.Art18Restriction,
              encrypted_reason_ref: "enc_ref_1",
            })
          : { h_commit: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", status: "ok" };
      const envelope = await bus.emit({
        event_type: eventType,
        partner_id: "partner_demo",
        pda_id: "pda_demo",
        data,
      });
      expect(envelope).toEqual(
        expect.objectContaining({
          event_id: expect.any(String),
          schema_version: "s2-5.1",
          event_type: eventType,
          created_at: expect.any(String),
          partner_id: "partner_demo",
          pda_id: "pda_demo",
          data: expect.any(Object),
        }),
      );
      const signed = signWebhookEnvelope({
        envelope,
        body: envelope,
        secret: "webhook_secret",
        timestamp: "1778500800",
      });
      expect(
        verifyWebhookSignature({
          rawBody: signed.rawBody,
          headers: signed.headers,
          secret: "webhook_secret",
          now: new Date("2026-05-11T12:00:00.000Z"),
        }),
      ).toBe(true);
      if (eventType === "g4.refused") {
        expect(envelope.data).toMatchObject({
          reason_code: "0x03",
          reason_label: "art_18_restriction",
          reason_visibility: "encrypted",
          encrypted_reason_ref: "enc_ref_1",
        });
      }
    }
    expect(seen).toEqual([...WEBHOOK_EVENT_TYPES]);
  });
});
