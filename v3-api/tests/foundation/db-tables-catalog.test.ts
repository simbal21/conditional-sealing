import { describe, it, expect } from "vitest";
import {
  V3_API_TABLE_NAMES,
  V3_API_TABLE_COUNT,
  ingestions,
  pre_sigma_sessions,
  g4_attestation_cache,
  reveals,
  event_cursors,
  g4_refusals,
  partners,
  user_accounts,
  user_sessions,
  idempotency_keys,
  onboarding_links,
  partner_agreements,
  webhook_deliveries,
  vault_audit_log,
  push_subscriptions,
  nonces,
  rate_limit_buckets,
} from "../../src/db/schema.js";

describe("DB schema catalog (Phase A locked table list)", () => {
  it("locks exactly 17 V3 API tables", () => {
    expect(V3_API_TABLE_NAMES.length).toBe(17);
    expect(V3_API_TABLE_COUNT).toBe(17);
  });

  it("Phase B owned tables exported", () => {
    expect(ingestions).toBeDefined();
    expect(pre_sigma_sessions).toBeDefined();
    expect(g4_attestation_cache).toBeDefined();
  });

  it("Phase C owned tables exported", () => {
    expect(reveals).toBeDefined();
    expect(event_cursors).toBeDefined();
    expect(g4_refusals).toBeDefined();
  });

  it("Phase D owned tables exported", () => {
    expect(partners).toBeDefined();
    expect(user_accounts).toBeDefined();
    expect(user_sessions).toBeDefined();
    expect(idempotency_keys).toBeDefined();
    expect(onboarding_links).toBeDefined();
    expect(partner_agreements).toBeDefined();
    expect(webhook_deliveries).toBeDefined();
    expect(vault_audit_log).toBeDefined();
    expect(push_subscriptions).toBeDefined();
  });

  it("R2b LBU operational tables exported (nonces + rate_limit_buckets)", () => {
    expect(nonces).toBeDefined();
    expect(rate_limit_buckets).toBeDefined();
  });

  it("table-name list contains all expected names", () => {
    const expected = [
      "ingestions",
      "pre_sigma_sessions",
      "g4_attestation_cache",
      "reveals",
      "event_cursors",
      "g4_refusals",
      "partners",
      "user_accounts",
      "user_sessions",
      "idempotency_keys",
      "onboarding_links",
      "partner_agreements",
      "webhook_deliveries",
      "vault_audit_log",
      "push_subscriptions",
      "nonces",
      "rate_limit_buckets",
    ];
    for (const name of expected) {
      expect(V3_API_TABLE_NAMES).toContain(name);
    }
  });
});
