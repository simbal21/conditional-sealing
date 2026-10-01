import { describe, expect, it } from "vitest";
import { deriveSdFieldSalt, deriveSdMasterSalt, deriveSdSaltContextDigest } from "../../src/commit/salt-derivation.js";
import { b32 } from "./helpers.js";

describe("SD-FIELD-004 salt rejection sampling", () => {
  it("forces at least one retry for a deterministic synthetic search vector", () => {
    const context = deriveSdSaltContextDigest({
      authorizationId: b32("auth-salt"),
      pda_root: b32("pda-root-salt"),
      schema_digest: b32("schema-salt"),
      partner_id: b32("partner-salt"),
      sd_plan_digest: b32("plan-salt"),
    });
    const master = deriveSdMasterSalt(b32("dek-salt"), context);
    let found: ReturnType<typeof deriveSdFieldSalt> | null = null;
    for (let i = 0; i < 128; i += 1) {
      const candidate = deriveSdFieldSalt({
        sd_master_salt: master,
        authorizationId: b32("auth-salt"),
        field_id: b32(`field-${i}`),
        field_index: i,
      });
      if (candidate.retry_count > 0) {
        found = candidate;
        break;
      }
    }
    expect(found).not.toBeNull();
    expect(found!.retry_count).toBeGreaterThan(0);
  });
});
