// Foundation test — §1.4 logging discipline allow-list + banned keys.

import { describe, it, expect } from "vitest";
import {
  ALLOWED_SAFE_REF_KEYS,
  BANNED_LOG_KEYS,
  isSafeRefs,
} from "../../src/errors/safe-refs.js";
import { SdError } from "../../src/errors/sd-error.js";
import { SdErrorCode } from "../../src/errors/codes.js";

describe("§1.4 logging discipline", () => {
  it("ALLOWED_SAFE_REF_KEYS contains the §1.4 spec-named keys", () => {
    const allowedSet = new Set<string>(ALLOWED_SAFE_REF_KEYS);
    for (const must of [
      "correlationId",
      "authorizationId",
      "h_commit",
      "pda_id",
      "partner_id",
      "claim_id",
      "field_id",
      "verifier_ref",
      "proof_length",
      "stage",
      "error_code",
      "timestamp",
    ]) {
      expect(allowedSet.has(must)).toBe(true);
    }
  });

  it("BANNED_LOG_KEYS are disjoint from ALLOWED_SAFE_REF_KEYS", () => {
    const allowedSet = new Set<string>(ALLOWED_SAFE_REF_KEYS);
    for (const banned of BANNED_LOG_KEYS) {
      expect(allowedSet.has(banned)).toBe(false);
    }
  });

  it("isSafeRefs accepts allow-listed keys with string/number/bigint values", () => {
    expect(isSafeRefs({})).toBe(true);
    expect(isSafeRefs({ correlationId: "abc", proof_length: 192 })).toBe(true);
    expect(isSafeRefs({ pda_version: 1n })).toBe(true);
  });

  it("isSafeRefs rejects banned / non-allow-listed keys", () => {
    expect(isSafeRefs({ plaintext: "secret" })).toBe(false);
    expect(isSafeRefs({ witness: "1234" })).toBe(false);
    expect(isSafeRefs({ salt: "deadbeef" })).toBe(false);
    expect(isSafeRefs({ proof_bytes: "0x..." })).toBe(false);
    expect(isSafeRefs({ unknown_key: "x" })).toBe(false);
  });

  it("isSafeRefs rejects object-valued payloads (only string/number/bigint)", () => {
    expect(isSafeRefs({ correlationId: { nested: "x" } })).toBe(false);
  });

  it("SdError constructor refuses safeRefs payloads with banned keys", () => {
    expect(() =>
      new SdError(SdErrorCode.PROOF_INVALID, {
        // @ts-expect-error - testing runtime refusal of banned key
        safeRefs: { plaintext: "secret" },
      }),
    ).toThrow(/banned keys/);
  });

  it("SdError constructor accepts safeRefs with only allow-listed keys", () => {
    const err = new SdError(SdErrorCode.PROOF_INVALID, {
      correlationId: "abc-123",
      safeRefs: { authorizationId: "0xdead", proof_length: 192 },
    });
    expect(err.code).toBe(SdErrorCode.PROOF_INVALID);
    expect(err.correlationId).toBe("abc-123");
  });
});
