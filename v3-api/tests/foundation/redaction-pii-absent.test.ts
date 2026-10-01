import { describe, it, expect } from "vitest";
import {
  SAFE_REF_KEYS,
  isSafeRefKey,
  pickSafeRefs,
  FORBIDDEN_TOKEN_PATTERNS,
} from "../../src/redaction/safe-refs.js";
import { sanitize, pinoLogFormatter } from "../../src/redaction/log-sanitize.js";

describe("Safe-refs allow-list (S2-5 §10.2 line 1014 — 9 keys)", () => {
  it("locks exactly 9 safe-ref keys", () => {
    expect(SAFE_REF_KEYS.length).toBe(9);
  });

  it("contains all 9 verbatim safe-ref keys", () => {
    expect(SAFE_REF_KEYS).toEqual([
      "authorizationId",
      "h_commit",
      "event_id",
      "block_number",
      "registry_ref",
      "pda_id",
      "partner_id",
      "artifact_digest",
      "encrypted_diagnostic_ref",
    ]);
  });

  it("isSafeRefKey accepts safe-ref names, rejects others", () => {
    expect(isSafeRefKey("h_commit")).toBe(true);
    expect(isSafeRefKey("authorizationId")).toBe(true);
    expect(isSafeRefKey("plaintext")).toBe(false);
    expect(isSafeRefKey("dek")).toBe(false);
    expect(isSafeRefKey("sigma_lit")).toBe(false);
  });

  it("pickSafeRefs strips non-allowed keys", () => {
    const input = {
      h_commit: "0xaa",
      pda_id: "p1",
      dek: "BAD",
      plaintext: "BAD",
      authorizationId: "0xbb",
    };
    const out = pickSafeRefs(input);
    expect(out.h_commit).toBe("0xaa");
    expect(out.pda_id).toBe("p1");
    expect(out.authorizationId).toBe("0xbb");
    expect("dek" in out).toBe(false);
    expect("plaintext" in out).toBe(false);
  });
});

describe("Log sanitize (PII never escapes redaction)", () => {
  it("redacts sigma-prefixed keys to '[REDACTED]'", () => {
    const out = sanitize({ sigma_lit: "0xabcdef", h_commit: "0xaa" }) as Record<string, unknown>;
    expect(out.sigma_lit).toBe("[REDACTED]");
    expect(out.h_commit).toBe("0xaa"); // safe-ref preserved
  });

  it("redacts DEK / file_key / share keys", () => {
    const out = sanitize({
      dek: "BAD",
      file_key: "BAD",
      share_record: "BAD",
      h_commit: "0xaa",
    }) as Record<string, unknown>;
    expect(out.dek).toBe("[REDACTED]");
    expect(out.file_key).toBe("[REDACTED]");
    expect(out.share_record).toBe("[REDACTED]");
    expect(out.h_commit).toBe("0xaa");
  });

  it("recursively redacts nested objects", () => {
    const out = sanitize({
      level1: {
        level2: { dek: "BAD", h_commit: "0xaa" },
      },
    }) as Record<string, unknown>;
    const l1 = out.level1 as Record<string, unknown>;
    const l2 = l1.level2 as Record<string, unknown>;
    expect(l2.dek).toBe("[REDACTED]");
    expect(l2.h_commit).toBe("0xaa");
  });

  it("forbidden patterns include all major PII tokens", () => {
    expect(FORBIDDEN_TOKEN_PATTERNS.length).toBeGreaterThanOrEqual(8);
    const patternSources = FORBIDDEN_TOKEN_PATTERNS.map((p) => p.source).join(" ");
    expect(patternSources).toMatch(/sigma/i);
    expect(patternSources).toMatch(/shamir/i);
    expect(patternSources).toMatch(/dek/i);
    expect(patternSources).toMatch(/file_key/i);
    expect(patternSources).toMatch(/sd_salt/i);
  });

  it("pinoLogFormatter is a callable formatter returning object", () => {
    const out = pinoLogFormatter({ dek: "BAD" });
    expect(out.dek).toBe("[REDACTED]");
  });
});
