import { describe, it, expect } from "vitest";
import {
  ERROR_CATEGORIES,
  ERROR_CATEGORY_COUNT,
  CATEGORY_DEFAULT_HTTP_STATUS,
  CATEGORY_MEANING,
} from "../../src/errors/categories.js";
import { ErrorCode } from "../../src/errors/codes.js";
import { problemFromCode, throwProblem, HttpProblem } from "../../src/errors/problem.js";

describe("Error category catalog (S2-5 §1.4 — 12 verbatim)", () => {
  it("locks exactly 12 categories", () => {
    expect(ERROR_CATEGORIES.length).toBe(12);
    expect(ERROR_CATEGORY_COUNT).toBe(12);
  });

  it("contains all 12 verbatim categories", () => {
    expect(ERROR_CATEGORIES).toEqual([
      "REQUEST",
      "AUTH",
      "ATTESTATION",
      "VAULT",
      "CHAIN",
      "COMBINER",
      "SCHEMA",
      "IDEMPOTENCY",
      "RATE_LIMIT",
      "TRANSPORT",
      "GOVERNANCE",
      "RETRY_EXHAUSTED",
    ]);
  });

  it("HTTP status map covers every category", () => {
    for (const cat of ERROR_CATEGORIES) {
      expect(CATEGORY_DEFAULT_HTTP_STATUS[cat]).toBeGreaterThanOrEqual(400);
    }
  });

  it("meaning strings match spec verbatim", () => {
    expect(CATEGORY_MEANING.RATE_LIMIT).toBe("Per-key or per-IP limit exceeded");
    expect(CATEGORY_MEANING.IDEMPOTENCY).toBe("Idempotency key replay with divergent request body");
  });

  it("special-case Mode B reserved code shape", () => {
    expect(ErrorCode.SCHEMA_MODE_B_RESERVED.code).toBe("SCHEMA.MODE_B_RESERVED");
    expect(ErrorCode.SCHEMA_MODE_B_RESERVED.httpStatus).toBe(409);
    expect(ErrorCode.SCHEMA_MODE_B_RESERVED.category).toBe("SCHEMA");
  });

  it("special-case ATTESTATION 4 checks all = 424", () => {
    expect(ErrorCode.ATTESTATION_LIT_ASSIGNMENT_MISSING.httpStatus).toBe(424);
    expect(ErrorCode.ATTESTATION_DCAP_INVALID.httpStatus).toBe(424);
    expect(ErrorCode.ATTESTATION_G3_PUBKEY_INVALID.httpStatus).toBe(424);
    expect(ErrorCode.ATTESTATION_G4_AUTHORITY_INVALID.httpStatus).toBe(424);
  });

  it("special-case 503 codes", () => {
    expect(ErrorCode.VAULT_UNAVAILABLE.httpStatus).toBe(503);
    expect(ErrorCode.CHAIN_ANCHOR_RETRY_EXHAUSTED.httpStatus).toBe(503);
  });

  it("problemFromCode produces well-formed Problem+JSON body", () => {
    const body = problemFromCode("SCHEMA_MODE_B_RESERVED", "corr_abc", {
      detail: "test detail",
      safe_refs: { h_commit: "0xaa", pda_id: "p1" },
      retryable: false,
    });
    expect(body.type).toContain("schema/mode_b_reserved");
    expect(body.code).toBe("SCHEMA.MODE_B_RESERVED");
    expect(body.category).toBe("SCHEMA");
    expect(body.status).toBe(409);
    expect(body.correlation_id).toBe("corr_abc");
    expect(body.retryable).toBe(false);
    expect(body.safe_refs?.h_commit).toBe("0xaa");
  });

  it("throwProblem raises HttpProblem with body attached", () => {
    try {
      throwProblem("AUTH_FORBIDDEN", "corr_def");
      throw new Error("should not reach");
    } catch (err) {
      expect(err).toBeInstanceOf(HttpProblem);
      const httpErr = err as HttpProblem;
      expect(httpErr.body.code).toBe("AUTH.FORBIDDEN");
      expect(httpErr.body.status).toBe(403);
    }
  });
});
