// Round 1 — Step 2 isolated: idempotency byte-identical retry (S2-5 §1.5).
//
// The S2-5 §1.5 distinct property — distinct from REPEATABILITY (which
// requires fresh subjectIds per run + cleanup). IDEMPOTENCY says: same
// Idempotency-Key + same body → byte-identical response. No vault
// double-write, no chain double-anchor.

import { describe, expect, it } from "vitest";
import { runRound1 } from "../../src/rounds/round1.js";
import {
  assertIdempotencyByteIdentical,
  DemoError,
  DEMO_ERR_CODES,
} from "../../src/index.js";

describe("Round 1 — Step 2 idempotency byte-identical replay (S2-5 §1.5)", () => {
  it("runRound1 internally retries Step 1 ingestion and assertion passes", async () => {
    // runRound1 itself drives the idempotency replay internally per
    // the internal build brief, Step 2. If `assertIdempotencyByteIdentical` fails,
    // runRound1 throws DemoError(DEMO_ERR_IDEMPOTENCY_VIOLATION). No
    // throw = invariant held.
    await expect(runRound1({ mode: "ci-anvil", skipArtifacts: true })).resolves.toBeDefined();
  });

  it("assertIdempotencyByteIdentical accepts identical JSON-shaped responses", () => {
    const fakeResp = { authorizationId: "0xabc", commit_block: 100 };
    expect(() =>
      assertIdempotencyByteIdentical({
        firstResponse: fakeResp,
        secondResponse: fakeResp,
        idempotencyKey: "idem-test",
      }),
    ).not.toThrow();
  });

  it("assertIdempotencyByteIdentical throws DEMO_ERR_IDEMPOTENCY_VIOLATION on drift", () => {
    const first = { authorizationId: "0xabc", commit_block: 100 };
    const second = { authorizationId: "0xabc", commit_block: 101 };
    expect(() =>
      assertIdempotencyByteIdentical({
        firstResponse: first,
        secondResponse: second,
        idempotencyKey: "idem-test",
      }),
    ).toThrow(DemoError);
    try {
      assertIdempotencyByteIdentical({
        firstResponse: first,
        secondResponse: second,
        idempotencyKey: "idem-test",
      });
    } catch (err) {
      expect(err).toBeInstanceOf(DemoError);
      expect((err as DemoError).code).toBe(DEMO_ERR_CODES.DEMO_ERR_IDEMPOTENCY_VIOLATION);
      expect((err as DemoError).safeRefs.idempotencyKey).toBe("idem-test");
    }
  });

  it("assertIdempotencyByteIdentical normalises object key order (sorted JSON)", () => {
    const first = { a: 1, b: 2 };
    const second = { b: 2, a: 1 };
    expect(() =>
      assertIdempotencyByteIdentical({
        firstResponse: first,
        secondResponse: second,
      }),
    ).not.toThrow();
  });

  it("happy-path idempotency runs implicitly verifies vault write count = 1", async () => {
    // Single happy-path call internally calls createModeAIngestion TWICE
    // with same Idempotency-Key. The vault writer counter inside round1.ts
    // would throw DEMO_ERR_IDEMPOTENCY_VIOLATION if the second call
    // triggered a write. No throw = vault count = 1 after replay.
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.verify.overall).toBe("pass");
  });
});
