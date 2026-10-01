import { describe, it, expect } from "vitest";
import { DEMO_ERR_CODES, DemoError, isDemoError, type DemoErrCode, type DemoSafeRefs } from "../../src/errors/index.js";

describe("demo-error catalog (PHASE-PLAN §2)", () => {
  it("exactly 14 codes — frozen at Phase A per Rule 47", () => {
    expect(Object.keys(DEMO_ERR_CODES)).toHaveLength(14);
  });

  it("each code is a string identical to its key (self-referential enum)", () => {
    for (const [key, value] of Object.entries(DEMO_ERR_CODES)) {
      expect(value).toBe(key);
      expect(value.startsWith("DEMO_ERR_")).toBe(true);
    }
  });

  it("DemoError carries (code, safeRefs) and is instanceof DemoError + Error", () => {
    const err = new DemoError(DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN, { service: "redis", reason: "test" });
    expect(err).toBeInstanceOf(DemoError);
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe(DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN);
    expect(err.safeRefs.service).toBe("redis");
    expect(err.safeRefs.reason).toBe("test");
  });

  it("isDemoError narrows unknown → DemoError", () => {
    const err = new DemoError(DEMO_ERR_CODES.DEMO_ERR_TIMEOUT, { timeoutMs: 1000 });
    const wide: unknown = err;
    expect(isDemoError(wide)).toBe(true);
    expect(isDemoError(new Error("plain"))).toBe(false);
    expect(isDemoError(null)).toBe(false);
    expect(isDemoError(undefined)).toBe(false);
  });

  it("auto-derives message from safeRefs when not supplied", () => {
    const err = new DemoError(DEMO_ERR_CODES.DEMO_ERR_UNEXPECTED_EVENT, {
      observedEventName: "RevealAuthorized",
      blockNumber: 12345n,
    });
    expect(err.message).toContain("DEMO_ERR_UNEXPECTED_EVENT");
    expect(err.message).toContain("RevealAuthorized");
    expect(err.message).toContain("12345");
  });

  it("DemoSafeRefs type accepts every pre-declared field (compile-time test)", () => {
    // This is a TS-only assertion that the union accepts every documented
    // field. If a field is removed, this test fails to typecheck.
    const refs: DemoSafeRefs = {
      roundId: 1,
      subjectId: "demo-subject-xyz",
      hCommit: "0x" + "ab".repeat(32) as `0x${string}`,
      authorizationId: "0x" + "cd".repeat(32) as `0x${string}`,
      pdaRoot: "0x" + "ef".repeat(32) as `0x${string}`,
      fixtureName: "testament",
      expectedEventName: "RevealAuthorized",
      observedEventName: "ShredFinalized",
      expectedReasonCode: 0x02,
      observedReasonCode: 0x02,
      fromBlock: 100n,
      toBlock: 200n,
      blockNumber: 150n,
      txHash: "0x" + "01".repeat(32) as `0x${string}`,
      ingestionResponseHash: "0x" + "11".repeat(32) as `0x${string}`,
      retryResponseHash: "0x" + "11".repeat(32) as `0x${string}`,
      idempotencyKey: "ik-test-1",
      port: 5432,
      service: "postgres",
      url: "http://localhost:5432",
      envVar: "DEMO_POSTGRES_URL",
      responsibleMilestone: "M3",
      gapDescription: "integration gap example",
      responsiblePackage: "@cealis/v3-custody",
      orphanCount: 0,
      orphanKind: "vault-row",
      deployStep: "compile",
      basescanUrl: "https://sepolia.basescan.org/tx/0xdead",
      walletBalance: "0.5 ETH",
      timeoutMs: 30000,
      elapsedMs: 5000,
      waitedFor: "RevealAuthorized",
      reason: "free-form audit reason",
    };
    expect(Object.keys(refs).length).toBeGreaterThan(20);
  });

  it("Every code in the §2 table is present (text fixture)", () => {
    // The PHASE-PLAN §2 table lists exactly these 14 codes.
    const expectedCodes: DemoErrCode[] = [
      "DEMO_ERR_PREREQ_PACKAGE_MISSING",
      "DEMO_ERR_INFRA_PORT_BUSY",
      "DEMO_ERR_INFRA_DOWN",
      "DEMO_ERR_CONTRACT_NOT_DEPLOYED",
      "DEMO_ERR_ROUND_PRECONDITION",
      "DEMO_ERR_EXPECTED_EVENT_MISSING",
      "DEMO_ERR_UNEXPECTED_EVENT",
      "DEMO_ERR_BUNDLE_VERIFY_FAIL",
      "DEMO_ERR_REFUSAL_BUNDLE_MISMATCH",
      "DEMO_ERR_INTEGRATION_GAP",
      "DEMO_ERR_REPEATABILITY_LEAK",
      "DEMO_ERR_IDEMPOTENCY_VIOLATION",
      "DEMO_ERR_LIVE_DEPLOY_FAIL",
      "DEMO_ERR_TIMEOUT",
    ];
    for (const code of expectedCodes) {
      expect(DEMO_ERR_CODES[code]).toBe(code);
    }
  });
});
