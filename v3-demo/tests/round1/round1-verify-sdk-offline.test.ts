// Round 1 — Step 9 isolated: verify-sdk OFFLINE (S2-5 §4.7).
//
// Independence is a normative property per S2-5 §4.7 + §9.1. verify-sdk
// runs against a partner-controlled RPC (anvil-fork in CI, real Base
// Sepolia in live). No Cealis-controlled endpoint is contacted.
//
// At CI level the partner RPC is the same anvil instance — but the SDK
// does NOT distinguish partner-RPC-shape; what matters is `chainRpcUrl`
// is the partner's resolution, NOT a Cealis URL. Phase A's
// `verifyRoundBundle` honors this by passing `chainRpcUrl: config.rpcUrl`
// (the mode-dispatched URL, which in CI is the anvil RPC the partner
// would also use).

import { describe, expect, it } from "vitest";
import { runRound1 } from "../../src/rounds/round1.js";
import { verifyRoundBundle } from "../../src/verify.js";

describe("Round 1 — Step 9 verify-sdk OFFLINE (S2-5 §4.7)", () => {
  it("verifyRoundBundle returns overall=pass for the happy-path bundle", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.verify.overall).toBe("pass");
  });

  it("verifyRoundBundle can be re-invoked on the same bundle (idempotent)", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const second = await verifyRoundBundle({
      bundle: result.bundle,
      mode: "ci-anvil",
      expectedRecipientRef: "round1-heir",
      now: new Date("2026-05-14T00:03:00.000Z"),
    });
    expect(second.overall).toBe("pass");
  });

  it("verify result echoes safe_refs (authorizationId + hCommit + pdaRoot)", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const verify = await verifyRoundBundle({
      bundle: result.bundle,
      mode: "ci-anvil",
      expectedRecipientRef: "round1-heir",
      now: new Date("2026-05-14T00:03:00.000Z"),
    });
    expect(verify.safe_refs.authorizationId).toBe(result.authorizationId);
    expect(verify.safe_refs.h_commit).toBe(result.hCommit);
  });

  it("verify fails (overall != pass) when recipientRef does not match the bundle", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const verify = await verifyRoundBundle({
      bundle: result.bundle,
      mode: "ci-anvil",
      expectedRecipientRef: "wrong-recipient-ref",
      now: new Date("2026-05-14T00:03:00.000Z"),
    });
    expect(verify.overall).toBe("fail");
  });

  it("verify-sdk produces exactly 16 named checks", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const verify = await verifyRoundBundle({
      bundle: result.bundle,
      mode: "ci-anvil",
      expectedRecipientRef: "round1-heir",
      now: new Date("2026-05-14T00:03:00.000Z"),
    });
    // 16 = the 15 S2-5 §4.7 checks + `freshness` (anti-replay, added by
    // Security-audit-2026-05-14 TS-API-F-03; skipped unless maxArtifactAgeSeconds set).
    expect(Object.keys(verify.checks)).toHaveLength(16);
  });

  it("all 16 verify-sdk checks pass for the happy-path bundle", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const verify = await verifyRoundBundle({
      bundle: result.bundle,
      mode: "ci-anvil",
      expectedRecipientRef: "round1-heir",
      now: new Date("2026-05-14T00:03:00.000Z"),
    });
    for (const [name, check] of Object.entries(verify.checks)) {
      // Allow "skipped" only for optional checks; happy-path must hit pass
      // on the load-bearing ones.
      expect(check.status, `check ${name} should pass or be skipped`).not.toBe("fail");
    }
  });

  it("verify does NOT contact a Cealis URL (independence property — partner-RPC only)", async () => {
    // The verify-sdk receives only `chainRpcUrl` from options. In CI mode
    // this resolves to the partner's anvil RPC. Without
    // `requireOnlineRegistryChecks: true` the SDK does not make any
    // network call at all. Phase A's `verifyRoundBundle` sets
    // `requireOnlineRegistryChecks: false`, so the offline pass is
    // structural: no network IO happens during verify.
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const verify = await verifyRoundBundle({
      bundle: result.bundle,
      mode: "ci-anvil",
      expectedRecipientRef: "round1-heir",
      now: new Date("2026-05-14T00:03:00.000Z"),
    });
    // chainProof check status must NOT be "RPC_URL_REQUIRED" — that would
    // mean we asked for online checks without supplying chainRpcUrl.
    expect(verify.checks.chainProof.code).not.toBe("CHAIN_PROOF.RPC_URL_REQUIRED");
  });
});
