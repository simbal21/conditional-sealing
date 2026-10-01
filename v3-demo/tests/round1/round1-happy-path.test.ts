// Round 1 — Escrow Tripwire Happy Path (full Steps 1-10).
//
// End-to-end exercise: subject onboarding → idempotency replay → chain
// anchor → TimeLock fire (synthetic) → ConditionEngine emits
// RevealAuthorized → combiner reconstructs DEK (σ-as-authorization) →
// AEAD decrypt → M5 reveal-delivery assembles 15-key bundle → recipient
// verify-sdk verifies OFFLINE → repeatability cleanup verifier.
//
// Synthetic adapter pattern per the internal integration-gap log: in-process M5 ingest
// + in-process reveal-event normalization + synthetic ConditionEngine log.
// Real anvil-fork integration deferred to M8 Phase F/G.

import { describe, expect, it } from "vitest";
import { runRound1 } from "../../src/rounds/round1.js";

describe("Round 1 — Escrow Tripwire Happy Path (full Steps 1-10)", () => {
  it("runs end-to-end and verify-sdk returns overall=pass", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.verify.overall).toBe("pass");
  });

  it("produces a fresh subjectId per run (REPEATABILITY)", async () => {
    const first = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const second = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(first.subjectId).not.toBe(second.subjectId);
    expect(first.runId).not.toBe(second.runId);
  });

  it("authorizationId + hCommit are 32-byte hex strings", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.authorizationId).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(result.hCommit).toMatch(/^0x[0-9a-fA-F]{64}$/);
  });

  it("commitTxHash is populated (Step 3 chain anchor)", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.commitTxHash).toBeTypeOf("string");
    expect(result.commitTxHash).toMatch(/^0x[0-9a-fA-F]{64}$/);
  });

  it("bundle has the locked 15 keys (Step 8)", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const keys = Object.keys(result.bundle).sort();
    expect(keys).toEqual(
      [
        "authorization",
        "bundle_version",
        "canonicalization",
        "chain_proofs",
        "issuer_attestation",
        "pda",
        "pii_statement",
        "plaintext",
        "provenance",
        "recipient",
        "registry_snapshots",
        "sd_refs",
        "shred_state",
        "sigma_block",
        "verification",
      ].sort(),
    );
  });

  it("recipient_ref in bundle equals the round1-heir selector", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.bundle.recipient.recipient_ref).toBe("round1-heir");
  });

  it("artifacts are skipped when skipArtifacts=true", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.artifacts.outDir).toBeUndefined();
  });
});
