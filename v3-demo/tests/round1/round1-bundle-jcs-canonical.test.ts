// Round 1 — Step 8 isolated: bundle 15 keys + JCS canonicalisation.
//
// The RevealArtifactBundle has 15 top-level keys per S2-5 §4. The bundle
// digest is keccak256(utf8(JCS(bundle))). JCS canonicalisation (RFC 8785)
// produces a stable byte sequence across invocations.

import { describe, expect, it } from "vitest";
import {
  runRound1,
  ROUND1_BUNDLE_15_KEYS,
  bundleJcsCanonicalBytes,
} from "../../src/rounds/round1.js";

describe("Round 1 — Step 8 bundle 15-key shape + JCS canonicalisation", () => {
  it("ROUND1_BUNDLE_15_KEYS literal lists exactly 15 keys", () => {
    expect(ROUND1_BUNDLE_15_KEYS).toHaveLength(15);
  });

  it("ROUND1_BUNDLE_15_KEYS matches the locked S2-5 §4 key set", () => {
    expect([...ROUND1_BUNDLE_15_KEYS].sort()).toEqual(
      [
        "bundle_version",
        "canonicalization",
        "authorization",
        "pda",
        "recipient",
        "plaintext",
        "issuer_attestation",
        "provenance",
        "sigma_block",
        "chain_proofs",
        "registry_snapshots",
        "shred_state",
        "sd_refs",
        "verification",
        "pii_statement",
      ].sort(),
    );
  });

  it("happy-path bundle has exactly the 15 keys", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const keys = Object.keys(result.bundle).sort();
    expect(keys).toEqual([...ROUND1_BUNDLE_15_KEYS].sort());
  });

  it("bundle.canonicalization.format = 'JCS' (S2-5 §4 lock)", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.bundle.canonicalization.format).toBe("JCS");
    expect(result.bundle.canonicalization.rfc).toBe("RFC8785");
  });

  it("bundle.pii_statement is the locked S2-5 §4 string literal", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.bundle.pii_statement).toBe("recipient_filtered_plaintext_after_valid_reveal");
  });

  it("JCS canonicalisation is stable across two invocations (byte-identical)", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const a = bundleJcsCanonicalBytes(result.bundle);
    const b = bundleJcsCanonicalBytes(result.bundle);
    expect(a).toEqual(b);
  });

  it("JCS canonicalisation produces deterministic output (sorted keys)", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    const bytes = bundleJcsCanonicalBytes(result.bundle);
    const decoded = new TextDecoder().decode(bytes);
    // JCS sorts keys lexicographically — the first key in the bundle JSON
    // must be "authorization" (alphabetically first among the 15).
    expect(decoded.startsWith('{"authorization":')).toBe(true);
  });

  it("bundle.verification.artifact_bundle_digest is a 32-byte hex", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.bundle.verification.artifact_bundle_digest).toMatch(/^0x[0-9a-fA-F]{64}$/);
  });

  it("bundleDigest from result matches bundle.verification.artifact_bundle_digest", async () => {
    const result = await runRound1({ mode: "ci-anvil", skipArtifacts: true });
    expect(result.bundleDigest).toBe(result.bundle.verification.artifact_bundle_digest);
  });
});
