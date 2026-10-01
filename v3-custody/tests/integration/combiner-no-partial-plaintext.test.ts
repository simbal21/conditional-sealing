import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES, combineAndDecrypt } from "../../src/index.js";
import { makeFixture } from "./combiner-testkit.js";

describe("combiner no partial plaintext", () => {
  it("does not return plaintext on any failure result", () => {
    const result = combineAndDecrypt(makeFixture({ canGatesSign: false }));
    expect(result.ok).toBe(false);
    expect("plaintext" in result).toBe(false);
  });

  it("requires supersession lineage evidence for non-zero commit generations", () => {
    const missingLineage = makeFixture({
      mutateCommitAAD(aad) {
        aad.commit_generation = 1;
        return aad;
      },
    });
    const missingResult = combineAndDecrypt(missingLineage);
    expect(missingResult.ok).toBe(false);
    if (!missingResult.ok) {
      expect(missingResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH);
    }

    const verifiedEvidence = missingLineage.sigmas.evidence.map((item) => ({
      ...item,
      metadata: { ...item.metadata, supersessionLineageVerified: "true" },
    }));
    const verifiedResult = combineAndDecrypt({
      ...missingLineage,
      sigmas: { ...missingLineage.sigmas, evidence: verifiedEvidence },
    });
    expect(verifiedResult.ok).toBe(true);
  });
});
