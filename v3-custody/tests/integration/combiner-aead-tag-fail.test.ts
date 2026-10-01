import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES, combineAndDecrypt } from "../../src/index.js";
import { readCommitContextDigest0 } from "../../src/combiner/index.js";
import { bytes32, makeFixture } from "./combiner-testkit.js";

describe("combiner AEAD tag failure", () => {
  it("wraps M1 AEAD tag failure and returns no plaintext", () => {
    const result = combineAndDecrypt(
      makeFixture({
        mutateAgeEnvelope(bytes) {
          const copy = new Uint8Array(bytes);
          copy[copy.length - 1] = (copy[copy.length - 1] ?? 0) ^ 0xff;
          return copy;
        },
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_AEAD_FAIL);
      expect(result.subCodes).toContain("ERR_AEAD_TAG_VERIFY_FAIL");
      expect("plaintext" in result).toBe(false);
    }
  });

  it("falls back to commit_AAD attestation digest when no metadata digest is present", () => {
    const fallback = bytes32(0x77);
    expect(readCommitContextDigest0({ metadataSources: [{}], fallback })).toBe(fallback);
  });
});
