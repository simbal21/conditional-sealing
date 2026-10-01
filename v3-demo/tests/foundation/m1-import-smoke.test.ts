import { describe, it, expect } from "vitest";
import * as M1 from "../../src/m1-imports.js";

describe("m1-imports smoke (M0+M1 @cealis/v3-crypto facade)", () => {
  it("re-exports all 30 TAG_*_V3 constants via TAG_DIGESTS", () => {
    expect(Object.keys(M1.TAG_DIGESTS)).toHaveLength(30);
    expect(M1.TAG_COMMIT_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(M1.TAG_AAD_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(M1.TAG_DRAND_ROUND_BINDING_V3).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("re-exports commit AAD encode/decode/digest", () => {
    expect(typeof M1.validateCommitAAD).toBe("function");
    expect(typeof M1.encodeCommitAAD).toBe("function");
    expect(typeof M1.decodeCommitAAD).toBe("function");
    expect(typeof M1.computeAADDigest).toBe("function");
    expect(M1.COMMIT_AAD_BYTES).toBe(523);
  });

  it("re-exports Shamir combineDek and AccessStructureProfile type via runtime constants", () => {
    expect(typeof M1.combineDek).toBe("function");
    // Phase A foundation test: just confirm the SHARE_ROLE_* constants exist
    // and that there is NO SHARE_ROLE_SUBJECT (σ_subject is commit-time
    // consent, not a Shamir share).
    expect(M1.SHARE_ROLE_LIT).toBe(0x01);
    expect(M1.SHARE_ROLE_G3).toBe(0x02);
    expect(M1.SHARE_ROLE_G4).toBe(0x03);
    expect("SHARE_ROLE_SUBJECT" in M1).toBe(false);
  });

  it("re-exports σ_subject + σ_Lit + σ_G3 + σ_G4 verifiers", () => {
    expect(typeof M1.verifySigmaSubject).toBe("function");
    expect(typeof M1.verifySigmaLit).toBe("function");
    expect(typeof M1.verifySigmaG3).toBe("function");
    expect(typeof M1.verifySigmaG4).toBe("function");
  });

  it("re-exports AEAD primitives and age-envelope decoder", () => {
    expect(typeof M1.encryptPayload).toBe("function");
    expect(typeof M1.decryptPayload).toBe("function");
    expect(typeof M1.decodeAgeEnvelope).toBe("function");
    expect(typeof M1.verifyEnvelope).toBe("function");
    expect(typeof M1.encodeAgeEnvelope).toBe("function");
  });

  it("re-exports hybrid PQ wrap surface (decap is σ-as-authorization step 1)", () => {
    expect(typeof M1.wrapShareForRecipient).toBe("function");
    expect(typeof M1.unwrapShareForRecipient).toBe("function");
    expect(M1.ML_KEM_768_PUBLIC_KEY_BYTES).toBe(1184);
  });
});
