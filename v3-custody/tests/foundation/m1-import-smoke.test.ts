// Foundation test — M1 import surface smoke test.
//
// Asserts every named export from `src/m1-imports.ts` is loadable and
// of the expected runtime shape (function for verifiers, constant for
// TAGs). If any name has drifted in M1, this test FAILS LOUDLY at
// boot — surfacing the rename before Codex chunks B/C/D/E start.
//
// Per Rule 6b + SPEC-COMPLIANCE-GUARD-M3 §21: M1 byte-exact discipline.

import { describe, it, expect } from "vitest";

import * as m1 from "../../src/m1-imports.js";

describe("M1 import smoke test (Phase A acceptance gate)", () => {
  it("re-exports all 4 σ verifier functions", () => {
    expect(typeof m1.verifySigmaSubject).toBe("function");
    expect(typeof m1.verifySigmaLit).toBe("function");
    expect(typeof m1.verifySigmaG3).toBe("function");
    expect(typeof m1.verifySigmaG4).toBe("function");
  });

  it("re-exports M1 Shamir typed combiner (Shamir + combineDek)", () => {
    expect(typeof m1.combineDek).toBe("function");
    expect(typeof m1.Shamir).toBe("object");
    expect(m1.Shamir).not.toBeNull();
  });

  it("re-exports M1 codecs (commit_AAD, share-record, PDA root, commit_context)", () => {
    expect(typeof m1.encodeCommitAAD).toBe("function");
    expect(typeof m1.decodeCommitAAD).toBe("function");
    expect(typeof m1.computeAADDigest).toBe("function");
    expect(typeof m1.encodeShareRecord).toBe("function");
    expect(typeof m1.decodeShareRecord).toBe("function");
    expect(typeof m1.computePDARoot).toBe("function");
    expect(typeof m1.computeCommitContextDigest).toBe("function");
    expect(typeof m1.computeAttestationContextDigest).toBe("function");
  });

  it("re-exports M1 envelope encode/decode/verify", () => {
    expect(typeof m1.encodeAgeEnvelope).toBe("function");
    expect(typeof m1.decodeAgeEnvelope).toBe("function");
    expect(typeof m1.verifyEnvelope).toBe("function");
    expect(typeof m1.verifyEnvelopeStanzaMacs).toBe("function");
  });

  it("re-exports stanza + conditional-recipient MAC helpers", () => {
    expect(typeof m1.computeStanzaMac).toBe("function");
    expect(typeof m1.computeConditionalRecipientMac).toBe("function");
    expect(typeof m1.stanzaMacEquals).toBe("function");
    expect(typeof m1.conditionalRecipientMacEquals).toBe("function");
  });

  it("re-exports TAG_*_V3 constants as 0x-prefixed 32-byte hex", () => {
    expect(m1.TAG_COMMIT_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_AUTHID_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_SUBJECT_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_PDA_ROOT_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_AAD_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_AEAD_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_LIT_ACC_BINDING_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_DCIPHER_IBE_BINDING_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_DRAND_ROUND_BINDING_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_G3_BINDING_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_G4_ATTESTATION_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_G4_ATTESTATION_AUTHORITY_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_STANZA_MAC_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_STANZA_WRAP_V3).toMatch(/^0x[0-9a-f]{64}$/);
    expect(m1.TAG_ARTIFACT_V3).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("re-exports σ-verifier error enums", () => {
    expect(typeof m1.SigmaLitError).toBe("object");
    expect(typeof m1.SigmaG3Error).toBe("object");
    expect(typeof m1.SigmaG4Error).toBe("object");
    expect(typeof m1.SigmaSubjectError).toBe("object");
  });

  it("re-exports M1 active commit version (LOCKED 2026-05-05)", () => {
    expect(m1.ACTIVE_COMMIT_VERSION).toBe(0x0302);
  });

  it("re-exports share-record domain + role constants", () => {
    expect(m1.SHARE_DOMAIN_TOP_LEVEL).toBe(0x01);
    expect(m1.SHARE_DOMAIN_RECIPIENT_BRANCH).toBe(0x02);
    expect(m1.SHARE_ROLE_LIT).toBe(0x01);
    expect(m1.SHARE_ROLE_G3).toBe(0x02);
    expect(m1.SHARE_ROLE_G4).toBe(0x03);
    expect(m1.SHARE_ROLE_RECIPIENT_AGGREGATE).toBe(0x04);
    expect(m1.SHARE_ROLE_CONDITIONAL_RECIPIENT).toBe(0x05);
    expect(m1.SHARE_RECORD_BYTES).toBe(39);
  });

  it("re-exports G4 phase + signing-input constants", () => {
    expect(typeof m1.G4_PHASE).toBe("object");
    expect(m1.G4_PHASE1_SIGNING_INPUT_BYTES).toBe(168);
  });

  it("re-exports G3 choice constants", () => {
    expect(typeof m1.G3_CHOICE).toBe("object");
  });
});
