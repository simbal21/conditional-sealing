import { describe, it, expect } from "vitest";
import * as M1 from "../../src/m1-imports.js";

describe("M1 facade smoke (re-export from @cealis/v3-crypto)", () => {
  it("re-exports pda_root construction surface", () => {
    expect(typeof M1.computePDARoot).toBe("function");
    expect(typeof M1.buildPDARootPreimage).toBe("function");
    expect(typeof M1.zeroPDARootInput).toBe("function");
  });

  it("re-exports commit_AAD codec + digest", () => {
    expect(typeof M1.encodeCommitAAD).toBe("function");
    expect(typeof M1.decodeCommitAAD).toBe("function");
    expect(typeof M1.computeAADDigest).toBe("function");
    expect(typeof M1.validateCommitAAD).toBe("function");
    expect(typeof M1.ACTIVE_COMMIT_VERSION).toBe("number");
    expect(M1.ACTIVE_COMMIT_VERSION).toBe(0x0302);
  });

  it("re-exports commit_context helpers", () => {
    expect(typeof M1.buildCommitContextPreimage).toBe("function");
    expect(typeof M1.computeCommitContextDigest).toBe("function");
    expect(typeof M1.computeAttestationContextDigest).toBe("function");
  });

  it("re-exports σ verifiers (Lit, G3, G4)", () => {
    expect(typeof M1.verifySigmaLit).toBe("function");
    expect(typeof M1.verifySigmaG3).toBe("function");
    expect(typeof M1.verifySigmaG4).toBe("function");
    expect(typeof M1.buildSigmaLitSigningInput).toBe("function");
    expect(typeof M1.buildSigmaG3DcipherSigningInput).toBe("function");
    expect(typeof M1.buildDrandRoundMessage).toBe("function");
    expect(typeof M1.buildSigmaG4Phase1SigningInput).toBe("function");
    expect(M1.G3_CHOICE).toBeDefined();
    expect(M1.G4_PHASE).toBeDefined();
    expect(M1.G4_PHASE1_SIGNING_INPUT_BYTES).toBe(168);
  });

  it("re-exports TAG constants (30 V3 TAGs)", () => {
    // Spot-check the ones consumed by Phase B/C/D.
    expect(M1.TAG_PDA_ROOT_V3).toBeDefined();
    expect(M1.TAG_COMMIT_V3).toBeDefined();
    expect(M1.TAG_AAD_V3).toBeDefined();
    expect(M1.TAG_AEAD_V3).toBeDefined();
    expect(M1.TAG_G4_ATTESTATION_V3).toBeDefined();
    expect(M1.TAG_ARTIFACT_V3).toBeDefined();
  });
});
