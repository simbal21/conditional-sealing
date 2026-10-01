import { describe, it, expect } from "vitest";
import * as M3 from "../../src/m3-imports.js";

describe("M3 facade smoke (re-export from @cealis/v3-custody)", () => {
  it("re-exports G2 Lit adapter", () => {
    expect(typeof M3.createLitAdapter).toBe("function");
  });

  it("re-exports G3 dispatch + dcipher + drand", () => {
    expect(typeof M3.dispatchG3).toBe("function");
    expect(typeof M3.readG3Choice).toBe("function");
    expect(typeof M3.createDcipherAdapter).toBe("function");
    expect(typeof M3.createDrandAdapter).toBe("function");
  });

  it("re-exports G4 Phase 1 + Phase 2 adapters + factory helpers", () => {
    expect(M3.G4Phase1Adapter).toBeDefined();
    expect(M3.G4Phase2Adapter).toBeDefined();
    expect(M3.G4Phase).toBeDefined();
    expect(typeof M3.createG4Phase1Adapter).toBe("function");
    expect(typeof M3.createG4Phase2Adapter).toBe("function");
  });

  it("re-exports combiner SDK core pipeline functions", () => {
    expect(typeof M3.combineAndDecrypt).toBe("function");
    expect(typeof M3.runPreVerifyPipeline).toBe("function");
    expect(typeof M3.decryptAeadPayload).toBe("function");
    expect(typeof M3.assembleRevealArtifactBundle).toBe("function");
    expect(typeof M3.jcsCanonicalize).toBe("function");
    expect(typeof M3.jcsDigest).toBe("function");
  });

  it("re-exports combiner SDK verifiers", () => {
    expect(typeof M3.verifyRegistrySnapshots).toBe("function");
    expect(typeof M3.verifyGateRecipientPubkeys).toBe("function");
    expect(typeof M3.orchestrateSigmas).toBe("function");
    expect(typeof M3.rejectMode3).toBe("function");
    expect(typeof M3.assertShredStateSignable).toBe("function");
    expect(typeof M3.verifySupersessionLineage).toBe("function");
    expect(typeof M3.verifyPluginIntegrity).toBe("function");
    expect(typeof M3.assertCrossVendorTeeDisjoint).toBe("function");
    expect(typeof M3.applyRuntimeHardening).toBe("function");
    expect(typeof M3.reconstructFileKey).toBe("function");
    expect(typeof M3.dispatchProfile).toBe("function");
  });

  it("re-exports refusal-code helpers (10-code enum + predicates)", () => {
    expect(M3.RefusalCode).toBeDefined();
    expect(M3.REFUSAL_CODES).toBeDefined();
    expect(M3.REFUSAL_CODE_COUNT).toBe(10);
    expect(typeof M3.isBlocking).toBe("function");
    expect(typeof M3.isAdvisory).toBe("function");
    expect(typeof M3.isEncryptedReasonMode).toBe("function");
  });
});
