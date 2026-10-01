import { describe, it, expect } from "vitest";
import * as M3 from "../../src/m3-imports.js";

describe("m3-imports smoke (M3 @cealis/v3-custody facade)", () => {
  it("re-exports combineAndDecrypt (high-level σ-as-authorization composite)", () => {
    expect(typeof M3.combineAndDecrypt).toBe("function");
  });

  it("re-exports reconstructFileKey (byte-exact Shamir step)", () => {
    expect(typeof M3.reconstructFileKey).toBe("function");
  });

  it("re-exports gate adapters: Lit + drand + G4 Phase 1 + G4 Phase 2", () => {
    expect(typeof M3.createLitAdapter).toBe("function");
    expect(typeof M3.createDrandAdapter).toBe("function");
    expect(typeof M3.createG4Phase1Adapter).toBe("function");
    expect(typeof M3.createG4Phase2Adapter).toBe("function");
    expect(typeof M3.G4Phase1Adapter).toBe("function");
    expect(typeof M3.G4Phase2Adapter).toBe("function");
  });

  it("re-exports dcipher adapter constructor (M8 unused but surface preserved)", () => {
    expect(typeof M3.createDcipherAdapter).toBe("function");
  });

  it("re-exports G3 dispatch helpers", () => {
    expect(typeof M3.dispatchG3).toBe("function");
    expect(typeof M3.readG3Choice).toBe("function");
  });

  it("re-exports pre-verify pipeline + σ orchestrator + artifact bundle assembler", () => {
    expect(typeof M3.runPreVerifyPipeline).toBe("function");
    expect(typeof M3.orchestrateSigmas).toBe("function");
    expect(typeof M3.assembleM3RevealArtifactBundle).toBe("function");
  });

  it("re-exports CustodyError + CUSTODY_ERROR_CODES catalog", () => {
    expect(typeof M3.CustodyError).toBe("function");
    expect(typeof M3.CUSTODY_ERROR_CODES).toBe("object");
    expect(Object.keys(M3.CUSTODY_ERROR_CODES).length).toBeGreaterThan(0);
  });
});
