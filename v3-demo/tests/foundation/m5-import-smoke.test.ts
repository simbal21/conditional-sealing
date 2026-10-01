import { describe, it, expect } from "vitest";
import * as M5 from "../../src/m5-imports.js";

describe("m5-imports smoke (M5 @cealis/v3-api facade)", () => {
  it("re-exports the ingest entry point + in-memory repository", () => {
    expect(typeof M5.createModeAIngestion).toBe("function");
    expect(typeof M5.InMemoryIngestionRepository).toBe("function");
    expect(M5.defaultIngestionRepository).toBeDefined();
  });

  it("re-exports reveal bundle assembly + storage ref helpers", () => {
    expect(typeof M5.assembleRevealArtifactBundle).toBe("function");
    expect(typeof M5.bundleStorageRef).toBe("function");
  });

  it("re-exports event-driven reveal entry point (combiner-orchestrator)", () => {
    expect(typeof M5.processRevealAuthorizedEvent).toBe("function");
  });
});
