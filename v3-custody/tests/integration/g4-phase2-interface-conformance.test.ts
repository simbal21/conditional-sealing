import { describe, expect, it } from "vitest";
import { GateKind } from "../../src/types/gate-recipient.js";
import { G4Phase2Adapter, IS_DEFERRED } from "../../src/g4-phase2/index.js";

describe("G4 Phase 2 interface conformance", () => {
  it("is explicitly deferred and still implements the adapter surface", async () => {
    const adapter = new G4Phase2Adapter();
    expect(IS_DEFERRED).toBe(true);
    expect(adapter.gateKind).toBe(GateKind.G4);
    await expect(adapter.healthProbe()).resolves.toMatchObject({
      status: "unavailable",
      gateKind: GateKind.G4,
    });
  });
});
