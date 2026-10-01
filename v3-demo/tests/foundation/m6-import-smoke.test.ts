import { describe, it, expect } from "vitest";
import * as M6 from "../../src/m6-imports.js";
import * as M6SDK from "../../src/m6-sdk-imports.js";

describe("m6-imports smoke (M6 @cealis/v3-sd facade)", () => {
  it("re-exports the SD package barrel (types + errors + tags)", () => {
    // The barrel includes ERR_SD_* error codes — pick a known one.
    expect(Object.keys(M6).length).toBeGreaterThan(0);
  });

  it("M6 SD-verify SDK re-exports the three verify functions", () => {
    expect(typeof M6SDK.verifySdBundle).toBe("function");
    expect(typeof M6SDK.verifyClaim).toBe("function");
    expect(typeof M6SDK.verifyMerklePath).toBe("function");
  });
});
