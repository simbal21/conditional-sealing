import { describe, expect, it } from "vitest";
import { assertAuthorizedChannel } from "../../g4-phase1/server/channel-mtls.js";

describe("G4 Phase 1 channel identity", () => {
  it("rejects unauthenticated channel before sigma admission", () => {
    expect(() => assertAuthorizedChannel({ authenticated: false })).toThrow("mTLS");
  });

  it("rejects mismatched mTLS identity", () => {
    expect(() =>
      assertAuthorizedChannel({ authenticated: true, fingerprint256: "AA" }, "BB"),
    ).toThrow("identity");
  });
});
