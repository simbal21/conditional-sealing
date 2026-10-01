import { describe, expect, it } from "vitest";
import { SdBoundaryImpl } from "../boundary.js";

describe("asymmetric boundary", () => {
  it("does not call SD when escrow failed", async () => {
    let called = false;
    const result = await SdBoundaryImpl.executeIfEscrowOk({ kind: "err", failure: "vault" }, async () => {
      called = true;
      return { kind: "sd_ok", value: "nope" };
    });
    expect(called).toBe(false);
    expect(result.sd.kind).toBe("sd_skipped");
  });
});
