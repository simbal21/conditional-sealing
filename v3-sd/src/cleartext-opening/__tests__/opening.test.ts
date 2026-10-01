import { describe, expect, it } from "vitest";
import { executeSdAtCommit } from "../../sd-plan/execute.js";
import { buildCleartextPlan, commitCtx, dek, payload } from "../../../tests/integration/helpers.js";

describe("cleartext opening smoke", () => {
  it("builds both opening modes", async () => {
    const plan = buildCleartextPlan();
    const result = await executeSdAtCommit({ plaintext: payload(), plan, dek: dek(), commit_ctx: commitCtx(plan) });
    expect(result.bundle.cleartext.map((c) => c.opening_mode).sort()).toEqual(["cleartext_attested", "cleartext_zk_opened"]);
  });
});
