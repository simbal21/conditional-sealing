import { describe, expect, it } from "vitest";
import { executeSdAtCommit } from "../../src/sd-plan/execute.js";
import { buildCleartextPlan, commitCtx, dek, payload } from "./helpers.js";

describe("cleartext opening builders", () => {
  it("emits zk_opened proof path and tee_attested digest path", async () => {
    const plan = buildCleartextPlan();
    const result = await executeSdAtCommit({
      plaintext: payload(),
      plan,
      dek: dek(),
      commit_ctx: commitCtx(plan),
    });
    expect(result.bundle.status).toBe("complete");
    const zk = result.bundle.cleartext.find((item) => item.opening_mode === "cleartext_zk_opened");
    const tee = result.bundle.cleartext.find((item) => item.opening_mode === "cleartext_attested");
    expect(zk?.opening_proof?.proof_system).toBe("plonk-bn254");
    expect(zk?.merkle_path.length).toBeGreaterThan(0);
    expect(tee?.cleartext_attestation_digest).toMatch(/^0x[0-9a-f]{64}$/);
    expect(tee?.merkle_path.length).toBeGreaterThan(0);
  });
});
