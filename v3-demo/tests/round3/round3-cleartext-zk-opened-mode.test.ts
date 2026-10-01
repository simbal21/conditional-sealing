// M8 Round 3 — Cleartext mode = cleartext_zk_opened DEFAULT (Step 1 + §4.4).
//
// Per S2-7 §4.4 lines 466-477 (LOCKED):
//   - DEFAULT for regulated partner integrations: `cleartext_zk_opened`
//   - Alternate (TEE attestation): `cleartext_attested` — must be marked
//     explicitly in `SdBundle.cleartext[*].opening_mode`.
//
// Round 3 happy path uses the DEFAULT mode. The cleartext field carries:
//   - field_commitment = Poseidon5(tag, authorization, field_id, salt, value)
//   - opening_mode = "cleartext_zk_opened"
//   - opening_proof (PLONK equality circuit; absent in synthetic test path)

import { describe, it, expect } from "vitest";
import { runRound3Structural } from "../../src/rounds/round3.js";
import { CLEARTEXT_OPENING_DEFAULT_LABEL } from "../../src/m6-imports.js";

describe("Round 3 — Cleartext mode = cleartext_zk_opened DEFAULT (§4.4)", () => {
  it("Round 3 result records the cleartext-opening default label", async () => {
    const result = await runRound3Structural();
    expect(result.cleartextOpeningModeLabel).toBe("cleartext_zk_opened");
  });

  it("CLEARTEXT_OPENING_DEFAULT_LABEL exported by M6 facade equals 'cleartext_zk_opened'", () => {
    expect(CLEARTEXT_OPENING_DEFAULT_LABEL).toBe("cleartext_zk_opened");
  });

  it("every cleartext item in the bundle uses cleartext_zk_opened mode", async () => {
    const result = await runRound3Structural();
    for (const item of result.recipient.sdBundle.cleartext) {
      expect(item.opening_mode).toBe("cleartext_zk_opened");
    }
  });

  it("cleartext items carry field_commitment + merkle_path fields per App. I.5", async () => {
    const result = await runRound3Structural();
    const first = result.recipient.sdBundle.cleartext[0];
    expect(first).toBeDefined();
    if (first === undefined) return;
    expect(first.field_id).toMatch(/^0x[0-9a-f]{64}$/);
    expect(first.field_commitment).toMatch(/^0x[0-9a-f]{64}$/);
    expect(Array.isArray(first.merkle_path)).toBe(true);
    expect(first.policy_code).toBe(1);
  });
});
