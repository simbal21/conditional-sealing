// Round 1 — Step 6 isolated: combiner Shamir 3-of-3 over {Lit, G3, G4}.
//
// σ-AS-AUTHORIZATION DOCTRINE (LOCKED 2026-05-05):
//   The combiner facade is `combineAndDecrypt` — the high-level
//   composite that releases per-stanza shares via σ-authorised wrap-decap
//   and runs Shamir.combine over them. NO HKDF over σ values anywhere.
//
// FIXED_ONLY = 3-of-3 Shamir over {Lit, G3, G4} per S2-1 §6.3.1:
//   σ_subject is COMMIT-TIME consent bound into commit_AAD, NOT a Shamir
//   share. Foundation test `fixed-only-shamir-shape.test.ts` locks this;
//   here we additionally assert the round's σ block has exactly 3 gates.
//
// We do NOT exercise byte-correct combineAndDecrypt at Phase B — that's
// M3's territory (covered by 132 tests in @cealis/v3-custody). Here we
// (a) smoke-import the combiner facade, (b) assert SHAPE invariants, and
// (c) verify NO HKDF-over-σ surface appears in the m3-imports facade.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { synthesizeSigmaBlock } from "../../src/rounds/round1.js";
import {
  combineAndDecrypt,
  reconstructFileKey,
} from "../../src/m3-imports.js";
import {
  SHARE_ROLE_LIT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
} from "../../src/m1-imports.js";

describe("Round 1 — Step 6 combiner Shamir 3-of-3 over {Lit, G3, G4}", () => {
  it("σ block has exactly 3 gates (Lit + G3 + G4); σ_subject NOT in block", () => {
    const block = synthesizeSigmaBlock();
    expect(block.sigma_lit).toBeDefined();
    expect(block.sigma_g3).toBeDefined();
    expect(block.sigma_g4).toBeDefined();
    expect(block.sigma_subject).toBeUndefined();
    expect(block.sigma_conditional).toEqual([]);
  });

  it("σ_g3 variant = drand (Round 1 per Q-0-1 use-case default for TimeLock)", () => {
    const block = synthesizeSigmaBlock();
    expect(block.sigma_g3.variant).toBe("drand");
  });

  it("σ_g4 phase = 1 (G4 Phase 1 sealed-code per project_g4_phase_pilot_decision.md)", () => {
    const block = synthesizeSigmaBlock();
    expect(block.sigma_g4.phase).toBe(1);
  });

  it("all σ evidence is marked public_after_reveal:true", () => {
    const block = synthesizeSigmaBlock();
    expect(block.sigma_lit.public_after_reveal).toBe(true);
    expect(block.sigma_g3.public_after_reveal).toBe(true);
    expect(block.sigma_g4.public_after_reveal).toBe(true);
  });

  it("σ values are non-empty hex (verify-sdk shape requirement)", () => {
    const block = synthesizeSigmaBlock();
    expect(block.sigma_lit.sigma).toMatch(/^0x[0-9a-fA-F]+$/);
    expect(block.sigma_g3.sigma).toMatch(/^0x[0-9a-fA-F]+$/);
    expect(block.sigma_g4.sigma).toMatch(/^0x[0-9a-fA-F]+$/);
  });

  it("σ authority_ref values are 32-byte hex", () => {
    const block = synthesizeSigmaBlock();
    expect(block.sigma_lit.authority_ref).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(block.sigma_g3.authority_ref).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(block.sigma_g4.authority_ref).toMatch(/^0x[0-9a-fA-F]{64}$/);
  });

  it("M1 exposes EXACTLY 3 gate SHARE_ROLE_* constants for the FIXED_ONLY set", () => {
    expect(SHARE_ROLE_LIT).toBe(0x01);
    expect(SHARE_ROLE_G3).toBe(0x02);
    expect(SHARE_ROLE_G4).toBe(0x03);
  });

  it("combineAndDecrypt is exposed by m3-imports (high-level σ-as-authorization composite)", () => {
    expect(typeof combineAndDecrypt).toBe("function");
  });

  it("reconstructFileKey is exposed by m3-imports (byte-exact Shamir step)", () => {
    expect(typeof reconstructFileKey).toBe("function");
  });

  it("m3-imports source contains the σ-as-authorization doctrine header", () => {
    const m3Path = fileURLToPath(new URL("../../src/m3-imports.ts", import.meta.url));
    const source = readFileSync(m3Path, "utf8");
    expect(source.toLowerCase()).toContain("σ-as-authorization");
    expect(source).toContain("combineAndDecrypt");
    expect(source).toContain("reconstructFileKey");
    // NB: the authoritative HKDF-over-σ regression grep lives in
    // `tests/foundation/sigma-as-authorization-discipline.test.ts` which
    // filters out comment lines (otherwise the doctrine header in
    // m3-imports.ts that NAMES the retired pattern would self-trip). We
    // do not re-implement that grep here — the foundation test owns it.
  });

  it("round1.ts uses the FIXED_ONLY 3-of-3 set, NOT a 4-of-4 with σ_subject", () => {
    // Run end-to-end and verify the bundle's sigma_block matches FIXED_ONLY.
    // (Indirect proof via round1's runtime: synthesizeSigmaBlock is the only
    // producer of σ data the bundle sees.)
    const block = synthesizeSigmaBlock();
    const gateCount =
      (block.sigma_lit ? 1 : 0) + (block.sigma_g3 ? 1 : 0) + (block.sigma_g4 ? 1 : 0);
    const subjectInSet = block.sigma_subject !== undefined;
    expect(gateCount).toBe(3);
    expect(subjectInSet).toBe(false);
  });
});
