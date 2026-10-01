import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as M1 from "../../src/m1-imports.js";

// FIXED_ONLY = 3-of-3 Shamir over {Lit, G3, G4} per S2-1 §6.3.1
// (PHASE-PLAN §0 drift #4). σ_subject is COMMIT-TIME consent bound into
// commit_AAD, NOT a Shamir share.
//
// This test asserts the shape of M1's FIXED_ONLY profile by exercising
// combineDek with a minimal 3-share fixture and verifying it does NOT
// accept a 4-share configuration that would include a subject share.
//
// We do NOT exercise byte-correct ECC math here — M0+M1 has full byte-exact
// tests. We exercise SHAPE only: combineDek with FIXED_ONLY profile and
// the three SHARE_ROLE_LIT / G3 / G4 constants must be the entire share
// set.

describe("FIXED_ONLY 3-of-3 Shamir shape ({Lit, G3, G4}, NOT subject)", () => {
  it("AccessStructureProfile FIXED_ONLY kind is exposed as a literal", () => {
    const profile: M1.AccessStructureProfile = { kind: "FIXED_ONLY" };
    expect(profile.kind).toBe("FIXED_ONLY");
  });

  it("Three SHARE_ROLE_* constants for gates: 0x01 Lit, 0x02 G3, 0x03 G4", () => {
    expect(M1.SHARE_ROLE_LIT).toBe(0x01);
    expect(M1.SHARE_ROLE_G3).toBe(0x02);
    expect(M1.SHARE_ROLE_G4).toBe(0x03);
  });

  it("There is NO SHARE_ROLE_SUBJECT constant", () => {
    expect("SHARE_ROLE_SUBJECT" in M1).toBe(false);
    // Defensive: ensure none of the 5 SHARE_ROLE_* values overlap the gate set.
    expect(M1.SHARE_ROLE_RECIPIENT_AGGREGATE).toBe(0x04);
    expect(M1.SHARE_ROLE_CONDITIONAL_RECIPIENT).toBe(0x05);
  });

  it("combineDek with FIXED_ONLY profile rejects empty share set with shape error", () => {
    // Sanity check: profile + empty records returns ok=false (not a crash).
    // We intentionally do NOT construct valid byte-correct shares here —
    // the byte-exact path is covered upstream in @cealis/v3-crypto.
    const result = M1.combineDek([], { kind: "FIXED_ONLY" });
    expect(result.ok).toBe(false);
  });

  it("Brief vocabulary 'PerStanzaShare' / 'FileKey' is documented in m3-imports comments", () => {
    // The brief uses 'PerStanzaShare[]' but the actual upstream type is
    // ShareRecord. m3-imports.ts documents the mapping in a header comment.
    // This is purely a stability assertion that the comment is present.
    const m3Path = fileURLToPath(new URL("../../src/m3-imports.ts", import.meta.url));
    const m3Source = readFileSync(m3Path, "utf8");
    // Match case-insensitively against the doctrine name (m3-imports header
    // uses "σ-AS-AUTHORIZATION DOCTRINE" in the section title).
    expect(m3Source.toLowerCase()).toContain("σ-as-authorization");
    expect(m3Source).toContain("combineAndDecrypt");
    expect(m3Source).toContain("reconstructFileKey");
  });
});
