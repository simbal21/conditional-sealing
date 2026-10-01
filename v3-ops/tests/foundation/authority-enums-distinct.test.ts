import { describe, it, expect } from "vitest";
import {
  ShredAuthority,
  PauseAuthority,
  SHRED_AUTHORITY_MODES,
  PAUSE_AUTHORITY_MODES,
  isShredAuthority,
  isPauseAuthority,
} from "../../src/types/authority-enums.js";

/**
 * Drift catch #3: pause authority vocab `Partner / Joint / None` vs shred
 * authority vocab `Subject / Joint / Operator / Timelock / Disabled` are
 * DISTINCT enums. BP-S2-6-1 RESOLVED in S2-6 §21.2 line 787.
 */
describe("Pause vs Shred authority enums (S2-6 §11.1 + §12.2, BP-S2-6-1)", () => {
  it("shred has exactly 5 modes", () => {
    expect(SHRED_AUTHORITY_MODES).toHaveLength(5);
  });

  it("pause has exactly 3 modes", () => {
    expect(PAUSE_AUTHORITY_MODES).toHaveLength(3);
  });

  it("shred contains Subject + Operator + Timelock + Disabled (not in pause)", () => {
    expect(SHRED_AUTHORITY_MODES).toContain(ShredAuthority.SUBJECT);
    expect(SHRED_AUTHORITY_MODES).toContain(ShredAuthority.OPERATOR);
    expect(SHRED_AUTHORITY_MODES).toContain(ShredAuthority.TIMELOCK);
    expect(SHRED_AUTHORITY_MODES).toContain(ShredAuthority.DISABLED);
    // Pause does NOT have these
    expect(PAUSE_AUTHORITY_MODES).not.toContain("Subject");
    expect(PAUSE_AUTHORITY_MODES).not.toContain("Operator");
    expect(PAUSE_AUTHORITY_MODES).not.toContain("Timelock");
    expect(PAUSE_AUTHORITY_MODES).not.toContain("Disabled");
  });

  it("pause contains Partner + None (not in shred)", () => {
    expect(PAUSE_AUTHORITY_MODES).toContain(PauseAuthority.PARTNER);
    expect(PAUSE_AUTHORITY_MODES).toContain(PauseAuthority.NONE);
    expect(SHRED_AUTHORITY_MODES).not.toContain("Partner");
    expect(SHRED_AUTHORITY_MODES).not.toContain("None");
  });

  it("Joint appears in both enums (only legitimate overlap)", () => {
    expect(SHRED_AUTHORITY_MODES).toContain(ShredAuthority.JOINT);
    expect(PAUSE_AUTHORITY_MODES).toContain(PauseAuthority.JOINT);
  });

  it("type-guard helpers reject cross-enum inputs", () => {
    expect(isShredAuthority("Partner")).toBe(false);
    expect(isShredAuthority("Subject")).toBe(true);
    expect(isPauseAuthority("Subject")).toBe(false);
    expect(isPauseAuthority("Partner")).toBe(true);
  });
});
