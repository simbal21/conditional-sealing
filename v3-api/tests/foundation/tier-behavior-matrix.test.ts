import { describe, it, expect } from "vitest";
import {
  OPERATIONAL_CLASSES,
  TIER_BEHAVIOR_AXES,
  TIER_BEHAVIOR_AXIS_COUNT,
  TIER_BEHAVIOR_CLASS_COUNT,
  TIER_BEHAVIOR_MATRIX,
  UNIVERSAL_TRIPWIRE_STATEMENT,
  TRUST_TIERS,
  type TierBehaviorAxis,
  type OperationalClass,
} from "../../src/types/tier-behavior.js";

describe("Per-PDA-tier behavior matrix (S2-5 §12 NORMATIVE — 12 × 4)", () => {
  it("locks exactly 12 behavior axes", () => {
    expect(TIER_BEHAVIOR_AXES.length).toBe(12);
    expect(TIER_BEHAVIOR_AXIS_COUNT).toBe(12);
  });

  it("locks exactly 4 operational classes", () => {
    expect(OPERATIONAL_CLASSES.length).toBe(4);
    expect(TIER_BEHAVIOR_CLASS_COUNT).toBe(4);
    expect(OPERATIONAL_CLASSES).toEqual(["consumer", "b2b_partner", "regulated", "legal_effect"]);
  });

  it("every axis has a value for every operational class (12 × 4 grid full)", () => {
    for (const axis of TIER_BEHAVIOR_AXES) {
      const row = TIER_BEHAVIOR_MATRIX[axis as TierBehaviorAxis];
      expect(row, `axis missing: ${axis}`).toBeDefined();
      for (const cls of OPERATIONAL_CLASSES) {
        const cell = row[cls as OperationalClass];
        expect(cell, `cell missing: ${axis} × ${cls}`).toBeDefined();
        expect(typeof cell).toBe("string");
        expect(cell.length).toBeGreaterThan(0);
      }
    }
  });

  it("g4_phase axis: regulated + legal_effect require Phase 2 (§12 line 1085)", () => {
    expect(TIER_BEHAVIOR_MATRIX.g4_phase.regulated).toBe("Phase 2 required");
    expect(TIER_BEHAVIOR_MATRIX.g4_phase.legal_effect).toBe("Phase 2 required");
  });

  it("subject_auth axis: legal_effect requires QTSP when qes_subject_required true", () => {
    expect(TIER_BEHAVIOR_MATRIX.subject_auth.legal_effect).toContain("QTSP");
  });

  it("retention_floor axis: b2b_partner = obligation + 3 years default", () => {
    expect(TIER_BEHAVIOR_MATRIX.retention_floor.b2b_partner).toContain("3 years");
  });

  it("artifact_verification axis: SDK required at b2b_partner and stricter", () => {
    expect(TIER_BEHAVIOR_MATRIX.artifact_verification.consumer).toContain("recommended");
    expect(TIER_BEHAVIOR_MATRIX.artifact_verification.b2b_partner).toContain("required");
    expect(TIER_BEHAVIOR_MATRIX.artifact_verification.regulated).toContain("required");
    expect(TIER_BEHAVIOR_MATRIX.artifact_verification.legal_effect).toContain("required");
  });

  it("trust tiers locked at 3 (tier_a, tier_b, tier_c)", () => {
    expect(TRUST_TIERS).toEqual(["tier_a", "tier_b", "tier_c"]);
  });

  it("universal tripwire statement is canonical verbatim", () => {
    expect(UNIVERSAL_TRIPWIRE_STATEMENT).toContain("No tier may bypass the universal tripwire");
    expect(UNIVERSAL_TRIPWIRE_STATEMENT).toContain("do not create alternate release conditions");
  });
});
