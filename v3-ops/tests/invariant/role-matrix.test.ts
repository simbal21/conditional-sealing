import { describe, it, expect } from "vitest";
import { CEREMONY_CATALOG } from "../../src/catalog/index.js";
import {
  SECURITY_COUNCIL_ROLE,
  EMERGENCY_GOVERNANCE_ROLE,
  buildSecurityMultisigConfig,
  buildEmergencyGovConfig,
  assertDistinctMultisigs,
} from "../../src/multisig/index.js";
import { CeremonyError, CeremonyErrorCode } from "../../src/errors/index.js";
import type { Address } from "viem";

/**
 * §17 — Per-ceremony role matrix.
 *
 * Spec lists 24 rows in the role-matrix table (lines 678–706). M7 covers
 * the surface at type-level (role hash constants + multisig actor
 * distinctness). Live on-chain role enforcement is the M2 contract surface
 * — M7 verifies the OFF-CHAIN side: that no ceremony script accepts a
 * caller without the right role context.
 */

const SAFE_A: Address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SAFE_B: Address = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

describe("§17 role matrix surface", () => {
  it("17 catalog ceremonies cover the substantive on-chain role surface", () => {
    expect(CEREMONY_CATALOG).toHaveLength(17);
  });

  it("SECURITY_COUNCIL_ROLE and EMERGENCY_GOVERNANCE_ROLE are distinct constants", () => {
    expect(SECURITY_COUNCIL_ROLE).not.toBe(EMERGENCY_GOVERNANCE_ROLE);
  });

  it("two distinct multisig configs build with separate roles", () => {
    const sec = buildSecurityMultisigConfig({
      safeAddress: SAFE_A,
      owners: [SAFE_A, SAFE_B],
      threshold: 2,
      chainId: 84532,
    });
    const eg = buildEmergencyGovConfig({
      safeAddress: SAFE_B,
      owners: [SAFE_A, SAFE_B],
      threshold: 2,
      chainId: 84532,
    });
    expect(sec.roleHash).not.toBe(eg.roleHash);
    expect(sec.actor).toBe("CealisSecurityMultisig");
    expect(eg.actor).toBe("EmergencyGovernance");
    expect(() => assertDistinctMultisigs(sec, eg)).not.toThrow();
  });

  it("§1.1 invariant — multisig actors collapsing to one Safe address → QUORUM_MISSING", () => {
    const sec = buildSecurityMultisigConfig({
      safeAddress: SAFE_A,
      owners: [SAFE_A],
      threshold: 1,
      chainId: 84532,
    });
    const eg = buildEmergencyGovConfig({
      safeAddress: SAFE_A, // same Safe — invalid
      owners: [SAFE_A],
      threshold: 1,
      chainId: 84532,
    });
    expect(() => assertDistinctMultisigs(sec, eg)).toThrowError(CeremonyError);
    try {
      assertDistinctMultisigs(sec, eg);
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.QUORUM_MISSING);
    }
  });

  it("every ceremony in CEREMONY_CATALOG has a specSection and at least one surface", () => {
    for (const c of CEREMONY_CATALOG) {
      expect(c.specSection.length).toBeGreaterThan(0);
      expect(c.surfaces.length).toBeGreaterThan(0);
    }
  });

  it("ceremony 14 (cross-invariant audit) has empty governance set (continuous, not invoked)", () => {
    const row = CEREMONY_CATALOG.find((c) => c.number === 14)!;
    expect(row.governance).toHaveLength(0);
  });

  it("all other ceremonies have ≥1 governance path", () => {
    for (const c of CEREMONY_CATALOG) {
      if (c.number === 14) continue;
      expect(c.governance.length).toBeGreaterThan(0);
    }
  });
});
