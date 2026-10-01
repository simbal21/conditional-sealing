import { describe, it, expect } from "vitest";
import {
  GovernancePath,
  GOVERNANCE_PATHS,
} from "../../src/types/ceremony.js";
import {
  GOVERNANCE_PATH_SPECS,
  ALL_GOVERNANCE_PATHS,
} from "../../src/multisig/governance-paths.js";

/**
 * Drift catch #19: 5 asymmetric governance paths per S2-6 §13.6 + §13.7.
 */
describe("Governance paths (S2-6 §13.6 + §13.7)", () => {
  it("has exactly 5 paths", () => {
    expect(GOVERNANCE_PATHS).toHaveLength(5);
    expect(ALL_GOVERNANCE_PATHS).toHaveLength(5);
  });

  it("TIMELOCK_7D_ADDITION uses 7-day delay via TimelockController", () => {
    const spec = GOVERNANCE_PATH_SPECS[GovernancePath.TIMELOCK_7D_ADDITION];
    expect(spec.delaySeconds).toBe(7 * 24 * 60 * 60);
    expect(spec.actor).toBe("TimelockController");
    expect(spec.requiresDisclosure).toBe(false);
  });

  it("EXPEDITED_24H_DEPRECATION uses 24h delay via CealisSecurityMultisig with disclosure", () => {
    const spec = GOVERNANCE_PATH_SPECS[GovernancePath.EXPEDITED_24H_DEPRECATION];
    expect(spec.delaySeconds).toBe(24 * 60 * 60);
    expect(spec.actor).toBe("CealisSecurityMultisig");
    expect(spec.requiresDisclosure).toBe(true);
  });

  it("INSTANT_NON_CANONICAL_DEPRECATION is 0-delay via CealisSecurityMultisig", () => {
    const spec = GOVERNANCE_PATH_SPECS[GovernancePath.INSTANT_NON_CANONICAL_DEPRECATION];
    expect(spec.delaySeconds).toBe(0);
    expect(spec.actor).toBe("CealisSecurityMultisig");
  });

  it("AUTO_CLEAR_72H is permissionless after 72h", () => {
    const spec = GOVERNANCE_PATH_SPECS[GovernancePath.AUTO_CLEAR_72H];
    expect(spec.delaySeconds).toBe(72 * 60 * 60);
    expect(spec.actor).toBe("Permissionless");
    expect(spec.cooldownSeconds).toBe(30 * 24 * 60 * 60);
  });

  it("COOLDOWN_30D triggers TimelockController for re-deprecation", () => {
    const spec = GOVERNANCE_PATH_SPECS[GovernancePath.COOLDOWN_30D];
    expect(spec.delaySeconds).toBe(30 * 24 * 60 * 60);
    expect(spec.actor).toBe("TimelockController");
  });
});
