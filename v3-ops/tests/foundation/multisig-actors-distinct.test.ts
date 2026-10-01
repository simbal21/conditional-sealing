import { describe, it, expect } from "vitest";
import {
  buildSecurityMultisigConfig,
  buildEmergencyGovConfig,
  assertDistinctMultisigs,
  SECURITY_COUNCIL_ROLE,
  EMERGENCY_GOVERNANCE_ROLE,
} from "../../src/multisig/index.js";
import { CeremonyError, CeremonyErrorCode } from "../../src/errors/index.js";
import type { Address } from "viem";

const SAFE_A: Address = "0xAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaa";
const SAFE_B: Address = "0xBBBBbbbbBBBBbbbbBBBBbbbbBBBBbbbbBBBBbbbb";
const OWNERS: readonly Address[] = [
  "0x1111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333",
];

/**
 * Drift catch #2: Two distinct multisig actors (S2-6 §1.1 lines 81–86).
 */
describe("Two distinct multisig actors (S2-6 §1.1)", () => {
  it("security + emergency configs build with correct actor labels", () => {
    const sec = buildSecurityMultisigConfig({
      safeAddress: SAFE_A,
      owners: OWNERS,
      threshold: 2,
      chainId: 84532,
    });
    const eg = buildEmergencyGovConfig({
      safeAddress: SAFE_B,
      owners: OWNERS,
      threshold: 2,
      chainId: 84532,
    });
    expect(sec.actor).toBe("CealisSecurityMultisig");
    expect(eg.actor).toBe("EmergencyGovernance");
  });

  it("distinct Safe addresses pass assertDistinctMultisigs", () => {
    const sec = buildSecurityMultisigConfig({
      safeAddress: SAFE_A,
      owners: OWNERS,
      threshold: 2,
      chainId: 84532,
    });
    const eg = buildEmergencyGovConfig({
      safeAddress: SAFE_B,
      owners: OWNERS,
      threshold: 2,
      chainId: 84532,
    });
    expect(() => assertDistinctMultisigs(sec, eg)).not.toThrow();
  });

  it("identical Safe addresses throw QUORUM_MISSING (would collapse to one Safe)", () => {
    const sec = buildSecurityMultisigConfig({
      safeAddress: SAFE_A,
      owners: OWNERS,
      threshold: 2,
      chainId: 84532,
    });
    const eg = buildEmergencyGovConfig({
      safeAddress: SAFE_A, // same address — invalid configuration
      owners: OWNERS,
      threshold: 2,
      chainId: 84532,
    });
    expect(() => assertDistinctMultisigs(sec, eg)).toThrowError(CeremonyError);
    try {
      assertDistinctMultisigs(sec, eg);
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.QUORUM_MISSING);
    }
  });

  it("role hashes are distinct", () => {
    expect(SECURITY_COUNCIL_ROLE).not.toBe(EMERGENCY_GOVERNANCE_ROLE);
  });
});
