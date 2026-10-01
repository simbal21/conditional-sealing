import { describe, it, expect } from "vitest";
import {
  CEREMONY_ERROR_CODES,
  CeremonyErrorCode,
  CeremonyError,
} from "../../src/errors/index.js";

/**
 * Drift catch #4: 9-class CEREMONY_ERR_* enum LOCKED at S2-6 §1.7 lines
 * 112–122. Names are verbatim.
 */
describe("CeremonyErrorCode catalog (S2-6 §1.7)", () => {
  it("contains exactly 9 codes", () => {
    expect(CEREMONY_ERROR_CODES).toHaveLength(9);
  });

  it("matches the 9 verbatim S2-6 §1.7 names", () => {
    const expected = [
      "CEREMONY_ERR_GOVERNANCE_TIMEOUT",
      "CEREMONY_ERR_REGISTRY_COLLISION",
      "CEREMONY_ERR_QUORUM_MISSING",
      "CEREMONY_ERR_TIMELOCK_NOT_EXPIRED",
      "CEREMONY_ERR_TOMBSTONE_CONFLICT",
      "CEREMONY_ERR_DEPRECATION_DISCLOSURE_MISSING",
      "CEREMONY_ERR_COMMIT_BLOCK_MISMATCH",
      "CEREMONY_ERR_TRIPWIRE_BYPASS",
      "CEREMONY_ERR_PII_IN_LOG",
    ];
    expect([...CEREMONY_ERROR_CODES].sort()).toEqual([...expected].sort());
  });

  it("CeremonyError carries code + stage + frozen safeRefs", () => {
    const err = new CeremonyError(
      CeremonyErrorCode.TIMELOCK_NOT_EXPIRED,
      "execute",
      { entryId: ("0x" + "ab".repeat(32)) as `0x${string}` },
    );
    expect(err.code).toBe("CEREMONY_ERR_TIMELOCK_NOT_EXPIRED");
    expect(err.stage).toBe("execute");
    expect(Object.isFrozen(err.safeRefs)).toBe(true);
    expect(err.name).toBe("CeremonyError");
  });

  it("rejects any unknown code via union narrowing (type-level only)", () => {
    // This is a compile-time-only check; we assert the runtime values are
    // all members of the named enum.
    for (const code of CEREMONY_ERROR_CODES) {
      const all = Object.values(CeremonyErrorCode) as readonly string[];
      expect(all).toContain(code);
    }
  });
});
