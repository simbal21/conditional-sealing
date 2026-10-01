// F-CRYPTO-2 round-trip tests: deal/split is the EXACT inverse of §6.3 combine.
//
// For each access-structure profile (FIXED_ONLY, RECIPIENT_1_OF_1, RECIPIENT_K_OF_N):
//   1. split(DEK, profile) -> shares -> combineDek(shares) === DEK   (positive round-trip)
//   2. shares are DISTINCT and individually useless (no degenerate share==DEK shortcut)
//   3. below-threshold subsets fail                                  (negative)
//   4. wrong-branch substitution (surplus recipient share for missing G4) fails (negative)
//
// We inject a deterministic coefficient source so the test is reproducible, AND we run one
// case with the real CSPRNG default to prove the production path round-trips too.

import { describe, expect, it } from "vitest";

import {
  combineDek,
  type AccessStructureProfile,
} from "../../src/crypto/shamir.js";
import {
  DealDekError,
  dealDek,
  splitDek,
  type RandomBytesFn,
} from "../../src/crypto/deal-dek.js";
import {
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_ROLE_G4,
  type ShareRecord,
} from "../../src/codecs/share-record.js";

const DEK_BYTES = 32;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** A 32-byte DEK with a recognizable, non-degenerate byte pattern. */
function sampleDek(salt: number): Uint8Array {
  return Uint8Array.from({ length: DEK_BYTES }, (_, i) => (i * 7 + salt * 31 + 0x42) & 0xff);
}

/**
 * Deterministic, non-zero coefficient source for reproducible tests. A simple LCG over a byte
 * stream; remaps a zero output to 1 so the dealer's non-zero-leading-coefficient draw always
 * succeeds on the first attempt (keeps the test deterministic and fast).
 */
function deterministicRandomBytes(seed: number): RandomBytesFn {
  let state = (seed >>> 0) || 1;
  return (length: number): Uint8Array => {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      state = (state * 1664525 + 1013904223) >>> 0;
      const b = (state >>> 16) & 0xff;
      out[i] = b === 0 ? 1 : b;
    }
    return out;
  };
}

const PROFILES: Array<{ name: string; profile: AccessStructureProfile }> = [
  { name: "FIXED_ONLY", profile: { kind: "FIXED_ONLY" } },
  { name: "RECIPIENT_1_OF_1", profile: { kind: "RECIPIENT_1_OF_1" } },
  { name: "RECIPIENT_K_OF_N (k=2,n=3)", profile: { kind: "RECIPIENT_K_OF_N", n_conditional: 3, k_conditional: 2 } },
  { name: "RECIPIENT_K_OF_N (k=3,n=5)", profile: { kind: "RECIPIENT_K_OF_N", n_conditional: 5, k_conditional: 3 } },
];

function expectRoundTrip(profile: AccessStructureProfile, shares: ShareRecord[], dek: Uint8Array): void {
  const result = combineDek(shares, profile);
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(`combine failed: ${result.error}`);
  expect(bytesToHex(result.dek)).toBe(bytesToHex(dek));
}

describe("F-CRYPTO-2 dealDek — round-trips combineDek for every profile", () => {
  for (const { name, profile } of PROFILES) {
    it(`${name}: split(DEK) -> combineDek === DEK (deterministic coeffs)`, () => {
      const dek = sampleDek(13);
      const shares = dealDek(dek, profile, { randomBytesFn: deterministicRandomBytes(0xc0ffee) });
      expectRoundTrip(profile, shares, dek);
    });

    it(`${name}: split(DEK) -> combineDek === DEK (real CSPRNG default)`, () => {
      const dek = sampleDek(99);
      const shares = dealDek(dek, profile); // production path: real randomBytes
      expectRoundTrip(profile, shares, dek);
    });

    it(`${name}: shares are DISTINCT and individually useless (no share == DEK)`, () => {
      const dek = sampleDek(7);
      const shares = dealDek(dek, profile, { randomBytesFn: deterministicRandomBytes(0xbadf00d) });
      const dekHex = bytesToHex(dek);
      const seen = new Set<string>();
      for (const share of shares) {
        const shareHex = bytesToHex(share.value);
        // NOT the degenerate every-share == DEK shortcut.
        expect(shareHex).not.toBe(dekHex);
        // Each share value is distinct (the share-record codec also forbids duplicate (domain,x)).
        const key = `${share.share_domain}:${share.x}:${shareHex}`;
        expect(seen.has(key)).toBe(false);
        seen.add(key);
        // Right length, valid metadata.
        expect(share.value.length).toBe(DEK_BYTES);
      }
    });
  }

  it("splitDek is the same producer as dealDek", () => {
    expect(splitDek).toBe(dealDek);
  });

  it("two deals of the same DEK produce different shares (real entropy, not deterministic)", () => {
    const dek = sampleDek(55);
    const a = dealDek(dek, { kind: "FIXED_ONLY" });
    const b = dealDek(dek, { kind: "FIXED_ONLY" });
    // The reconstructed secret is identical...
    expectRoundTrip({ kind: "FIXED_ONLY" }, a, dek);
    expectRoundTrip({ kind: "FIXED_ONLY" }, b, dek);
    // ...but the share polynomials differ (overwhelmingly likely with real randomness).
    const aHex = a.map((s) => bytesToHex(s.value)).join("|");
    const bHex = b.map((s) => bytesToHex(s.value)).join("|");
    expect(aHex).not.toBe(bHex);
  });

  it("does not mutate the caller's DEK buffer", () => {
    const dek = sampleDek(3);
    const before = bytesToHex(dek);
    dealDek(dek, { kind: "FIXED_ONLY" });
    expect(bytesToHex(dek)).toBe(before);
  });
});

describe("F-CRYPTO-2 dealDek — produces the §6.3.2 typed share-record shape", () => {
  it("FIXED_ONLY emits exactly the 3 fixed top-level shares at x=1,2,3", () => {
    const shares = dealDek(sampleDek(1), { kind: "FIXED_ONLY" }, { randomBytesFn: deterministicRandomBytes(1) });
    expect(shares).toHaveLength(3);
    expect(shares.map((s) => s.x)).toEqual([1, 2, 3]);
    expect(shares.every((s) => s.share_domain === SHARE_DOMAIN_TOP_LEVEL)).toBe(true);
  });

  it("RECIPIENT_1_OF_1 emits 4 top-level shares incl. the aggregate at x=4", () => {
    const shares = dealDek(sampleDek(2), { kind: "RECIPIENT_1_OF_1" }, { randomBytesFn: deterministicRandomBytes(2) });
    expect(shares).toHaveLength(4);
    expect(shares.map((s) => s.x)).toEqual([1, 2, 3, 4]);
    expect(shares.every((s) => s.share_domain === SHARE_DOMAIN_TOP_LEVEL)).toBe(true);
  });

  it("RECIPIENT_K_OF_N emits 3 fixed top shares + n_conditional branch shares (no top aggregate)", () => {
    const profile: AccessStructureProfile = { kind: "RECIPIENT_K_OF_N", n_conditional: 5, k_conditional: 3 };
    const shares = dealDek(sampleDek(4), profile, { randomBytesFn: deterministicRandomBytes(4) });
    const top = shares.filter((s) => s.share_domain === SHARE_DOMAIN_TOP_LEVEL);
    const branch = shares.filter((s) => s.share_domain === SHARE_DOMAIN_RECIPIENT_BRANCH);
    expect(top).toHaveLength(3); // Lit/G3/G4 only — aggregate is NOT emitted at top level
    expect(branch).toHaveLength(5); // n_conditional branch shares
    expect(branch.map((s) => s.x)).toEqual([1, 2, 3, 4, 5]); // x = recipient_index + 1
    // any k_conditional branch shares reconstruct (combiner uses the first k); full set round-trips
    expectRoundTrip(profile, shares, sampleDek(4));
  });
});

describe("F-CRYPTO-2 dealDek — negative: below-threshold and wrong-branch substitution fail", () => {
  it("FIXED_ONLY: dropping any one of {Lit,G3,G4} fails (below threshold)", () => {
    const profile: AccessStructureProfile = { kind: "FIXED_ONLY" };
    const shares = dealDek(sampleDek(8), profile, { randomBytesFn: deterministicRandomBytes(8) });
    for (let drop = 0; drop < shares.length; drop++) {
      const subset = shares.filter((_, i) => i !== drop);
      const result = combineDek(subset, profile);
      expect(result.ok).toBe(false);
    }
  });

  it("RECIPIENT_1_OF_1: dropping the recipient aggregate fails (4-of-4 not met)", () => {
    const profile: AccessStructureProfile = { kind: "RECIPIENT_1_OF_1" };
    const shares = dealDek(sampleDek(9), profile, { randomBytesFn: deterministicRandomBytes(9) });
    const withoutAggregate = shares.slice(0, 3);
    const result = combineDek(withoutAggregate, profile);
    expect(result.ok).toBe(false);
  });

  it("RECIPIENT_K_OF_N: fewer than k_conditional branch shares fails", () => {
    const profile: AccessStructureProfile = { kind: "RECIPIENT_K_OF_N", n_conditional: 5, k_conditional: 3 };
    const shares = dealDek(sampleDek(10), profile, { randomBytesFn: deterministicRandomBytes(10) });
    const top = shares.filter((s) => s.share_domain === SHARE_DOMAIN_TOP_LEVEL);
    const branch = shares
      .filter((s) => s.share_domain === SHARE_DOMAIN_RECIPIENT_BRANCH)
      .slice(0, profile.k_conditional - 1); // one short
    const result = combineDek([...top, ...branch], profile);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.error).toBe("ERR_SHAMIR_THRESHOLD_NOT_MET");
  });

  it("RECIPIENT_K_OF_N: surplus recipient shares cannot substitute for a missing mandatory G4", () => {
    const profile: AccessStructureProfile = { kind: "RECIPIENT_K_OF_N", n_conditional: 5, k_conditional: 3 };
    const shares = dealDek(sampleDek(11), profile, { randomBytesFn: deterministicRandomBytes(11) });
    // Drop the G4 top-level share but keep ALL recipient branch shares.
    const withoutG4 = shares.filter(
      (s) => !(s.share_domain === SHARE_DOMAIN_TOP_LEVEL && s.share_role === SHARE_ROLE_G4),
    );
    const result = combineDek(withoutG4, profile);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected failure");
    expect(result.error).toBe("ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT");
  });

  it("cross-profile substitution: FIXED_ONLY shares do not combine under a recipient profile", () => {
    const fixedShares = dealDek(sampleDek(12), { kind: "FIXED_ONLY" }, { randomBytesFn: deterministicRandomBytes(12) });
    // FIXED_ONLY only deals 3 top shares; RECIPIENT_1_OF_1 needs the 4th aggregate.
    const result = combineDek(fixedShares, { kind: "RECIPIENT_1_OF_1" });
    expect(result.ok).toBe(false);
  });
});

describe("F-CRYPTO-2 dealDek — input validation", () => {
  it("rejects a DEK that is not 32 bytes", () => {
    expect(() => dealDek(new Uint8Array(16), { kind: "FIXED_ONLY" })).toThrow(DealDekError);
    expect(() => dealDek(new Uint8Array(33), { kind: "FIXED_ONLY" })).toThrow(DealDekError);
  });

  it("rejects an invalid RECIPIENT_K_OF_N profile (k > n)", () => {
    expect(() =>
      dealDek(sampleDek(1), { kind: "RECIPIENT_K_OF_N", n_conditional: 2, k_conditional: 3 }),
    ).toThrow(DealDekError);
  });

  it("rejects a profile with non-integer / out-of-range conditional counts", () => {
    expect(() =>
      dealDek(sampleDek(1), { kind: "RECIPIENT_K_OF_N", n_conditional: 0, k_conditional: 1 }),
    ).toThrow(DealDekError);
    expect(() =>
      dealDek(sampleDek(1), { kind: "RECIPIENT_K_OF_N", n_conditional: 300, k_conditional: 1 }),
    ).toThrow(DealDekError);
  });
});
