// Regression tests for the canonical-address pin (security-audit-2026-05-14 TS-CRYPTO-F-08).

import { describe, expect, it } from "vitest";
import {
  CANONICAL_ADDRESSES,
  CanonicalAddressMismatchError,
  assertCanonicalConditionEngineAddress,
  isCanonicalConditionEngineAddress,
} from "../../src/chain/canonical-addresses.js";

describe("canonical-address pin (TS-CRYPTO-F-08)", () => {
  const BASE_SEPOLIA_CHAIN_ID = 84_532;
  const CANONICAL_CE = "0xb09a8300423CA3BD0E028bAB6A6245A248520D02" as const;

  it("CANONICAL_ADDRESSES contains a Base Sepolia entry with the live deploy address", () => {
    const entry = CANONICAL_ADDRESSES.find((e) => e.chainId === BASE_SEPOLIA_CHAIN_ID);
    expect(entry).toBeDefined();
    expect(entry?.conditionEngine.toLowerCase()).toBe(CANONICAL_CE.toLowerCase());
  });

  it("CANONICAL_ADDRESSES is a Frozen array (compile-time pin discipline)", () => {
    expect(Object.isFrozen(CANONICAL_ADDRESSES)).toBe(true);
  });

  it("accepts the canonical address on the registered chainId", () => {
    expect(() =>
      assertCanonicalConditionEngineAddress(CANONICAL_CE, BASE_SEPOLIA_CHAIN_ID),
    ).not.toThrow();
  });

  it("accepts the canonical address regardless of EIP-55 checksum casing", () => {
    expect(() =>
      assertCanonicalConditionEngineAddress(
        CANONICAL_CE.toLowerCase() as `0x${string}`,
        BASE_SEPOLIA_CHAIN_ID,
      ),
    ).not.toThrow();
    expect(() =>
      assertCanonicalConditionEngineAddress(
        CANONICAL_CE.toUpperCase().replace("0X", "0x") as `0x${string}`,
        BASE_SEPOLIA_CHAIN_ID,
      ),
    ).not.toThrow();
  });

  it("throws CanonicalAddressMismatchError on a non-canonical address (Base Sepolia)", () => {
    expect(() =>
      assertCanonicalConditionEngineAddress(
        "0x0000000000000000000000000000000000000bad" as `0x${string}`,
        BASE_SEPOLIA_CHAIN_ID,
      ),
    ).toThrow(CanonicalAddressMismatchError);
  });

  it("throws on an unregistered chainId (e.g., mainnet before promotion)", () => {
    // Base Mainnet 8453 is intentionally NOT in CANONICAL_ADDRESSES until Phase H.
    expect(() =>
      assertCanonicalConditionEngineAddress(CANONICAL_CE, 8_453),
    ).toThrow(CanonicalAddressMismatchError);
  });

  it("isCanonicalConditionEngineAddress matches the assert semantics without throwing", () => {
    expect(isCanonicalConditionEngineAddress(CANONICAL_CE, BASE_SEPOLIA_CHAIN_ID)).toBe(true);
    expect(
      isCanonicalConditionEngineAddress(
        "0x0000000000000000000000000000000000000bad" as `0x${string}`,
        BASE_SEPOLIA_CHAIN_ID,
      ),
    ).toBe(false);
    expect(isCanonicalConditionEngineAddress(CANONICAL_CE, 8_453)).toBe(false);
  });
});
