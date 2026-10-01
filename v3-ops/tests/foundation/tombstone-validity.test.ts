import { describe, it, expect } from "vitest";
import { isValidAtBlock, type TombstoneTuple } from "../../src/types/tombstone.js";

const REF = "0xabcdef" as `0x${string}`;

/**
 * Drift catch #6: Tombstone tuple validity rule per S2-6 §1.4 lines 96–98:
 *   entry valid at block B  iff  effective_block <= B AND
 *                                (tombstone_block == 0n OR B < tombstone_block).
 */
describe("isValidAtBlock (S2-6 §1.4)", () => {
  it("returns false before effective_block", () => {
    const t: TombstoneTuple = { hashOrRef: REF, effectiveBlock: 100n, tombstoneBlock: 0n };
    expect(isValidAtBlock(t, 99n)).toBe(false);
  });

  it("returns true AT effective_block (inclusive)", () => {
    const t: TombstoneTuple = { hashOrRef: REF, effectiveBlock: 100n, tombstoneBlock: 0n };
    expect(isValidAtBlock(t, 100n)).toBe(true);
  });

  it("returns true when tombstone_block === 0 (no future expiry)", () => {
    const t: TombstoneTuple = { hashOrRef: REF, effectiveBlock: 100n, tombstoneBlock: 0n };
    expect(isValidAtBlock(t, 1_000_000n)).toBe(true);
  });

  it("returns true BEFORE tombstone_block (exclusive)", () => {
    const t: TombstoneTuple = { hashOrRef: REF, effectiveBlock: 100n, tombstoneBlock: 200n };
    expect(isValidAtBlock(t, 199n)).toBe(true);
  });

  it("returns false AT tombstone_block (exclusive)", () => {
    const t: TombstoneTuple = { hashOrRef: REF, effectiveBlock: 100n, tombstoneBlock: 200n };
    expect(isValidAtBlock(t, 200n)).toBe(false);
  });

  it("returns false after tombstone_block", () => {
    const t: TombstoneTuple = { hashOrRef: REF, effectiveBlock: 100n, tombstoneBlock: 200n };
    expect(isValidAtBlock(t, 300n)).toBe(false);
  });
});
