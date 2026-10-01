import { describe, it, expect } from "vitest";
import { readEntryAt, type RegistryReader } from "../../src/registry/at-commit-block.js";
import type { TombstoneTuple } from "../../src/types/tombstone.js";
import { CeremonyError, CeremonyErrorCode } from "../../src/errors/index.js";

const HIST_TUPLE: TombstoneTuple = {
  hashOrRef: ("0x" + "11".repeat(32)) as `0x${string}`,
  effectiveBlock: 100n,
  tombstoneBlock: 200n,
};
const CURRENT_TUPLE: TombstoneTuple = {
  hashOrRef: ("0x" + "22".repeat(32)) as `0x${string}`,
  effectiveBlock: 250n,
  tombstoneBlock: 0n,
};

function makeReader(): RegistryReader {
  return {
    registryName: "MockRegistry",
    async getEntryAt(_ref, atBlock) {
      if (atBlock >= 100n && atBlock < 200n) return HIST_TUPLE;
      if (atBlock >= 250n) return CURRENT_TUPLE;
      return undefined;
    },
  };
}

/**
 * Drift catch #7: At-commit-block reading discipline (S2-6 §1.3 NORMATIVE).
 */
describe("readEntryAt (S2-6 §1.3)", () => {
  it("historical block returns the historical entry", async () => {
    const reader = makeReader();
    const tup = await readEntryAt(reader, "0xdeadbeef" as `0x${string}`, 150n);
    expect(tup.effectiveBlock).toBe(100n);
    expect(tup.tombstoneBlock).toBe(200n);
  });

  it("current head block returns the current entry (when valid)", async () => {
    const reader = makeReader();
    const tup = await readEntryAt(reader, "0xdeadbeef" as `0x${string}`, 300n);
    expect(tup.effectiveBlock).toBe(250n);
  });

  it("commitBlock === 0n throws COMMIT_BLOCK_MISMATCH", async () => {
    const reader = makeReader();
    await expect(
      readEntryAt(reader, "0xdeadbeef" as `0x${string}`, 0n),
    ).rejects.toThrowError(CeremonyError);
    try {
      await readEntryAt(reader, "0xdeadbeef" as `0x${string}`, 0n);
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.COMMIT_BLOCK_MISMATCH);
    }
  });

  it("registry returns no entry at the requested block → REGISTRY_COLLISION", async () => {
    const reader = makeReader();
    try {
      await readEntryAt(reader, "0xdeadbeef" as `0x${string}`, 220n); // gap between 200..249
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.REGISTRY_COLLISION);
    }
  });

  it("tombstoned entry at the asked block → TOMBSTONE_CONFLICT", async () => {
    // Build a reader that returns a tombstoned tuple at the asked block
    // (deliberately returns the historical tuple but at a block past its
    // tombstone — caller-side mistake the helper catches).
    const reader: RegistryReader = {
      registryName: "MockTombstoneRegistry",
      async getEntryAt() {
        return { ...HIST_TUPLE, effectiveBlock: 100n, tombstoneBlock: 200n };
      },
    };
    try {
      await readEntryAt(reader, "0xdeadbeef" as `0x${string}`, 250n);
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as CeremonyError).code).toBe(CeremonyErrorCode.TOMBSTONE_CONFLICT);
    }
  });
});
