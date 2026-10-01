import { describe, expect, it } from "vitest";
import {
  CUSTODY_ERROR_CODES,
  combineAndDecrypt,
  computeCanonicalBinaryHash,
} from "../../src/index.js";
import { hex32, makeFixture } from "./combiner-testkit.js";

describe("combiner plugin integrity", () => {
  it("aborts when the plugin hash was tombstoned before authorization", () => {
    const result = combineAndDecrypt(makeFixture({ pluginTombstoneBlock: 15n }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
      expect(result.subCodes).toContain("ERR_REGISTRY_DEPRECATED_PRE_AUTHORIZATION");
    }
  });

  it("rejects plugin digest, effective-block, and binary hash mismatches before sigma handling", () => {
    const digestMismatch = makeFixture();
    const digestResult = combineAndDecrypt({
      ...digestMismatch,
      registrySnapshots: {
        ...digestMismatch.registrySnapshots,
        commitSnapshot: {
          ...digestMismatch.registrySnapshots.commitSnapshot,
          plugin: {
            ...digestMismatch.registrySnapshots.commitSnapshot.plugin,
            pluginVersionDigest: hex32(0x99),
          },
        },
      },
    });
    expect(digestResult.ok).toBe(false);
    if (!digestResult.ok) expect(digestResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);

    const futureEffective = makeFixture();
    const futureResult = combineAndDecrypt({
      ...futureEffective,
      registrySnapshots: {
        ...futureEffective.registrySnapshots,
        commitSnapshot: {
          ...futureEffective.registrySnapshots.commitSnapshot,
          plugin: {
            ...futureEffective.registrySnapshots.commitSnapshot.plugin,
            effectiveBlock: 21n,
          },
        },
      },
    });
    expect(futureResult.ok).toBe(false);
    if (!futureResult.ok) expect(futureResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);

    const prior = process.env.CEALIS_COMBINER_BINARY_HASH;
    process.env.CEALIS_COMBINER_BINARY_HASH = hex32(0x98);
    try {
      const binaryResult = combineAndDecrypt(makeFixture());
      expect(binaryResult.ok).toBe(false);
      if (!binaryResult.ok) expect(binaryResult.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
    } finally {
      if (prior === undefined) delete process.env.CEALIS_COMBINER_BINARY_HASH;
      else process.env.CEALIS_COMBINER_BINARY_HASH = prior;
    }
  });

  it("computes canonical binary hash from an explicit seed when supplied", () => {
    const prior = process.env.CEALIS_COMBINER_BINARY_SEED;
    process.env.CEALIS_COMBINER_BINARY_SEED = "seeded-combiner-binary";
    try {
      expect(computeCanonicalBinaryHash(hex32(0x45))).toHaveLength(32);
    } finally {
      if (prior === undefined) delete process.env.CEALIS_COMBINER_BINARY_SEED;
      else process.env.CEALIS_COMBINER_BINARY_SEED = prior;
    }
  });
});
