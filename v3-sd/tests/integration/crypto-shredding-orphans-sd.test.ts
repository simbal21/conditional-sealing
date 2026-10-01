import { describe, expect, it } from "vitest";
import { RevocationWorker } from "../../src/onchain/revocation-worker.js";
import { b32 } from "./helpers.js";

describe("§13 crypto-shredding interaction", () => {
  it("mock ShredRegistry revokes active SD disclosures without claiming partner-held proof deletion", async () => {
    const writes: unknown[] = [];
    const worker = new RevocationWorker({
      publicClient: { watchEvent: () => () => undefined } as never,
      walletClient: { writeContract: async (call: unknown) => { writes.push(call); return "0xabc"; } } as never,
      shredRegistryAddress: "0x0000000000000000000000000000000000000001",
      revocationRegistryAddress: "0x0000000000000000000000000000000000000002",
      disclosureIndex: { listActiveUnexpiredDisclosureIds: async () => [`0x${"01".repeat(32)}`, `0x${"02".repeat(32)}`] },
    });
    const result = await worker.handleShredFinalized({ authorizationId: `0x${Buffer.from(b32("auth")).toString("hex")}`, hCommit: "0x00", proofShred: "0x00", blockNumber: 7n });
    expect(result.attempted).toBe(2);
    expect(result.revoked).toBe(2);
    expect(writes).toHaveLength(2);
  });
});
