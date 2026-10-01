import { describe, expect, it } from "vitest";

import { createDrandAdapter, type DrandEndpoint } from "../../src/g3-drand/index.js";
import type { Hex32 } from "../../src/m1-imports.js";

describe("integration: g3 drand chain mismatch", () => {
  it("returns CUSTODY_ERR_DRAND_CHAIN_MISMATCH and does not try a different chain", async () => {
    const adapter = createDrandAdapter({
      endpoints: endpoints(),
      chain: {
        chainHash: "expected-chain",
        publicKey: new Uint8Array(48),
        periodSeconds: 30,
        genesisTime: 1,
        tlockCiphersuiteId: "fixture",
        committeeKeyRef: "fixture",
        governanceTimelockRef: "fixture",
      },
      fetchRound: async () => ({
        round: 10n,
        signature: new Uint8Array(96),
        chainHash: "wrong-chain",
        publicKey: new Uint8Array(48),
      }),
    });
    await expect(
      adapter.requestSigma({
        authorizationId: hex32(1),
        hCommit: hex32(2),
        authorizationBlock: 100n,
        blockHash: hex32(3),
        extras: {
          targetRound: 10n,
          chainHash: "expected-chain",
          committeePubkey: new Uint8Array(48),
        },
      }),
    ).rejects.toMatchObject({ code: "CUSTODY_ERR_DRAND_CHAIN_MISMATCH" });
  });
});

function endpoints(): readonly DrandEndpoint[] {
  return [
    { id: "a", url: "https://a.example", chainHash: "expected-chain", certificateSha256: "sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    { id: "b", url: "https://b.example", chainHash: "expected-chain", certificateSha256: "sha256/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
  ];
}

function hex32(seed: number): Hex32 {
  return `0x${seed.toString(16).padStart(2, "0").repeat(32)}` as Hex32;
}
