import { describe, expect, it } from "vitest";

import { createDrandAdapter, type DrandEndpoint } from "../../src/g3-drand/index.js";
import type { Hex32 } from "../../src/m1-imports.js";

describe("integration: g3 drand round mismatch", () => {
  it("returns CUSTODY_ERR_DRAND_ROUND_MISMATCH and never tries an adjacent round", async () => {
    const attempted: bigint[] = [];
    const adapter = createDrandAdapter({
      endpoints: endpoints(),
      chain: {
        chainHash: "fixture-chain",
        publicKey: new Uint8Array(48),
        periodSeconds: 30,
        genesisTime: 1,
        tlockCiphersuiteId: "fixture",
        committeeKeyRef: "fixture",
        governanceTimelockRef: "fixture",
      },
      fetchRound: async (_endpoint, round) => {
        attempted.push(round);
        return {
          round: round + 1n,
          signature: new Uint8Array(96),
          chainHash: "fixture-chain",
          publicKey: new Uint8Array(48),
        };
      },
    });
    await expect(
      adapter.requestSigma({
        authorizationId: hex32(1),
        hCommit: hex32(2),
        authorizationBlock: 100n,
        blockHash: hex32(3),
        extras: {
          targetRound: 10n,
          chainHash: "fixture-chain",
          committeePubkey: new Uint8Array(48),
        },
      }),
    ).rejects.toMatchObject({ code: "CUSTODY_ERR_DRAND_ROUND_MISMATCH" });
    expect(new Set(attempted)).toEqual(new Set([10n]));
  });
});

function endpoints(): readonly DrandEndpoint[] {
  return [
    { id: "a", url: "https://a.example", chainHash: "fixture-chain", certificateSha256: "sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    { id: "b", url: "https://b.example", chainHash: "fixture-chain", certificateSha256: "sha256/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
  ];
}

function hex32(seed: number): Hex32 {
  return `0x${seed.toString(16).padStart(2, "0").repeat(32)}` as Hex32;
}
