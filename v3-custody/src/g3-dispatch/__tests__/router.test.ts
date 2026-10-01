import { describe, expect, it } from "vitest";

import type { Hex32 } from "../../m1-imports.js";
import {
  encodeCommitAAD,
  zeroCommitAADInput,
} from "../../m1-imports.js";
import { createDrandAdapter, type DrandEndpoint } from "../../g3-drand/index.js";
import { dispatchG3, readG3Choice } from "../index.js";

describe("g3-dispatch router", () => {
  it("reads g3_choice from commit_AAD through the M1 decoder", () => {
    expect(readG3Choice(commitAAD(0))).toEqual({ ok: true, g3Choice: 0 });
    expect(readG3Choice(commitAAD(1))).toEqual({ ok: true, g3Choice: 1 });
  });

  it("does not fall back from excluded dcipher to drand", async () => {
    let drandFetches = 0;
    const drand = createDrandAdapter({
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
      fetchRound: async () => {
        drandFetches += 1;
        return {
          round: 1n,
          signature: new Uint8Array(96),
          chainHash: "fixture-chain",
          publicKey: new Uint8Array(48),
        };
      },
    });

    const result = await dispatchG3(
      commitAAD(0),
      {
        drand,
        isDcipherIncluded: () => false,
        getDcipherExclusionReason: () => "test-excluded",
      },
      {
        kind: "requestSigma",
        input: {
          authorizationId: hex32(1),
          hCommit: hex32(2),
          authorizationBlock: 100n,
          blockHash: hex32(3),
          extras: {
            targetRound: 1n,
            chainHash: "fixture-chain",
            committeePubkey: new Uint8Array(48),
          },
        },
      },
    );
    expect(result).toMatchObject({
      ok: false,
      g3Choice: 0,
      code: "CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED",
    });
    expect(drandFetches).toBe(0);
  });
});

function commitAAD(g3Choice: number): Uint8Array {
  const input = zeroCommitAADInput();
  input.g3_choice = g3Choice;
  input.phase = 2;
  return encodeCommitAAD(input);
}

function endpoints(): readonly DrandEndpoint[] {
  return [
    {
      id: "a",
      url: "https://a.example",
      chainHash: "fixture-chain",
      certificateSha256:
        "sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    {
      id: "b",
      url: "https://b.example",
      chainHash: "fixture-chain",
      certificateSha256:
        "sha256/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
  ];
}

function hex32(seed: number): Hex32 {
  return `0x${seed.toString(16).padStart(2, "0").repeat(32)}` as Hex32;
}
