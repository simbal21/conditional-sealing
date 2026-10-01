import { describe, expect, it } from "vitest";

import type { Hex32 } from "../../src/m1-imports.js";
import {
  encodeCommitAAD,
  zeroCommitAADInput,
} from "../../src/m1-imports.js";
import { createDrandAdapter, type DrandEndpoint } from "../../src/g3-drand/index.js";
import { dispatchG3 } from "../../src/g3-dispatch/index.js";

describe("integration: g3 dispatch no runtime fallback", () => {
  it("returns SDK-not-pinned for dcipher commits and never fetches drand", async () => {
    let drandFetches = 0;
    const drand = createDrandAdapter({
      endpoints: endpoints(),
      chain: chainProfile(),
      fetchRound: async () => {
        drandFetches += 1;
        return {
          round: 7n,
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
        input: requestInput(),
      },
    );
    expect(result).toMatchObject({
      ok: false,
      g3Choice: 0,
      code: "CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED",
    });
    expect(drandFetches).toBe(0);
  });

  it("routes drand commits to drand", async () => {
    let drandFetches = 0;
    const drand = createDrandAdapter({
      endpoints: endpoints(),
      chain: chainProfile(),
      fetchRound: async () => {
        drandFetches += 1;
        return {
          round: 7n,
          signature: new Uint8Array(96),
          chainHash: "fixture-chain",
          publicKey: new Uint8Array(48),
        };
      },
    });
    const result = await dispatchG3(
      commitAAD(1),
      { drand, isDcipherIncluded: () => false },
      {
        kind: "requestSigma",
        input: requestInput(),
      },
    );
    expect(result.ok).toBe(true);
    expect(drandFetches).toBe(2);
  });
});

function commitAAD(g3Choice: number): Uint8Array {
  const input = zeroCommitAADInput();
  input.g3_choice = g3Choice;
  input.phase = 2;
  return encodeCommitAAD(input);
}

function requestInput() {
  return {
    authorizationId: hex32(1),
    hCommit: hex32(2),
    authorizationBlock: 100n,
    blockHash: hex32(3),
    extras: {
      targetRound: 7n,
      chainHash: "fixture-chain",
      committeePubkey: new Uint8Array(48),
    },
  };
}

function chainProfile() {
  return {
    chainHash: "fixture-chain",
    publicKey: new Uint8Array(48),
    periodSeconds: 30,
    genesisTime: 1,
    tlockCiphersuiteId: "fixture",
    committeeKeyRef: "fixture",
    governanceTimelockRef: "fixture",
  };
}

function endpoints(): readonly DrandEndpoint[] {
  return [
    { id: "a", url: "https://a.example", chainHash: "fixture-chain", certificateSha256: "sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    { id: "b", url: "https://b.example", chainHash: "fixture-chain", certificateSha256: "sha256/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
  ];
}

function hex32(seed: number): Hex32 {
  return `0x${seed.toString(16).padStart(2, "0").repeat(32)}` as Hex32;
}
