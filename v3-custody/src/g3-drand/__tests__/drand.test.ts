import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import type { Hex32 } from "../../m1-imports.js";
import { sanitizeLog, SigmaBuffer } from "../../redaction/index.js";
import {
  createDrandAdapter,
  createFixtureDrandTlockCiphertext,
  decapDrandTlockShare,
  deriveDrandTargetRound,
  verifyDrandSigma,
  type DrandChainProfile,
  type DrandEndpoint,
} from "../index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vector = JSON.parse(
  readFileSync(join(here, "../../../tests/fixtures/vendor/drand/round-vector.json"), "utf8"),
) as {
  chainHash: string;
  targetRound: string;
  publicKey: string;
  signature: string;
  expectedShare: string;
};
const chainInfo = JSON.parse(
  readFileSync(join(here, "../../../tests/fixtures/vendor/drand/chain-info.json"), "utf8"),
) as {
  chainHash: string;
  periodSeconds: number;
  genesisTime: number;
  publicKey: string;
  tlockCiphersuiteId: string;
  committeeKeyRef: string;
  governanceTimelockRef: string;
  endpoints: readonly {
    id: string;
    url: `https://${string}`;
    certificateSha256: string;
  }[];
};

describe("g3-drand adapter", () => {
  it("derives a frozen target round from policy time and chain profile", () => {
    const target = deriveDrandTargetRound({
      policyRevealNotBeforeUnix: BigInt(chainInfo.genesisTime + chainInfo.periodSeconds * 10),
      chainGenesisTime: BigInt(chainInfo.genesisTime),
      chainPeriodSeconds: BigInt(chainInfo.periodSeconds),
      chainHash: chainInfo.chainHash,
      expectedChainHash: chainInfo.chainHash,
    });
    expect(target).toEqual({
      targetRound: 11n,
      chainHash: chainInfo.chainHash,
      frozenAtCommit: true,
    });
  });

  it("requests and verifies the locked drand round vector through M1", async () => {
    const adapter = createFixtureAdapter();
    const request = await adapter.requestSigma({
      authorizationId: hex32(1),
      hCommit: hex32(2),
      authorizationBlock: 100n,
      blockHash: hex32(3),
      extras: {
        targetRound: BigInt(vector.targetRound),
        chainHash: vector.chainHash,
        committeePubkey: hexBytes(vector.publicKey),
      },
    });
    expect(request.sigma).toEqual(hexBytes(vector.signature));

    const verified = await adapter.verifySigma({
      authorizationId: hex32(1),
      hCommit: hex32(2),
      authorizationBlock: 100n,
      blockHash: hex32(3),
      extras: {
        targetRound: BigInt(vector.targetRound),
        chainHash: vector.chainHash,
        committeePubkey: hexBytes(vector.publicKey),
      },
      sigma: request.sigma,
    });
    expect(verified).toEqual({ ok: true });
  });

  it("maps wrong drand round to the drand signature failure class", () => {
    expect(
      verifyDrandSigma({
        targetRound: BigInt(vector.targetRound) + 1n,
        signature: hexBytes(vector.signature),
        committeePubkey: hexBytes(vector.publicKey),
      }),
    ).toEqual({
      ok: false,
      code: "CUSTODY_ERR_DRAND_SIG_INVALID",
      detail: "ERR_SIGMA_G3_DRAND_INVALID",
    });
  });

  it("redacts and zeroizes process-memory sigma buffers", () => {
    const sigma = new SigmaBuffer(hexBytes(vector.signature));
    const sanitized = sanitizeLog({ sigma_g3: sigma });
    expect(JSON.stringify(sanitized)).not.toContain(vector.signature.slice(2, 18));
    sigma.zeroize();
    expect(() => sigma.unwrap()).toThrow(/zeroized/);
  });

  it("recovers the fixture G3 share from committed drand tlock context", () => {
    const context = {
      chainHash: vector.chainHash,
      targetRound: BigInt(vector.targetRound),
      drandGateRecipientKemPubkeyDigest: sha256Local(hexBytes(vector.publicKey)),
      hCommit: hexBytes(hex32(9)),
      stanzaIndex: 1,
      g3Choice: 1 as const,
      tlockCiphersuiteId: chainInfo.tlockCiphersuiteId,
      shareDomain: "TOP_LEVEL" as const,
      shareRole: "G3" as const,
    };
    const ciphertext = createFixtureDrandTlockCiphertext(
      hexBytes(vector.expectedShare),
      hexBytes(vector.signature),
      context,
    );
    expect(
      decapDrandTlockShare({
        context,
        returnedChainHash: vector.chainHash,
        returnedRound: BigInt(vector.targetRound),
        returnedPublicKey: hexBytes(vector.publicKey),
        returnedSignature: hexBytes(vector.signature),
        tlockCiphertext: ciphertext,
      }),
    ).toEqual(hexBytes(vector.expectedShare));
  });
});

function createFixtureAdapter() {
  const endpoints = chainInfo.endpoints as readonly DrandEndpoint[];
  const chain: DrandChainProfile = {
    chainHash: chainInfo.chainHash,
    publicKey: hexBytes(chainInfo.publicKey),
    periodSeconds: chainInfo.periodSeconds,
    genesisTime: chainInfo.genesisTime,
    tlockCiphersuiteId: chainInfo.tlockCiphersuiteId,
    committeeKeyRef: chainInfo.committeeKeyRef,
    governanceTimelockRef: chainInfo.governanceTimelockRef,
  };
  return createDrandAdapter({
    endpoints,
    chain,
    fetchRound: async () => ({
      round: BigInt(vector.targetRound),
      signature: hexBytes(vector.signature),
      chainHash: vector.chainHash,
      publicKey: hexBytes(vector.publicKey),
    }),
  });
}

function hex32(seed: number): Hex32 {
  return `0x${seed.toString(16).padStart(2, "0").repeat(32)}` as Hex32;
}

function hexBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function sha256Local(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}
