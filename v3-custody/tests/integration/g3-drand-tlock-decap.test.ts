import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  createFixtureDrandTlockCiphertext,
  decapDrandTlockShare,
} from "../../src/g3-drand/index.js";

const vector = JSON.parse(
  readFileSync(join(process.cwd(), "tests/fixtures/vendor/drand/round-vector.json"), "utf8"),
) as {
  chainHash: string;
  targetRound: string;
  publicKey: string;
  signature: string;
  expectedShare: string;
};
const chain = JSON.parse(
  readFileSync(join(process.cwd(), "tests/fixtures/vendor/drand/chain-info.json"), "utf8"),
) as { tlockCiphersuiteId: string };

describe("integration: g3 drand tlock decap", () => {
  it("recovers the expected 32-byte G3 share under the committed context", () => {
    const context = {
      chainHash: vector.chainHash,
      targetRound: BigInt(vector.targetRound),
      drandGateRecipientKemPubkeyDigest: sha256(hexBytes(vector.publicKey)),
      hCommit: new Uint8Array(32).fill(0x33),
      stanzaIndex: 1,
      g3Choice: 1 as const,
      tlockCiphersuiteId: chain.tlockCiphersuiteId,
      shareDomain: "TOP_LEVEL" as const,
      shareRole: "G3" as const,
    };
    const ciphertext = createFixtureDrandTlockCiphertext(
      hexBytes(vector.expectedShare),
      hexBytes(vector.signature),
      context,
    );
    const share = decapDrandTlockShare({
      context,
      returnedChainHash: vector.chainHash,
      returnedRound: BigInt(vector.targetRound),
      returnedPublicKey: hexBytes(vector.publicKey),
      returnedSignature: hexBytes(vector.signature),
      tlockCiphertext: ciphertext,
    });
    expect(share).toEqual(hexBytes(vector.expectedShare));
  });
});

function hexBytes(hex: string): Uint8Array {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}
