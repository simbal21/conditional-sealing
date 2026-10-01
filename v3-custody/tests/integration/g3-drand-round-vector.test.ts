import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { verifyDrandSigma } from "../../src/g3-drand/index.js";

const vector = JSON.parse(
  readFileSync(join(process.cwd(), "tests/fixtures/vendor/drand/round-vector.json"), "utf8"),
) as {
  targetRound: string;
  publicKey: string;
  signature: string;
};

describe("integration: g3 drand round vector", () => {
  it("accepts the fixed M1-compatible drand signature vector", () => {
    expect(
      verifyDrandSigma({
        targetRound: BigInt(vector.targetRound),
        signature: hexBytes(vector.signature),
        committeePubkey: hexBytes(vector.publicKey),
      }),
    ).toEqual({ ok: true });
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
