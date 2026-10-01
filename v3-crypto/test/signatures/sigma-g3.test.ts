import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildDrandRoundMessage,
  verifySigmaG3,
  type SigmaG3DcipherInput,
  type SigmaG3DrandInput,
} from "../../src/signatures/sigma-g3.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "sigma-g3.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { comment: string };
  drand: {
    target_drand_round: string;
    target_drand_round_message_uint64_be: string;
    committee_pubkey: string;
    signature: string;
  };
  dcipher_stub: {
    authorizationId: string;
    h_commit: string;
    block_hash: string;
    committee_pubkey: string;
    signature: string;
  };
};

function hexBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

function drandInput(): SigmaG3DrandInput {
  return {
    g3_choice: 1,
    target_drand_round: BigInt(golden.drand.target_drand_round),
    committee_pubkey: hexBytes(golden.drand.committee_pubkey),
    signature: hexBytes(golden.drand.signature),
  };
}

function dcipherInput(): SigmaG3DcipherInput {
  return {
    g3_choice: 0,
    authorizationId: hexBytes(golden.dcipher_stub.authorizationId),
    h_commit: hexBytes(golden.dcipher_stub.h_commit),
    block_hash: hexBytes(golden.dcipher_stub.block_hash),
    committee_pubkey: hexBytes(golden.dcipher_stub.committee_pubkey),
    signature: hexBytes(golden.dcipher_stub.signature),
  };
}

describe("σ_G3 — §8 drand verifier + dcipher Phase C stub", () => {
  it("goldens are marked as locked Phase C seeds", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase C seed");
  });

  it("encodes the target drand round as uint64 BE", () => {
    expect(bytesToHex(buildDrandRoundMessage(BigInt(golden.drand.target_drand_round)))).toBe(
      golden.drand.target_drand_round_message_uint64_be,
    );
  });

  it("accepts the positive drand BLS12-381 round vector", () => {
    expect(verifySigmaG3(drandInput())).toEqual({ ok: true });
  });

  it("rejects a tampered drand signature", () => {
    const input = drandInput();
    input.signature = input.signature.slice();
    input.signature[input.signature.length - 1]! ^= 0x01;
    expect(verifySigmaG3(input)).toEqual({ ok: false, error: "ERR_SIGMA_G3_DRAND_INVALID" });
  });

  it("rejects the wrong target drand round", () => {
    expect(verifySigmaG3({ ...drandInput(), target_drand_round: BigInt(golden.drand.target_drand_round) + 1n })).toEqual({
      ok: false,
      error: "ERR_SIGMA_G3_DRAND_INVALID",
    });
  });

  it("rejects the wrong drand committee pubkey", () => {
    const input = drandInput();
    input.committee_pubkey = input.committee_pubkey.slice();
    input.committee_pubkey[input.committee_pubkey.length - 1]! ^= 0x01;
    expect(verifySigmaG3(input)).toEqual({ ok: false, error: "ERR_SIGMA_G3_DRAND_INVALID" });
  });

  it("routes dcipher to the Phase C SDK-integration stub", () => {
    expect(verifySigmaG3(dcipherInput())).toEqual({ ok: false, error: "ERR_SIGMA_G3_DCIPHER_VERIFY_STUB" });
  });

  it("rejects an unknown g3_choice with a typed path error", () => {
    expect(verifySigmaG3({ ...drandInput(), g3_choice: 2 } as unknown as SigmaG3DrandInput)).toEqual({
      ok: false,
      error: "ERR_SIGMA_G3_PATH_MISMATCH",
    });
  });
});
