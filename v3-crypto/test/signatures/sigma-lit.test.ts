import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildSigmaLitSigningInput, verifySigmaLit, type SigmaLitInput } from "../../src/signatures/sigma-lit.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "sigma-lit.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { comment: string };
  authorizationId: string;
  h_commit: string;
  block_hash: string;
  lit_acc_binding_digest: string;
  pubkey: string;
  signature: string;
  signing_input: string;
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

function litInput(): SigmaLitInput {
  return {
    authorizationId: hexBytes(golden.authorizationId),
    h_commit: hexBytes(golden.h_commit),
    block_hash: hexBytes(golden.block_hash),
    lit_acc_binding_digest: hexBytes(golden.lit_acc_binding_digest),
    pubkey: hexBytes(golden.pubkey),
    signature: hexBytes(golden.signature),
  };
}

describe("σ_Lit — §7 BLS12-381 verifier-only API", () => {
  it("goldens are marked as locked Phase C seeds", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase C seed");
  });

  it("rebuilds the 96-byte signing input byte-exactly", () => {
    const signingInput = buildSigmaLitSigningInput(litInput());
    expect(signingInput.length).toBe(96);
    expect(bytesToHex(signingInput)).toBe(golden.signing_input);
  });

  it("accepts the positive BLS12-381 tuple", () => {
    expect(verifySigmaLit(litInput())).toEqual({ ok: true });
  });

  it("rejects a tampered signature", () => {
    const input = litInput();
    input.signature = input.signature.slice();
    input.signature[input.signature.length - 1]! ^= 0x01;
    expect(verifySigmaLit(input)).toEqual({ ok: false, error: "ERR_SIGMA_LIT_VERIFY_FAIL" });
  });

  it("rejects the wrong pubkey", () => {
    const input = litInput();
    input.pubkey = input.pubkey.slice();
    input.pubkey[input.pubkey.length - 1]! ^= 0x01;
    expect(verifySigmaLit(input)).toEqual({ ok: false, error: "ERR_SIGMA_LIT_VERIFY_FAIL" });
  });

  it("rejects the wrong block_hash in the signing input", () => {
    const input = litInput();
    input.block_hash = input.block_hash.slice();
    input.block_hash[0]! ^= 0x01;
    expect(verifySigmaLit(input)).toEqual({ ok: false, error: "ERR_SIGMA_LIT_VERIFY_FAIL" });
  });
});
