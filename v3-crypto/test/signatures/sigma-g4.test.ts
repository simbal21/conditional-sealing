import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  G4_PHASE1_SIGNING_INPUT_BYTES,
  buildSigmaG4Phase1SigningInput,
  verifySigmaG4,
  type SigmaG4Phase1Input,
  type SigmaG4Phase2Input,
} from "../../src/signatures/sigma-g4.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = join(__dirname, "..", "fixtures", "sigma-g4.golden.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf-8")) as {
  _meta: { comment: string };
  phase1: {
    binary_hash: string;
    block_hash: string;
    authorizationId: string;
    h_commit: string;
    timestamp: string;
    signing_input: string;
    authority_pubkey: string;
    signature: string;
  };
  phase2_stub: { dcap_quote: string };
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

function phase1Input(): SigmaG4Phase1Input {
  return {
    phase: 1,
    binary_hash: hexBytes(golden.phase1.binary_hash),
    block_hash: hexBytes(golden.phase1.block_hash),
    authorizationId: hexBytes(golden.phase1.authorizationId),
    h_commit: hexBytes(golden.phase1.h_commit),
    timestamp: BigInt(golden.phase1.timestamp),
    authority_pubkey: hexBytes(golden.phase1.authority_pubkey),
    signature: hexBytes(golden.phase1.signature),
  };
}

function phase2Input(): SigmaG4Phase2Input {
  return {
    phase: 2,
    dcap_quote: hexBytes(golden.phase2_stub.dcap_quote),
  };
}

describe("σ_G4 — §9 Phase 1 Ed25519 verifier + Phase 2 stub", () => {
  it("goldens are marked as locked Phase C seeds", () => {
    expect(golden._meta.comment).toContain("LOCKED — Phase C seed");
  });

  it("rebuilds the 168-byte Phase 1 signing input byte-exactly", () => {
    const signingInput = buildSigmaG4Phase1SigningInput(phase1Input());
    expect(signingInput.length).toBe(G4_PHASE1_SIGNING_INPUT_BYTES);
    expect(bytesToHex(signingInput)).toBe(golden.phase1.signing_input);
  });

  it("accepts the positive Phase 1 Ed25519 vector", () => {
    expect(verifySigmaG4(phase1Input())).toEqual({ ok: true });
  });

  it("rejects a tampered Phase 1 signature", () => {
    const input = phase1Input();
    input.signature = input.signature.slice();
    input.signature[input.signature.length - 1]! ^= 0x01;
    expect(verifySigmaG4(input)).toEqual({ ok: false, error: "ERR_SIGMA_G4_PHASE1_INVALID" });
  });

  it("rejects a tampered binary_hash", () => {
    const input = phase1Input();
    input.binary_hash = input.binary_hash.slice();
    input.binary_hash[0]! ^= 0x01;
    expect(verifySigmaG4(input)).toEqual({ ok: false, error: "ERR_SIGMA_G4_PHASE1_INVALID" });
  });

  it("rejects a tampered timestamp", () => {
    expect(verifySigmaG4({ ...phase1Input(), timestamp: BigInt(golden.phase1.timestamp) + 1n })).toEqual({
      ok: false,
      error: "ERR_SIGMA_G4_PHASE1_INVALID",
    });
  });

  it("rejects the wrong authority_pubkey", () => {
    const input = phase1Input();
    input.authority_pubkey = input.authority_pubkey.slice();
    input.authority_pubkey[input.authority_pubkey.length - 1]! ^= 0x01;
    expect(verifySigmaG4(input)).toEqual({ ok: false, error: "ERR_SIGMA_G4_PHASE1_INVALID" });
  });

  it("rejects Phase 1 field-width drift before signature verification", () => {
    const input = phase1Input();
    input.binary_hash = input.binary_hash.slice(1);
    expect(verifySigmaG4(input)).toEqual({ ok: false, error: "ERR_SIGMA_G4_FIELD_LENGTH" });
  });

  it("routes Phase 2 to the Phase C DCAP stub", () => {
    expect(verifySigmaG4(phase2Input())).toEqual({ ok: false, error: "ERR_SIGMA_G4_PHASE2_VERIFY_STUB" });
  });

  it("rejects an unknown phase with a typed phase error", () => {
    expect(verifySigmaG4({ ...phase1Input(), phase: 3 } as unknown as SigmaG4Phase1Input)).toEqual({
      ok: false,
      error: "ERR_SIGMA_G4_PHASE_MISMATCH",
    });
  });
});
