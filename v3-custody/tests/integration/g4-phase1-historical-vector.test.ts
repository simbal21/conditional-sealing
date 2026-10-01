import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildSigmaG4Phase1SigningInput } from "../../src/m1-imports.js";
import { verifyG4Phase1Sigma } from "../../src/g4-phase1/sigma-verify.js";

const bytes32 = (value: number) => new Uint8Array(32).fill(value);

describe("G4 Phase 1 historical vector", () => {
  it("verifies a Phase 1 signature through the M1 verifier facade", () => {
    const keys = generateKeyPairSync("ed25519");
    const binaryHash = bytes32(1);
    const blockHash = bytes32(2);
    const authorizationId = bytes32(3);
    const hCommit = bytes32(4);
    const timestamp = 42n;
    const signingInput = buildSigmaG4Phase1SigningInput({
      binary_hash: binaryHash,
      block_hash: blockHash,
      authorizationId,
      h_commit: hCommit,
      timestamp,
    });
    const signature = new Uint8Array(sign(null, signingInput, keys.privateKey));
    const publicDer = new Uint8Array(keys.publicKey.export({ type: "spki", format: "der" }));
    const authorityPubkey = publicDer.slice(publicDer.length - 32);

    expect(
      verifyG4Phase1Sigma({
        sigma: signature,
        binaryHash,
        blockHash,
        authorizationId,
        hCommit,
        timestamp,
        authorityPubkey,
      }),
    ).toEqual({ ok: true });
  });
});
