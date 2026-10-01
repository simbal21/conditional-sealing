import { describe, expect, it } from "vitest";
import { CUSTODY_ERROR_CODES } from "../../src/errors.js";
import {
  buildG4Phase1KemDecapProof,
  verifyG4Phase1KemBindingProof,
} from "../../src/g4-phase1/kem-binding-proof.js";
import { GateKind, type GateRecipientPubkeyEntry } from "../../src/types/gate-recipient.js";

const authorizationId = "0x1111111111111111111111111111111111111111111111111111111111111111";
const hCommit = "0x2222222222222222222222222222222222222222222222222222222222222222";
const blockHash = "0x3333333333333333333333333333333333333333333333333333333333333333";

const entry: GateRecipientPubkeyEntry = {
  authorizationId,
  gateKind: GateKind.G4,
  conditionalRecipientIndex: 0,
  kemPubkey: new Uint8Array([1, 2, 3, 4]),
  attestationRef: "0x4444444444444444444444444444444444444444444444444444444444444444",
  effectiveBlock: 1n,
  tombstoneBlock: 0n,
  perCommitEphemeral: true,
};

describe("G4 Phase 1 split-key enforcement", () => {
  it("rejects bare sigma without separate KEM decap proof", () => {
    expect(() => verifyG4Phase1KemBindingProof(undefined, entry)).toThrow(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
    );
  });

  it("accepts a proof bound to the commit-time G4 KEM pubkey", () => {
    const proof = buildG4Phase1KemDecapProof({
      authorizationId,
      hCommit,
      blockHash,
      kemPubkey: entry.kemPubkey,
    });
    expect(() => verifyG4Phase1KemBindingProof(proof, entry)).not.toThrow();
  });

  it("rejects proof when the registry KEM pubkey changes", () => {
    const proof = buildG4Phase1KemDecapProof({
      authorizationId,
      hCommit,
      blockHash,
      kemPubkey: new Uint8Array([9, 9, 9]),
    });
    expect(() => verifyG4Phase1KemBindingProof(proof, entry)).toThrow(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
    );
  });
});
