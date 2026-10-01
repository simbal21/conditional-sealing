import { sha256 } from "@noble/hashes/sha2";
import type { Hex32 } from "@cealis/v3-crypto";
import { CustodyError, CUSTODY_ERROR_CODES } from "../errors.js";
import { GateKind, type GateRecipientPubkeyEntry } from "../types/gate-recipient.js";

export const G4_PHASE1_KEM_PROOF_ALGORITHM = "cealis-g4-phase1-kem-decap-proof-v1" as const;

export interface G4Phase1KemPubkey {
  readonly authorizationId: Hex32;
  readonly kemPubkey: Uint8Array;
  readonly attestationRef: Hex32;
}

export interface G4Phase1KemDecapProof {
  readonly algorithm: typeof G4_PHASE1_KEM_PROOF_ALGORITHM;
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
  readonly kemPubkeyDigest: Hex32;
  readonly proofDigest: Hex32;
}

export interface G4Phase1KemProofInput {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly blockHash: Hex32;
  readonly kemPubkey: Uint8Array;
}

export function buildG4Phase1KemDecapProof(input: G4Phase1KemProofInput): G4Phase1KemDecapProof {
  const kemPubkeyDigest = digestHex(input.kemPubkey);
  return {
    algorithm: G4_PHASE1_KEM_PROOF_ALGORITHM,
    authorizationId: input.authorizationId,
    hCommit: input.hCommit,
    blockHash: input.blockHash,
    kemPubkeyDigest,
    proofDigest: digestHex(
      concatBytes(
        asciiBytes(G4_PHASE1_KEM_PROOF_ALGORITHM),
        hexToBytes(input.authorizationId),
        hexToBytes(input.hCommit),
        hexToBytes(input.blockHash),
        hexToBytes(kemPubkeyDigest),
      ),
    ),
  };
}

export function verifyG4Phase1KemBindingProof(
  proof: G4Phase1KemDecapProof | undefined,
  entry: GateRecipientPubkeyEntry | null,
): void {
  if (proof === undefined || entry === null) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
      "G4 KEM decap proof missing; sigma alone cannot admit TopShare(G4)",
    );
  }
  if (entry.gateKind !== GateKind.G4) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
      `G4 KEM proof checked against wrong gate kind ${entry.gateKind}`,
    );
  }
  const expected = buildG4Phase1KemDecapProof({
    authorizationId: entry.authorizationId,
    hCommit: proof.hCommit,
    blockHash: proof.blockHash,
    kemPubkey: entry.kemPubkey,
  });
  if (
    expected.authorizationId !== proof.authorizationId ||
    expected.kemPubkeyDigest !== proof.kemPubkeyDigest ||
    expected.proofDigest !== proof.proofDigest
  ) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
      "G4 KEM decap proof does not bind the commit-time G4 KEM pubkey",
    );
  }
}

function digestHex(bytes: Uint8Array): Hex32 {
  return bytesToHex32(sha256(bytes));
}

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function asciiBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hexToBytes(hex: Hex32): Uint8Array {
  const stripped = hex.slice(2);
  const out = new Uint8Array(stripped.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(stripped.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex32(bytes: Uint8Array): Hex32 {
  if (bytes.length !== 32) throw new Error(`expected 32 bytes, got ${bytes.length}`);
  let hex = "0x";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex as Hex32;
}
