import { createHash } from "node:crypto";

export interface KemDecapProofInput {
  readonly authorizationId: string;
  readonly hCommit: string;
  readonly blockHash: string;
  readonly kemPubkey: Uint8Array;
}

export interface KemDecapProof {
  readonly algorithm: "cealis-g4-phase1-kem-decap-proof-v1";
  readonly authorizationId: string;
  readonly hCommit: string;
  readonly blockHash: string;
  readonly kemPubkeyDigest: string;
  readonly proofDigest: string;
}

export function produceKemDecapProof(input: KemDecapProofInput): KemDecapProof {
  const kemPubkeyDigest = digest(input.kemPubkey);
  const proofDigest = digest(
    Buffer.concat([
      Buffer.from("cealis-g4-phase1-kem-decap-proof-v1", "ascii"),
      Buffer.from(strip0x(input.authorizationId), "hex"),
      Buffer.from(strip0x(input.hCommit), "hex"),
      Buffer.from(strip0x(input.blockHash), "hex"),
      Buffer.from(strip0x(kemPubkeyDigest), "hex"),
    ]),
  );
  return {
    algorithm: "cealis-g4-phase1-kem-decap-proof-v1",
    authorizationId: input.authorizationId,
    hCommit: input.hCommit,
    blockHash: input.blockHash,
    kemPubkeyDigest,
    proofDigest,
  };
}

function digest(bytes: Uint8Array): string {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

function strip0x(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}
