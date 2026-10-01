import { concatHex, keccak256, stringToHex, type Hex } from "viem";

const SHRED_EVIDENCE_DOMAIN = "PDA_SHRED_FINALIZED";

export function shredFinalizedEvidenceRef(authorizationId: Hex, blockNumber: bigint): Hex {
  if (blockNumber < 0n) {
    throw new Error("blockNumber must be non-negative");
  }
  const blockNumberU64 = `0x${blockNumber.toString(16).padStart(16, "0")}` as Hex;
  return keccak256(concatHex([stringToHex(SHRED_EVIDENCE_DOMAIN), authorizationId, blockNumberU64]));
}

