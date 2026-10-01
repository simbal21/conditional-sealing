import { createHash } from "node:crypto";

export interface EndpointAttestationInput {
  readonly binaryHash: Uint8Array;
  readonly effectiveBlock: bigint;
}

export function endpointAttestationDigest(input: EndpointAttestationInput): string {
  const block = Buffer.alloc(8);
  block.writeBigUInt64BE(input.effectiveBlock);
  return `0x${createHash("sha256")
    .update(Buffer.from("CEALIS_G4_PHASE1_ENDPOINT_ATTESTATION", "ascii"))
    .update(input.binaryHash)
    .update(block)
    .digest("hex")}`;
}
