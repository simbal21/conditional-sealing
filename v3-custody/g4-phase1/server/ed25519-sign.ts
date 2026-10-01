import { createPrivateKey, sign } from "node:crypto";
import { buildSigmaG4Phase1SigningInput } from "@cealis/v3-crypto";

export interface Phase1SignInput {
  readonly privateKeyPem: string;
  readonly binaryHash: Uint8Array;
  readonly blockHash: Uint8Array;
  readonly authorizationId: Uint8Array;
  readonly hCommit: Uint8Array;
  readonly timestamp: bigint;
}

export function signPhase1Sigma(input: Phase1SignInput): Uint8Array {
  const key = createPrivateKey(input.privateKeyPem);
  const signingInput = buildSigmaG4Phase1SigningInput({
    binary_hash: input.binaryHash,
    block_hash: input.blockHash,
    authorizationId: input.authorizationId,
    h_commit: input.hCommit,
    timestamp: input.timestamp,
  });
  return new Uint8Array(sign(null, signingInput, key));
}
