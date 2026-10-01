import { keccak_256 } from "@noble/hashes/sha3.js";
import { hexToBytes } from "@noble/hashes/utils.js";

import { SdSdkError, SdSdkErrorCode, type EscrowCommitReference, type PdaClaimConfig, type SdBundle, type SdClaimItem } from "./types.js";

export function recomputePublicInputs(input: {
  readonly claimConfig: PdaClaimConfig;
  readonly sdBundle: SdBundle;
  readonly escrowCommit: EscrowCommitReference;
  readonly claimItem: SdClaimItem;
}): readonly string[] {
  if (input.claimConfig.expected_public_inputs) return input.claimConfig.expected_public_inputs;
  const fieldSetDigest = digestHexList(input.claimItem.field_ids);
  return [
    hexToScalar(input.sdBundle.authorizationId),
    hexToScalar(input.sdBundle.h_commit),
    hexToScalar(input.sdBundle.partner_id),
    hexToScalar(input.sdBundle.pda_id),
    hexToScalar(input.claimItem.claim_id),
    hexToScalar(fieldSetDigest),
    hexToScalar(input.sdBundle.sdMerkleRoot ?? "0x" + "00".repeat(32)),
    "0",
    "0",
    "0",
    input.claimItem.expiry_timestamp.toString(),
    hexToScalar(input.claimItem.disclosure_id),
    hexToScalar(input.claimItem.verifier_ref),
    hexToScalar(input.claimItem.proof_context_digest ?? digestHexList([input.claimItem.proof])),
  ];
}

export function assertPublicInputsMatch(actual: readonly string[], expected: readonly string[]): void {
  if (actual.length !== expected.length) throw new SdSdkError(SdSdkErrorCode.PUBLIC_INPUT_MISMATCH);
  for (let i = 0; i < actual.length; i += 1) {
    if (actual[i] !== expected[i]) throw new SdSdkError(SdSdkErrorCode.PUBLIC_INPUT_MISMATCH);
  }
}

function digestHexList(values: readonly string[]): `0x${string}` {
  const bytes = values.flatMap((value) => [...hexToBytes(value.startsWith("0x") ? value.slice(2) : value)]);
  return `0x${Buffer.from(keccak_256(new Uint8Array(bytes))).toString("hex")}`;
}

function hexToScalar(value: string): string {
  const clean = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new SdSdkError(SdSdkErrorCode.PUBLIC_INPUT_MISMATCH);
  return BigInt(`0x${clean || "0"}`).toString();
}

