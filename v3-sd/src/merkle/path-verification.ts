import type { BN254Scalar } from "../commit/construction.js";
import type { SdFieldPolicyCode } from "../types/sd-field-policy.js";
import type { Bytes32 } from "../tags/preimages.js";
import { computeMerkleLeaf, computeMerkleNode, type SdMerklePathInternalElement } from "./tree.js";

export interface VerifyMerklePathInput {
  readonly field_index: number;
  readonly field_id: Bytes32;
  readonly field_commitment: BN254Scalar;
  readonly policy: SdFieldPolicyCode;
  readonly path: ReadonlyArray<SdMerklePathInternalElement>;
  readonly expected_root: BN254Scalar;
}

export function verifyMerklePath(input: VerifyMerklePathInput): boolean {
  let current = computeMerkleLeaf({
    field_index: input.field_index,
    field_id: input.field_id,
    field_commitment: input.field_commitment,
    policy: input.policy,
  });
  for (const element of input.path) {
    current = element.direction === 0 ? computeMerkleNode(current, element.sibling) : computeMerkleNode(element.sibling, current);
  }
  return current === input.expected_root;
}
