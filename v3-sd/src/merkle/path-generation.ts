import type { Bytes32 } from "../tags/preimages.js";
import type { SdFieldPolicyCode } from "../types/sd-field-policy.js";
import type { BN254Scalar } from "../commit/construction.js";
import type { SdMerklePathElement } from "../types/sd-merkle-path.js";
import { scalarHex } from "../encoding/field-encoding.js";
import { buildBinaryPoseidonTree, canonicallyOrderLeaves, type SdMerkleLeafInput, type SdMerkleTreeResult } from "./tree.js";

export interface OrderedMerkleInput extends SdMerkleLeafInput {
  readonly field_path_hash: Bytes32;
  readonly field_type_code: number;
  readonly declaration_index: number;
}

export interface BuildSdMerkleTreeResult extends SdMerkleTreeResult {
  readonly ordered_leaves: ReadonlyArray<OrderedMerkleInput>;
}

export function buildSdMerkleTree(leaves: ReadonlyArray<OrderedMerkleInput>): BuildSdMerkleTreeResult {
  const ordered = canonicallyOrderLeaves(leaves);
  const tree = buildBinaryPoseidonTree(ordered);
  return { ...tree, ordered_leaves: ordered };
}

export function pathToBundlePath(path: ReadonlyArray<{ readonly sibling: BN254Scalar; readonly direction: 0 | 1 }>): ReadonlyArray<SdMerklePathElement> {
  return path.map((element) => ({ sibling: scalarHex(element.sibling), direction: element.direction }));
}

export function policyCode(policy: SdFieldPolicyCode): SdFieldPolicyCode {
  return policy;
}
