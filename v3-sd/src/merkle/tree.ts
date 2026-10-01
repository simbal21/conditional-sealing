// sdMerkleRoot construction — Phase A signatures only.
//
// §5.1 lines 485-505 + §5.2 lines 507-519 + §5.3 lines 521-530 + §D.3 lines
// 1705-1730 NORMATIVE.
//
// VERBATIM normative blocks:
//
//   leaf_i = Poseidon5(
//     tag_merkle_scalar,
//     field_index_scalar,
//     field_id_scalar,
//     field_commitment_i,
//     policy_code_scalar
//   )
//
//   tag_merkle_scalar = OS2IP(TAG_SD_MERKLE_V3) mod p
//   policy_code is `1 cleartext`, `2 zkp`, `3 escrow_only`
//
//   node = Poseidon3(tag_merkle_scalar, left_child, right_child)
//
//   padding_leaf_j = Poseidon5(tag_merkle_scalar, j, 0, 0, 0)
//
// §5.2 line 509 verbatim:
//   "The tree is a complete binary tree with depth d = max(1, ceil_log2(leaf_count))
//   where 2^d >= leaf_count. d must be between 1 and 16 for V2 launch,
//   supporting 1 to 65,536 SD leaves."
//
// §5.3 lines 522-528 leaf canonical ordering:
//   1. ascending field_path_hash
//   2. then ascending field_type_code
//   3. then ascending field_id
//   4. then stable schema declaration order as a final tie-breaker

import type { Bytes32 } from "../tags/preimages.js";
import type { BN254Scalar } from "../commit/construction.js";
import type { SdFieldPolicyCode } from "../types/sd-field-policy.js";
import { createRequire } from "node:module";

import { TAG_SD } from "../tags/tags.js";
import { assertBn254Scalar, scalarFromBytesMod } from "../encoding/field-encoding.js";
import { SdError } from "../errors/sd-error.js";
import { SdErrorCode } from "../errors/codes.js";

export const MERKLE_MIN_DEPTH = 1 as const;
export const MERKLE_MAX_DEPTH = 16 as const;
export const MERKLE_MAX_LEAVES = 65_536 as const;

export interface SdMerkleLeafInput {
  readonly field_index: number;
  readonly field_id: Bytes32;
  readonly field_commitment: BN254Scalar;
  readonly policy: SdFieldPolicyCode;
}

export interface SdMerklePathInternalElement {
  readonly sibling: BN254Scalar;
  readonly direction: 0 | 1;
}

export interface SdMerkleTreeResult {
  readonly root: BN254Scalar;
  readonly depth: number;
  readonly leaf_count: number;
  readonly padded_leaf_count: number;
  readonly paths: ReadonlyArray<ReadonlyArray<SdMerklePathInternalElement>>;
}

/**
 * `buildBinaryPoseidonTree` — Phase B body. Signature only at Phase A.
 *
 * Inputs are CANONICALLY ORDERED per §5.3 BEFORE entering this function.
 * Phase B's `buildSdMerkleTree` (in `merkle/path-generation.ts` Phase B file)
 * wraps this with the ordering step.
 *
 * Padding (§D.3 lines 1714-1716):
 *   padded = leaves
 *   for j from len(leaves) to target - 1:
 *     padded.push(Poseidon5(TAG_SD_MERKLE_V3, j, 0, 0, 0))
 *
 * One-leaf SD plan (§5.2 line 519):
 *   "A one-leaf SD plan is represented as a depth-1 tree with target = 2:
 *   the real leaf is index 0 and one padding leaf at index 1."
 */
export interface BuildBinaryPoseidonTree {
  (leaves: ReadonlyArray<SdMerkleLeafInput>): SdMerkleTreeResult;
}

/**
 * `canonicallyOrderLeaves` — Phase B body. §5.3 lines 522-528.
 *
 * 4-key sort:
 *   1. field_path_hash asc
 *   2. field_type_code asc
 *   3. field_id asc
 *   4. stable schema declaration index
 */
export interface CanonicallyOrderLeaves<TIn> {
  (leaves: ReadonlyArray<TIn>): ReadonlyArray<TIn>;
}

type PoseidonFn = ((inputs: ReadonlyArray<bigint>) => Uint8Array) & {
  F: { toObject(value: Uint8Array): bigint };
};

const require = createRequire(import.meta.url);
const { buildPoseidon } = require("circomlibjs") as { buildPoseidon: () => Promise<PoseidonFn> };
const poseidon: PoseidonFn = await buildPoseidon();

export function computeMerkleLeaf(input: SdMerkleLeafInput): BN254Scalar {
  return poseidonScalar([
    scalarFromBytesMod(TAG_SD.TAG_SD_MERKLE_V3),
    BigInt(input.field_index),
    scalarFromBytesMod(input.field_id),
    input.field_commitment,
    BigInt(input.policy),
  ]);
}

export function computeMerklePaddingLeaf(index: number): BN254Scalar {
  return poseidonScalar([scalarFromBytesMod(TAG_SD.TAG_SD_MERKLE_V3), BigInt(index), 0n, 0n, 0n]);
}

export function computeMerkleNode(left_child: BN254Scalar, right_child: BN254Scalar): BN254Scalar {
  return poseidonScalar([scalarFromBytesMod(TAG_SD.TAG_SD_MERKLE_V3), left_child, right_child]);
}

export function buildBinaryPoseidonTree(leaves: ReadonlyArray<SdMerkleLeafInput>): SdMerkleTreeResult {
  if (leaves.length === 0) {
    throw new SdError(SdErrorCode.MERKLE_PATH_INVALID, { stage: "commitment_build" });
  }
  const depth = Math.max(MERKLE_MIN_DEPTH, Math.ceil(Math.log2(leaves.length)));
  if (depth < MERKLE_MIN_DEPTH || depth > MERKLE_MAX_DEPTH || leaves.length > MERKLE_MAX_LEAVES) {
    throw new SdError(SdErrorCode.MERKLE_PATH_INVALID, { stage: "commitment_build" });
  }
  const target = 2 ** depth;
  const padded: BN254Scalar[] = leaves.map(computeMerkleLeaf);
  for (let j = leaves.length; j < target; j += 1) padded.push(computeMerklePaddingLeaf(j));

  const levels: BN254Scalar[][] = [padded];
  let current = padded;
  while (current.length > 1) {
    const next: BN254Scalar[] = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(computeMerkleNode(current[i]!, current[i + 1]!));
    }
    levels.push(next);
    current = next;
  }

  return {
    root: current[0]!,
    depth,
    leaf_count: leaves.length,
    padded_leaf_count: target,
    paths: derivePaths(levels, leaves.length),
  };
}

export function canonicallyOrderLeaves<
  TIn extends {
    readonly field_path_hash: Bytes32;
    readonly field_type_code: number;
    readonly field_id: Bytes32;
    readonly declaration_index: number;
  },
>(leaves: ReadonlyArray<TIn>): ReadonlyArray<TIn> {
  return [...leaves].sort((a, b) => {
    const byPath = compareBytes(a.field_path_hash, b.field_path_hash);
    if (byPath !== 0) return byPath;
    if (a.field_type_code !== b.field_type_code) return a.field_type_code - b.field_type_code;
    const byId = compareBytes(a.field_id, b.field_id);
    if (byId !== 0) return byId;
    return a.declaration_index - b.declaration_index;
  });
}

function derivePaths(levels: ReadonlyArray<ReadonlyArray<BN254Scalar>>, realLeafCount: number): ReadonlyArray<ReadonlyArray<SdMerklePathInternalElement>> {
  const paths: SdMerklePathInternalElement[][] = [];
  for (let leafIndex = 0; leafIndex < realLeafCount; leafIndex += 1) {
    const path: SdMerklePathInternalElement[] = [];
    let idx = leafIndex;
    for (let level = 0; level < levels.length - 1; level += 1) {
      const siblingIndex = idx % 2 === 0 ? idx + 1 : idx - 1;
      path.push({ sibling: levels[level]![siblingIndex]!, direction: idx % 2 === 0 ? 0 : 1 });
      idx = Math.floor(idx / 2);
    }
    paths.push(path);
  }
  return paths;
}

function poseidonScalar(inputs: ReadonlyArray<bigint>): BN254Scalar {
  try {
    for (const input of inputs) assertBn254Scalar(input);
    const out = poseidon(inputs);
    const scalar = poseidon.F.toObject(out);
    assertBn254Scalar(scalar);
    return scalar;
  } catch (cause) {
    throw new SdError(SdErrorCode.MERKLE_PATH_INVALID, { stage: "commitment_build", cause });
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const av = a[i]!;
    const bv = b[i]!;
    if (av !== bv) return av - bv;
  }
  return a.length - b.length;
}
