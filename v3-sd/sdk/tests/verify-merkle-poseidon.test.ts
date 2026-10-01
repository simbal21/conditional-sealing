// Closure test for finding D1 (sd-spec-conformance): SDK off-chain Merkle
// verification used keccak256(left||right) while the producer
// (`v3-sd/src/merkle/tree.ts` computeMerkleNode) builds the tree with
// Poseidon3(tag_merkle_scalar, left, right) over BN254. A real multi-leaf Poseidon
// path could therefore never recompute to the Poseidon root under the SDK, so the
// §5.5 / §D.4 "verify Merkle path to sdMerkleRoot" check was cryptographically
// inconsistent with the bundle producer (App. F SD-MERKLE-001/003).
//
// This test drives a REAL multi-leaf Poseidon Merkle path through the SDK's public
// `verifyMerklePath` and asserts it recomputes to the producer's root. It is NOT a
// synthetic/empty path — the leaf, siblings and root are produced inline with the
// SAME Poseidon construction the producer uses (circomlibjs buildPoseidon, identical
// OS2IP tag scalar, identical §5.1 leaf/node/padding formulas).
//
// Producer-fidelity anchor: the root + leaf-0 path below were captured by running
// the producer's own dist `buildSdMerkleTree` + `pathToBundlePath` + `scalarHex`
// against the same 3-leaf input (HEAD e87c108). The inline reconstruction must
// reproduce them byte-for-byte; the EXPECTED_ROOT constant guards against drift in
// either the reconstruction or the SDK.
//
// VULNERABLE BEHAVIOR (keccak hashNode): the Poseidon walk does not equal the
// Poseidon root, so verifyMerklePath returns false for an honest path -> this test
// FAILS against the pre-fix code.
// FIXED BEHAVIOR (Poseidon3 hashNode): the walk equals the root -> this test PASSES.

import { describe, expect, it } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { createRequire } from "node:module";

import { verifyMerklePath, type SdMerklePathElement } from "../src/index.js";

const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

type PoseidonFn = ((inputs: ReadonlyArray<bigint>) => Uint8Array) & {
  F: { toObject(value: Uint8Array): bigint };
};

const require = createRequire(import.meta.url);
const { buildPoseidon } = require("circomlibjs") as { buildPoseidon: () => Promise<PoseidonFn> };
const poseidon: PoseidonFn = await buildPoseidon();

function os2ipMod(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc % BN254_PRIME;
}

// tag_merkle_scalar = OS2IP(TAG_SD_MERKLE_V3) mod p; TAG_SD_MERKLE_V3 = keccak256("CEALIS_SD_MERKLE_V3")
const TAG = os2ipMod(keccak_256(utf8ToBytes("CEALIS_SD_MERKLE_V3")));

// §5.1 leaf  = Poseidon5(tag, field_index, field_id, field_commitment, policy_code)
function leafScalar(field_index: bigint, field_id: bigint, field_commitment: bigint, policy: bigint): bigint {
  return poseidon.F.toObject(poseidon([TAG, field_index, field_id, field_commitment, policy]));
}
// §5.1 node  = Poseidon3(tag, left, right)
function node(left: bigint, right: bigint): bigint {
  return poseidon.F.toObject(poseidon([TAG, left, right]));
}
// §5.2 padding leaf = Poseidon5(tag, j, 0, 0, 0)
function paddingScalar(j: bigint): bigint {
  return poseidon.F.toObject(poseidon([TAG, j, 0n, 0n, 0n]));
}
const toHex = (v: bigint) => `0x${v.toString(16).padStart(64, "0")}` as `0x${string}`;

// Three real leaves -> depth 2, target 4 (one padding leaf at j=3), matching the
// producer's buildSdMerkleTree padded layout. field_id / field_commitment / policy
// chosen to equal the producer cross-check fixture.
const leaf0 = leafScalar(0n, 0x05n, 111n, 1n);
const leaf1 = leafScalar(1n, 0x06n, 222n, 2n);
const leaf2 = leafScalar(2n, 0x07n, 333n, 1n);
const pad3 = paddingScalar(3n);

const padded = [leaf0, leaf1, leaf2, pad3];
const level1 = [node(padded[0]!, padded[1]!), node(padded[2]!, padded[3]!)];
const ROOT = node(level1[0]!, level1[1]!);

// Producer-captured anchor (HEAD e87c108). If this ever drifts, the reconstruction
// or the producer changed and conformance must be re-verified.
const EXPECTED_ROOT = "0x0cbaf27de5735f4afe70c042c6e93d500c2778adea11933ba7994b9d9912894f";

describe("D1 — verifyMerklePath uses Poseidon3 matching the producer", () => {
  it("inline reconstruction reproduces the producer's captured root byte-for-byte", () => {
    expect(toHex(ROOT)).toBe(EXPECTED_ROOT);
  });

  it("recomputes a REAL multi-leaf Poseidon path to the Poseidon root (leaf 0, both siblings on the right)", () => {
    // leaf 0 is a left child at both levels -> direction 0 at every step.
    const path: SdMerklePathElement[] = [
      { sibling: toHex(padded[1]!), direction: 0 },
      { sibling: toHex(level1[1]!), direction: 0 },
    ];
    expect(
      verifyMerklePath({ fieldCommitment: toHex(leaf0), merklePath: path, expectedRoot: toHex(ROOT) }),
    ).toBe(true);
  });

  it("recomputes a REAL Poseidon path where the leaf is a RIGHT child (direction 1 exercised)", () => {
    // leaf 1 is a right child at level 0 (sibling leaf0, direction 1), then its
    // parent level1[0] is a left child at level 1 (sibling level1[1], direction 0).
    const path: SdMerklePathElement[] = [
      { sibling: toHex(padded[0]!), direction: 1 },
      { sibling: toHex(level1[1]!), direction: 0 },
    ];
    expect(
      verifyMerklePath({ fieldCommitment: toHex(leaf1), merklePath: path, expectedRoot: toHex(ROOT) }),
    ).toBe(true);
  });

  it("recomputes a REAL Poseidon path that mixes directions (leaf 2: left then right)", () => {
    // leaf 2 is a left child at level 0 (sibling pad3, direction 0), then its parent
    // level1[1] is a right child at level 1 (sibling level1[0], direction 1).
    const path: SdMerklePathElement[] = [
      { sibling: toHex(pad3), direction: 0 },
      { sibling: toHex(level1[0]!), direction: 1 },
    ];
    expect(
      verifyMerklePath({ fieldCommitment: toHex(leaf2), merklePath: path, expectedRoot: toHex(ROOT) }),
    ).toBe(true);
  });

  it("rejects a real Poseidon path against the WRONG root (no false-accept regression)", () => {
    const path: SdMerklePathElement[] = [
      { sibling: toHex(padded[1]!), direction: 0 },
      { sibling: toHex(level1[1]!), direction: 0 },
    ];
    // keccak recombination would also reject this, but so must Poseidon3 — guards
    // against a fix that returns true unconditionally.
    expect(
      verifyMerklePath({ fieldCommitment: toHex(leaf0), merklePath: path, expectedRoot: toHex(level1[0]!) }),
    ).toBe(false);
  });

  it("rejects a tampered sibling on a real Poseidon path", () => {
    const tampered: SdMerklePathElement[] = [
      { sibling: toHex((padded[1]! + 1n) % BN254_PRIME), direction: 0 },
      { sibling: toHex(level1[1]!), direction: 0 },
    ];
    expect(
      verifyMerklePath({ fieldCommitment: toHex(leaf0), merklePath: tampered, expectedRoot: toHex(ROOT) }),
    ).toBe(false);
  });
});
