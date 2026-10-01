// Off-chain Merkle path verification for the partner SD SDK.
//
// sd-spec-v2.md (S2-7) §5.1 NORMATIVE: the sdMerkleRoot tree internal nodes are
//
//   node = Poseidon3(tag_merkle_scalar, left_child, right_child)
//   tag_merkle_scalar = OS2IP(TAG_SD_MERKLE_V3) mod p   (TAG_SD_MERKLE_V3 = keccak256("CEALIS_SD_MERKLE_V3"))
//
// over the BN254 scalar field. The producer (`v3-sd/src/merkle/tree.ts`
// `computeMerkleNode`) hashes nodes with exactly this Poseidon3 construction. A
// partner-facing verifier that recombines path siblings with any other hash will
// NEVER recompute the Poseidon root for a real multi-leaf bundle, so the off-chain
// "verify Merkle path to sdMerkleRoot" check (§D.4 / §5.5 step 2, App. F
// SD-MERKLE-001/003) would silently reject every honest path or accept forged ones.
//
// This SDK is an INDEPENDENT published package (§9.5 NORMATIVE): it must not import
// from any `@cealis/*` workspace package, so it cannot reuse the producer's
// `computeMerkleNode` directly. Instead it loads the SAME Poseidon implementation
// the producer uses (`circomlibjs` `buildPoseidon`, BN254, circom round constants),
// which guarantees a bit-exact match without coupling to Cealis runtime code.
//
// Scalars cross the SDK boundary as the producer serializes them via `scalarHex`:
// `0x` + 32-byte big-endian field element. We parse to bigint, compute Poseidon3 in
// the field, and re-serialize to the same canonical hex before comparison.

import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { createRequire } from "node:module";

import { SdSdkError, SdSdkErrorCode, type HexScalar, type SdMerklePathElement } from "./types.js";

// BN254 scalar field modulus (must equal the producer's BN254_PRIME).
const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

type PoseidonFn = ((inputs: ReadonlyArray<bigint>) => Uint8Array) & {
  F: { toObject(value: Uint8Array): bigint };
};

const require = createRequire(import.meta.url);
const { buildPoseidon } = require("circomlibjs") as { buildPoseidon: () => Promise<PoseidonFn> };
const poseidon: PoseidonFn = await buildPoseidon();

// tag_merkle_scalar = OS2IP(keccak256("CEALIS_SD_MERKLE_V3")) mod p. Big-endian
// OS2IP matches the producer's `scalarFromBytesMod(TAG_SD_MERKLE_V3)`.
const TAG_MERKLE_SCALAR = os2ipMod(keccak_256(utf8ToBytes("CEALIS_SD_MERKLE_V3")));

export function verifyMerklePath(input: {
  readonly fieldCommitment: HexScalar;
  readonly merklePath: readonly SdMerklePathElement[];
  readonly expectedRoot: HexScalar;
}): boolean {
  let current = normalizeScalarHex(input.fieldCommitment);
  if (input.merklePath.length === 0) return current === normalizeScalarHex(input.expectedRoot);
  for (const element of input.merklePath) {
    if (element.direction !== 0 && element.direction !== 1) throw new SdSdkError(SdSdkErrorCode.MERKLE_PATH_INVALID);
    const sibling = normalizeScalarHex(element.sibling);
    current = element.direction === 0 ? hashNode(current, sibling) : hashNode(sibling, current);
  }
  return current === normalizeScalarHex(input.expectedRoot);
}

export function normalizeScalarHex(value: string): HexScalar {
  const lower = value.toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(lower)) throw new SdSdkError(SdSdkErrorCode.MERKLE_PATH_INVALID);
  return lower as HexScalar;
}

// node = Poseidon3(tag_merkle_scalar, left_child, right_child) over BN254.
function hashNode(left: HexScalar, right: HexScalar): HexScalar {
  const leftScalar = scalarFromHex(left);
  const rightScalar = scalarFromHex(right);
  const node = poseidon.F.toObject(poseidon([TAG_MERKLE_SCALAR, leftScalar, rightScalar]));
  if (node < 0n || node >= BN254_PRIME) throw new SdSdkError(SdSdkErrorCode.MERKLE_PATH_INVALID);
  return scalarToHex(node);
}

function scalarFromHex(value: HexScalar): bigint {
  const scalar = BigInt(value);
  // Path elements and the root are field elements; anything outside [0, p) is malformed.
  if (scalar < 0n || scalar >= BN254_PRIME) throw new SdSdkError(SdSdkErrorCode.MERKLE_PATH_INVALID);
  return scalar;
}

function scalarToHex(value: bigint): HexScalar {
  return `0x${value.toString(16).padStart(64, "0")}` as HexScalar;
}

function os2ipMod(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc % BN254_PRIME;
}
