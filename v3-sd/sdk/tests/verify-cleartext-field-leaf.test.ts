// Closure test for finding D1 (sd-spec-conformance, second half): the SDK
// cleartext verifier (`src/verify-cleartext-field.ts`) started the Merkle walk from
// the RAW per-field Poseidon5 field_commitment, but the producer
// (`v3-sd/src/merkle/tree.ts` computeMerkleLeaf) commits each LEAF as
//
//   leaf_i = Poseidon5(tag_merkle_scalar, field_index, field_id, field_commitment, policy_code)   (§5.1)
//
// The Phase-0 fix corrected hashNode to Poseidon3, but the walk still entered the
// tree at field_commitment, one Poseidon5 hop BELOW the real leaf. For any real
// multi-leaf bundle the Poseidon3 walk from field_commitment can NEVER reach the
// producer's Poseidon root, so verifyCleartextField rejected every honest cleartext
// disclosure (§5.5 / §D.4 "verify Merkle path to sdMerkleRoot", App. F SD-MERKLE-001).
// It also severed the binding between the disclosed field's (index, id, policy) and
// the committed root — a forged field_index / field_id / policy on an attacker bundle
// would not be detected because those scalars never entered the recomputation.
//
// This test drives a REAL multi-leaf cleartext bundle end-to-end through the PUBLIC
// verifyCleartextField: it builds the tree inline with the SAME §5.1 Poseidon5 leaf /
// Poseidon3 node / Poseidon5 padding construction the producer uses (circomlibjs
// buildPoseidon, identical OS2IP tag scalar), then asserts verifyCleartextField
// resolves (leaf recompute + Poseidon3 path + root match). The 3-leaf fixture reuses
// the producer-captured root anchor from verify-merkle-poseidon.test.ts (HEAD e87c108)
// so any drift in either the reconstruction or the SDK leaf formula is caught.
//
// VULNERABLE BEHAVIOR (walk starts at field_commitment): the Poseidon3 walk from
// field_commitment does not equal the root -> verifyCleartextField throws
// MERKLE_PATH_INVALID for an honest bundle -> the end-to-end "resolves" assertion
// FAILS against the pre-fix code.
// FIXED BEHAVIOR (walk starts at recomputed §5.1 leaf): the walk equals the root ->
// verifyCleartextField resolves.

import { describe, expect, it } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { createRequire } from "node:module";

import {
  SdSdkError,
  SdSdkErrorCode,
  verifyCleartextField,
  type EscrowCommitReference,
  type Hex32,
  type HexScalar,
  type PdaFieldConfig,
  type PdaSdConfig,
  type SdBundle,
  type SdCleartextItem,
  type SdMerklePathElement,
  type VerifierRegistryClient,
} from "../src/index.js";

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

// §5.1 leaf = Poseidon5(tag, field_index, field_id, field_commitment, policy_code).
function leafScalar(field_index: bigint, field_id: bigint, field_commitment: bigint, policy: bigint): bigint {
  return poseidon.F.toObject(poseidon([TAG, field_index, field_id, field_commitment, policy]));
}
// §5.1 node = Poseidon3(tag, left, right).
function node(left: bigint, right: bigint): bigint {
  return poseidon.F.toObject(poseidon([TAG, left, right]));
}
// §5.2 padding leaf = Poseidon5(tag, j, 0, 0, 0).
function paddingScalar(j: bigint): bigint {
  return poseidon.F.toObject(poseidon([TAG, j, 0n, 0n, 0n]));
}
const toHex = (v: bigint) => `0x${v.toString(16).padStart(64, "0")}` as HexScalar;
const toHex32 = (v: bigint) => `0x${v.toString(16).padStart(64, "0")}` as Hex32;

// Three real leaves -> depth 2, target 4 (one padding leaf at j=3), matching the
// producer's buildSdMerkleTree padded layout AND the verify-merkle-poseidon fixture.
//   leaf0: field_index 0, field_id 0x05, field_commitment 111, policy 1 (cleartext)
//   leaf1: field_index 1, field_id 0x06, field_commitment 222, policy 2 (zkp -> in
//          the tree but NOT a cleartext item; a real mixed-policy bundle sibling)
//   leaf2: field_index 2, field_id 0x07, field_commitment 333, policy 1 (cleartext)
const FC0 = 111n;
const FC2 = 333n;
const leaf0 = leafScalar(0n, 0x05n, FC0, 1n);
const leaf1 = leafScalar(1n, 0x06n, 222n, 2n);
const leaf2 = leafScalar(2n, 0x07n, FC2, 1n);
const pad3 = paddingScalar(3n);

const padded = [leaf0, leaf1, leaf2, pad3];
const level1 = [node(padded[0]!, padded[1]!), node(padded[2]!, padded[3]!)];
const ROOT = node(level1[0]!, level1[1]!);

// Producer-captured anchor (HEAD e87c108) — identical fixture to verify-merkle-poseidon.test.ts.
const EXPECTED_ROOT = "0x0cbaf27de5735f4afe70c042c6e93d500c2778adea11933ba7994b9d9912894f";

// Path for leaf 0 (left child at both levels -> direction 0 at every step).
const PATH0: SdMerklePathElement[] = [
  { sibling: toHex(padded[1]!), direction: 0 },
  { sibling: toHex(level1[1]!), direction: 0 },
];
// Path for leaf 2 (left child at level 0 sibling pad3, then right child at level 1).
const PATH2: SdMerklePathElement[] = [
  { sibling: toHex(pad3), direction: 0 },
  { sibling: toHex(level1[0]!), direction: 1 },
];

const PARTNER_ID = `0x${"11".repeat(32)}` as Hex32;
const AUTH_ID = `0x${"22".repeat(32)}` as Hex32;
const PDA_ID = `0x${"33".repeat(32)}` as Hex32;

// PDA config field_id MUST be the Hex32 whose OS2IP-mod-p equals the leaf's field_id
// scalar, so the SDK's computeCleartextLeaf reproduces the producer leaf. 0x05 / 0x07
// are < p, so the Hex32 is simply 0x00..05 / 0x00..07.
const pdaSdConfig: PdaSdConfig = {
  sd_enabled: true,
  ingestion_mode: "MODE_A",
  fields: [
    { field_id: toHex32(0x05n), policy: "cleartext", field_type_code: 2, field_index: 0 },
    { field_id: toHex32(0x06n), policy: "zkp", field_type_code: 2, field_index: 1 },
    { field_id: toHex32(0x07n), policy: "cleartext", field_type_code: 2, field_index: 2 },
  ],
  claims: [],
};

const escrowCommit: EscrowCommitReference = {
  commit_version: "0x0302",
  authorizationId: AUTH_ID,
  h_commit: `0x${"00".repeat(32)}`,
  pda_root: `0x${"00".repeat(32)}`,
  partner_id: PARTNER_ID,
  pda_id: PDA_ID,
  pda_version: "1.0",
  schema_digest: `0x${"00".repeat(32)}`,
  authorizationBlock: 1000n,
  commit_AAD: { sdMerkleRoot: toHex32(ROOT) },
};

// SD never verifies a registry/proof for cleartext_attested mode, so this stub is unused.
const verifierRegistry: VerifierRegistryClient = {
  getVerifierAt: () => null,
};

function cleartextItem(opts: {
  field_id: Hex32;
  field_commitment: HexScalar;
  merkle_path: readonly SdMerklePathElement[];
  value: unknown;
}): SdCleartextItem {
  return {
    field_id: opts.field_id,
    field_type_code: 2,
    value: opts.value,
    field_commitment: opts.field_commitment,
    policy_code: 1,
    merkle_path: opts.merkle_path,
    opening_mode: "cleartext_attested",
    cleartext_attestation_digest: `0x${"ab".repeat(32)}`,
  };
}

function bundleWith(items: readonly SdCleartextItem[]): SdBundle {
  return {
    sd_version: "s2-7-1.0",
    status: "complete",
    authorizationId: AUTH_ID,
    h_commit: `0x${"00".repeat(32)}`,
    pda_root: `0x${"00".repeat(32)}`,
    partner_id: PARTNER_ID,
    pda_id: PDA_ID,
    pda_version: "1.0",
    schema_digest: `0x${"00".repeat(32)}`,
    sdMerkleRoot: toHex(ROOT),
    sd_salt_context_digest: `0x${"00".repeat(32)}`,
    sd_plan_digest: `0x${"00".repeat(32)}`,
    sd_bundle_digest: `0x${"00".repeat(32)}`,
    rootBindingLevel: "commit_AAD",
    generated_at: "2026-06-02T00:00:00.000Z",
    cleartext: items,
    claims: [],
  };
}

async function rejectionCode(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return "RESOLVED";
  } catch (error) {
    return error instanceof SdSdkError ? error.code : "UNKNOWN";
  }
}

describe("D1 — verifyCleartextField recomputes the §5.1 Poseidon5 leaf before the Merkle walk", () => {
  it("inline reconstruction reproduces the producer's captured root byte-for-byte", () => {
    expect(toHex(ROOT)).toBe(EXPECTED_ROOT);
  });

  it("resolves a REAL multi-leaf cleartext bundle end-to-end (leaf 0, recompute + Poseidon3 path + root match)", async () => {
    const item = cleartextItem({ field_id: toHex32(0x05n), field_commitment: toHex(FC0), merkle_path: PATH0, value: 111 });
    await expect(
      verifyCleartextField({ sdBundle: bundleWith([item]), cleartextItem: item, escrowCommit, pdaSdConfig, verifierRegistry }),
    ).resolves.toBeUndefined();
  });

  it("resolves the second real cleartext leaf in the same tree (leaf 2, mixed directions)", async () => {
    const item = cleartextItem({ field_id: toHex32(0x07n), field_commitment: toHex(FC2), merkle_path: PATH2, value: 333 });
    await expect(
      verifyCleartextField({ sdBundle: bundleWith([item]), cleartextItem: item, escrowCommit, pdaSdConfig, verifierRegistry }),
    ).resolves.toBeUndefined();
  });

  it("REJECTS the pre-fix vulnerable walk: a path crafted for the raw field_commitment (one Poseidon5 hop too low) no longer verifies", async () => {
    // Pre-fix, the SDK started the walk at field_commitment (FC0 = 111). Build the
    // sibling path that WOULD make a Poseidon3 walk from 111 reach the root; the fixed
    // verifier starts from the recomputed leaf instead, so this honest-for-old-code
    // path must now fail. (The producer never emits such a path; this asserts the
    // entry point actually moved up to the §5.1 leaf.)
    const fakeLevel1 = [node(FC0, padded[1]!), node(padded[2]!, padded[3]!)];
    const fakeRoot = node(fakeLevel1[0]!, fakeLevel1[1]!);
    const pathForRawCommitment: SdMerklePathElement[] = [
      { sibling: toHex(padded[1]!), direction: 0 },
      { sibling: toHex(fakeLevel1[1]!), direction: 0 },
    ];
    const item = cleartextItem({ field_id: toHex32(0x05n), field_commitment: toHex(FC0), merkle_path: pathForRawCommitment, value: 111 });
    const bundle: SdBundle = { ...bundleWith([item]), sdMerkleRoot: toHex(fakeRoot) };
    // The fixed verifier recomputes leaf0 (!= FC0) and walks against fakeRoot -> mismatch.
    expect(await rejectionCode(verifyCleartextField({ sdBundle: bundle, cleartextItem: item, escrowCommit: { ...escrowCommit, commit_AAD: { sdMerkleRoot: toHex(fakeRoot) } }, pdaSdConfig, verifierRegistry }))).toBe(SdSdkErrorCode.MERKLE_PATH_INVALID);
  });

  it("REJECTS a forged field_index in the bundle's claimed field (index now binds into the leaf)", async () => {
    // Config field_index for 0x05 is 0; recomputing leaf with a config that says
    // field_index 9 yields a different leaf -> path to the honest root fails. This is
    // the attack the raw-commitment start could not catch (index never entered the hash).
    const forgedConfig: PdaSdConfig = {
      ...pdaSdConfig,
      fields: pdaSdConfig.fields.map((f) => (f.field_id === toHex32(0x05n) ? { ...f, field_index: 9 } : f)),
    };
    const item = cleartextItem({ field_id: toHex32(0x05n), field_commitment: toHex(FC0), merkle_path: PATH0, value: 111 });
    expect(await rejectionCode(verifyCleartextField({ sdBundle: bundleWith([item]), cleartextItem: item, escrowCommit, pdaSdConfig: forgedConfig, verifierRegistry }))).toBe(SdSdkErrorCode.MERKLE_PATH_INVALID);
  });

  it("REJECTS a tampered sibling on an otherwise-valid recomputed-leaf path", async () => {
    const tampered: SdMerklePathElement[] = [
      { sibling: toHex((padded[1]! + 1n) % BN254_PRIME), direction: 0 },
      { sibling: toHex(level1[1]!), direction: 0 },
    ];
    const item = cleartextItem({ field_id: toHex32(0x05n), field_commitment: toHex(FC0), merkle_path: tampered, value: 111 });
    expect(await rejectionCode(verifyCleartextField({ sdBundle: bundleWith([item]), cleartextItem: item, escrowCommit, pdaSdConfig, verifierRegistry }))).toBe(SdSdkErrorCode.MERKLE_PATH_INVALID);
  });

  it("REJECTS a tampered field_commitment (leaf recompute changes, path no longer reaches the root)", async () => {
    const item = cleartextItem({ field_id: toHex32(0x05n), field_commitment: toHex((FC0 + 1n) % BN254_PRIME), merkle_path: PATH0, value: 111 });
    expect(await rejectionCode(verifyCleartextField({ sdBundle: bundleWith([item]), cleartextItem: item, escrowCommit, pdaSdConfig, verifierRegistry }))).toBe(SdSdkErrorCode.MERKLE_PATH_INVALID);
  });
});
