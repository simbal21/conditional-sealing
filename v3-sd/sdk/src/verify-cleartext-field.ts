import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { createRequire } from "node:module";

import { SdSdkError, SdSdkErrorCode, type EscrowCommitReference, type HexScalar, type PdaFieldConfig, type PdaSdConfig, type SdBundle, type SdCleartextItem, type VerifierRegistryClient } from "./types.js";
import { normalizeScalarHex, verifyMerklePath } from "./verify-merkle.js";

// BN254 scalar field modulus (must equal the producer's BN254_PRIME).
const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

type PoseidonFn = ((inputs: ReadonlyArray<bigint>) => Uint8Array) & {
  F: { toObject(value: Uint8Array): bigint };
};

const require = createRequire(import.meta.url);
const { buildPoseidon } = require("circomlibjs") as { buildPoseidon: () => Promise<PoseidonFn> };
const poseidon: PoseidonFn = await buildPoseidon();

// tag_merkle_scalar = OS2IP(keccak256("CEALIS_SD_MERKLE_V3")) mod p. Big-endian
// OS2IP matches the producer's `scalarFromBytesMod(TAG_SD_MERKLE_V3)`
// (`v3-sd/src/merkle/tree.ts`).
const TAG_MERKLE_SCALAR = os2ipMod(keccak_256(utf8ToBytes("CEALIS_SD_MERKLE_V3")));

export async function verifyCleartextField(input: {
  readonly sdBundle: SdBundle;
  readonly cleartextItem: SdCleartextItem;
  readonly escrowCommit: EscrowCommitReference;
  readonly pdaSdConfig: PdaSdConfig;
  readonly verifierRegistry: VerifierRegistryClient;
}): Promise<void> {
  if (input.sdBundle.partner_id.toLowerCase() !== input.escrowCommit.partner_id.toLowerCase()) throw new SdSdkError(SdSdkErrorCode.PARTNER_MISMATCH);
  if (input.sdBundle.authorizationId.toLowerCase() !== input.escrowCommit.authorizationId.toLowerCase()) throw new SdSdkError(SdSdkErrorCode.AUTHORIZATION_MISMATCH);
  const field = fieldById(input.pdaSdConfig, input.cleartextItem.field_id);
  if (!field || field.policy !== "cleartext") throw new SdSdkError(SdSdkErrorCode.FIELD_POLICY_UNKNOWN);
  const encoded = encodeComparable(input.cleartextItem.value, field);
  // §5.1 NORMATIVE: the Merkle LEAF is NOT the raw per-field field_commitment. The
  // producer (`v3-sd/src/merkle/tree.ts` computeMerkleLeaf) builds each
  // leaf as Poseidon5(tag_merkle_scalar, field_index, field_id, field_commitment,
  // policy_code). The off-chain walk must start from that recomputed leaf — starting
  // from the raw field_commitment can never reproduce the Poseidon root for a real
  // multi-leaf bundle (every honest path rejected) and severs the binding between the
  // disclosed field's (index, id, policy) and the committed root (App. F SD-MERKLE-001).
  const leaf = computeCleartextLeaf(field, input.cleartextItem);
  if (!verifyMerklePath({
    fieldCommitment: leaf,
    merklePath: input.cleartextItem.merkle_path,
    expectedRoot: input.sdBundle.sdMerkleRoot ?? leaf,
  })) {
    throw new SdSdkError(SdSdkErrorCode.MERKLE_PATH_INVALID);
  }

  if (input.cleartextItem.opening_mode === "cleartext_zk_opened") {
    const proof = input.cleartextItem.opening_proof;
    if (!proof) throw new SdSdkError(SdSdkErrorCode.PROOF_INVALID);
    if (proof.public_inputs[0] !== encoded) throw new SdSdkError(SdSdkErrorCode.PUBLIC_INPUT_MISMATCH);
    const verifier = await input.verifierRegistry.getVerifierAt(proof.verifier_ref, BigInt(input.escrowCommit.authorizationBlock));
    if (!verifier || !(await verifier.verifyProof(proof, proof.public_inputs))) throw new SdSdkError(SdSdkErrorCode.PROOF_INVALID);
    return;
  }
  if (input.cleartextItem.opening_mode === "cleartext_attested") {
    if (!input.cleartextItem.cleartext_attestation_digest) throw new SdSdkError(SdSdkErrorCode.PROOF_INVALID);
    return;
  }
  throw new SdSdkError(SdSdkErrorCode.PROOF_INVALID);
}

function fieldById(pda: PdaSdConfig, fieldId: string): PdaFieldConfig | undefined {
  return pda.fields.find((field) => field.field_id.toLowerCase() === fieldId.toLowerCase());
}

// Recompute the §5.1 Merkle leaf the producer committed:
//   leaf = Poseidon5(tag_merkle_scalar, field_index, field_id, field_commitment, policy_code)
// (`v3-sd/src/merkle/tree.ts` computeMerkleLeaf). field_index, field_id
// and policy_code come from the PDA-configured field (the trusted side), NOT from the
// attacker-supplied bundle item, so a forged (index, id, policy) cannot recompute the
// honest root. field_commitment is the raw per-field commitment carried in the bundle.
function computeCleartextLeaf(field: PdaFieldConfig, item: SdCleartextItem): HexScalar {
  const fieldCommitment = scalarFromHex(normalizeScalarHex(item.field_commitment));
  const fieldIdScalar = os2ipMod(hexToBytes32(field.field_id));
  const leaf = poseidon.F.toObject(
    poseidon([
      TAG_MERKLE_SCALAR,
      BigInt(field.field_index),
      fieldIdScalar,
      fieldCommitment,
      BigInt(policyCode(field.policy)),
    ]),
  );
  if (leaf < 0n || leaf >= BN254_PRIME) throw new SdSdkError(SdSdkErrorCode.MERKLE_PATH_INVALID);
  return scalarToHex(leaf);
}

// policy_code per §5.1: 1 cleartext, 2 zkp, 3 escrow_only. Derived from the
// PDA-configured policy — nothing hardcoded at the call site.
function policyCode(policy: PdaFieldConfig["policy"]): 1 | 2 | 3 {
  switch (policy) {
    case "cleartext":
      return 1;
    case "zkp":
      return 2;
    case "escrow_only":
      return 3;
    default:
      throw new SdSdkError(SdSdkErrorCode.FIELD_POLICY_UNKNOWN);
  }
}

function scalarFromHex(value: HexScalar): bigint {
  const scalar = BigInt(value);
  if (scalar < 0n || scalar >= BN254_PRIME) throw new SdSdkError(SdSdkErrorCode.MERKLE_PATH_INVALID);
  return scalar;
}

function scalarToHex(value: bigint): HexScalar {
  return `0x${value.toString(16).padStart(64, "0")}` as HexScalar;
}

// 0x + 64 hex chars -> 32 bytes, big-endian. field_id is a Bytes32 reference.
function hexToBytes32(value: string): Uint8Array {
  const lower = value.toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(lower)) throw new SdSdkError(SdSdkErrorCode.FIELD_ENCODING_INVALID);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = parseInt(lower.slice(2 + i * 2, 4 + i * 2), 16);
  return out;
}

function os2ipMod(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc % BN254_PRIME;
}

function encodeComparable(value: unknown, field: PdaFieldConfig): string {
  if (value === null || value === undefined) {
    if (field.nullable) return "0";
    throw new SdSdkError(SdSdkErrorCode.FIELD_ENCODING_INVALID);
  }
  switch (field.field_type_code) {
    case 2:
      return parseUnsigned(value).toString();
    case 4:
      if (typeof value !== "boolean") throw new SdSdkError(SdSdkErrorCode.FIELD_ENCODING_INVALID);
      return value ? "1" : "0";
    case 9:
      if (typeof value !== "string" || !/^[a-zA-Z]{2}$/.test(value)) throw new SdSdkError(SdSdkErrorCode.FIELD_ENCODING_INVALID);
      return ((BigInt(value.toUpperCase().charCodeAt(0)) << 8n) + BigInt(value.toUpperCase().charCodeAt(1))).toString();
    default:
      if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value).toString();
      if (typeof value === "bigint") return value.toString();
      if (typeof value === "string" && /^[0-9]+$/.test(value)) return value;
      return "0";
  }
}

function parseUnsigned(value: unknown): bigint {
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^[0-9]+$/.test(value)) return BigInt(value);
  throw new SdSdkError(SdSdkErrorCode.FIELD_ENCODING_INVALID);
}

