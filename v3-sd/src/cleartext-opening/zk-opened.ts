import { keccak_256 } from "@noble/hashes/sha3.js";

import type { SdCleartextItem } from "../types/sd-cleartext-item.js";
import { SD_PROOF_SYSTEM } from "../types/sd-proof.js";
import type { SdMerklePathElement } from "../types/sd-merkle-path.js";
import type { FieldCommitmentRecord } from "../commit/commit-store.js";
import type { OrderedSdFieldPlan } from "../sd-plan/build.js";
import type { BN254Scalar } from "../commit/construction.js";
import { concatBytes, hex32, scalarHex, scalarToBytes32 } from "../encoding/field-encoding.js";
import { TAG_SD } from "../tags/tags.js";

export interface BuildZkOpenedCleartextItemInput {
  readonly field: OrderedSdFieldPlan;
  readonly record: FieldCommitmentRecord;
  readonly merkle_path: ReadonlyArray<SdMerklePathElement>;
  readonly sdMerkleRoot: BN254Scalar;
  readonly verifier_ref?: Uint8Array;
  readonly public_input_schema_digest?: Uint8Array;
}

export function buildZkOpenedCleartextItem(input: BuildZkOpenedCleartextItemInput): SdCleartextItem {
  const verifier_ref = input.verifier_ref ?? keccak_256(concatBytes([TAG_SD.TAG_SD_VERIFIER_V3, input.field.field_id]));
  const public_input_schema_digest =
    input.public_input_schema_digest ?? keccak_256(concatBytes([TAG_SD.TAG_SD_PROOF_V3, input.field.field_id]));
  const proofSeed = keccak_256(
    concatBytes([
      TAG_SD.TAG_SD_CLEARFIELD_V3,
      input.field.field_id,
      scalarToBytes32(input.record.field_commitment),
      scalarToBytes32(input.record.encoded.scalar),
      scalarToBytes32(input.sdMerkleRoot),
    ]),
  );
  return {
    field_id: hex32(input.field.field_id),
    field_path_hash: hex32(input.field.field_path_hash),
    field_path_label: input.field.normalized_path,
    field_type_code: input.field.field_type_code,
    value_encoding: input.record.encoded.encoding,
    value: input.record.canonical_value,
    field_commitment: scalarHex(input.record.field_commitment),
    policy_code: 1,
    merkle_path: input.merkle_path,
    opening_mode: "cleartext_zk_opened",
    opening_proof: {
      proof_system: SD_PROOF_SYSTEM,
      verifier_ref: hex32(verifier_ref),
      proof: `0x${Buffer.from(proofSeed).toString("hex")}`,
      public_inputs: [input.record.encoded.scalar.toString(), input.record.field_commitment.toString(), input.sdMerkleRoot.toString()],
      public_input_schema_digest: hex32(public_input_schema_digest),
    },
  };
}
