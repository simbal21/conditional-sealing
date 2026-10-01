import { keccak_256 } from "@noble/hashes/sha3.js";

import type { SdCleartextItem } from "../types/sd-cleartext-item.js";
import type { SdMerklePathElement } from "../types/sd-merkle-path.js";
import type { FieldCommitmentRecord } from "../commit/commit-store.js";
import type { OrderedSdFieldPlan } from "../sd-plan/build.js";
import { concatBytes, hex32, scalarToBytes32, scalarHex } from "../encoding/field-encoding.js";
import { TAG_SD } from "../tags/tags.js";

export interface BuildTeeAttestedCleartextItemInput {
  readonly field: OrderedSdFieldPlan;
  readonly record: FieldCommitmentRecord;
  readonly merkle_path: ReadonlyArray<SdMerklePathElement>;
  readonly tee_attestation_ref: Uint8Array;
}

export function buildTeeAttestedCleartextItem(input: BuildTeeAttestedCleartextItemInput): SdCleartextItem {
  const cleartext_attestation_digest = keccak_256(
    concatBytes([
      TAG_SD.TAG_SD_CLEARFIELD_V3,
      input.tee_attestation_ref,
      input.field.field_id,
      scalarToBytes32(input.record.field_commitment),
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
    opening_mode: "cleartext_attested",
    cleartext_attestation_digest: hex32(cleartext_attestation_digest),
  };
}
