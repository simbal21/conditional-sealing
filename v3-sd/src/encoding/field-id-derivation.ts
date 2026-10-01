import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { TAG_SD } from "../tags/tags.js";
import type { Bytes32, FieldIdInputs } from "../tags/preimages.js";
import { bytes32, concatBytes, fieldTypeCodeFromName, normalizeFieldPath, type FieldTypeName } from "./field-encoding.js";

export interface DeriveFieldIdInput {
  readonly schema_digest: Bytes32;
  readonly normalized_field_path: string;
  readonly field_type: FieldTypeName | number;
}

export interface DeriveFieldIdResult {
  readonly field_id: Bytes32;
  readonly field_path_hash: Bytes32;
  readonly field_type_code: number;
  readonly normalized_field_path: string;
}

export function deriveFieldPathHash(normalized_field_path: string): Bytes32 {
  return keccak_256(utf8ToBytes(normalizeFieldPath(normalized_field_path)));
}

export function deriveFieldIdFromParts(input: FieldIdInputs): Bytes32 {
  const code = input.field_type_code;
  if (!Number.isInteger(code) || code < 0 || code > 0xff) throw new RangeError(`field_type_code: ${code}`);
  return keccak_256(
    concatBytes([
      TAG_SD.TAG_SD_FIELD_ID_V3,
      bytes32(input.schema_digest, "schema_digest"),
      bytes32(input.field_path_hash, "field_path_hash"),
      new Uint8Array([code]),
    ]),
  );
}

export function deriveFieldId(input: DeriveFieldIdInput): DeriveFieldIdResult {
  const normalized_field_path = normalizeFieldPath(input.normalized_field_path);
  const field_type_code =
    typeof input.field_type === "number" ? input.field_type : fieldTypeCodeFromName(input.field_type);
  const field_path_hash = deriveFieldPathHash(normalized_field_path);
  const field_id = deriveFieldIdFromParts({
    schema_digest: input.schema_digest,
    field_path_hash,
    field_type_code,
  });
  return { field_id, field_path_hash, field_type_code, normalized_field_path };
}
