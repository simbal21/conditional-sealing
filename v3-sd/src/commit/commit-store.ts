import type { Bytes32 } from "../tags/preimages.js";
import type { BN254Scalar } from "./construction.js";
import type { EncodedFieldValue } from "../encoding/field-encoding.js";
import type { SdFieldPolicyCode } from "../types/sd-field-policy.js";
import { hex32 } from "../encoding/field-encoding.js";

export interface FieldCommitmentRecord {
  readonly field_index: number;
  readonly field_id: Bytes32;
  readonly field_path_hash: Bytes32;
  readonly field_type_code: number;
  readonly field_commitment: BN254Scalar;
  readonly policy: SdFieldPolicyCode;
  readonly encoded: EncodedFieldValue;
  readonly canonical_value: unknown;
  readonly salt_scalar: BN254Scalar;
  readonly salt_bytes: Uint8Array;
  readonly retry_count: number;
}

export class CommitStore {
  readonly #records = new Map<string, FieldCommitmentRecord>();

  set(record: FieldCommitmentRecord): void {
    this.#records.set(hex32(record.field_id), record);
  }

  get(field_id: Bytes32): FieldCommitmentRecord | undefined {
    return this.#records.get(hex32(field_id));
  }

  values(): ReadonlyArray<FieldCommitmentRecord> {
    return [...this.#records.values()];
  }

  zeroizeSalts(): void {
    for (const record of this.#records.values()) record.salt_bytes.fill(0);
  }
}
