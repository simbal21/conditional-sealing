import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import type { Bytes32 } from "../../src/tags/preimages.js";
import { buildSdPlan, type BuildSdPlanResult } from "../../src/sd-plan/build.js";
import { CLEARTEXT_OPENING_MODE, SD_FIELD_POLICY_CODE } from "../../src/types/sd-field-policy.js";
import { deriveFieldId } from "../../src/encoding/field-id-derivation.js";
import { canonicalizeSchema, type SchemaDefinition } from "../../src/encoding/schema-canonicalization.js";
import type { SdCommitContext } from "../../src/sd-plan/execute.js";

export function b32(label: string): Bytes32 {
  return keccak_256(utf8ToBytes(label));
}

export const baseSchema: SchemaDefinition = {
  fields: [
    { path: "profile.name", type: "string", max_byte_length: 80 },
    { path: "profile.age", type: "uint", numeric_bit_width: 16 },
  ],
};

export function buildCleartextPlan(): BuildSdPlanResult {
  const schema = canonicalizeSchema(baseSchema);
  const name = deriveFieldId({ schema_digest: schema.digest, normalized_field_path: "profile.name", field_type: "string" });
  const age = deriveFieldId({ schema_digest: schema.digest, normalized_field_path: "profile.age", field_type: "uint" });
  return buildSdPlan({
    pda_config: {
      sd_enabled: true,
      ingestion_mode: "MODE_A",
      pda_id: b32("pda"),
      pda_version: 1n,
      cleartext_attestation_allowed: true,
    },
    schema: baseSchema,
    partner_id: b32("partner"),
    field_policy_overrides: [
      { field_id: name.field_id, policy: SD_FIELD_POLICY_CODE.CLEARTEXT, cleartext_opening_mode: CLEARTEXT_OPENING_MODE.ZK_OPENED },
      { field_id: age.field_id, policy: SD_FIELD_POLICY_CODE.CLEARTEXT, cleartext_opening_mode: CLEARTEXT_OPENING_MODE.TEE_ATTESTED },
    ],
  });
}

export function commitCtx(plan: BuildSdPlanResult): SdCommitContext {
  return {
    authorizationId: b32("authorization"),
    h_commit: b32("h_commit"),
    pda_root: b32("pda_root"),
    partner_id: plan.sd_plan.partner_id,
    pda_id: plan.sd_plan.pda_id,
    pda_version: plan.sd_plan.pda_version.toString(),
    schema_digest: plan.sd_plan.schema_digest,
    ingestion_mode: "MODE_A",
  };
}

export function payload(): Record<string, unknown> {
  return { profile: { name: "Alice", age: 37 } };
}

export function dek(): Uint8Array {
  return b32("dek");
}
