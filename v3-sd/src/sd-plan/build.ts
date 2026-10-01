import type { Bytes32 } from "../tags/preimages.js";
import type { SdPlan } from "../types/sd-plan.js";
import { SD_PLAN_VERSION, MODE_A_INGESTION_MODE_CODE, MODE_B_INGESTION_MODE_CODE } from "../types/sd-plan.js";
import type { SdFieldPolicyCode, CleartextOpeningModeCode } from "../types/sd-field-policy.js";
import { CLEARTEXT_OPENING_MODE, PII_CLASS, SD_FIELD_POLICY_CODE } from "../types/sd-field-policy.js";
import type { SdClaimConfig } from "../types/sd-claim-config.js";
import { CLAIM_TYPE_CODE } from "../types/sd-claim-config.js";
import { SdError } from "../errors/sd-error.js";
import { SdErrorCode } from "../errors/codes.js";
import { assertModeBSdCompatible, type IngestionMode } from "../mode-b/rejection.js";
import { bytes32, hex32 } from "../encoding/field-encoding.js";
import { canonicalizeSchema, type CanonicalSchemaField, type SchemaDefinition } from "../encoding/schema-canonicalization.js";
import { deriveFieldId } from "../encoding/field-id-derivation.js";
import { canonicallyOrderLeaves } from "../merkle/tree.js";
import { deriveSdPlanDigest, digestCanonical } from "./digest.js";

export interface PdaSdConfig {
  readonly sd_enabled: boolean;
  readonly ingestion_mode: IngestionMode;
  readonly pda_id: Bytes32;
  readonly pda_version: bigint;
  readonly pda_root?: Bytes32;
  readonly cleartext_attestation_allowed?: boolean;
  readonly public_composability_allowed?: boolean;
  readonly default_expiry_policy_ref?: Bytes32;
  readonly revocation_policy_ref?: Bytes32;
}

export interface FieldPolicyOverride {
  readonly path?: string;
  readonly field_id?: Bytes32;
  readonly policy: SdFieldPolicyCode;
  readonly cleartext_opening_mode?: CleartextOpeningModeCode;
  readonly pii_class?: number;
}

export interface OrderedSdFieldPlan {
  readonly field_index: number;
  readonly field_id: Bytes32;
  readonly normalized_path: string;
  readonly field_path_hash: Bytes32;
  readonly field_type_code: number;
  readonly declaration_index: number;
  readonly policy: SdFieldPolicyCode;
  readonly cleartext_opening_mode: CleartextOpeningModeCode;
  readonly pii_class: number;
  readonly schema: CanonicalSchemaField;
}

export interface BuildSdPlanInput {
  readonly pda_config: PdaSdConfig;
  readonly schema: SchemaDefinition;
  readonly partner_id: Bytes32;
  readonly claim_configs?: ReadonlyArray<SdClaimConfig>;
  readonly field_policy_overrides?: ReadonlyArray<FieldPolicyOverride>;
}

export interface BuildSdPlanResult {
  readonly sd_plan: SdPlan;
  readonly sd_plan_digest: Bytes32;
  readonly ordered_fields: ReadonlyArray<OrderedSdFieldPlan>;
  readonly claim_plan: ReadonlyArray<SdClaimConfig>;
  readonly schema: ReturnType<typeof canonicalizeSchema>;
}

const ZERO32 = new Uint8Array(32) as Bytes32;

export function buildSdPlan(input: BuildSdPlanInput): BuildSdPlanResult {
  assertModeBSdCompatible({
    ingestion_mode: input.pda_config.ingestion_mode,
    sd_enabled: input.pda_config.sd_enabled,
  });

  const schema = canonicalizeSchema(input.schema);
  if (!input.pda_config.sd_enabled) {
    const disabledPlan: SdPlan = {
      sd_version: SD_PLAN_VERSION,
      partner_id: bytes32(input.partner_id, "partner_id"),
      pda_id: bytes32(input.pda_config.pda_id, "pda_id"),
      pda_version: input.pda_config.pda_version,
      schema_digest: schema.digest,
      ingestion_mode: input.pda_config.ingestion_mode === "MODE_B" ? MODE_B_INGESTION_MODE_CODE : MODE_A_INGESTION_MODE_CODE,
      sd_enabled: false,
      field_policy_root: ZERO32,
      claim_plan_root: ZERO32,
      default_expiry_policy_ref: input.pda_config.default_expiry_policy_ref ?? ZERO32,
      revocation_policy_ref: input.pda_config.revocation_policy_ref ?? ZERO32,
      cleartext_attestation_allowed: input.pda_config.cleartext_attestation_allowed ?? false,
      public_composability_allowed: input.pda_config.public_composability_allowed ?? false,
    };
    return {
      sd_plan: disabledPlan,
      sd_plan_digest: deriveSdPlanDigest(disabledPlan),
      ordered_fields: [],
      claim_plan: [],
      schema,
    };
  }

  if (input.pda_config.ingestion_mode !== "MODE_A") {
    throw new SdError(SdErrorCode.CONFIG_MODE_B_INCOMPATIBLE, { stage: "schema_validation" });
  }

  const unordered = schema.normalized.fields.map((field) => {
    const id = deriveFieldId({
      schema_digest: schema.digest,
      normalized_field_path: field.path,
      field_type: field.type,
    });
    const override = findOverride(input.field_policy_overrides ?? [], field.path, id.field_id);
    const policy = override?.policy ?? SD_FIELD_POLICY_CODE.ESCROW_ONLY;
    if (!Object.values(SD_FIELD_POLICY_CODE).includes(policy)) {
      throw new SdError(SdErrorCode.FIELD_POLICY_UNKNOWN, { stage: "schema_validation" });
    }
    return {
      field_index: 0,
      field_id: id.field_id,
      normalized_path: id.normalized_field_path,
      field_path_hash: id.field_path_hash,
      field_type_code: id.field_type_code,
      declaration_index: field.declaration_index,
      policy,
      cleartext_opening_mode:
        override?.cleartext_opening_mode ??
        (policy === SD_FIELD_POLICY_CODE.CLEARTEXT ? CLEARTEXT_OPENING_MODE.ZK_OPENED : CLEARTEXT_OPENING_MODE.NONE),
      pii_class: override?.pii_class ?? PII_CLASS.ORDINARY,
      schema: field,
    };
  });

  const ordered = canonicallyOrderLeaves(unordered).map(
    (field, field_index): OrderedSdFieldPlan => ({ ...field, field_index }),
  );

  const field_policy_root = digestCanonical(
    ordered.map((field) => ({
      field_index: field.field_index,
      field_id: hex32(field.field_id),
      field_path_hash: hex32(field.field_path_hash),
      field_type_code: field.field_type_code,
      policy: field.policy,
      cleartext_opening_mode: field.cleartext_opening_mode,
      pii_class: field.pii_class,
    })),
  );
  const claim_plan = [...(input.claim_configs ?? [])];
  for (const claim of claim_plan) {
    if (!Object.values(CLAIM_TYPE_CODE).includes(claim.claim_type)) {
      throw new SdError(SdErrorCode.FIELD_POLICY_UNKNOWN, { stage: "schema_validation" });
    }
  }
  const claim_plan_root = digestCanonical(
    claim_plan.map((claim) => ({ ...claim, claim_id: hex32(claim.claim_id), expression_digest: hex32(claim.expression_digest) })),
  );
  const sd_plan: SdPlan = {
    sd_version: SD_PLAN_VERSION,
    partner_id: bytes32(input.partner_id, "partner_id"),
    pda_id: bytes32(input.pda_config.pda_id, "pda_id"),
    pda_version: input.pda_config.pda_version,
    schema_digest: schema.digest,
    ingestion_mode: MODE_A_INGESTION_MODE_CODE,
    sd_enabled: true,
    field_policy_root,
    claim_plan_root,
    default_expiry_policy_ref: input.pda_config.default_expiry_policy_ref ?? ZERO32,
    revocation_policy_ref: input.pda_config.revocation_policy_ref ?? ZERO32,
    cleartext_attestation_allowed: input.pda_config.cleartext_attestation_allowed ?? false,
    public_composability_allowed: input.pda_config.public_composability_allowed ?? false,
  };
  return { sd_plan, sd_plan_digest: deriveSdPlanDigest(sd_plan), ordered_fields: ordered, claim_plan, schema };
}

function findOverride(
  overrides: ReadonlyArray<FieldPolicyOverride>,
  path: string,
  fieldId: Bytes32,
): FieldPolicyOverride | undefined {
  const idHex = hex32(fieldId);
  return overrides.find((o) => o.path === path || (o.field_id !== undefined && hex32(o.field_id) === idHex));
}
