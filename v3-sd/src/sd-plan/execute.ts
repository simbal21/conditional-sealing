import type { Bytes32 } from "../tags/preimages.js";
import type { SdBundle, SdBundleStatus } from "../types/sd-bundle.js";
import { ROOT_BINDING_LEVEL, SD_BUNDLE_VERSION } from "../types/sd-bundle.js";
import { SD_FIELD_POLICY_CODE } from "../types/sd-field-policy.js";
import type { SdFailureItem } from "../types/sd-failure-item.js";
import { SdError } from "../errors/sd-error.js";
import { SdErrorCode, type SdErrorCodeValue } from "../errors/codes.js";
import type { SdFailureStage } from "../types/failure-modes.js";
import { CommitStore } from "../commit/commit-store.js";
import { buildFieldCommitmentFromBytes } from "../commit/construction.js";
import { deriveSdFieldSalt, deriveSdMasterSalt, deriveSdSaltContextDigest } from "../commit/salt-derivation.js";
import { encodeFieldValue, hex32, scalarHex, scalarToBytes32 } from "../encoding/field-encoding.js";
import { normalizePayloadAgainstSchema } from "../encoding/schema-canonicalization.js";
import { buildSdMerkleTree, pathToBundlePath } from "../merkle/path-generation.js";
import { buildZkOpenedCleartextItem } from "../cleartext-opening/zk-opened.js";
import { buildTeeAttestedCleartextItem } from "../cleartext-opening/tee-attested.js";
import { deriveSdBundleDigest } from "./digest.js";
import { finalizeSdExecution } from "./finalizer.js";
import type { BuildSdPlanResult } from "./build.js";

export interface SdCommitContext {
  readonly authorizationId: Bytes32;
  readonly h_commit: Bytes32;
  readonly pda_root: Bytes32;
  readonly partner_id: Bytes32;
  readonly pda_id: Bytes32;
  readonly pda_version: string;
  readonly schema_digest: Bytes32;
  readonly ingestion_mode: "MODE_A" | "MODE_B";
}

export interface ExecuteSdAtCommitInput {
  readonly plaintext: Record<string, unknown>;
  readonly commit_ctx: SdCommitContext;
  readonly plan: BuildSdPlanResult;
  readonly dek: Uint8Array;
  readonly tee_attestation_ref?: Bytes32;
  readonly induce_failure_stage?: SdFailureStage;
}

export interface ExecuteSdAtCommitResult {
  readonly status: SdBundleStatus;
  readonly bundle: SdBundle;
  readonly sdMerkleRootBytes: Bytes32;
}

const ZERO32 = new Uint8Array(32) as Bytes32;

export async function executeSdAtCommit(input: ExecuteSdAtCommitInput): Promise<ExecuteSdAtCommitResult> {
  if (!input.plan.sd_plan.sd_enabled) return disabledBundle(input);
  if (input.commit_ctx.ingestion_mode !== "MODE_A") {
    throw new SdError(SdErrorCode.CONFIG_MODE_B_INCOMPATIBLE, { stage: "schema_validation" });
  }

  let status: SdBundleStatus = "complete";
  const failures: SdFailureItem[] = [];
  let fatal_sd_error: SdFailureItem | null = null;
  let skip_generation = false;
  let normalized_payload: Record<string, unknown> | null = null;
  let sd_master_salt: Uint8Array | null = null;
  const field_salts: Uint8Array[] = [];
  const encoded_values: Array<{ readonly bytes?: Uint8Array }> = [];
  const commitStore = new CommitStore();
  let sd_salt_context_digest: Bytes32 | null = null;
  let sdMerkleRootBytes: Bytes32 | null = null;

  try {
    maybeInduce(input, "schema_validation");
    normalized_payload = normalizePayloadAgainstSchema(input.plaintext, input.plan.schema);

    if (!skip_generation) {
      maybeInduce(input, "salt_derivation");
      sd_salt_context_digest = deriveSdSaltContextDigest({
        authorizationId: input.commit_ctx.authorizationId,
        pda_root: input.commit_ctx.pda_root,
        schema_digest: input.plan.sd_plan.schema_digest,
        partner_id: input.commit_ctx.partner_id,
        sd_plan_digest: input.plan.sd_plan_digest,
      });
      sd_master_salt = deriveSdMasterSalt(input.dek, sd_salt_context_digest);
    }

    if (!skip_generation && sd_master_salt && normalized_payload) {
      for (const field of input.plan.ordered_fields) {
        const value = normalized_payload[field.normalized_path];
        const encoded = encodeFieldValue(value, field.field_type_code, {
          nullable: field.schema.nullable,
          max_byte_length: field.schema.max_byte_length,
          numeric_bit_width: field.schema.numeric_bit_width,
          decimal_scale: field.schema.decimal_scale,
          enum_values: field.schema.enum_values,
          field_id_hex: hex32(field.field_id),
        });
        encoded_values.push(encoded);
        const salt = deriveSdFieldSalt({
          sd_master_salt,
          authorizationId: input.commit_ctx.authorizationId,
          field_id: field.field_id,
          field_index: field.field_index,
        });
        field_salts.push(salt.salt_bytes);
        maybeInduce(input, "commitment_build");
        const field_commitment = buildFieldCommitmentFromBytes({
          authorizationId: input.commit_ctx.authorizationId,
          field_id: field.field_id,
          field_salt_bytes: salt.salt_bytes,
          value_scalar_encoded_bytes: scalarToBytes32(encoded.scalar),
        });
        commitStore.set({
          field_index: field.field_index,
          field_id: field.field_id,
          field_path_hash: field.field_path_hash,
          field_type_code: field.field_type_code,
          field_commitment,
          policy: field.policy,
          encoded,
          canonical_value: encoded.normalized_value,
          salt_scalar: salt.scalar,
          salt_bytes: salt.salt_bytes,
          retry_count: salt.retry_count,
        });
      }

      const merkle = buildSdMerkleTree(
        commitStore.values().map((record) => ({
          field_index: record.field_index,
          field_id: record.field_id,
          field_commitment: record.field_commitment,
          policy: record.policy,
          field_path_hash: record.field_path_hash,
          field_type_code: record.field_type_code,
          declaration_index: input.plan.ordered_fields[record.field_index]?.declaration_index ?? record.field_index,
        })),
      );
      sdMerkleRootBytes = scalarToBytes32(merkle.root) as Bytes32;

      const cleartext = [];
      for (const [idx, field] of input.plan.ordered_fields.entries()) {
        const record = commitStore.get(field.field_id);
        if (!record || field.policy !== SD_FIELD_POLICY_CODE.CLEARTEXT) continue;
        const path = merkle.paths[idx] ?? [];
        if (field.cleartext_opening_mode === 2) {
          cleartext.push(
            buildTeeAttestedCleartextItem({
              field,
              record,
              merkle_path: pathToBundlePath(path),
              tee_attestation_ref: input.tee_attestation_ref ?? ZERO32,
            }),
          );
        } else {
          maybeInduce(input, "proving");
          cleartext.push(
            buildZkOpenedCleartextItem({
              field,
              record,
              merkle_path: pathToBundlePath(path),
              sdMerkleRoot: merkle.root,
            }),
          );
        }
      }
      maybeInduce(input, "response_assembly");
      maybeInduce(input, "partner_verify");
      maybeInduce(input, "revocation_check");

      const rootBytes = sdMerkleRootBytes;
      const saltContext = sd_salt_context_digest;
      if (rootBytes === null || saltContext === null) {
        throw new SdError(SdErrorCode.ONBOARDING_PARTIAL_FAILURE, { stage: "response_assembly" });
      }
      const bundleDigest = deriveSdBundleDigest({
        authorizationId: input.commit_ctx.authorizationId,
        h_commit: input.commit_ctx.h_commit,
        pda_root: input.commit_ctx.pda_root,
        partner_id: input.commit_ctx.partner_id,
        sdMerkleRoot: rootBytes,
        sd_salt_context_digest: saltContext,
        sd_plan_digest: input.plan.sd_plan_digest,
      });
      return {
        status,
        sdMerkleRootBytes: rootBytes,
        bundle: {
          sd_version: SD_BUNDLE_VERSION,
          status,
          authorizationId: hex32(input.commit_ctx.authorizationId),
          h_commit: hex32(input.commit_ctx.h_commit),
          pda_root: hex32(input.commit_ctx.pda_root),
          partner_id: hex32(input.commit_ctx.partner_id),
          pda_id: hex32(input.commit_ctx.pda_id),
          pda_version: input.commit_ctx.pda_version,
          schema_digest: hex32(input.plan.sd_plan.schema_digest),
          sdMerkleRoot: scalarHex(merkle.root),
          sd_salt_context_digest: hex32(saltContext),
          sd_plan_digest: hex32(input.plan.sd_plan_digest),
          sd_bundle_digest: hex32(bundleDigest),
          rootBindingLevel: ROOT_BINDING_LEVEL,
          generated_at: new Date(0).toISOString(),
          tee_attestation_ref: input.tee_attestation_ref ? hex32(input.tee_attestation_ref) : undefined,
          cleartext,
          claims: [],
          failures,
        },
      };
    }
  } catch (cause) {
    status = "failed";
    const err = cause instanceof SdError ? cause : new SdError(SdErrorCode.ONBOARDING_PARTIAL_FAILURE, { stage: "response_assembly", cause });
    fatal_sd_error = failureFromError(err);
    failures.push(fatal_sd_error);
    skip_generation = true;
  } finally {
    finalizeSdExecution({
      plaintext: input.plaintext,
      normalized_payload,
      sd_master_salt,
      field_salts,
      encoded_values,
      commit_store: commitStore,
    });
  }

  if (status === "failed" && (sdMerkleRootBytes === null || skip_generation)) {
    const sd_salt_context_digest_safe = sd_salt_context_digest ?? ZERO32;
    const bundleDigest = deriveSdBundleDigest({
      authorizationId: input.commit_ctx.authorizationId,
      h_commit: input.commit_ctx.h_commit,
      pda_root: input.commit_ctx.pda_root,
      partner_id: input.commit_ctx.partner_id,
      sdMerkleRoot: ZERO32,
      sd_salt_context_digest: sd_salt_context_digest_safe,
      sd_plan_digest: input.plan.sd_plan_digest,
    });
    return {
      status: "failed",
      sdMerkleRootBytes: ZERO32,
      bundle: {
        sd_version: SD_BUNDLE_VERSION,
        status: "failed",
        authorizationId: hex32(input.commit_ctx.authorizationId),
        h_commit: hex32(input.commit_ctx.h_commit),
        pda_root: hex32(input.commit_ctx.pda_root),
        partner_id: hex32(input.commit_ctx.partner_id),
        pda_id: hex32(input.commit_ctx.pda_id),
        pda_version: input.commit_ctx.pda_version,
        schema_digest: hex32(input.plan.sd_plan.schema_digest),
        sd_salt_context_digest: hex32(sd_salt_context_digest_safe),
        sd_plan_digest: hex32(input.plan.sd_plan_digest),
        sd_bundle_digest: hex32(bundleDigest),
        rootBindingLevel: ROOT_BINDING_LEVEL,
        generated_at: new Date(0).toISOString(),
        cleartext: [],
        claims: [],
        failures,
      },
    };
  }

  throw new SdError(SdErrorCode.ONBOARDING_PARTIAL_FAILURE, { stage: "response_assembly" });
}

function disabledBundle(input: ExecuteSdAtCommitInput): ExecuteSdAtCommitResult {
  return {
    status: "not_configured",
    sdMerkleRootBytes: ZERO32,
    bundle: {
      sd_version: SD_BUNDLE_VERSION,
      status: "not_configured",
      authorizationId: hex32(input.commit_ctx.authorizationId),
      h_commit: hex32(input.commit_ctx.h_commit),
      pda_root: hex32(input.commit_ctx.pda_root),
      partner_id: hex32(input.commit_ctx.partner_id),
      pda_id: hex32(input.commit_ctx.pda_id),
      pda_version: input.commit_ctx.pda_version,
      schema_digest: hex32(input.plan.sd_plan.schema_digest),
      sd_salt_context_digest: hex32(ZERO32),
      sd_plan_digest: hex32(input.plan.sd_plan_digest),
      sd_bundle_digest: hex32(ZERO32),
      rootBindingLevel: ROOT_BINDING_LEVEL,
      generated_at: new Date(0).toISOString(),
      cleartext: [],
      claims: [],
      failures: [],
    },
  };
}

function maybeInduce(input: ExecuteSdAtCommitInput, stage: SdFailureStage): void {
  if (input.induce_failure_stage !== stage) return;
  const code: SdErrorCodeValue =
    stage === "salt_derivation"
      ? SdErrorCode.SALT_DERIVATION_FAIL
      : stage === "commitment_build"
        ? SdErrorCode.COMMITMENT_MISMATCH
        : stage === "proving" || stage === "partner_verify"
          ? SdErrorCode.PROOF_INVALID
          : stage === "revocation_check"
            ? SdErrorCode.CLAIM_REVOKED
            : stage === "response_assembly"
              ? SdErrorCode.ONBOARDING_PARTIAL_FAILURE
              : SdErrorCode.FIELD_ENCODING_INVALID;
  throw new SdError(code, { stage });
}

function failureFromError(err: SdError): SdFailureItem {
  return {
    scope: "bundle",
    error: err.code,
    retryable: err.code === SdErrorCode.SALT_DERIVATION_FAIL || err.code === SdErrorCode.ONBOARDING_PARTIAL_FAILURE,
  };
}
