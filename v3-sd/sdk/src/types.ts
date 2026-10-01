export const SDK_PACKAGE_VERSION = "0.1.0" as const;
export const SDK_PACKAGE_PHASE = "E_SHIPPED" as const;

export const SD_BUNDLE_VERSION = "s2-7-1.0" as const;
export const ROOT_BINDING_LEVEL = "commit_AAD" as const;
export const ZERO_HEX_32 = `0x${"00".repeat(32)}` as const;

export const SdSdkErrorCode = {
  CONFIG_MODE_B_INCOMPATIBLE: "ERR_SD_CONFIG_MODE_B_INCOMPATIBLE",
  FIELD_POLICY_UNKNOWN: "ERR_SD_FIELD_POLICY_UNKNOWN",
  FIELD_ENCODING_INVALID: "ERR_SD_FIELD_ENCODING_INVALID",
  MERKLE_PATH_INVALID: "ERR_SD_MERKLE_PATH_INVALID",
  ROOT_BINDING_MISSING: "ERR_SD_ROOT_BINDING_MISSING",
  PROOF_INVALID: "ERR_SD_PROOF_INVALID",
  PUBLIC_INPUT_MISMATCH: "ERR_SD_PUBLIC_INPUT_MISMATCH",
  CLAIM_EXPIRED: "ERR_SD_CLAIM_EXPIRED",
  CLAIM_REVOKED: "ERR_SD_CLAIM_REVOKED",
  PARTNER_MISMATCH: "ERR_SD_PARTNER_MISMATCH",
  PDA_MISMATCH: "ERR_SD_PDA_MISMATCH",
  AUTHORIZATION_MISMATCH: "ERR_SD_AUTHORIZATION_MISMATCH",
  ONBOARDING_PARTIAL_FAILURE: "ERR_SD_ONBOARDING_PARTIAL_FAILURE",
} as const;

export type SdSdkErrorCodeValue = typeof SdSdkErrorCode[keyof typeof SdSdkErrorCode];
export type Hex = `0x${string}`;
export type Hex32 = `0x${string}`;
export type HexScalar = `0x${string}`;
export type SdBundleStatus = "complete" | "partial" | "failed" | "not_configured";
export type ClaimTypeLabel = "range" | "equality" | "set_membership" | "non_equality" | "composed";
export type CleartextOpeningModeLabel = "cleartext_zk_opened" | "cleartext_attested";
export type SdBindingMode = "sd_disabled" | "sd_enabled" | "sd_failed_before_root";

export type VerifySdBundleResult = {
  status: "valid" | "partial" | "invalid";
  rootBindingLevel: "commit_AAD";
  acceptedClaims: string[];
  rejectedClaims: { claimId: string; error: string }[];
  acceptedCleartextFields: string[];
  rejectedCleartextFields: { fieldId: string; error: string }[];
};

export interface EscrowCommitReference {
  readonly commit_version: "0x0302";
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly pda_root: Hex32;
  readonly partner_id: Hex32;
  readonly pda_id: Hex32;
  readonly pda_version: string;
  readonly schema_digest: Hex32;
  readonly authorizationBlock: bigint | number;
  readonly commit_AAD: {
    readonly sdMerkleRoot: Hex32;
  };
}

export interface SdMerklePathElement {
  readonly sibling: HexScalar;
  readonly direction: 0 | 1;
}

export interface SdProof {
  readonly proof_system: "plonk-bn254";
  readonly verifier_ref: Hex32;
  readonly proof: Hex;
  readonly public_inputs: readonly string[];
  readonly public_input_schema_digest: Hex32;
}

export interface SdCleartextItem {
  readonly field_id: Hex32;
  readonly field_path_hash?: Hex32;
  readonly field_path_label?: string;
  readonly field_type_code: number;
  readonly value_encoding?: string;
  readonly value: unknown;
  readonly field_commitment: HexScalar;
  readonly policy_code: 1;
  readonly merkle_path: readonly SdMerklePathElement[];
  readonly opening_mode: CleartextOpeningModeLabel;
  readonly opening_proof?: SdProof;
  readonly cleartext_attestation_digest?: Hex32;
}

export interface SdClaimItem {
  readonly claim_id: Hex32;
  readonly claim_type: ClaimTypeLabel;
  readonly field_ids: readonly Hex32[];
  readonly verifier_ref: Hex32;
  readonly proof: Hex;
  readonly public_inputs: readonly string[];
  readonly proof_context_digest?: Hex32;
  readonly expiry_timestamp: number;
  readonly disclosure_id: Hex32;
  readonly on_chain_registered?: boolean;
}

export interface SdFailureItem {
  readonly scope: "bundle" | "field" | "claim" | "registry" | "mode" | "prover" | "verifier";
  readonly field_id?: Hex32;
  readonly claim_id?: Hex32;
  readonly error: SdSdkErrorCodeValue;
  readonly retryable: boolean;
  readonly detail_ref?: Hex32;
}

export interface SdBundle {
  readonly sd_version: typeof SD_BUNDLE_VERSION;
  readonly status: SdBundleStatus;
  readonly authorizationId: Hex32;
  readonly h_commit: Hex32;
  readonly pda_root: Hex32;
  readonly partner_id: Hex32;
  readonly pda_id: Hex32;
  readonly pda_version: string;
  readonly schema_digest: Hex32;
  readonly sdMerkleRoot?: HexScalar;
  readonly sd_salt_context_digest: Hex32;
  readonly sd_plan_digest: Hex32;
  readonly sd_bundle_digest: Hex32;
  readonly rootBindingLevel: typeof ROOT_BINDING_LEVEL;
  readonly generated_at: string;
  readonly tee_attestation_ref?: Hex32;
  readonly cleartext: readonly SdCleartextItem[];
  readonly claims: readonly SdClaimItem[];
  readonly failures?: readonly SdFailureItem[];
}

export interface PdaFieldConfig {
  readonly field_id: Hex32;
  readonly policy: "cleartext" | "zkp" | "escrow_only";
  readonly field_type_code: number;
  readonly field_index: number;
  readonly nullable?: boolean;
  readonly max_byte_length?: number;
  readonly numeric_bit_width?: number;
  readonly decimal_scale?: number;
  readonly enum_values?: readonly string[];
}

export interface PdaClaimConfig {
  readonly claim_id: Hex32;
  readonly claim_type: ClaimTypeLabel;
  readonly field_ids: readonly Hex32[];
  readonly expected_public_inputs?: readonly string[];
  readonly public_input_schema_digest?: Hex32;
}

export interface PdaSdConfig {
  readonly sd_enabled: boolean;
  readonly ingestion_mode: "MODE_A" | "MODE_B";
  readonly fields: readonly PdaFieldConfig[];
  readonly claims: readonly PdaClaimConfig[];
  readonly sd_plan_digest?: Hex32;
  readonly allow_offline_revocation_grace?: boolean;
}

export interface Verifier {
  readonly publicInputSchemaDigest?: Hex32;
  verifyProof(proof: Hex | SdProof, publicInputs: readonly string[]): boolean | Promise<boolean>;
}

export interface VerifierRegistryClient {
  getVerifierAt(verifierRef: Hex32, authorizationBlock: bigint): Promise<Verifier | null> | Verifier | null;
}

export interface RevocationRegistryClient {
  isRevoked(disclosureId: Hex32): Promise<boolean> | boolean;
}

export interface VerifySdBundleInput {
  readonly escrowCommit: EscrowCommitReference;
  readonly sdBundle?: SdBundle;
  readonly pdaSdConfig: PdaSdConfig;
  readonly verifierRegistry: VerifierRegistryClient;
  readonly revocationRegistry: RevocationRegistryClient;
  readonly now: Date;
}

export class SdSdkError extends Error {
  readonly code: SdSdkErrorCodeValue;

  constructor(code: SdSdkErrorCodeValue, message = code) {
    super(message);
    this.name = "SdSdkError";
    this.code = code;
  }
}

