// ERR_SD_* canonical error catalog — 16 entries verbatim from §1.3 lines
// 185-202. PHASE A LOCKED.
//
// §1.3 normative: "These errors are fail-closed for the SD artifact being
// verified, but do not fail escrow commit or escrow reveal unless the caller
// explicitly configured a business-level onboarding policy outside the escrow
// pipeline."
//
// Error contexts MUST NOT include PII, salts, witness values, malformed
// plaintext, raw proof bytes, partial AAD bytes, or σ values. Hashes, ids,
// enum values, timestamps, and proof lengths are acceptable per §1.4.

export const SdErrorCode = {
  CONFIG_MODE_B_INCOMPATIBLE: "ERR_SD_CONFIG_MODE_B_INCOMPATIBLE",
  FIELD_POLICY_UNKNOWN: "ERR_SD_FIELD_POLICY_UNKNOWN",
  FIELD_ENCODING_INVALID: "ERR_SD_FIELD_ENCODING_INVALID",
  SALT_DERIVATION_FAIL: "ERR_SD_SALT_DERIVATION_FAIL",
  SALT_ESCAPED_TEE: "ERR_SD_SALT_ESCAPED_TEE",
  COMMITMENT_MISMATCH: "ERR_SD_COMMITMENT_MISMATCH",
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

export type SdErrorCodeValue = typeof SdErrorCode[keyof typeof SdErrorCode];

/** Canonical 16-row trigger table per §1.3 lines 186-202, verbatim. */
export const SD_ERROR_TRIGGER_TABLE: ReadonlyArray<{ code: SdErrorCodeValue; trigger: string }> = Object.freeze([
  { code: SdErrorCode.CONFIG_MODE_B_INCOMPATIBLE, trigger: "PDA enables SD under Mode B" },
  { code: SdErrorCode.FIELD_POLICY_UNKNOWN, trigger: "field mapping has no valid state" },
  { code: SdErrorCode.FIELD_ENCODING_INVALID, trigger: "field value cannot be encoded canonically" },
  { code: SdErrorCode.SALT_DERIVATION_FAIL, trigger: "HKDF failed or returned wrong length" },
  { code: SdErrorCode.SALT_ESCAPED_TEE, trigger: "implementation attempted to store/log/export an SD salt" },
  { code: SdErrorCode.COMMITMENT_MISMATCH, trigger: "disclosed field does not match commitment" },
  { code: SdErrorCode.MERKLE_PATH_INVALID, trigger: "Merkle proof does not lead to expected root" },
  { code: SdErrorCode.ROOT_BINDING_MISSING, trigger: "expected escrow binding of SD root is absent" },
  { code: SdErrorCode.PROOF_INVALID, trigger: "PLONK verifier rejects proof" },
  { code: SdErrorCode.PUBLIC_INPUT_MISMATCH, trigger: "proof public inputs do not match Claim bundle" },
  { code: SdErrorCode.CLAIM_EXPIRED, trigger: "proof expiry timestamp has passed" },
  { code: SdErrorCode.CLAIM_REVOKED, trigger: "revocation registry marks claim/disclosure revoked" },
  { code: SdErrorCode.PARTNER_MISMATCH, trigger: "proof/bundle bound to another partner" },
  { code: SdErrorCode.PDA_MISMATCH, trigger: "proof/bundle bound to another PDA" },
  { code: SdErrorCode.AUTHORIZATION_MISMATCH, trigger: "proof/bundle bound to another authorization" },
  { code: SdErrorCode.ONBOARDING_PARTIAL_FAILURE, trigger: "SD failed while escrow pipeline continued" },
]);

/** Expected count = 16. Phase A foundation test enforces. */
export const SD_ERROR_COUNT = 16 as const;
