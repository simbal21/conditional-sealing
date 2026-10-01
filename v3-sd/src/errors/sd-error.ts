// SdError — typed error class for all ERR_SD_* codes.
//
// Discipline:
//  - `code` is one of the 16 codes from §1.3.
//  - `safeRefs` is a SafeRefs object — every key in the §1.4 allow-list.
//  - `correlationId` is partner-traceable but not subject-identifying.
//  - `stage` names the §15.2 stage at which the failure occurred.
//  - NEVER captures plaintext, salts, witnesses, proof bytes, or σ values.

import { SdErrorCode, type SdErrorCodeValue } from "./codes.js";
import { isSafeRefs, type SafeRefs } from "./safe-refs.js";

export type SdFailureStageName =
  | "schema_validation"
  | "salt_derivation"
  | "commitment_build"
  | "proving"
  | "response_assembly"
  | "partner_verify"
  | "revocation_check";

export interface SdErrorOptions {
  readonly correlationId?: string;
  readonly stage?: SdFailureStageName;
  readonly safeRefs?: SafeRefs;
  readonly cause?: unknown;
}

export class SdError extends Error {
  public readonly code: SdErrorCodeValue;
  public readonly correlationId: string | undefined;
  public readonly stage: SdFailureStageName | undefined;
  public readonly safeRefs: SafeRefs;
  public override readonly cause: unknown;

  constructor(code: SdErrorCodeValue, opts: SdErrorOptions = {}) {
    super(code);
    this.name = "SdError";
    this.code = code;
    this.correlationId = opts.correlationId;
    this.stage = opts.stage;
    this.cause = opts.cause;
    const refs = opts.safeRefs ?? {};
    if (!isSafeRefs(refs)) {
      // Constructor MUST refuse SafeRefs objects with banned keys.
      // This is a defence-in-depth: callers should never reach here, but if
      // they do (e.g. attempted PII passthrough), throw an inert error.
      throw new Error(`SdError: safeRefs payload contains banned keys for code=${code}`);
    }
    this.safeRefs = refs;
  }
}

/** Throw helpers — single named function per code, returns `never`. */
export const sdErrors = {
  configModeBIncompatible: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.CONFIG_MODE_B_INCOMPATIBLE, opts);
  },
  fieldPolicyUnknown: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.FIELD_POLICY_UNKNOWN, opts);
  },
  fieldEncodingInvalid: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.FIELD_ENCODING_INVALID, opts);
  },
  saltDerivationFail: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.SALT_DERIVATION_FAIL, opts);
  },
  saltEscapedTee: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.SALT_ESCAPED_TEE, opts);
  },
  commitmentMismatch: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.COMMITMENT_MISMATCH, opts);
  },
  merklePathInvalid: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.MERKLE_PATH_INVALID, opts);
  },
  rootBindingMissing: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.ROOT_BINDING_MISSING, opts);
  },
  proofInvalid: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.PROOF_INVALID, opts);
  },
  publicInputMismatch: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.PUBLIC_INPUT_MISMATCH, opts);
  },
  claimExpired: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.CLAIM_EXPIRED, opts);
  },
  claimRevoked: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.CLAIM_REVOKED, opts);
  },
  partnerMismatch: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.PARTNER_MISMATCH, opts);
  },
  pdaMismatch: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.PDA_MISMATCH, opts);
  },
  authorizationMismatch: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.AUTHORIZATION_MISMATCH, opts);
  },
  onboardingPartialFailure: (opts: SdErrorOptions = {}): never => {
    throw new SdError(SdErrorCode.ONBOARDING_PARTIAL_FAILURE, opts);
  },
} as const;
