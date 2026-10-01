import { verifyBindingMode } from "./verify-binding.js";
import { verifyClaim } from "./verify-claim.js";
import { verifyCleartextField } from "./verify-cleartext-field.js";
import { SdSdkError, SdSdkErrorCode, type VerifySdBundleInput, type VerifySdBundleResult } from "./types.js";

export async function verifySdBundle(input: VerifySdBundleInput): Promise<VerifySdBundleResult> {
  const mode = verifyBindingMode(input.escrowCommit, input.pdaSdConfig, input.sdBundle);
  if (mode === "sd_disabled") return emptyResult("valid");
  if (mode === "sd_failed_before_root") {
    return {
      ...emptyResult("invalid"),
      rejectedClaims: input.sdBundle?.claims.map((claim) => ({ claimId: claim.claim_id, error: SdSdkErrorCode.ONBOARDING_PARTIAL_FAILURE })) ?? [],
      rejectedCleartextFields: input.sdBundle?.cleartext.map((field) => ({ fieldId: field.field_id, error: SdSdkErrorCode.ONBOARDING_PARTIAL_FAILURE })) ?? [],
    };
  }
  const bundle = input.sdBundle;
  if (!bundle) throw new SdSdkError(SdSdkErrorCode.ROOT_BINDING_MISSING);
  assertBundleContext(input);

  const acceptedClaims: string[] = [];
  const rejectedClaims: { claimId: string; error: string }[] = [];
  const acceptedCleartextFields: string[] = [];
  const rejectedCleartextFields: { fieldId: string; error: string }[] = [];

  for (const item of bundle.cleartext) {
    try {
      await verifyCleartextField({ sdBundle: bundle, cleartextItem: item, escrowCommit: input.escrowCommit, pdaSdConfig: input.pdaSdConfig, verifierRegistry: input.verifierRegistry });
      acceptedCleartextFields.push(item.field_id);
    } catch (error) {
      rejectedCleartextFields.push({ fieldId: item.field_id, error: codeOf(error) });
    }
  }
  for (const item of bundle.claims) {
    try {
      await verifyClaim({ sdBundle: bundle, claimItem: item, escrowCommit: input.escrowCommit, pdaSdConfig: input.pdaSdConfig, verifierRegistry: input.verifierRegistry, revocationRegistry: input.revocationRegistry, now: input.now });
      acceptedClaims.push(item.claim_id);
    } catch (error) {
      rejectedClaims.push({ claimId: item.claim_id, error: codeOf(error) });
    }
  }

  const rejected = rejectedClaims.length + rejectedCleartextFields.length;
  const accepted = acceptedClaims.length + acceptedCleartextFields.length;
  return {
    status: rejected === 0 ? "valid" : accepted > 0 ? "partial" : "invalid",
    rootBindingLevel: "commit_AAD",
    acceptedClaims,
    rejectedClaims,
    acceptedCleartextFields,
    rejectedCleartextFields,
  };
}

function emptyResult(status: VerifySdBundleResult["status"]): VerifySdBundleResult {
  return {
    status,
    rootBindingLevel: "commit_AAD",
    acceptedClaims: [],
    rejectedClaims: [],
    acceptedCleartextFields: [],
    rejectedCleartextFields: [],
  };
}

function assertBundleContext(input: VerifySdBundleInput): void {
  const bundle = input.sdBundle;
  if (!bundle) throw new SdSdkError(SdSdkErrorCode.ROOT_BINDING_MISSING);
  if (bundle.partner_id.toLowerCase() !== input.escrowCommit.partner_id.toLowerCase()) throw new SdSdkError(SdSdkErrorCode.PARTNER_MISMATCH);
  if (bundle.authorizationId.toLowerCase() !== input.escrowCommit.authorizationId.toLowerCase()) throw new SdSdkError(SdSdkErrorCode.AUTHORIZATION_MISMATCH);
  if (bundle.pda_id.toLowerCase() !== input.escrowCommit.pda_id.toLowerCase() || bundle.pda_version !== input.escrowCommit.pda_version) throw new SdSdkError(SdSdkErrorCode.PDA_MISMATCH);
}

function codeOf(error: unknown): string {
  return error instanceof SdSdkError ? error.code : SdSdkErrorCode.PROOF_INVALID;
}

