import {
  ACTIVE_COMMIT_VERSION,
  decodeCommitAAD,
  type CommitAADInput,
} from "../m1-imports.js";
import type { AccessStructureProfile, SigmaEvidenceBundle } from "../types/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import { metadataNumber, metadataString } from "./jcs-canonicalize.js";
import {
  computeConditionalRecipientsPolicyDigest,
  policyDigestEquals,
  type ConditionalRecipientsPolicy,
} from "../access-structure/policy-digest.js";

const COMMIT_VERSION_OFFSET = 128;
const HISTORICAL_3GATE_MAX_VERSION = 0x0301;

export interface ProfileDispatchResult {
  readonly profile: AccessStructureProfile;
  readonly commitAAD: CommitAADInput;
  readonly commitVersion: number;
  readonly mode: "FULL_4GATE" | "HISTORICAL_3GATE";
}

/**
 * Dispatch profile from on-wire commit_AAD bytes + caller-supplied policy.
 *
 * `conditionalRecipientsPolicy` is REQUIRED at the type level when the
 * commit_AAD's `conditional_recipients_stanza_count > 1` (i.e., the
 * profile is `RECIPIENT_K_OF_N`). Absent for `FIXED_ONLY` (count=0) and
 * `RECIPIENT_1_OF_1` (count=1). The policy's `k_conditional` is the
 * authoritative threshold value — σ-metadata's `kConditional` /
 * `k_conditional` keys are NO LONGER read for the threshold (was the
 * trust-by-default defect named in the R2b-3 brief).
 *
 * Digest binding: `keccak256(jcsCanonicalize(policy))` MUST match
 * `decodedCommitAAD.conditional_recipients_policy_digest`. Mismatch ⇒
 * throw `ERR_K_CONDITIONAL_POLICY_DIGEST_MISMATCH`. Cross-AAD constraint:
 * `policy.n_conditional` MUST equal
 * `decodedCommitAAD.conditional_recipients_stanza_count` ⇒
 * `ERR_K_CONDITIONAL_POLICY_N_MISMATCH`.
 */
export function dispatchProfile(input: {
  readonly commitAAD: Uint8Array;
  readonly sigmas: SigmaEvidenceBundle;
  readonly conditionalRecipientsPolicy?: ConditionalRecipientsPolicy;
}): ProfileDispatchResult {
  const commitVersion = readCommitVersion(input.commitAAD);
  const override = readProfileOverride(input.sigmas);
  const decoded = decodeActiveCompatibleCommitAAD(input.commitAAD, commitVersion);

  if (commitVersion >= ACTIVE_COMMIT_VERSION) {
    if (override?.historicalProfile === true || override?.gateCount === 3) {
      throw profileMismatch("3-gate profile cannot be used for a 4-gate commit");
    }
    return {
      commitAAD: decoded,
      commitVersion,
      mode: "FULL_4GATE",
      profile:
        override?.profile ??
        inferProfile(decoded, input.conditionalRecipientsPolicy),
    };
  }

  if (commitVersion <= HISTORICAL_3GATE_MAX_VERSION) {
    return {
      commitAAD: decoded,
      commitVersion,
      mode: "HISTORICAL_3GATE",
      profile: { kind: "FIXED_ONLY" },
    };
  }

  throw profileMismatch(`unsupported commit_version 0x${commitVersion.toString(16)}`);
}

export function readCommitVersion(commitAAD: Uint8Array): number {
  if (commitAAD.length < COMMIT_VERSION_OFFSET + 2) {
    throw profileMismatch("commit_AAD too short to contain commit_version");
  }
  return (commitAAD[COMMIT_VERSION_OFFSET] ?? 0) | ((commitAAD[COMMIT_VERSION_OFFSET + 1] ?? 0) << 8);
}

function inferProfile(
  commitAAD: CommitAADInput,
  policy: ConditionalRecipientsPolicy | undefined,
): AccessStructureProfile {
  const conditionalCount = commitAAD.conditional_recipients_stanza_count;
  if (conditionalCount === 0) return { kind: "FIXED_ONLY" };
  if (conditionalCount === 1) return { kind: "RECIPIENT_1_OF_1" };

  // R2b-3 closure: `k_conditional` MUST come from the caller-supplied
  // policy (verified against the on-chain-anchored AAD digest), NOT
  // σ-metadata. The σ-metadata read path (`firstMetadataNumber(sigmas,
  // "kConditional")`) is removed — it was the trust-by-default defect
  // the brief names. The policy field is type-discriminated REQUIRED
  // for this code path; absent ⇒ refuse.
  if (policy === undefined) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      "RECIPIENT_K_OF_N profile requires conditionalRecipientsPolicy input (k_conditional from σ-metadata is rejected)",
      { subCodes: ["ERR_K_CONDITIONAL_POLICY_MISSING"] },
    );
  }

  // Cross-AAD constraint: the policy's `n_conditional` MUST equal the
  // on-chain-anchored stanza count. A caller forging a policy with
  // different n is refused here. This is independent of the digest
  // verification — both checks must pass.
  if (policy.n_conditional !== conditionalCount) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      `conditionalRecipientsPolicy.n_conditional (${policy.n_conditional}) does not match commitAAD.conditional_recipients_stanza_count (${conditionalCount})`,
      { subCodes: ["ERR_K_CONDITIONAL_POLICY_N_MISMATCH"] },
    );
  }

  // Sanity: k ∈ [1, n]. validateAccessStructureProfile re-checks this
  // downstream, but throwing the typed sub-code here gives a more
  // informative error than the generic validation message.
  if (
    !Number.isInteger(policy.k_conditional) ||
    policy.k_conditional < 1 ||
    policy.k_conditional > policy.n_conditional
  ) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      `conditionalRecipientsPolicy.k_conditional (${policy.k_conditional}) must be an integer in [1, ${policy.n_conditional}]`,
      { subCodes: ["ERR_K_CONDITIONAL_OUT_OF_RANGE"] },
    );
  }

  // GATE-3-class digest binding: recompute the policy digest and assert
  // equality with the on-chain-anchored `conditional_recipients_policy
  // _digest`. Mismatch ⇒ the policy is not the one the on-chain commit
  // sealed under, refuse. This is the brief's literal "from commitAAD
  // not σ-metadata" rule at the binding layer.
  const computed = computeConditionalRecipientsPolicyDigest(policy);
  const anchored = commitAAD.conditional_recipients_policy_digest;
  if (!policyDigestEquals(computed, anchored)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "conditional_recipients_policy_digest mismatch — policy does not match commitAAD-anchored digest",
      { subCodes: ["ERR_K_CONDITIONAL_POLICY_DIGEST_MISMATCH"] },
    );
  }

  return {
    kind: "RECIPIENT_K_OF_N",
    n_conditional: conditionalCount,
    k_conditional: policy.k_conditional,
  };
}

function readProfileOverride(
  sigmas: SigmaEvidenceBundle,
): { readonly profile?: AccessStructureProfile; readonly gateCount?: number; readonly historicalProfile?: boolean } | undefined {
  const kind =
    firstMetadataString(sigmas, "profileKind") ??
    firstMetadataString(sigmas, "accessStructureProfile");
  const gateCount = firstMetadataNumber(sigmas, "gateCount");
  const historicalProfile = firstMetadataString(sigmas, "historicalProfile") === "true";
  if (kind === undefined && gateCount === undefined && !historicalProfile) return undefined;
  // R2b-3 v0.3 closure (dw-quality-2 NARROWING-axis follow-up, 2026-05-21):
  // σ-metadata `profileKind` is fully label-only for ALL profile kinds,
  // not just RECIPIENT_K_OF_N. Returning a constructed `profile` from
  // here (FIXED_ONLY or RECIPIENT_1_OF_1) would let σ-metadata override
  // the AAD-derived profile kind — the inverse of the threshold-
  // narrowing attack class the v0.2 cycle closed:
  //
  //   Attacker on a K_OF_N AAD injects σ-metadata
  //   `profileKind: "FIXED_ONLY"` → dispatcher returned the override,
  //   bypassed `inferProfile`'s K_OF_N branch entirely, AND bypassed
  //   `assertConditionalRecipientsPolicyDigest` (which early-returns on
  //   non-K_OF_N at pre-verify-pipeline.ts:assertConditional...). The
  //   downstream Shamir reconstruction ran FIXED_ONLY with 3 σs instead
  //   of K_OF_N with n+k σs — implicit AEAD defense only.
  //
  // Symmetric fix: ALL σ-metadata-supplied `profileKind` values now
  // fall through to `inferProfile(decoded, policy)` via `profile:
  // undefined`. AAD-derived `conditional_recipients_stanza_count` is the
  // single source of truth for profile kind. The `profileKind` string
  // remains in σ-metadata as a debug-labeling hint but contributes ZERO
  // to dispatch decisions. (Caller-supplied
  // `conditionalRecipientsPolicy` is the authoritative source for k
  // when K_OF_N is dispatched.)
  //
  // `UNSUPPORTED_PROFILE` is still rejected — that's a string-value
  // validation independent of the override-mechanism deletion.
  if (kind === "FIXED_ONLY" || kind === "RECIPIENT_1_OF_1" || kind === "RECIPIENT_K_OF_N") {
    return { gateCount, historicalProfile };
  }
  if (kind !== undefined) throw profileMismatch(`unsupported access structure profile ${kind}`);
  return { gateCount, historicalProfile };
}

function firstMetadataString(sigmas: SigmaEvidenceBundle, key: string): string | undefined {
  for (const evidence of sigmas.evidence) {
    const value = metadataString(evidence.metadata, key);
    if (value !== undefined) return value;
  }
  return undefined;
}

function firstMetadataNumber(sigmas: SigmaEvidenceBundle, key: string): number | undefined {
  for (const evidence of sigmas.evidence) {
    const value = metadataNumber(evidence.metadata, key);
    if (value !== undefined) return value;
  }
  return undefined;
}

function profileMismatch(message: string): CustodyError {
  return new CustodyError(
    CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
    message,
    { subCodes: ["ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT"] },
  );
}

function decodeActiveCompatibleCommitAAD(bytes: Uint8Array, commitVersion: number): CommitAADInput {
  if (commitVersion >= ACTIVE_COMMIT_VERSION) return decodeCommitAAD(bytes);
  const patched = new Uint8Array(bytes);
  patched[COMMIT_VERSION_OFFSET] = ACTIVE_COMMIT_VERSION & 0xff;
  patched[COMMIT_VERSION_OFFSET + 1] = (ACTIVE_COMMIT_VERSION >>> 8) & 0xff;
  return decodeCommitAAD(patched);
}
