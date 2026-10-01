import type { Address } from "viem";
import type { Hex32 } from "../m1-imports.js";
import type {
  AuthorizationRegistrySnapshot,
  CommitRegistrySnapshot,
  DecryptResult,
  SigmaEvidenceBundle,
} from "../types/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import { zeroize } from "../redaction/zeroize.js";
import type { ConditionalRecipientsPolicy } from "../access-structure/policy-digest.js";
import { applyRuntimeHardening } from "./runtime-hardening.js";
import { dispatchProfile } from "./profile-dispatch.js";
import { runPreVerifyPipeline } from "./pre-verify-pipeline.js";
import { orchestrateSigmas } from "./sigma-orchestrator.js";
import { reconstructFileKey } from "./shamir-dispatch.js";
import { decryptAeadPayload, readCommitContextDigest0 } from "./aead-decrypt.js";
import { assembleRevealArtifactBundle } from "./artifact-bundle.js";

export interface CombineAndDecryptInput {
  readonly authorizationId: Hex32;
  readonly hCommit: Hex32;
  readonly authorizationBlock: bigint;
  readonly blockHash: Hex32;
  readonly commitAAD: Uint8Array;
  readonly ageEnvelope: Uint8Array;
  readonly sigmas: SigmaEvidenceBundle;
  readonly registrySnapshots: {
    readonly commitSnapshot: CommitRegistrySnapshot;
    readonly authorizationSnapshot: AuthorizationRegistrySnapshot;
  };
  /**
   * MANDATORY canonical-address pin context (Security-audit-2026-05-14
   * TS-CRYPTO-F-08 hardening, R2b-3 closure 2026-05-20).
   *
   * Asserts `configuredConditionEngine` matches the compile-time canonical
   * address in `chain/canonical-addresses.ts` for the given `chainId`.
   * Enforcement moved INSIDE `runPreVerifyPipeline` (pre-verify ladder
   * alongside C1) — there is no opt-in/`undefined` guard at the caller
   * boundary anymore. Production deployments, scaffolds, AND tests MUST
   * pass this field. The test fixture (`combiner-testkit.ts`) supplies
   * the canonical Base Sepolia pair by default; tests asserting the
   * mismatch surface construct the pin explicitly with a non-canonical
   * value.
   *
   * The original F-08 vulnerability was the combiner relying solely on
   * the subscription-time address filter in `registry-reader.ts`, with
   * the address sourced from a user-injectable deployment manifest. A
   * compromised manifest could redirect the combiner to subscribe to a
   * "fake ConditionEngine" emitting forged `RevealAuthorized` topics.
   * Compile-time pinning + mandatory pipeline-internal assertion closes
   * that class of attack.
   *
   * Additionally enforced (new at R2b-3 closure): `chainId` MUST match
   * `commitSnapshot.snapshot.chainId` — catches an attacker pinning a
   * mainnet address while the snapshot was taken on testnet (or vice
   * versa), an attack class the original opt-in form did not cover even
   * when the caller passed the pin.
   */
  readonly canonicalAddressPin: {
    readonly configuredConditionEngine: Address;
    readonly chainId: number;
  };
  /**
   * Conditional-recipients policy (Security-audit-2026-05-14
   * "k_conditional from commitAAD not σ-metadata" B2 closure, R2b-3
   * 2026-05-20).
   *
   * Carries the authoritative `n_conditional` + `k_conditional` values
   * for `RECIPIENT_K_OF_N` profiles. The combiner JCS-canonicalizes the
   * policy and keccak256s the canonical bytes, then byte-compares the
   * resulting digest against the on-chain-anchored
   * `commit_AAD.conditional_recipients_policy_digest`. Mismatch ⇒
   * `ERR_K_CONDITIONAL_POLICY_DIGEST_MISMATCH`.
   *
   * Type-discriminated REQUIRED when
   * `commit_AAD.conditional_recipients_stanza_count > 1` (the K_OF_N
   * case). Absent (`undefined`) for `FIXED_ONLY` (stanza_count=0) and
   * `RECIPIENT_1_OF_1` (stanza_count=1) — those profiles do not consume
   * a threshold so the digest-binding step is structurally skipped.
   *
   * Closes the σ-metadata-trust-by-default defect: prior code read
   * `kConditional` from σ-metadata (attacker-influenceable sigma-
   * evidence bag); the new code reads from this caller-supplied + AAD-
   * digest-bound field only. The σ-metadata `kConditional` /
   * `k_conditional` / `nConditional` / `n_conditional` keys are NO
   * LONGER consulted for the threshold.
   *
   * See `access-structure/policy-digest.ts` for the canonical digest
   * construction.
   */
  readonly conditionalRecipientsPolicy?: ConditionalRecipientsPolicy;
}

export function combineAndDecrypt(input: CombineAndDecryptInput): DecryptResult {
  let fileKey: Uint8Array | undefined;
  try {
    applyRuntimeHardening();

    // TS-CRYPTO-F-08 enforcement is in `runPreVerifyPipeline` (pre-verify
    // ladder alongside C1). NO opt-in guard remains here; the pin is a
    // required field on `CombineAndDecryptInput`, the assertion is
    // unconditional, and substitution-resistance (pin.chainId ≡
    // snapshot.chainId) is also pipeline-internal.

    const profileDispatch = dispatchProfile({
      commitAAD: input.commitAAD,
      sigmas: input.sigmas,
      conditionalRecipientsPolicy: input.conditionalRecipientsPolicy,
    });
    const preVerified = runPreVerifyPipeline({
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      authorizationBlock: input.authorizationBlock,
      blockHash: input.blockHash,
      commitAADBytes: input.commitAAD,
      ageEnvelope: input.ageEnvelope,
      sigmas: input.sigmas,
      profileDispatch,
      registrySnapshots: input.registrySnapshots,
      canonicalAddressPin: input.canonicalAddressPin,
      conditionalRecipientsPolicy: input.conditionalRecipientsPolicy,
    });
    const sigmas = orchestrateSigmas({
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      authorizationBlock: input.authorizationBlock,
      blockHash: input.blockHash,
      commitAAD: profileDispatch.commitAAD,
      profile: preVerified.profile,
      sigmas: input.sigmas,
    });
    fileKey = reconstructFileKey({
      shares: sigmas.admittedShares,
      profile: preVerified.profile,
    });
    const plaintext = decryptAeadPayload({
      fileKey,
      envelope: preVerified.envelope,
      commitAAD: profileDispatch.commitAAD,
      commitContextDigest0: readCommitContextDigest0({
        metadataSources: input.sigmas.evidence.map((evidence) => evidence.metadata),
        fallback: profileDispatch.commitAAD.endpoint_attestation_digest,
      }),
    });
    fileKey = undefined;
    const artifact = assembleRevealArtifactBundle({
      authorizationId: input.authorizationId,
      hCommit: input.hCommit,
      authorizationBlock: input.authorizationBlock,
      blockHash: input.blockHash,
      profile: preVerified.profile,
      sigmaEvidence: sigmas.evidence,
      plaintext,
      commitSnapshot: preVerified.commitSnapshot,
      authorizationSnapshot: preVerified.authorizationSnapshot,
    });
    return {
      ok: true,
      plaintext,
      artifactDigest: artifact.digest,
    };
  } catch (error) {
    return toFailure(error);
  } finally {
    if (fileKey !== undefined) zeroize(fileKey);
    for (const evidence of input.sigmas.evidence) zeroize(evidence.sigmaBytes);
  }
}

function toFailure(error: unknown): DecryptResult {
  if (error instanceof CustodyError) {
    return {
      ok: false,
      code: error.code,
      subCodes: error.subCodes,
      metadata: error.metadata,
    };
  }
  return {
    ok: false,
    code: CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
    subCodes: ["ERR_COMBINER_UNEXPECTED_ABORT"],
    metadata: {
      reason: error instanceof Error ? error.message : "unknown combiner failure",
    },
  };
}
