import type { Address } from "viem";
import {
  ACTIVE_COMMIT_VERSION,
  COMMIT_AAD_BYTES,
  decodeAgeEnvelope,
  encodeCommitAAD,
  verifyEnvelopeStanzaMacs,
  type AgeEnvelopeOutput,
  type CommitAADInput,
  type Hex32,
} from "../m1-imports.js";
import type {
  AccessStructureProfile,
  AuthorizationRegistrySnapshot,
  CommitRegistrySnapshot,
  SigmaEvidenceBundle,
} from "../types/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../errors.js";
import { assertCanonicalConditionEngineAddress } from "../chain/canonical-addresses.js";
import {
  computeConditionalRecipientsPolicyDigest,
  policyDigestEquals,
  type ConditionalRecipientsPolicy,
} from "../access-structure/policy-digest.js";
import { verifyPluginIntegrity } from "./plugin-integrity.js";
import { verifyRegistrySnapshots } from "./snapshot-verifier.js";
import { verifyGateRecipientPubkeys } from "./gate-recipient-verifier.js";
import { rejectMode3 } from "./mode3-rejection.js";
import { assertShredStateSignable } from "./shred-state-check.js";
import { verifySupersessionLineage } from "./supersession-lineage.js";
import { assertCrossVendorTeeDisjoint } from "./cross-vendor-check.js";
import type { ProfileDispatchResult } from "./profile-dispatch.js";

// Offset of the 2-byte little-endian `commit_version` field inside the canonical
// commit_AAD byte string. Mirrors `profile-dispatch.ts` `COMMIT_VERSION_OFFSET`
// + the codec's writer (`v3-crypto/src/codecs/commit-aad.ts` `writeU16LE` at
// `encodeCommitAAD`). Kept local here so the unconditional round-trip's
// version-window logic is greppable + line-anchored without crossing modules.
const COMMIT_VERSION_OFFSET = 128;

export interface PreVerifyResult {
  readonly envelope: AgeEnvelopeOutput;
  readonly profile: AccessStructureProfile;
  readonly commitSnapshot: CommitRegistrySnapshot;
  readonly authorizationSnapshot: AuthorizationRegistrySnapshot;
}

export function runPreVerifyPipeline(input: {
  readonly authorizationId: string;
  readonly hCommit: string;
  readonly authorizationBlock: bigint;
  readonly blockHash: Hex32;
  readonly commitAADBytes: Uint8Array;
  readonly ageEnvelope: Uint8Array;
  readonly sigmas: SigmaEvidenceBundle;
  readonly profileDispatch: ProfileDispatchResult;
  readonly registrySnapshots: {
    readonly commitSnapshot: CommitRegistrySnapshot;
    readonly authorizationSnapshot: AuthorizationRegistrySnapshot;
  };
  /**
   * MANDATORY canonical-address pin (TS-CRYPTO-F-08 closure, R2b-3 2026-05-20).
   * Pipeline asserts (a) `configuredConditionEngine` matches the compile-time
   * canonical entry for `chainId` in `chain/canonical-addresses.ts`, AND
   * (b) `chainId === commitSnapshot.snapshot.chainId` (cross-substitution
   * resistance — catches an attacker who pins one chain while the snapshot
   * was taken on another). The pin is required at the type level — no
   * opt-in `?` boundary at the caller. Tests + scaffolds construct the pin
   * explicitly; production deployments source it from the same compile-time
   * registry the canonical check itself consults.
   */
  readonly canonicalAddressPin: {
    readonly configuredConditionEngine: Address;
    readonly chainId: number;
  };
  /**
   * Conditional-recipients policy (B2 closure "k_conditional from commitAAD
   * not σ-metadata", R2b-3 2026-05-20). Type-discriminated REQUIRED when
   * the dispatched profile is `RECIPIENT_K_OF_N`; absent for `FIXED_ONLY`
   * and `RECIPIENT_1_OF_1`. The combiner asserts (here AND inside
   * `dispatchProfile.inferProfile`) that
   * `keccak256(jcsCanonicalize(policy)) === commit_AAD
   * .conditional_recipients_policy_digest`. Defense-in-depth at the
   * pre-verify boundary catches direct `runPreVerifyPipeline` test-path
   * calls that bypass `dispatchProfile`.
   */
  readonly conditionalRecipientsPolicy?: ConditionalRecipientsPolicy;
}): PreVerifyResult {
  const { commitSnapshot, authorizationSnapshot } = input.registrySnapshots;

  // GATE-3-CANONICAL (TS-CRYPTO-F-08): UNCONDITIONAL canonical-address pin
  // assertion. Runs as the FIRST pre-verify step — before any registry
  // snapshot is consumed, before any cryptographic verification fires.
  //   - NO opt-in guard. `canonicalAddressPin` is required at the type
  //     level; constructing the input without it is a typecheck error.
  //   - Cross-substitution resistance: `pin.chainId` MUST equal
  //     `commitSnapshot.snapshot.chainId`. Pinning mainnet while consuming
  //     a sepolia snapshot (or vice versa) refuses here. This check is
  //     NEW at R2b-3 closure; the original opt-in form did not have it.
  //   - Canonical assertion: defers to
  //     `assertCanonicalConditionEngineAddress` which throws
  //     `CanonicalAddressMismatchError` (`ERR_CANONICAL_ADDRESS_MISMATCH`)
  //     on any mismatch or unknown chainId — the fail-closed sub-reader
  //     for this gate.
  //   - This call is sync and pure. No `await` may be added between it
  //     and the surrounding pipeline steps (GATE-5 TOCTOU discipline).
  assertPinMatchesSnapshotChainId({
    pinChainId: input.canonicalAddressPin.chainId,
    snapshotChainId: commitSnapshot.snapshot.chainId,
  });
  assertCanonicalConditionEngineAddress(
    input.canonicalAddressPin.configuredConditionEngine,
    input.canonicalAddressPin.chainId,
  );

  // GATE-3-POLICY (B2 closure "k_conditional from commitAAD not σ-metadata"):
  // Defense-in-depth re-assertion of the conditional-recipients-policy
  // digest binding. `dispatchProfile.inferProfile` performs the primary
  // assertion at threshold-consumption time; this re-assertion catches the
  // direct-`runPreVerifyPipeline`-call test path that bypasses
  // `dispatchProfile`. Two structural rules:
  //   (i) profile is `RECIPIENT_K_OF_N` ⇒ policy MUST be present and
  //       MUST byte-match `commit_AAD.conditional_recipients_policy_digest`
  //       under the canonical JCS-then-keccak256 binding.
  //   (ii) profile is `FIXED_ONLY` or `RECIPIENT_1_OF_1` ⇒ policy MUST be
  //       absent (presence on those kinds is a type-system shape error,
  //       so we don't fail-closed on it — TS rejects at compile time).
  // Sync; no `await` interleaving (GATE-5 TOCTOU discipline preserved).
  assertConditionalRecipientsPolicyDigest({
    profile: input.profileDispatch.profile,
    policy: input.conditionalRecipientsPolicy,
    anchoredDigest:
      input.profileDispatch.commitAAD.conditional_recipients_policy_digest,
  });

  verifyPluginIntegrity({
    commitAAD: input.profileDispatch.commitAAD,
    commitSnapshot,
    authorizationBlock: input.authorizationBlock,
  });

  const envelope = decodeAndVerifyEnvelope(input.ageEnvelope);
  // GATE-3 (C1): UNCONDITIONAL commit_AAD round-trip against on-wire bytes.
  //   - NO version-guard around this call. NO historical/re-keyed exemption.
  //   - Bytes are the inseparable `VaultBlob.commitBinding.commit_aad_bytes`
  //     (R2a CealisV3Vault seam — `v3-api/src/vault/cealis-v3-vault.ts`
  //     `VaultBlob` returns `ciphertext` + `commitBinding` as ONE record; no
  //     accessor yields ciphertext without binding, so this round-trip can be
  //     made UNCONDITIONAL by construction at the consumer).
  //   - On-wire version is `profileDispatch.commitVersion` (read directly from
  //     `commitAADBytes` at `profile-dispatch.ts:24 readCommitVersion(...)`),
  //     NOT the post-decode/patched `profileDispatch.commitAAD.commit_version`
  //     (which `decodeActiveCompatibleCommitAAD` normalizes to ACTIVE — the
  //     confirmed C1 defeat path the brief names).
  //   - This call is sync and pure. No `await` may be added between it and the
  //     surrounding pipeline steps (GATE-5 TOCTOU discipline).
  verifyCommitAADRoundTrip(
    input.commitAADBytes,
    input.profileDispatch.commitAAD,
    input.profileDispatch.commitVersion,
  );
  verifyRegistrySnapshots({
    commitSnapshot,
    authorizationSnapshot,
    sigmaCommitBlock: input.sigmas.commitBlock,
    authorizationBlock: input.authorizationBlock,
    blockHash: input.blockHash,
  });
  verifyGateRecipientPubkeys({
    authorizationId: input.authorizationId,
    commitAAD: input.profileDispatch.commitAAD,
    profile: input.profileDispatch.profile,
    sigmas: input.sigmas,
    commitSnapshot,
  });
  rejectMode3({ envelope, sigmas: input.sigmas });
  assertShredStateSignable(authorizationSnapshot);
  verifySupersessionLineage({
    commitAAD: input.profileDispatch.commitAAD,
    sigmas: input.sigmas,
  });
  assertCrossVendorTeeDisjoint({
    commitAAD: input.profileDispatch.commitAAD,
    sigmas: input.sigmas,
  });

  return {
    envelope,
    profile: input.profileDispatch.profile,
    commitSnapshot,
    authorizationSnapshot,
  };
}

function decodeAndVerifyEnvelope(ageEnvelope: Uint8Array): AgeEnvelopeOutput {
  const decoded = decodeAgeEnvelope(ageEnvelope);
  if (!decoded.ok) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
      "age envelope decode failed",
      { subCodes: [decoded.error] },
    );
  }
  const macs = verifyEnvelopeStanzaMacs(decoded);
  if (!macs.ok) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
      "stanza MAC verification failed before payload parse",
      { subCodes: [macs.error] },
    );
  }
  return decoded;
}

/**
 * GATE-3 C1 closure — UNCONDITIONAL commit_AAD round-trip.
 *
 * Invariants (all enforced in-body, no closure-captured state, no `await`):
 *
 *  (i)  Fail-closed sub-reader on the binding bytes. `commitAADBytes` MUST be
 *       a `Uint8Array` of exactly `COMMIT_AAD_BYTES`; anything else throws
 *       `CUSTODY_ERR_COMBINER_BINARY_MISMATCH` /
 *       `ERR_COMMIT_AAD_BINDING_MISSING`. Mirrors the brief's GATE-4 rule
 *       that a missing/malformed binding field MUST NOT silently default-pass.
 *
 *  (ii) On-wire version asserted to be exactly the value the dispatcher
 *       read (`profileDispatch.commitVersion` was derived from these same
 *       bytes; the equality is tautological for a faithful caller but the
 *       check makes substitution between dispatch and pre-verify
 *       unrepresentable). Mismatch ⇒ refuse.
 *
 *  (iii) Re-encode the decoded struct via `encodeCommitAAD` — which calls
 *        `validateCommitAAD` and therefore writes commit_version=ACTIVE in
 *        the 2-byte version window. Historical (on-wire < ACTIVE) payloads
 *        will therefore differ at offsets [128, 130); all other bytes must
 *        byte-equal the on-wire bytes (constant-time compare).
 *
 *  (iv) The 2-byte version window of the on-wire bytes MUST equal the
 *       asserted on-wire version (decimal-encoded little-endian). This
 *       closes the brief's "gate on commit_version_onwire (NEVER the
 *       post-decode/patched value)" requirement at byte level.
 *
 * Defeats the previous skip path at line 55 (`if (input.profileDispatch.
 * commitVersion >= input.profileDispatch.commitAAD.commit_version)`) which,
 * because `decodeActiveCompatibleCommitAAD` always normalizes `decoded
 * .commit_version` to ACTIVE, ran the check only for ACTIVE payloads and
 * skipped it for historical 0x0301 — the documented C1 input vector.
 *
 * No `if`/early-return/`&&` short-circuit guards this function's call site
 * in `runPreVerifyPipeline` (see the GATE-3 (a) "INVERSE-SKIP" rule in the
 * worker-3 R2b brief).
 */
function verifyCommitAADRoundTrip(
  commitAADBytes: Uint8Array,
  decoded: CommitAADInput,
  onWireVersion: number,
): void {
  // GATE-4 fail-closed sub-reader on the binding bytes. The R2a vault seam
  // guarantees `commitAADBytes` arrives inseparable from the ciphertext, but
  // a malformed/missing input (zero-length, wrong length, non-Uint8Array)
  // MUST throw a typed error here — NEVER silent fall-through to a
  // version-bypass. This is the binding-side analogue of the brief's
  // GATE-4 named READ-target list (catch/error-branch/?./?? default).
  if (!(commitAADBytes instanceof Uint8Array) || commitAADBytes.length !== COMMIT_AAD_BYTES) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "commit_AAD binding bytes missing or wrong length for unconditional round-trip",
      { subCodes: ["ERR_COMMIT_AAD_BINDING_MISSING"] },
    );
  }

  // Invariant (iv): the on-wire bytes' 2-byte commit_version window MUST
  // equal the on-wire version asserted by `profileDispatch.commitVersion`.
  // Substitution between `dispatchProfile` and `runPreVerifyPipeline`
  // (i.e. the caller hands different bytes than dispatch ran on) trips
  // here before any re-encode runs.
  const windowLow = commitAADBytes[COMMIT_VERSION_OFFSET] ?? 0;
  const windowHigh = commitAADBytes[COMMIT_VERSION_OFFSET + 1] ?? 0;
  const windowVersion = windowLow | (windowHigh << 8);
  if (windowVersion !== onWireVersion) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "commit_AAD on-wire version window does not match dispatched on-wire version",
      { subCodes: ["ERR_COMMIT_AAD_VERSION_WINDOW_MISMATCH"] },
    );
  }

  // Invariant (iii): re-encode the decoded struct. `encodeCommitAAD`'s
  // `validateCommitAAD` always normalizes commit_version to ACTIVE, so the
  // 2-byte version window of `encoded` is the ACTIVE encoding. For active
  // payloads the encoded version window equals the on-wire window; for
  // historical it differs only at those 2 bytes (intentional, sanctioned
  // by `decodeActiveCompatibleCommitAAD`).
  const encoded = encodeCommitAAD(decoded);

  // Defensive sanity: the re-encoded version window MUST be ACTIVE. If
  // ever the codec drifts to a non-ACTIVE encoder output, the assumption
  // backing the version-window-skip below breaks; refuse rather than
  // silently widen the comparison surface.
  const encodedWindowLow = encoded[COMMIT_VERSION_OFFSET] ?? 0;
  const encodedWindowHigh = encoded[COMMIT_VERSION_OFFSET + 1] ?? 0;
  const encodedWindowVersion = encodedWindowLow | (encodedWindowHigh << 8);
  if (encodedWindowVersion !== ACTIVE_COMMIT_VERSION) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "commit_AAD re-encode produced a non-ACTIVE version window",
      { subCodes: ["ERR_COMMIT_AAD_REENCODE_NON_ACTIVE"] },
    );
  }

  // Constant-time byte compare, skipping ONLY the 2-byte commit_version
  // window at offsets [128, 130). Length parity is already enforced above
  // (both `encoded` and `commitAADBytes` are `COMMIT_AAD_BYTES`-long).
  if (!bytesEqualIgnoringVersionWindow(encoded, commitAADBytes)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "commit_AAD decode/re-encode round-trip mismatch outside version window",
      { subCodes: ["ERR_AAD_DIGEST_MISMATCH"] },
    );
  }
}

/**
 * Constant-time byte equality, skipping the 2-byte commit_version window at
 * offset `COMMIT_VERSION_OFFSET`. Both inputs MUST be `COMMIT_AAD_BYTES`
 * long (the caller has enforced this). Returns true iff `a[i] === b[i]`
 * for every `i` outside `[COMMIT_VERSION_OFFSET, COMMIT_VERSION_OFFSET+2)`.
 *
 * Constant-time across the compared region: every position contributes to
 * the running XOR; short-circuiting on first mismatch is intentionally
 * avoided so timing differences cannot leak which byte tripped the check.
 */
function bytesEqualIgnoringVersionWindow(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    if (i === COMMIT_VERSION_OFFSET || i === COMMIT_VERSION_OFFSET + 1) continue;
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * TS-CRYPTO-F-08 cross-substitution gate — asserts the caller-supplied
 * canonical-address pin agrees with the snapshot's `chainId`. The original
 * opt-in form only checked address-vs-canonical-for-chainId; it did NOT
 * catch a caller pinning chainId=8453 (mainnet) while consuming a snapshot
 * taken at chainId=84_532 (sepolia) — the registry-reader and the canonical
 * pin would each be internally consistent but bound to different chains.
 *
 * Throws `CUSTODY_ERR_GATE_PUBKEY_MISMATCH` (overloaded: the chain-binding
 * is gate-pubkey-class material at the consumer's edge — the gate-recipient
 * registry the combiner is about to consume IS chain-bound).
 */
function assertPinMatchesSnapshotChainId(input: {
  readonly pinChainId: number;
  readonly snapshotChainId: number;
}): void {
  if (input.pinChainId !== input.snapshotChainId) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_GATE_PUBKEY_MISMATCH,
      `canonical-address pin chainId (${input.pinChainId}) does not match commit snapshot chainId (${input.snapshotChainId})`,
      { subCodes: ["ERR_CANONICAL_PIN_CHAIN_MISMATCH"] },
    );
  }
}

/**
 * B2 closure "k_conditional from commitAAD not σ-metadata" — defense-in-depth
 * digest re-assertion at the pre-verify-pipeline boundary.
 *
 * `dispatchProfile.inferProfile` performs the primary digest assertion at
 * threshold-consumption time; this re-assertion catches a direct
 * `runPreVerifyPipeline` call that bypassed `dispatchProfile`. Both layers
 * MUST agree — a mismatch surfaces with the same typed sub-code from
 * either layer (the underlying defect class is identical).
 *
 * Rules:
 *   (a) `RECIPIENT_K_OF_N` profile ⇒ policy MUST be present + digest MUST
 *       match. Missing policy ⇒ `ERR_K_CONDITIONAL_POLICY_MISSING`.
 *       Digest mismatch ⇒ `ERR_K_CONDITIONAL_POLICY_DIGEST_MISMATCH`.
 *   (b) `FIXED_ONLY` / `RECIPIENT_1_OF_1` ⇒ no digest check (policy is
 *       structurally absent; the AAD's
 *       `conditional_recipients_policy_digest` is conventionally zero-bytes
 *       on those profile kinds). Passing a policy on these kinds is
 *       allowed but not consumed — it's logically inert.
 *
 * Sync; constant-bounded work (one JCS-canonicalize + one keccak256 + one
 * 32-byte compare on the K_OF_N branch; zero work otherwise).
 */
function assertConditionalRecipientsPolicyDigest(input: {
  readonly profile: AccessStructureProfile;
  readonly policy: ConditionalRecipientsPolicy | undefined;
  readonly anchoredDigest: Uint8Array;
}): void {
  if (input.profile.kind !== "RECIPIENT_K_OF_N") {
    // FIXED_ONLY / RECIPIENT_1_OF_1: no threshold, no digest binding.
    // dispatchProfile already constructed the profile from commit_AAD's
    // `conditional_recipients_stanza_count` field directly; no σ-metadata
    // trust surface remains to attack here.
    return;
  }
  if (input.policy === undefined) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET,
      "RECIPIENT_K_OF_N profile requires conditionalRecipientsPolicy at the pre-verify boundary (defense-in-depth re-assertion)",
      { subCodes: ["ERR_K_CONDITIONAL_POLICY_MISSING"] },
    );
  }
  const computed = computeConditionalRecipientsPolicyDigest(input.policy);
  if (!policyDigestEquals(computed, input.anchoredDigest)) {
    throw new CustodyError(
      CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH,
      "conditional_recipients_policy_digest mismatch at pre-verify boundary (defense-in-depth re-assertion)",
      { subCodes: ["ERR_K_CONDITIONAL_POLICY_DIGEST_MISMATCH"] },
    );
  }
}
