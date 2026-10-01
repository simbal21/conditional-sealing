// Conditional-recipients policy → digest helper.
//
// Security-audit-2026-05-14 "k_conditional from commitAAD not σ-metadata"
// B2 closure (R2b-3, 2026-05-20):
//
// `CommitAAD.conditional_recipients_policy_digest` is the on-chain-anchored
// 32-byte commitment to the recipient-policy structure (n_conditional,
// k_conditional, and any future policy fields). Before this closure, the
// combiner read `k_conditional` from σ-metadata — an attacker-influenceable
// surface (sigma-evidence carries the metadata bag, partially attacker-
// crafted). The trust-by-default defect class is identical to C1 + F-08:
// the read pulled from an untrusted source rather than the on-chain-anchored
// binding.
//
// Closure: callers MUST pass `conditionalRecipientsPolicy: { n_conditional,
// k_conditional }` as a top-level input field. The pipeline JCS-canonicalizes
// the policy and keccak256s the canonical bytes, then byte-compares the
// resulting digest against `decodedCommitAAD.conditional_recipients_policy
// _digest`. Mismatch ⇒ throw `ERR_K_CONDITIONAL_POLICY_DIGEST_MISMATCH`.
//
// **JCS canonical shape (binding, do not drift):** the policy is JCS-
// canonicalized AS A FLAT OBJECT with the two fields `n_conditional` +
// `k_conditional` (RFC 8785 sorts keys alphabetically and emits canonical
// JSON). The TAG_CONDITIONAL_RECIPIENTS_POLICY_V3 byte string is NOT
// pre-pended here — that tag is the upstream commit-time binding's
// responsibility (ingestion side); the digest itself is keccak256 of the
// JCS bytes, which is what M1 / the configurator / the PDA-ingestion path
// computes as `conditional_recipients_policy_digest`. This file's role is
// the consumer-side recomputation + byte-compare; the upstream side is
// outside R2b-3 scope (configurator/PDA seam owns it).
//
// Two-step defense (mirrors F-08 + C1):
//   (a) `dispatchProfile` (first consumer of `k_conditional`) recomputes
//       the digest and asserts the match — refuses to construct a
//       `RECIPIENT_K_OF_N` profile with an unverified k.
//   (b) `runPreVerifyPipeline` re-asserts the digest at the pre-verify
//       ladder boundary — defense-in-depth at the seam (catches a
//       direct-pipeline-call test path that bypassed dispatch).
//
// FIXED_ONLY profile (commit_AAD.conditional_recipients_stanza_count === 0):
// no policy needed; the policy field is type-discriminated `undefined`. The
// digest assertion is structurally skipped (no digest to compare against —
// `conditional_recipients_policy_digest` is zero-bytes by convention when
// no policy exists).
//
// V1 ISOLATION: no `@cealis/shared` imports; no `../../packages/*` references.

import { keccak_256 } from "@noble/hashes/sha3";
import { jcsCanonicalize } from "../combiner/jcs-canonicalize.js";

/**
 * Conditional-recipients policy. The shape JCS-canonicalized to produce
 * the digest stored in `commit_AAD.conditional_recipients_policy_digest`.
 *
 * `n_conditional` MUST equal `commit_AAD.conditional_recipients_stanza_count`
 * (cross-AAD constraint asserted by the caller of this module).
 * `k_conditional` MUST satisfy `1 ≤ k ≤ n` (sanity invariant asserted by
 * `validateAccessStructureProfile` after dispatch).
 *
 * Future fields (per-recipient acl, time-windows, etc.) extend this struct.
 * Field-order extension is JCS-canonical-safe because JCS sorts keys
 * alphabetically — new fields can be added without breaking the digest of
 * commits that did not include them.
 */
export interface ConditionalRecipientsPolicy {
  readonly n_conditional: number;
  readonly k_conditional: number;
}

/**
 * Compute the 32-byte digest of a `ConditionalRecipientsPolicy` per the
 * canonical JCS-then-keccak256 binding rule.
 *
 * Pure / sync / no I/O. Constant work; no policy-content branches that
 * would leak timing information about k or n (JCS canonicalization +
 * keccak256 are both content-dependent at the cryptographic primitive
 * level, which is the intended behavior).
 */
export function computeConditionalRecipientsPolicyDigest(
  policy: ConditionalRecipientsPolicy,
): Uint8Array {
  // JCS-canonicalize the policy struct. `jcsCanonicalize` returns the
  // canonical JSON bytes (RFC 8785). Keys are sorted alphabetically; the
  // output is deterministic for any equivalent input.
  const canonical = jcsCanonicalize({
    k_conditional: policy.k_conditional,
    n_conditional: policy.n_conditional,
  });
  return keccak_256(canonical);
}

/**
 * Constant-time 32-byte equality. Both inputs MUST be exactly 32 bytes.
 * Returns `false` (no throw) on length mismatch — the caller decides how
 * to surface that as a typed error.
 */
export function policyDigestEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== 32 || b.length !== 32) return false;
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
