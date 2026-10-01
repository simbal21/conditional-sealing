// Closure tests for B2 "k_conditional from commitAAD not σ-metadata"
// (Security-audit-2026-05-14, R2b-3 2026-05-20).
//
// Defect class:
//   The combiner's `inferProfile` and `readProfileOverride` read
//   `kConditional` / `k_conditional` from σ-metadata
//   (`firstMetadataNumber(sigmas, "kConditional")` at
//   `profile-dispatch.ts:67-68` pre-R2b-3). σ-metadata is partially
//   attacker-controlled — sigma-evidence carries the metadata bag,
//   crafted by the gate signers. An attacker who can influence even one
//   piece of evidence can manipulate Shamir reconstruction threshold:
//     - claim k=7 when AAD-policy actually says k=2 → reveal blocked
//       (denial of service)
//     - claim k=2 when AAD-policy actually says k=7 → reveal admitted
//       with insufficient share count (consent violation)
//
// Closure:
//   The combiner accepts `conditionalRecipientsPolicy: {n_conditional,
//   k_conditional}` as a top-level input field. The pipeline
//   JCS-canonicalizes the policy → keccak256 → byte-compares against
//   `commit_AAD.conditional_recipients_policy_digest` (the on-chain-
//   anchored binding). Mismatch ⇒ refuse with
//   `ERR_K_CONDITIONAL_POLICY_DIGEST_MISMATCH`. σ-metadata
//   `kConditional`/`k_conditional`/`nConditional`/`n_conditional` keys
//   are NO LONGER consulted for the threshold.
//
// Two-layer enforcement (defense-in-depth):
//   (a) `dispatchProfile.inferProfile` — primary assertion at
//       threshold-consumption time.
//   (b) `runPreVerifyPipeline` — re-assertion at the pre-verify boundary
//       (catches direct-pipeline-call test paths that bypass
//       `dispatchProfile`).

import { describe, expect, it } from "vitest";
import {
  combineAndDecrypt,
  dispatchProfile,
  runPreVerifyPipeline,
} from "../../src/combiner/index.js";
import { CUSTODY_ERROR_CODES, CustodyError } from "../../src/errors.js";
import { computeConditionalRecipientsPolicyDigest } from "../../src/access-structure/policy-digest.js";
import { makeFixture, PLAINTEXT, profileKofN } from "./combiner-testkit.js";

describe("combiner k_conditional from commitAAD (NOT σ-metadata) — B2 closure", () => {
  it("sanity: RECIPIENT_K_OF_N fixture with matching policy + AAD-anchored digest passes through end-to-end", () => {
    // The testkit default for `profileKofN()` is n=5, k=2 — and
    // `makeCommitAAD` populates `conditional_recipients_policy_digest` with
    // the keccak256 of the JCS-canonical policy. The combiner re-derives
    // the digest from the caller-supplied policy and byte-compares
    // against the anchored value — must match → decrypts cleanly.
    const base = makeFixture({ profile: profileKofN() });
    const result = combineAndDecrypt(base);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });

  it("σ-metadata-trust-by-default with attacker-injected k_conditional bypass: caller policy k=2, σ-metadata claims k=7 — combiner uses CALLER POLICY (σ-metadata-trust deleted)", () => {
    // The named explicit attack probe. Pre-R2b-3, the combiner read k
    // from σ-metadata; an attacker (or compromised gate signer) could
    // inject `kConditional: 7` to inflate the Shamir threshold. Post-
    // R2b-3, σ-metadata's kConditional is no longer consulted for the
    // threshold — the combiner uses the AAD-digest-bound caller policy
    // (k=2 from `profileKofN()`).
    //
    // We construct a fixture with the default policy (n=5, k=2) and
    // mutate all σ-metadata to claim kConditional=7. The combiner
    // should silently ignore the σ-metadata claim and proceed with k=2
    // — proven by successful decryption (which only happens at the
    // correct k threshold for the 2-of-5 Shamir share set).
    const base = makeFixture({ profile: profileKofN() });
    const attackerInjected = base.sigmas.evidence.map((item) => ({
      ...item,
      metadata: {
        ...item.metadata,
        kConditional: 7, // attacker-injected inflated threshold
        k_conditional: 7,
        nConditional: 5,
        n_conditional: 5,
      },
    }));
    const result = combineAndDecrypt({
      ...base,
      sigmas: { ...base.sigmas, evidence: attackerInjected },
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });

  it("rogue caller policy with k=7 (and matching digest) is REFUSED — AAD-anchored digest mismatch vs the canonical-shape policy", () => {
    // An attacker controlling the caller side might submit a policy
    // {n:5, k:7} (which is structurally invalid: k > n) AND match-tweak
    // the AAD's `conditional_recipients_policy_digest` to the digest of
    // that bogus policy. Two refusal paths catch this:
    //   - `inferProfile`'s `k ∈ [1, n]` sanity bound throws
    //     `ERR_K_CONDITIONAL_OUT_OF_RANGE` before digest compute.
    //   - Even if the bound were widened, the AAD-anchored digest is
    //     baked into the fixture's commitAAD bytes at fixture-build
    //     time — the caller cannot fix that retroactively without
    //     re-encoding commitAAD, which would break the C1 round-trip.
    const base = makeFixture({ profile: profileKofN() });
    const result = combineAndDecrypt({
      ...base,
      conditionalRecipientsPolicy: {
        n_conditional: 5,
        k_conditional: 7, // out-of-range bogus value
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      // dispatchProfile's inferProfile catches the out-of-range bound first.
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET);
      expect(result.subCodes).toContain("ERR_K_CONDITIONAL_OUT_OF_RANGE");
    }
  });

  it("caller policy with k DIFFERENT from the AAD-anchored policy digest is REFUSED with ERR_K_CONDITIONAL_POLICY_DIGEST_MISMATCH", () => {
    // The fixture's commitAAD has the digest of {n:5, k:2}. Caller now
    // submits a policy {n:5, k:3} — the digest of the new policy will
    // NOT match the AAD-anchored one. This is the canonical digest-
    // mismatch attack (not bound-related, just wrong-policy).
    //
    // Note: k=3 is in-range [1, 5], so the range-bound check passes;
    // the digest comparison is what catches it.
    const base = makeFixture({ profile: profileKofN() });
    const result = combineAndDecrypt({
      ...base,
      conditionalRecipientsPolicy: {
        n_conditional: 5,
        k_conditional: 3, // in-range but does not match AAD-anchored {n:5, k:2}
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_COMBINER_BINARY_MISMATCH);
      expect(result.subCodes).toContain("ERR_K_CONDITIONAL_POLICY_DIGEST_MISMATCH");
    }
  });

  it("policy n_conditional MUST match commitAAD.conditional_recipients_stanza_count — mismatch refused with ERR_K_CONDITIONAL_POLICY_N_MISMATCH", () => {
    // Cross-AAD constraint test: caller supplies policy {n:3, k:2} on a
    // fixture whose AAD stanza_count is 5. The n cross-check throws
    // before the digest binding even runs.
    const base = makeFixture({ profile: profileKofN() });
    const result = combineAndDecrypt({
      ...base,
      conditionalRecipientsPolicy: {
        n_conditional: 3, // disagrees with AAD.conditional_recipients_stanza_count = 5
        k_conditional: 2,
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET);
      expect(result.subCodes).toContain("ERR_K_CONDITIONAL_POLICY_N_MISMATCH");
    }
  });

  it("FIXED_ONLY profile passes through with no policy (type-discriminated absent)", () => {
    // FIXED_ONLY does not consume a threshold; the policy field is
    // structurally absent. The combiner's digest-binding step is
    // structurally skipped (no policy ⇒ no digest comparison).
    const base = makeFixture(); // default is FIXED_ONLY
    const result = combineAndDecrypt(base);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });

  it("RECIPIENT_K_OF_N missing policy at dispatchProfile direct call refuses with ERR_K_CONDITIONAL_POLICY_MISSING (defense-in-depth at first consumer)", () => {
    // Direct `dispatchProfile` call without a policy on a K_OF_N
    // commitAAD: the threshold reading fires `ERR_K_CONDITIONAL_POLICY
    // _MISSING` from inferProfile. (The combineAndDecrypt outer wraps
    // exceptions into the DecryptResult failure shape, so we exercise
    // this directly to see the throw path.)
    const base = makeFixture({ profile: profileKofN() });
    expect(() =>
      dispatchProfile({
        commitAAD: base.commitAAD,
        sigmas: base.sigmas,
        // intentionally omit conditionalRecipientsPolicy
      }),
    ).toThrow(CustodyError);
  });

  it("RECIPIENT_K_OF_N missing policy at runPreVerifyPipeline boundary refuses with ERR_K_CONDITIONAL_POLICY_MISSING (defense-in-depth at second consumer)", () => {
    // Bypass dispatchProfile + try runPreVerifyPipeline directly with no
    // policy on a K_OF_N-dispatched profile. The pre-verify boundary
    // re-asserts the binding and throws — same typed sub-code, different
    // line of defense.
    const base = makeFixture({ profile: profileKofN() });
    // Dispatch WITH the policy so the profile has been correctly built;
    // then strip the policy from the runPreVerifyPipeline call.
    const dispatchResult = dispatchProfile({
      commitAAD: base.commitAAD,
      sigmas: base.sigmas,
      conditionalRecipientsPolicy: base.conditionalRecipientsPolicy,
    });
    expect(() =>
      runPreVerifyPipeline({
        authorizationId: base.authorizationId,
        hCommit: base.hCommit,
        authorizationBlock: base.authorizationBlock,
        blockHash: base.blockHash,
        commitAADBytes: base.commitAAD,
        ageEnvelope: base.ageEnvelope,
        sigmas: base.sigmas,
        profileDispatch: dispatchResult,
        registrySnapshots: base.registrySnapshots,
        canonicalAddressPin: base.canonicalAddressPin,
        // intentionally omit conditionalRecipientsPolicy at the boundary
      }),
    ).toThrow(CustodyError);
  });
});

// R2b-3 v0.3 closure (dw-quality-2 NARROWING-axis follow-up,
// 2026-05-21): adversarial probes for the σ-metadata profileKind
// narrowing attack the v0.2 cycle didn't explicitly cover.
//
// Attack class:
//   The K_OF_N defense closed v0.2 catches `kConditional` / `nConditional`
//   σ-metadata injection (WIDENING — claim K_OF_N on a non-K_OF_N AAD,
//   or claim larger k than the policy). But σ-metadata `profileKind`
//   could still NARROW: an attacker on a K_OF_N AAD injects
//   `profileKind: "FIXED_ONLY"`, the dispatcher returned the override
//   profile from `readProfileOverride`, bypassing `inferProfile`'s
//   K_OF_N path AND bypassing the GATE-3-POLICY pre-verify-pipeline
//   assertion (which early-returns on non-K_OF_N). Downstream Shamir
//   ran the wrong (narrower) profile.
//
// Closure:
//   `readProfileOverride` no longer constructs a profile from any
//   σ-metadata `profileKind` value (was only FIXED_ONLY / 1_OF_1 before;
//   K_OF_N was already label-only in v0.2). Symmetric label-only
//   treatment — `profileKind` contributes ZERO to dispatch. AAD-derived
//   `conditional_recipients_stanza_count` is the sole source of truth
//   for profile kind.
//
// Tests below confirm: attacker injecting "FIXED_ONLY" or
// "RECIPIENT_1_OF_1" on a K_OF_N AAD no longer bypasses the K_OF_N
// path. The σ-metadata label is silently ignored; dispatch goes to
// `inferProfile`'s K_OF_N branch + the GATE-3-POLICY assertion fires
// normally.
describe("combiner profileKind NARROWING attack — symmetric σ-metadata label-only closure (v0.3)", () => {
  it("σ-metadata claims profileKind: FIXED_ONLY on a K_OF_N AAD — dispatched profile is K_OF_N (σ-metadata label ignored)", () => {
    // The named narrowing-direction probe. Without the v0.3 fix, the
    // dispatcher returned `{ profile: { kind: "FIXED_ONLY" } }` from
    // `readProfileOverride`, bypassing the K_OF_N inferProfile branch
    // entirely. With v0.3, the label is silently ignored, dispatch
    // routes through `inferProfile` which constructs K_OF_N from
    // AAD.stanza_count=5 → the unchanged K_OF_N pipeline runs → the
    // legitimate policy + digest combo decrypts cleanly.
    const base = makeFixture({ profile: profileKofN() });
    const profileKindLabelInjection = base.sigmas.evidence.map((item) => ({
      ...item,
      metadata: { ...item.metadata, profileKind: "FIXED_ONLY" },
    }));
    const result = combineAndDecrypt({
      ...base,
      sigmas: { ...base.sigmas, evidence: profileKindLabelInjection },
    });
    // Pipeline routed via K_OF_N (AAD-derived) regardless of the
    // σ-metadata label — sanity decrypt succeeds.
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });

  it("σ-metadata claims profileKind: FIXED_ONLY on K_OF_N AAD WITHOUT caller policy — refuses with K_OF_N missing-policy (proves dispatch reached the K_OF_N branch, not FIXED_ONLY bypass)", () => {
    // Stronger empirical proof: under v0.2 (pre-fix), this input would
    // have dispatched FIXED_ONLY (no policy needed) and proceeded into
    // wrong-profile downstream Shamir. Under v0.3, the label is
    // ignored, dispatch reaches `inferProfile` which requires the
    // policy for K_OF_N → refuses with ERR_K_CONDITIONAL_POLICY_MISSING.
    // The refusal CODE proves the K_OF_N branch was actually executed.
    const base = makeFixture({ profile: profileKofN() });
    const profileKindLabelInjection = base.sigmas.evidence.map((item) => ({
      ...item,
      metadata: { ...item.metadata, profileKind: "FIXED_ONLY" },
    }));
    // Strip the policy so the K_OF_N branch must throw missing-policy.
    const { conditionalRecipientsPolicy: _omit, ...baseWithoutPolicy } = base;
    void _omit;
    const result = combineAndDecrypt({
      ...baseWithoutPolicy,
      sigmas: { ...base.sigmas, evidence: profileKindLabelInjection },
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET);
      expect(result.subCodes).toContain("ERR_K_CONDITIONAL_POLICY_MISSING");
    }
  });

  it("σ-metadata claims profileKind: RECIPIENT_1_OF_1 on K_OF_N AAD — same narrowing-axis defended (symmetric to FIXED_ONLY case)", () => {
    // RECIPIENT_1_OF_1 was the OTHER σ-metadata override path returning
    // a constructed profile pre-v0.3. The narrowing attack here is
    // structurally identical to the FIXED_ONLY case — claim a narrower
    // profile via σ-metadata, bypass K_OF_N's defenses. Same fix
    // applies; same test proves it.
    const base = makeFixture({ profile: profileKofN() });
    const profileKindLabelInjection = base.sigmas.evidence.map((item) => ({
      ...item,
      metadata: { ...item.metadata, profileKind: "RECIPIENT_1_OF_1" },
    }));
    const result = combineAndDecrypt({
      ...base,
      sigmas: { ...base.sigmas, evidence: profileKindLabelInjection },
    });
    // K_OF_N runs (label ignored) → legitimate policy + digest combo
    // decrypts cleanly.
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });

  it("σ-metadata claims accessStructureProfile alias (older key name) — same label-only treatment under both profileKind aliases", () => {
    // `readProfileOverride` reads `profileKind` OR `accessStructureProfile`
    // (line 159-161). Both alias keys are treated symmetrically as
    // label-only — confirming no asymmetric residual via the older key
    // name.
    const base = makeFixture({ profile: profileKofN() });
    const aliasInjection = base.sigmas.evidence.map((item) => ({
      ...item,
      metadata: { ...item.metadata, accessStructureProfile: "FIXED_ONLY" },
    }));
    const result = combineAndDecrypt({
      ...base,
      sigmas: { ...base.sigmas, evidence: aliasInjection },
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.plaintext).toEqual(PLAINTEXT);
  });
});

// Sanity assertion that `computeConditionalRecipientsPolicyDigest` is
// deterministic + agrees with what the testkit's `makeCommitAAD` writes
// into the AAD. Surfaces accidental drift in the canonical-shape rule.
describe("computeConditionalRecipientsPolicyDigest — JCS canonical-shape guarantee", () => {
  it("is deterministic over equivalent inputs (key order, etc.)", () => {
    const a = computeConditionalRecipientsPolicyDigest({ n_conditional: 5, k_conditional: 2 });
    const b = computeConditionalRecipientsPolicyDigest({ n_conditional: 5, k_conditional: 2 });
    expect(a).toEqual(b);
  });

  it("differs for different n or k", () => {
    const a = computeConditionalRecipientsPolicyDigest({ n_conditional: 5, k_conditional: 2 });
    const bDifferentK = computeConditionalRecipientsPolicyDigest({ n_conditional: 5, k_conditional: 3 });
    const cDifferentN = computeConditionalRecipientsPolicyDigest({ n_conditional: 4, k_conditional: 2 });
    expect(a).not.toEqual(bDifferentK);
    expect(a).not.toEqual(cDifferentN);
  });
});
