> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

_Base Sepolia deployment note: testnet only; deployed bytecode may lag or diverge from this source. See deployments/README.md._

# Combiner cluster reconciliation — HEAD e87c108 (2026-06-02)

Read-only audit. Verdicts from ACTUAL CODE at HEAD, not old finding text.
Closing commit for this cluster: `98d41e3` "V3 R2b close: auth durability + combiner hardening + ...".

## C1 (CRITICAL) — commitAAD round-trip skipped for historical/re-keyed — FIXED
- `pre-verify-pipeline.ts:157-161` calls `verifyCommitAADRoundTrip(commitAADBytes, profileDispatch.commitAAD, profileDispatch.commitVersion)` UNCONDITIONALLY. No `if`/version-guard at the call site.
- Old defeat path (`if (commitVersion >= commitAAD.commit_version)` skipping historical 0x0301 because `decodeActiveCompatibleCommitAAD` normalizes decoded.commit_version to ACTIVE) is gone. Documented at lines 243-251.
- Round-trip gates on ON-WIRE version (`profileDispatch.commitVersion` read directly from bytes at `profile-dispatch.ts:48 readCommitVersion`), not the patched/normalized value. `bytesEqualIgnoringVersionWindow` (pre-verify-pipeline.ts:333) skips ONLY the 2-byte version window [128,130) so historical payloads compare clean on all other bytes.
- Test `combiner-c1-unconditional-roundtrip.test.ts`: line 83 proves historical 0x0301 now RUNS the round-trip and passes; line 195 tampers a non-version byte on a historical payload and proves it now THROWS (would have been skipped under old guard). Real assertions, not stubs.

## TS-CRYPTO-F-06 — assertSigmaVerified fail-open when metadata absent — FIXED
- `sigma-orchestrator.ts:189`: `if (verified !== "true" || (code !== undefined && code !== "ok"))` → throws. Requires explicit `verified === "true"`; absent metadata (undefined) now fails closed. Sub-code `ERR_SIGMA_VERIFY_METADATA_MISSING` (line 193).
- Same fail-closed pattern applied to the sibling `assertStanzaIndex` at `sigma-orchestrator.ts:291`: `if (actual === undefined || actual !== expected)` → throws.
- Note (not a reopen): the combiner's σ-admission trust model is metadata-string-based; real cryptographic σ verification (`verifySigmaLit/G3/G4/Subject`, see `m1-imports.ts:71-117`) is the σ-as-authorization upstream step. The specific F-06 fail-OPEN-on-absent-metadata bug is closed.

## TS-CRYPTO-F-07 — combiner binary self-check bypass via env override — PARTIAL
- Effective protection IS present: `plugin-integrity.ts:87-94` and `:97-103` — `computeCanonicalBinaryHash` throws `ERR_COMBINER_BINARY_OVERRIDE_FORBIDDEN_IN_PRODUCTION` when `CEALIS_COMBINER_BINARY_HASH` or `..._SEED` is set AND `NODE_ENV==="production"`. Since `verifyPluginIntegrity` (the on-path check at `pre-verify-pipeline.ts:136`) calls `computeCanonicalBinaryHash` at `plugin-integrity.ts:42`, the env override is refused in production ON THE HOT PATH. This is the real defense and it is wired.
- GAP: the dedicated bootstrap belt-and-suspenders guard `assertNoBinaryHashOverridesInProduction` (`plugin-integrity.ts:70`) is defined+exported but has ZERO call sites anywhere in the packages (grep: only its own definition + a doc-comment). Its doc says "Call this at server bootstrap." It is never called — not in `combiner-orchestrator/index.ts`, not in `m3-bridge.ts`, not in any `v3-api` entry. So fail-fast-at-startup behavior is absent; protection only fires lazily when the first reveal hits `computeCanonicalBinaryHash`.
- Severity: original was HIGH/CRITICAL-class. Because the on-path inline guard closes the exploit, residual is the LOW-severity "defense-in-depth bootstrap not wired" gap. Net: PARTIAL.
- fix_location: wire `assertNoBinaryHashOverridesInProduction(process.env)` into the combiner-orchestrator/v3-api server bootstrap (e.g. start of the reveal pipeline init in `v3-api/src/combiner-orchestrator/` or the process entrypoint).

## TS-CRYPTO-F-08 — ConditionEngine canonical-address-pin not asserted in pre-verify — FIXED (stronger than original)
- Pin assertion moved INSIDE `runPreVerifyPipeline` as GATE-3-CANONICAL, runs FIRST. `pre-verify-pipeline.ts:107-114`: `assertPinMatchesSnapshotChainId(...)` then `assertCanonicalConditionEngineAddress(input.canonicalAddressPin.configuredConditionEngine, input.canonicalAddressPin.chainId)`.
- `canonicalAddressPin` is a REQUIRED (non-optional) field on both `runPreVerifyPipeline` input (`:72-75`) and `CombineAndDecryptInput` (`combine-and-decrypt.ts:60-63`). No opt-in `?`/undefined guard — constructing input without it is a typecheck error.
- NEW cross-substitution gate `assertPinMatchesSnapshotChainId` (`:355`) refuses `pin.chainId !== commitSnapshot.snapshot.chainId` (mainnet-pin-vs-sepolia-snapshot) → `ERR_CANONICAL_PIN_CHAIN_MISMATCH`. Canonical pin source `chain/canonical-addresses.ts` (compile-time frozen, Base Sepolia `0xb09a8300...520D02`).
- Test `combiner-canonicaladdresspin-mandatory.test.ts`: non-canonical address refused (:57), unknown chainId refused (:92), cross-substitution `ERR_CANONICAL_PIN_CHAIN_MISMATCH` (:125). Real attack-vector tests.

## k_conditional-from-commitAAD-not-σ-metadata — FIXED
- σ-metadata threshold read DELETED. `profile-dispatch.ts:85-154 inferProfile` takes `k_conditional` from the caller-supplied `ConditionalRecipientsPolicy`, NOT σ-metadata. Confirmed no residual read: grep for `kConditional`/`k_conditional` metadata reads in v3-custody/src returns only doc-comments (no live `firstMetadataNumber(sigmas,"kConditional")`).
- Triple binding: (1) `policy.n_conditional === commitAAD.conditional_recipients_stanza_count` (`:111`); (2) k in [1,n] (`:122`); (3) `keccak256(jcsCanonicalize(policy)) === commitAAD.conditional_recipients_policy_digest` (`:139-147`, sub-code `ERR_K_CONDITIONAL_POLICY_DIGEST_MISMATCH`).
- Defense-in-depth re-assertion at pre-verify boundary `assertConditionalRecipientsPolicyDigest` (`pre-verify-pipeline.ts:129-134, 391-418`) catches direct `runPreVerifyPipeline` test-path calls bypassing `dispatchProfile`.
- σ-metadata `profileKind` also neutered to label-only for ALL kinds (`profile-dispatch.ts:191-192`, R2b-3 v0.3) — closes the inverse override attack (K_OF_N AAD + σ-metadata profileKind="FIXED_ONLY").
- Test `combiner-kconditional-from-commitaad.test.ts:57`: attacker σ-metadata k=7 vs caller policy k=2 → combiner uses caller policy. Real.

## BR-B (architectural) — combiner host root sees plaintext for in-flight reveal — ARCHITECTURAL-ACCEPTED
- Plaintext is materialized on the combiner host. `combine-and-decrypt.ts:137-145 decryptAeadPayload` returns `plaintext` in-process; zeroize only covers `fileKey` + σ bytes (`:166-167`), not the returned plaintext (it's the deliverable).
- Stated mitigation = Phase-2 rented TEE (G4 Phase 2), not yet shipped (`canonical-addresses.ts` notes Phase G live, Phase H/mainnet pending; types/registries.ts:98 references "G4 Phase 2 TEE" as the cross-vendor-disjoint anchor). Phase-1 path is sealed-code server, operational-grade not cryptographic-non-custody (matches the project's phase-honesty policy §0 + Rule 30).
- Interim host-hardening present but NOT a substitute for TEE: `runtime-hardening.ts applyRuntimeHardening` (called `combine-and-decrypt.ts:98`) blocks network egress, debug logging, IPC export, crash-dump dir during σ path. Reduces exfil surface; does not remove host-root plaintext visibility.
- Status = architecturally accepted/phased, consistent with the documented V3 non-custody phasing. Not a new OPEN code bug.
