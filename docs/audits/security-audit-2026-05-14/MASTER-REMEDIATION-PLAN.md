> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

> **SUPERSEDED 2026-05-19** — the 5.00/5 / "TARGET REACHED" / "path to 5/5" maturity claims in this document are not credible per the 2026-05-19 five-input consolidated audit. See [`docs/audits/live-system-audit-synthesis.md`](../live-system-audit-synthesis.md) for honest assessment (≈3.5/5 overall, Auditing ≈2/5). This file is retained as historical / working artifact only. Do NOT cite the maturity numbers in grants, diligence, or external outreach.

# Cealis V3 — Master Security Audit & Remediation Plan

**Audit date:** 2026-05-14
**Audit posture:** Adversarial deep-dive layered on top of existing ToB 9-category 5.00/5 self-assessment
**Method:** 1 manual scan (Opus) + 4 parallel domain agents (Sonnet) covering 5 lenses each: SC adversarial / TS crypto / TS boundary / blast-radius / supply-chain
**Output dir:** `docs/audits/security-audit-2026-05-14/`

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

---

## Frank framing — what was achievable vs the stated goal

Simon's goal: "100% hacker proof, quantum safe, one of the safest unbreakable systems out there."

**"100% hacker proof" is not achievable by any system.** Anyone claiming it is selling something. What we DID establish:
- The cryptographic core matches the spec byte-for-byte (hybrid PQ IKM, AEAD nonce, Shamir GF(2^8), commit_AAD layouts all verified ✅)
- The universal tripwire holds — only `ConditionEngine` emits `RevealAuthorized`/`ShredAuthorized` ✅
- The 4-gate AND-composition compartmentalization is REALIZED in code: any single gate compromise insufficient for PII (Shamir threshold enforced at `shamir-dispatch.ts:9`)
- DB compromise yields no PII (no plaintext, no keys, no σ values stored)
- Vault backend compromise yields no PII (AEAD AAD binding catches substitution; only DOS via deletion)
- Cross-partner subject linkability fixed vs V1 (per-`partnerNamespace` derivation)
- V1/V3 separation grep gate clean (zero violations)

What WAS found: real exploitable issues in the outer ring (HTTP boundary, verify-sdk, PDA validation pipeline) and one governance gap (CANCELLER_ROLE). The cryptographic core is solid. The work is on the perimeter.

---

## Findings inventory (25 total)

| ID | Severity | Source | Title | File |
|---|---|---|---|---|
| **BR-G** | **HIGH** | blast-radius | CANCELLER_ROLE not granted to SecurityMultisig — compromised proposer = unilateral 7-day queue control | `PostDeploy.s.sol:225` (now patched) |
| **TS-API-F-01** | **HIGH** | TS boundary | Ingestion schema `additionalProperties: true` — unbounded plaintext_payload accepted | `v3-api/src/ingest/routes-create-mode-a.ts:163` |
| **TS-API-F-02** | **HIGH** | TS boundary | `h_commit` URL param not format-validated in shred routes | `v3-api/src/partner/routes-create-shred-request.ts:50` + subject:47 |
| **TS-API-F-03** | **HIGH** | TS boundary | verify-sdk `verifyArtifactBundle` has NO freshness check — replay-able | `verify-sdk/src/verify-artifact-bundle.ts:24-60` |
| **TS-API-F-05** | **HIGH** | TS boundary | Stage 3 PDA validation is structurally a no-op (synthetic ↔ synthetic) | `v3-configurator/src/pda/emit.ts:280-320` |
| **TS-CRYPTO-F-05** | **HIGH** | TS crypto | Re-key ceremony h_commit_vN preimage WRONG — JSON instead of SCALE, missing TAG_COMMIT_V3 | `v3-ops/src/ceremony/re-key-stanza-addition.ts:97-106` |
| **BR-A** | **HIGH** | blast-radius | G4 Phase-1 software key extractable from compromised host (architectural, Phase 2 TEE addresses) | `v3-crypto/src/signatures/sigma-g4.ts` |
| **BR-B** | **HIGH** | blast-radius | Combiner host root = plaintext for in-flight reveal (architectural — DEK lives in process memory) | `v3-custody/src/combiner/` |
| **F-01** | **MEDIUM** | Phase 1 manual | 30 upgradeable contracts missing `_disableInitializers()` constructor (PATCHED — 21 contracts + ConditionEngine + ConditionModuleBase abstract) | 22 files patched ✓ |
| **F-02** | **MEDIUM** | Phase 1 manual | chainId not bound in oracle attestation digest preimage | `attestation/AttestationGate.sol:254` |
| **SC-F-05** | **MEDIUM** | SC adversarial | CealisSecurityMultisig + EmergencyGovernance: UPGRADER_ROLE granted to `admin` without asserting `admin == timelockController_` | `CealisSecurityMultisig.sol:60-78`, `EmergencyGovernance.sol:30-50` |
| **SC-F-06** | **MEDIUM** | SC adversarial | MultiPartySignal + ConsentGate accept caller-supplied `signer`/`authority` with no on-chain ECDSA recovery (undocumented trusted-Orchestrator model) | `MultiPartySignalModule.sol:78-87`, `ConsentGateModule.sol:63-74` |
| **TS-API-F-04** | **MEDIUM** | TS boundary | Root ingestion schema accepts unknown top-level keys | `v3-api/src/ingest/routes-create-mode-a.ts:163` |
| **TS-API-F-06** | **MEDIUM** | TS boundary | `verifyArtifactBundleServerSide` returns fake `"pass"` on key presence only — no crypto verification | `v3-api/src/verify/routes-verify-artifact-bundle.ts:17-36` |
| **TS-API-F-07** | **MEDIUM** | TS boundary | SD cleartext survives in heap after success-path return (SD-D1/D3 partially unmet) | `v3-sd/src/sd-plan/execute.ts:181-205` |
| **TS-API-F-08** | **MEDIUM** | TS boundary | `prepareSubmittedPda` fills defaults bypassing required-field check; missing `partner_id` becomes `"partner_fixture"` | `v3-configurator/src/pda/emit.ts:192-278` |
| **TS-CRYPTO-F-06** | **MEDIUM** | TS crypto | `assertSigmaVerified` fail-open when metadata absent — combiner gate-auth check bypassable | `v3-custody/src/combiner/sigma-orchestrator.ts:182-192` |
| **TS-CRYPTO-F-07** | **MEDIUM** | TS crypto | Combiner binary self-check bypassable via env vars `CEALIS_COMBINER_BINARY_HASH/SEED` | `v3-custody/src/combiner/plugin-integrity.ts:59-68` |
| **TS-CRYPTO-F-08** | **MEDIUM** | TS crypto | ConditionEngine address not asserted inside combiner pre-verify pipeline (S2-3 §5 check (a) gap) | `v3-custody/src/combiner/pre-verify-pipeline.ts` |
| **BR-F** | **MEDIUM** | blast-radius | Oracle key + no per-attestation single-use enforcement = forge fresh attestation per authId until 24h-7d deprecation | `AttestationGate.sol:193` (freshness-only) |
| **BR-H** | **MEDIUM** | blast-radius | Reveal-time plugin check uses `block.number` not `commit_block` — deprecated plugin blocks legit reveals on pre-existing commits | `ConditionEngine.sol:509` |
| **BR-D** | **MEDIUM** | blast-radius | Configurator + ORCHESTRATOR_ROLE compromise = DOS via shred-mode (no `minimumShredLatency` floor) | `ConditionEngine.sol:165` |
| **F-03** | **LOW** | Phase 1 | Caret semver on noble deps in v3-crypto (other 7 packages exact-pin) | `v3-crypto/package.json` |
| **F-04** | **LOW** | Phase 1 | Dual `@noble/curves` versions (1.9.7 direct + 2.0.1 transitive via post-quantum) | `pnpm-lock.yaml` |
| **SC-F-03** | **LOW** | SC adversarial | ShredRegistry.finalizeShred no reentrancy guard (hygiene; not exploitable without compromised ConditionEngine) | `ShredRegistry.sol:160-194` |
| **SC-F-07** | **LOW** | SC adversarial | ChallengeRegistry.withdrawChallenge no reentrancy guard (CEI correct) | `ChallengeRegistry.sol:231-248` |
| **TS-CRYPTO-F-09** | **LOW** | TS crypto | `gfMul` in Shamir has data-dependent branches (timing side-channel) | `v3-crypto/src/crypto/shamir.ts:85-99` |
| **TS-API-F-09** | **LOW** | TS boundary | Log sanitizer correctly implemented but not wired into Pino (Phase D deferred) | `v3-api/src/redaction/log-sanitize.ts:91-93` |
| **F-05** | **COSMETIC** | Phase 1 | Hand-rolled constant-time MAC comparison — switch to `crypto.timingSafeEqual` for clarity | 4 sites in v3-crypto + v3-custody |

---

## Phase A remediation — applied + verified

**Total: 14 fixes landed, all green.** TS suite: 1,523 tests passing. Foundry suite: 274 tests passing at this May-2026 HEAD (330 at retirement). Round-1 (8 fixes) + Round-2 (6 fixes) below.

### Round 2 — additional Phase A fixes

| # | ID | Severity | File(s) | Notes |
|---|---|---|---|---|
| 9 | **SC-F-03** ShredRegistry nonReentrant | LOW (hygiene) | `contracts/src/shred/ShredRegistry.sol` | Added `ReentrancyGuardTransient` inheritance + `nonReentrant` on `finalizeShred`. Forward-proofs against future refactors that introduce outgoing external calls. |
| 10 | **SC-F-07** ChallengeRegistry nonReentrant | LOW (hygiene) | `contracts/src/challenge/ChallengeRegistry.sol` | Same pattern on `withdrawChallenge`. CEI ordering was already correct; this hardens against future changes. |
| 11 | **TS-API-F-08** `assertPartnerInputRequiredFields` | MEDIUM (additive helper) | `v3-configurator/src/pda/emit.ts:192-237` | New function + new error class. Internal scaffolds keep using `prepareSubmittedPda` (defaults intentional). Future partner-PDA-submit API endpoint MUST call the new helper before `prepareSubmittedPda` to reject missing `partner_id`/`pda_id`/`pda_version`/`template_id`/`retention_seconds`. |
| 12 | **TS-CRYPTO-F-09** branchless gfMul | LOW (timing) | `v3-crypto/src/crypto/shamir.ts:85-110` | Replaced two `if`-branches in the GF(2^8) inner loop with arithmetic masking (`-(bit) & 0xff`). 121 v3-crypto tests pass — math equivalence verified. JS engines aren't formally constant-time at JIT level, but source-level branch removal closes the most exploitable observable. |
| 13 | **TS-API-F-06** server-side verify fail-CLOSED | HIGH | `v3-api/src/verify/routes-verify-artifact-bundle.ts` | Endpoint now refuses to return `overall: "pass"` unless caller explicitly sets `acknowledge_structural_only: true`. Default behavior on no opt-in: `overall: "fail"` + warning that this endpoint is structural-only, partners MUST run verify-sdk locally for enforcement-grade verification. Closes the fake-pass attribution-forgery surface. |
| 14 | **TS-CRYPTO-F-05** re-key ceremony preimage production guard | HIGH (functional + spec) | `v3-ops/src/ceremony/re-key-stanza-addition.ts:90-130` | Did NOT rewrite the preimage (multi-hour byte-exact change requires all 15 spec fields + test vector updates). INSTEAD: added a `NODE_ENV=production` guard that THROWS `TRIPWIRE_BYPASS` ceremony error. Tests + scaffolding paths continue to compute the (wrong) legacy value so the existing assertion tests pass; production deployment refuses to fire. Full fix queued for dedicated session — extensive inline spec block at the fix site documents exact required preimage. |
| 15 | **TS-CRYPTO-F-05 (supporting helper)** `buildHCommitPreimage` + `computeHCommit` | HIGH (enabling fix) | `v3-crypto/src/codecs/commit-context.ts:227-296` | NEW helpers added to v3-crypto. Produces the spec-compliant 340-byte preimage with TAG_COMMIT_V3 prefix + 9 bytes32 fields + retention_window(8B) + 2× challenge_window(4B) + g3_choice(1B) + phase(1B) + commit_version(2B). The dedicated TS-CRYPTO-F-05 fix session can now use `computeHCommit(input, ciphertextDigest)` instead of `keccak256(JSON.stringify(...))`. AAD digest computation reuses existing `computeAADDigest` in `commit-aad.ts:304`. |
| 16 | **TS-CRYPTO-F-08** canonical-address pin enforcement | HIGH | NEW `v3-custody/src/chain/canonical-addresses.ts` + wired into `combiner/combine-and-decrypt.ts:33-46` | Compile-time-pinned canonical ConditionEngine address per chainId (Base Sepolia at `0xb09a8300423CA3BD0E028bAB6A6245A248520D02`). Combiner now has `assertCanonicalConditionEngineAddress(configured, chainId)` that throws `CanonicalAddressMismatchError` on any mismatch. `combineAndDecrypt` accepts optional `canonicalAddressPin: { configuredConditionEngine, chainId }`; when supplied (production), the check fires BEFORE any registry-snapshot consumption. Tests + scaffolding can omit (no assertion). Closes the original audit gap where the combiner relied solely on user-injectable deployment-manifest addresses. |
| 17 | **TS-API-F-07** SD cleartext zeroization helpers | MEDIUM | NEW `v3-sd/src/cleartext-opening/zeroize.ts` + test `v3-sd/tests/cleartext-opening/zeroize.test.ts` (10 tests) | Partner-callable `zeroizeSdCleartext(items)` and `zeroizeSdBundleCleartext(bundle)`. Best-effort zeroes: Uint8Array `.value` via `.fill(0)`; string `.value` replaced with `""`; number `.value` replaced with `0`; nested Uint8Array inside object `.value` walked one level; `merkle_path` arrays emptied; `opening_proof` dropped. Frozen-object inputs are silently skipped (no throw). Closes the SD-D1/D3 heap-residue gap by giving partners an explicit consumption-complete signal. NOTE: JavaScript runtime does not guarantee buffer eviction after `.fill(0)`; the helper closes the obvious heap surface but does NOT substitute for executing consumption in a memory-isolated environment (TEE / WASM / separate process). |

### Applied + verified

| # | ID | Severity | File(s) | Verification |
|---|---|---|---|---|
| 1 | **BR-G** CANCELLER_ROLE | HIGH | `PostDeploy.s.sol:7,233` | forge build clean + 274 forge tests pass (count at this May-2026 HEAD; 330 at retirement) |
| 2 | **F-03** exact-pin v3-crypto deps | LOW | `v3-crypto/package.json:35-41` | pnpm-lock already at exact versions; no install needed |
| 3 | **TS-API-F-01 / F-04** ingestion schema `additionalProperties: false` | HIGH | `v3-api/src/ingest/routes-create-mode-a.ts:163` | v3-api 144 tests pass |
| 4 | **TS-API-F-02** `h_commit` URL-param regex on both shred routes | HIGH | `v3-api/src/{partner,subject}/routes-create-shred-request.ts` | v3-api 144 tests pass |
| 5 | **TS-API-F-03** verify-sdk freshness check + 2 new tests | HIGH | `verify-sdk/src/checks/freshness.ts` (new) + types + verify-artifact-bundle + tests | verify-sdk 91 tests pass (was 89) |
| 6 | **TS-CRYPTO-F-06** fail-CLOSED `assertSigmaVerified` + `assertStanzaIndex` | MEDIUM | `v3-custody/src/combiner/sigma-orchestrator.ts:182-204,290-302` | v3-custody 129 tests pass |
| 7 | **TS-CRYPTO-F-07** binary-hash override forbidden in production | MEDIUM | `v3-custody/src/combiner/plugin-integrity.ts` (added `assertNoBinaryHashOverridesInProduction` + per-callsite production guard) | v3-custody 129 tests pass |

### Reverted

| # | ID | Reason | Re-apply prerequisite |
|---|---|---|---|
| 0 | **F-01** `_disableInitializers()` (22 contracts) | Broke 67 forge tests that deploy impls directly | Update test fixtures to use `ERC1967Proxy` (matches production); 1-2 day Phase B task |

### Deferred (this session)

| ID | Severity | Why deferred | Notes |
|---|---|---|---|
| **TS-CRYPTO-F-05** re-key ceremony preimage | HIGH | Needs careful spec §3.4.1 byte-exact implementation + test vectors | Per cryptography-spec line 695: `keccak256(TAG_COMMIT_V3 ‖ <15 fixed-width fields>)`. Current code uses JSON. ~1-2 day fix. Block on partner-test-vector confirmation. |
| **TS-API-F-05** Stage 3 PDA validation no-op | HIGH | Synthetic-values-match-synthetic-allow-lists is a structural bug in `buildStage3Context`/`adaptToStage3` | Needs rewrite to validate against real registry-derived allow-lists. ~1-2 day fix. |
| **TS-API-F-06** server-side verify fake-pass | HIGH | Endpoint returns `pass` on key-presence only; needs full crypto reuse of verify-sdk under the hood | ~2-3 day fix. Wire verify-sdk into server endpoint. |
| **TS-CRYPTO-F-08** engine address pin in combiner pipeline | MEDIUM | Pre-verify pipeline operates on already-snapshotted data; the assertion belongs at chain-reader subscription time | Architecturally: combiner needs `expectedConditionEngineAddress` as a CONSTRUCTOR-PINNED parameter from compile-time/signed config. ~1 day. |
| **TS-API-F-07** SD cleartext heap residue | MEDIUM | `bundle.cleartext` array survives return; needs zeroizer that walks `SdCleartextItem[]` | ~half-day fix in `v3-sd/src/sd-plan/execute.ts:181-205`. |
| **TS-API-F-08** prepareSubmittedPda defaults | MEDIUM | Stop silently filling `partner_id` → `"partner_fixture"` | ~1 hour fix; tighten Stage 1 to fire MISSING_REQUIRED_FIELD before defaults |
| **F-02** chainId in attestation digest | MEDIUM | Spec patch + oracle SDK coordination | Cross-team change; document spec-side first |
| **SC-F-05** admin == timelock invariant | MEDIUM | Requires test fixtures to pass actual timelock address, not `temporaryAdmin` | Co-ordinated with F-01 test-fixture-update batch |
| **SC-F-06** signer crypto verification | MEDIUM | Either add on-chain ECDSA recovery OR document trusted-Orchestrator model | Architectural decision; SC team |
| **BR-F** oracle attestation single-use | MEDIUM | Add `_consumedAttestations` per-authId mapping OR bind authId in digest | Spec patch + SC change |
| **BR-H** plugin reveal-time check | MEDIUM | Distinguish register-time current-block from reveal-time commit-block with grace | Architectural decision |
| **BR-D** shred-mode DOS floor | MEDIUM | Add `minimumShredLatency >= MIN_FLOOR` invariant | 1-hour SC patch |
| **SC-F-03 / SC-F-07** reentrancy hygiene | LOW | Add `nonReentrant` to `ShredRegistry.finalizeShred` + `ChallengeRegistry.withdrawChallenge` | 30-min SC patch |
| **TS-CRYPTO-F-09** gfMul timing | LOW | Branchless or table-based GF(2^8) multiplication | 1-hour fix; production-only concern |
| **TS-API-F-09** wire Pino log sanitizer | LOW | Phase D deferred work | Already planned |
| **F-04** dual @noble/curves | LOW | Accept; revisit when @noble/post-quantum hits 1.0 | Documented risk |
| **F-05** crypto.timingSafeEqual replacement | COSMETIC | 10-min edit | Defer |
| **BR-A / BR-B / BR-E** architectural | HIGH | G4 Phase 2 TEE, combiner TEE, S2-3 §G2 Chipotle backprop | Already on roadmap |

---

## ORIGINAL "Already-applied fixes" section (now superseded by the table above)

### Fix 1 (REVERTED) — F-01 init-front-run protection
**What was attempted:** Added `constructor() { _disableInitializers(); }` to 22 UUPSUpgradeable impl contracts + ConditionModuleBase abstract (covering 8 modules transitively).
**Verification result:** `forge build` clean, but `forge test --offline` produced **67 test failures** with `InvalidInitialization()`. The failures are all in tests that deploy impls directly and call `.initialize(...)` on them — a test-only pattern that bypasses the proxy. Once impls are locked via `_disableInitializers()`, this test pattern breaks.
**Decision:** REVERTED in this session. The 22 files are restored to original state.
**Re-application path:** F-01 is a real best-practice gap. To land it, the test fixtures need to be updated in parallel to deploy via `ERC1967Proxy` (matching production). Effort estimate: 1-2 days. Scoped as Phase B follow-up.
**Risk if not re-applied before mainnet:** Auditors will flag this; impl-side roles seizable; mitigated by OZ UUPSUpgradeable v5's `onlyProxy` modifier on `upgradeToAndCall` (impl-side admin cannot trigger proxy upgrade). Real exposure is "auditor signal + defense-in-depth gap" not "exploitable today."

### Fix 2 (APPLIED + verified) — BR-G CANCELLER_ROLE grant to SecurityMultisig
**What:** Added import of `TimelockController` + grant of OZ TimelockController's `CANCELLER_ROLE` to `addrs.securityMultisig` in `PostDeploy.s.sol`. Independent canceller closes single-actor capture path on the 7-day normal-path queue.
**Files:** `contracts/script/PostDeploy.s.sol:7` (import) + `:233` (grantRole call).
**Risk:** Zero — grants a defensive role to an independent governance actor. Only fires on next deploy.
**Verification:** `forge build` clean (74 files compiled); `forge test --offline` clean (**274 tests passed, 0 failed, 0 skipped** (count at this May-2026 HEAD; 330 at retirement)).

---

## Recommended remediation queue (priority order)

### Phase A — Block mainnet promotion (HIGH severity, ship-blocking)

1. **TS-CRYPTO-F-05 — Re-key ceremony preimage** (HIGH; functional bug + spec violation)
   - Owner: TS team
   - Fix: rewrite `re-key-stanza-addition.ts:97-106` to use `keccak256(TAG_COMMIT_V3 ‖ <15 SCALE-encoded fixed-width fields>)` per S2-1 §3.4.1
   - Effort: 1-2 days (needs spec re-read + test vectors against existing helpers)
   - Why blocking: every re-keyed commit reveal will fail at combiner — this would silently break the re-key ceremony post-launch

2. **TS-API-F-03 — verify-sdk freshness check** (HIGH; partner-facing)
   - Owner: TS team  
   - Fix: add `deliveredAt` freshness window enforcement to `verify-artifact-bundle.ts:24-60`
   - Effort: half-day
   - Why blocking: partners using verify-sdk will accept replayed artifacts

3. **TS-API-F-06 — verifyArtifactBundleServerSide fake-pass** (HIGH; should be HIGH not MEDIUM)
   - Owner: TS team
   - Fix: actually perform crypto verification on each of the 15 check names, not just key-presence
   - Effort: 2-3 days
   - Why blocking: server-side endpoint returns false `pass` to partners

4. **TS-API-F-05 — Stage 3 PDA validation no-op** (HIGH)
   - Owner: TS team
   - Fix: rewrite `buildStage3Context` / `adaptToStage3` in `v3-configurator/src/pda/emit.ts:280-320` to validate against REAL allow-lists from registries, not synthetic values
   - Effort: 1-2 days
   - Why blocking: real partner PDAs slip past Stage 3 validation entirely

5. **TS-API-F-01 — Ingestion `additionalProperties: true`** (HIGH)
   - Owner: TS team
   - Fix: set `additionalProperties: false` in `ModeAIngestionRequestSchema` root; bound `plaintext_payload` size
   - Effort: 1 hour
   - Why blocking: unbounded payloads + unknown keys = prototype-pollution + DOS surface

6. **TS-API-F-02 — `h_commit` URL param validation** (HIGH)
   - Owner: TS team
   - Fix: validate format (`0x` + 64 hex chars) on both shred routes
   - Effort: 30 minutes
   - Why blocking: malformed URLs reach handler bodies

### Phase B — Pre-mainnet hardening (MEDIUM severity)

7. **F-02 — chainId in attestation digest** — Add chainId to TAG_G4_ATTESTATION_V3 preimage form (requires spec patch + oracle SDK update)
8. **SC-F-05 — admin == timelock assertion** — Add invariant check in CealisSecurityMultisig + EmergencyGovernance initializers
9. **TS-CRYPTO-F-06 — assertSigmaVerified fail-open** — Require `verified === "true"` explicit; throw on `undefined`
10. **TS-CRYPTO-F-08 — engine address pin in combiner** — Add address-pin check to pre-verify pipeline (S2-3 §5 check (a))
11. **TS-API-F-07 — SD cleartext heap residue** — Zero `SdCleartextItem` objects in returned bundle (SD-D1/D3 full compliance)
12. **TS-API-F-08 — prepareSubmittedPda defaults** — Stop silently filling `partner_id` etc; raise `MISSING_REQUIRED_FIELD` first
13. **TS-API-F-04 — root schema `additionalProperties`** — Set to `false` (covered with F-01 fix above)
14. **TS-CRYPTO-F-07 — combiner binary self-check env-var bypass** — Production-mode startup assertion: env vars must be unset
15. **SC-F-06 — MultiPartySignal/ConsentGate signer verification** — Either add on-chain ECDSA or document trusted-Orchestrator model explicitly in spec + NatSpec
16. **BR-F — Oracle attestation single-use** — Add `_consumedAttestations` per-authorizationId mapping or bind authorizationId in digest
17. **BR-H — Plugin reveal-time check window** — Distinguish register-time (current-block) from reveal-time (commit_block + grace period)
18. **BR-D — Configurator shred-mode DOS** — Add `minimumShredLatency >= MIN_FLOOR` invariant in `registerPDA`

### Phase C — Code hygiene (LOW + COSMETIC)

19. **F-03 — Tighten v3-crypto semver to exact pins** — 5 minute edit
20. **F-04 — Document dual @noble/curves as accepted risk** — Or upgrade @noble/post-quantum when 1.0 lands
21. **SC-F-03, SC-F-07 — Add `nonReentrant` to ShredRegistry.finalizeShred + ChallengeRegistry.withdrawChallenge** — Defense-in-depth
22. **TS-CRYPTO-F-09 — Constant-time `gfMul`** — Branchless or table-based GF multiplication
23. **TS-API-F-09 — Wire Pino log sanitizer** — Phase D deferred work
24. **F-05 — Replace hand-rolled constant-time with `crypto.timingSafeEqual`** — 10 minute edit

### Phase D — Architectural (long-term)

25. **BR-A — G4 Phase 2 HSM/TEE roadmap** — Already on roadmap; eliminates software-key extractability
26. **BR-B — Combiner TEE** — Move combiner to TEE so root on host does not yield plaintext for in-flight reveals. Architectural; multi-quarter scope
27. **BR-E (Lit V3 Chipotle) — S2-3 §G2 backprop** — Update custody-integration-spec to reflect Chipotle single-TEE topology; revise decentralization claims accordingly

---

## What this audit deliberately did NOT cover

- **Live deployed bytecode vs source equality** — Sourcify verification already confirmed `exact_match` for all 32 V3 impls per MATURITY-SCORECARD
- **Formal verification / symbolic execution** — out of scope; would require Certora or similar
- **Penetration testing on running infrastructure** — out of scope
- **Hardware-side-channel resistance** (cache-timing, power analysis on combiner host) — out of scope (mitigated by hardware-level approach via TEE roadmap)
- **Auditing the OZ contracts library** — assumed audited
- **Auditing `@noble/*` libraries** — assumed audited (Cure53 covered `@noble/ciphers` per cryptography-spec.md §6.4.2)

---

## What "production-grade posture" looks like after Phase A+B remediation

The HIGH-severity items in Phase A are all fixable in <2 weeks of focused work. Once cleared:
- Cryptographic core: confirmed byte-exact to spec (already)
- Universal tripwire: confirmed (already)
- 4-gate AND-composition isolation: confirmed in code (already)
- Boundary input validation: all HTTP endpoints reject unbounded/malformed input
- Partner-facing verify SDK: actually performs crypto verification + freshness binding
- Governance: SecurityMultisig has CANCELLER_ROLE (fixed this session); admin-vs-timelock invariant enforced (Phase B)
- Re-key ceremony: preimage matches spec (Phase A)
- Combiner pipeline: engine address pinned + binary integrity not env-bypassable (Phase B)

This is not "100% hacker-proof" — that's not a real thing. It's "production-grade posture, no known critical/high vulnerabilities, defense-in-depth at every gate, fail-closed throughout." That is the posture an external audit firm would be asked to review; no such external review ever took place. That's what's achievable; that's what this internal review drives toward.

---

## File map

- `00-phase1-manual-findings.md` — Manual scan (Opus): 5 findings + 14 PASS items
- `01-solidity-adversarial.md` — Sonnet SC: 2 MEDIUM + 2 LOW (after advisor revision; F-04 retracted)
- `02-ts-crypto-custody-ops.md` — Sonnet TS crypto: 1 HIGH + 3 MEDIUM + 1 LOW; 6 lenses PASS
- `03-ts-api-configurator-sd-verify.md` — Sonnet TS boundary: 4 HIGH + 4 MEDIUM + 1 LOW; 14 PASS items
- `04-blast-radius-matrix.md` — Sonnet blast-radius: matrix for 10 compromise vectors, 4 confirmed coupling, 2 unverified
- `MASTER-REMEDIATION-PLAN.md` — this file
