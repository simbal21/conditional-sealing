> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Spec-to-Code Conformance — v3-custody vs S2-3 (custody-integration-spec.md)

Audit date: 2026-06-02 | HEAD e87c108 | Auditor: spec-conformance subagent
Method: Rule-45 — verdict from ACTUAL CODE at HEAD via Read/Grep, tests run live.

## Verdict: CONFORMANT (read-path / full-engine scope)

The v3-custody package (`v3-custody/`) faithfully implements the
S2-3 read-path integration surface. 177 vitest cases PASS, 3 skipped (vendor-gated
dcipher + live-network E2E — both correctly deferred). `tsc -p tsconfig.test.json`
clean.

## Verified surfaces

| S2-3 ref | Surface | Code | Status |
|---|---|---|---|
| §3.4 / §7.2 | Lit DCAP user_data = RAW `authId‖hCommit‖blockHash` digest + 32B zero-pad (NO TAG_G4); G4 P2 = `TAG_G4_ATTESTATION_V3` prefixed digest | `g2-lit/dcap-verify.ts:40-62`, `g4-phase2/dcap-verify.ts:11-24` | PASS — deliberate asymmetry correct |
| §2.4 | Cross-vendor TEE disjoint: vendor-family normalization (SGX+TDX→INTEL, Nitro own, SEV-SNP→AMD) + fail-closed-on-AMBIGUOUS | `g2-lit/vendor-family-normalize.ts`, `combiner/cross-vendor-check.ts` (phase==1 early-return correct) | PASS |
| §6.2 / §4.1 | No auto-fallback dcipher↔drand; dcipher-selected-but-unpinned → `CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED`, never drand | `g3-dispatch/router.ts:91-103` | PASS |
| §2.2 / §2.5 / §9.4 | g3_choice/phase read from commit_AAD not adapter config; commit-block-state vs auth-block-state separation | `g3-dispatch/router.ts:134`, `combiner/snapshot-verifier.ts:21-27`, `gate-recipient-verifier.ts` | PASS |
| §2.5 | Gate-recipient KEM pubkey at commit-block, current-head substitution rejected, σ-evidence pubkey matched to commit snapshot; split-key (KEM-at-commit vs σ-verify-at-auth) | `combiner/gate-recipient-verifier.ts:71-98` | PASS |
| §9.2 | Fixed σ ordering Lit→G3→G4→conditional; duplicate/extra/missing/out-of-order rejected | `combiner/sigma-orchestrator.ts:107-180` | PASS |
| §9.3 (11-item pre-verify) | plugin integrity, commit_AAD round-trip (UNCONDITIONAL incl. historical), registry snapshots, gate-recipient pubkeys, Mode 3 reject, shred-state signable, supersession lineage, cross-vendor, σ verify | `combiner/pre-verify-pipeline.ts` | PASS — all 11 present, no skip-guards |
| §9.4 | Shamir reconstruction delegated to M1 `combineDek` typed access structure (FIXED_ONLY 3of3 / 1of1 4of4 / KofN nested); zeroize after | `combiner/shamir-dispatch.ts`, `combine-and-decrypt.ts:133-146` | PASS |
| §9.5 / §9.7 | file_key zeroized; no partial plaintext on failure; runtime hardening (crash dump off, debug off, egress blocked, IPC blocked, SIGABRT/SIGQUIT suppressors) | `combine-and-decrypt.ts`, `combiner/runtime-hardening.ts` | PASS (see DEV-1 on IPC escape hatch) |
| §7.0–§7.2 | G4 pre-sign checklist; Phase 1 Ed25519 dev-scaffold-only eligibility; Phase 2 DCAP; reverse-substitution forbidden both directions (`G4_PHASE_MISMATCH` / `G4_PHASE_NOT_ELIGIBLE`) | `g4-phase1/*`, `g4-phase2/*`, `g4-shared/pda-type-guard.ts` | PASS |
| §7.7 | Refusal enum 0x01-0x09 blocking + 0x0A advisory; 0x02/0x03 encrypted-reason mode | `refusal/codes.ts` | PASS |
| §7.9 | Commit-time G4 ingestion TEE boundary | architecture honored (combiner is recipient-side; ingest TEE is v3-crypto/M1 scope) | PASS (boundary not in this pkg) |
| §10.5 | SD asymmetric isolation: zero SD imports in custody; `CUSTODY_ERR_SD_ONBOARDING_PARTIAL_FAILURE` must-not-block-escrow | `errors.ts:56`; no SD code path in pkg | PASS |
| §13.1 | 37 core CUSTODY_ERR_* codes verbatim incl. deprecated alias | `errors.ts:23-64` | PASS |
| §1.4 / §3.5 / §7.6 / §14.1 | σ-redaction in logs; no-σ-in-logs test assertions; SigmaBuffer + zeroize | `redaction/*`, `combiner-adversarial-redaction.test.ts`, `combiner-crash-dump-disabled.test.ts` | PASS |

## Deviations

### DEV-1 (LOW) — IPC export hardening has env-gated escape hatch
`combiner/runtime-hardening.ts:68-75` — `assertNoIpcExportSurface()` permits IPC
export when `CEALIS_ALLOW_COMBINER_IPC === "1"`. §9.7 states the combiner runtime
MUST disable "IPC export of σ values" with no documented exception. The escape hatch
is an operator-controlled override of a "must-disable" control. Crash-dump / debug /
egress controls have NO such hatch (correctly). LOW because: requires local env-var
control of the combiner process (already trusted boundary), and SigmaBuffer + the
log-sanitize redaction filter provide defense-in-depth. Recommend either removing the
override or documenting it as a sanctioned test-only seam in the spec.

### DEV-2 (INFO, not a defect) — Controlled-use write-path (§7.10–§7.16, §3.8/§4.8/§5.6, §13.1 CU_ERR_*) not implemented
The Stream 2 cosign protocol, G4 write-validation TEE (5-check), on-chain policy-hash
replay, read-event ingest API, and the 10 `CU_ERR_*` controlled-use codes are absent
from v3-custody. This is the `commit_version = 0x0303` S2-8 profile which the spec
itself scopes as "Non-controlled-use deployments do not exercise these paths." The
current build (per project design constraints §0, M1–M8) targets the read-path full-engine scope. NOT a
conformance defect for the audited read-path scope; flagged so the controlled-use
surface is not assumed-built. When S2-8 controlled-use is built, the §13.1 second
error list + §7.10-§7.16 surfaces become net-new conformance obligations.

## Notes
- Vendor-gated stubs (`g4-phase2/dcap-quote-types.ts` G4Phase2QuoteStub, dcipher
  adapter excluded-by-default) are CORRECT per §0.5 vendor-confirmation-gate discipline
  + §4.1 — not missing implementation. Skipped dcipher tests align.
- The pre-verify pipeline's C1 commit_AAD round-trip (`pre-verify-pipeline.ts:253-321`)
  is notably hardened: unconditional, historical-version-aware (skips only the 2-byte
  version window), constant-time compare, fail-closed on malformed binding bytes. This
  closes the documented C1 defeat path. Strong.
- TS-CRYPTO-F-06 (fail-closed σ-verified + stanzaIndex metadata) and TS-CRYPTO-F-08
  (mandatory canonical-address pin + chainId cross-substitution) closures are present
  and type-enforced (no opt-in `?` at caller).
