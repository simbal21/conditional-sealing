> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# V3 Go-Live — Consolidated Audit Synthesis (2026-05-19)

*5 source-verified inputs (4 adversarial auditors + backlog reconciliation, all at HEAD `7481713`), meta-partner-vetted twice. Authoritative over the prior internal "5.00/5" framing.*

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

## Honest headline

On-chain V3 contracts are genuinely live + Sourcify-verified + smoke-9/9 on Base Sepolia, and M0–M8 unit/contract tests are real-green (independently re-verified: typecheck 9/9, vitest pass, forge 274/274 at this document's May-2026 HEAD (330 at retirement)). **The cryptographic core is verified solid** (Universal Tripwire, σ-as-authorization, Shamir threshold, shred-race guardrail, fail-closed — all hold). BUT: the off-chain *runtime* (host server, reveal-coordinator process, V3 vault, real DB/Redis/queue) was never built or run — all in-memory mocks. And the "**ToB 5.00/5**" in the internal status headline is **not credible** — honest ≈**3.5/5** (Auditing ≈2/5; self-graded docs as code maturity, predates an unremediated security backlog). Internal status headline corrected 2026-05-19.

## 3 distinct CRITICALs

| ID | What | Location | Bucket |
|---|---|---|---|
| **C1** | commitAAD round-trip integrity check silently skipped for historical/re-keyed commits (version-patch defeats the guard); compounds with cross-vendor-bypass + g3_choice into one wire-input attack | `combiner/pre-verify-pipeline.ts:55` + `profile-dispatch.ts:130` | **B2** (net-new combiner TS, not yet deployed → fix-by-authoring-right) |
| **C2** | ChallengeRegistry `eligibleChallengersRoot` merkle allowlist stored + NatDoc'd-as-enforced but `openChallenge()` never verifies it → **permissionless challenge-open on a LIVE deployed contract** = system-locked-principle breach | `src/challenge/ChallengeRegistry.sol` | **B3** (in-scope-now) |
| **C3** | (a) Rule-25 snapshot-once preconditions in `processRevealAuthorizedEvent` (shred-race + Art.18 bypass) → **B1** (the live coordinator we author must re-validate per-step by construction). (b) unmarked fake-success TEE stub `sealPlaintextForVault` → **B4, FIXED 2026-05-19** (marked + NODE_ENV=production guard) | `combiner-orchestrator/index.ts:94` ; `g4/sealed-code-server.ts` | split B1 / B4 |

## 4-bucket disposition (meta-partner-corrected)

- **B1 — R2 BUILD-SCOPE** (closed by authoring R2 to the corrected spec, not "shipped-broken"): the LBU-1…10 mock→real seams (repo/vault/chain-anchor/queue/schema), **Rule-25 per-step revalidation in the live coordinator**, Art.18 freeze wiring, real BullMQ/Redis durability, real Postgres schema+migrations. *Severity not downgraded — fix is relocated into the build we're already committed to.*
- **B2 — FIX-NOW off-chain** (required for "everything green"): **C1** commitAAD round-trip; re-key SCALE-preimage (TS-CRYPTO-F-05); Stage-3 PDA validation no-op (TS-API-F-05); verify-sdk real crypto sigma-verification + freshness-default; canonicalAddressPin enforced *inside* pipeline (TS-CRYPTO-F-08); k_conditional from commitAAD not sigma-metadata; opt-in→enforced cluster (TS-API-F-03/06/07); Pino sanitizer wiring (TS-API-F-09); `timingSafeEqual` (F-05).
- **B3 — CONTRACT, IN-SCOPE-NOW, batched into ONE go-live redeploy** (Rule-44-compliant: the single integration-milestone deploy Rule 44 reserves — *not* a mid-build redeploy): **C2** + ChallengeRegistry bond-permanently-locked + MultiParty/Consent signer-set-never-cleared + ShredRegistry OPERATOR→Timelock conflation + `_evaluateAxis` no module-whitelist + recordRevealCompleted no refusal-recheck + F-02 chainId + SC-F-05/06 + BR-F/H/D + G4RefusalRegistry OPERATOR-grant.
- **B4 — HONESTY/DOC, DONE 2026-05-19**: internal status headline 5.00/5→~3.5/5 corrected; TEE stub marked + prod-guarded; this synthesis written. Open line-item: **F-01** (UUPS `_disableInitializers` — needs the documented 1–2-day test-fixture migration to ERC1967Proxy; in or explicitly out).

## Backlog reconciliation (source-verified, Rule 45)

29 findings: **10 FIXED · 6 PARTIAL · 12 DEFERRED-OPEN · 1 net-new CRITICAL**. The prior `security-audit-2026-05-14/` backlog is largely real-still-open (5/8 HIGH, 10/13 MEDIUM not closed). Crypto-core fixes that ARE real-verified: TS-CRYPTO-F-06 (fail-closed), F-07, F-09, F-03, BR-G, TS-API-F-01/02/04.

## Cost reality + the decision

This is the **second** material cost escalation. DP3 ~doubled scope (Stage-4 off-chain layer pulled forward). DP5 ~doubles again (B2 security cluster + B3 contract fixes + one batched contract redeploy + full re-verify) **and re-touches deployed-contract source**. The internal project plan defaults to funding-over-build; the cost/benefit approved at DP3 has moved — Simon must re-confirm build-still-wins at the new total, and explicitly approve B3-now + the single batched go-live redeploy, before any R2/B2/B3 authoring. B1 closes C1/C3 *by construction* (not severity-downgrade). Plan-approval gate applies on top once the authoring plan exists.
