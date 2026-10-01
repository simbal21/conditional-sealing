# V3 Code Maturity Self-Assessment (Trail-of-Bits 9-category framework)

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

**Generated:** 2026-05-25 (honest rewrite; supersedes 2026-05-14 self-assessment)
**Scope:** `contracts/` (V3 stack; V1 phased out per Rule 29)
**Framework:** Trail of Bits 9-category code-maturity rubric (per `building-secure-contracts:code-maturity-assessor` skill)
**Method:** Grades reconciled against five-input consolidated audit synthesis (2026-05-19), not self-authored doc completeness
**Source of truth:** [docs/audits/live-system-audit-synthesis.md](../docs/audits/live-system-audit-synthesis.md)

## Honest Headline (2026-05-25 rewrite)

On-chain V3 contracts are genuinely live + Sourcify-verified + smoke-9/9 on Base Sepolia, and M0–M8 unit/contract tests are real-green (independently re-verified: typecheck 9/9, vitest pass, forge 274/274 at this document's May-2026 HEAD (330 at retirement)). **The cryptographic core is verified solid** (Universal Tripwire, σ-as-authorization, Shamir threshold, shred-race guardrail, fail-closed — all hold). BUT: the off-chain *runtime* (host server, reveal-coordinator process, V3 vault, real DB/Redis/queue) was never built or run — all in-memory mocks. And the "**ToB 5.00/5**" in the prior version of this file is **not credible** — honest ≈**3.5/5** (Auditing ≈2/5; self-graded docs as code maturity, predates an unremediated security backlog).

**Prior 5.00/5 self-grading withdrawn — not credible per 2026-05-19 five-input audit synthesis.**

## Scorecard summary

| Category | Score | Notes |
|---|---|---|
| Arithmetic safety | **4.0/5** | Solidity 0.8.28 default checked math; `ArithmeticBoundaries.fuzz.t.sol` exercises uint64/uint8/uint32/uint16 bounds; no fixed-point math. Residual: not every arithmetic edge across 42 contracts is fuzz-covered. |
| Auditing practices | **2.0/5** | Local Slither + audit-prep docs exist, but no independent third-party audit (PRO-44 cost-blocked). Prior scorecard treated self-authored docs as maturity evidence. 29-finding backlog: 10 FIXED · 6 PARTIAL · 12 DEFERRED-OPEN · 1 net-new CRITICAL (C1). |
| Authentication / access controls | **3.5/5** | 17 AccessControl roles + UUPS + timelock are real. **C2**: `ChallengeRegistry.openChallenge()` never verifies stored `eligibleChallengersRoot` on a live deployed contract. B3 backlog: ShredRegistry OPERATOR→Timelock conflation, G4RefusalRegistry OPERATOR-grant, MultiParty/Consent signer-set-never-cleared, `_evaluateAxis` no module-whitelist. **F-01**: UUPS `_disableInitializers` migration still open. |
| Complexity management | **3.5/5** | 42 contracts × 79 state-changing entry points — deliberate full-engine scope (Rule 31). ARCHITECTURE.md + NatSpec + SPEC-COMPLIANCE.md make the surface navigable, but ConditionEngine at 76% EIP-170 and ClaimDSL/FSM composition remain high-auditor-load by design. |
| Decentralization | **3.5/5** | Base Sepolia deploy live (ConditionEngine `0xb09a8300…`, 17-role governance, UUPS proxies). Crypto-non-custody architecture (4-gate AND, rented G2/G3) documented in DECENTRALIZATION-POSTURE.md. Off-chain combiner/coordinator runtime is Cealis-operated and still mock-backed — operational decentralization story incomplete until R2 build. |
| Documentation | **4.0/5** | 8 Stage-2 specs (`docs/specs/`) + GLOSSARY + ARCHITECTURE.md (8 diagrams) + TRIAGE.md + INCIDENT-RESPONSE.md + MEV-EXPOSURE.md. Strong for internal sign-off. Gap: documentation volume previously inflated maturity grades; several NatSpec claims (e.g. ChallengeRegistry allowlist) diverge from deployed behavior (C2). |
| Front-running resistance | **4.0/5** | MEV-EXPOSURE.md: 9/11 MEV categories eliminated by design (no AMM/swap/auction surfaces; commitment-only pre-reveal). 1 LIMITED (challenge-bond front-run — `eligibleCaller` PDA mitigates but C2 undermines allowlist enforcement). 1 LOW (inclusion-censorship / L1 fallback). |
| Low-level manipulation | **4.0/5** | Exactly 2 assembly blocks in `AttestationGate._oracleAddress` with bounds-gated NatSpec. OZ ReentrancyGuardTransient (TSTORE) inherited. `abi.encode` used post Task#13 fix for collision-prone paths. Residual B2: re-key SCALE-preimage (TS-CRYPTO-F-05), canonicalAddressPin not enforced inside pipeline (TS-CRYPTO-F-08). |
| Testing & verification | **3.5/5** | **forge 274/274 at this document's May-2026 HEAD (330 at retirement)**, vitest pass across 9 v3-* packages, typecheck 9/9, live-smoke 9/9 on Base Sepolia. 56 Foundry fuzz tests + 3 invariant suites. Gap: off-chain runtime never built (in-memory mocks only); forge coverage blocked on Tags.sol stack-too-deep; integration path (B1) not yet real. |
| **WEIGHTED AVG** | **≈3.5/5** | Honest aggregate per 2026-05-19 synthesis. Prior **5.00/5 withdrawn.** |

## Detailed category notes

### 1. Arithmetic safety — **4.0/5**

Solidity 0.8.28 default-checked math verified; no `unchecked` in critical paths. `test/fuzz/ArithmeticBoundaries.fuzz.t.sol` (11 fuzz tests) covers uint64 deadline overflow, five uint8 enum cast bounds, uint32 extension counter, and uint16 generation overflow. ChallengeRegistry window math uses uint64 — bounded by design.

- **Open backlog:** No category-specific B1–B4 blockers; extend fuzz to remaining boundary surfaces as polish (optional, not synthesis-critical).

### 2. Auditing practices — **2.0/5**

Local audit-prep stack is substantive: Slither 0 HIGH / 9 MEDIUM (TRIAGE.md), SPEC-COMPLIANCE.md (5 invariants), INCIDENT-RESPONSE.md (6 runbooks). **This is not equivalent to an independent Trail of Bits or equivalent third-party review.** The 2026-05-14 scorecard graded itself 5/5 partly by counting self-authored documentation as audit maturity. Synthesis backlog reconciliation: **29 findings — 10 FIXED · 6 PARTIAL · 12 DEFERRED-OPEN · 1 net-new CRITICAL (C1).** Prior `docs/audits/security-audit-2026-05-14/` backlog largely still open (5/8 HIGH, 10/13 MEDIUM).

- **Open backlog (B2/B3/B4):** External paid audit deferred (PRO-44). **C1** (commitAAD round-trip skip — `combiner/pre-verify-pipeline.ts:55`). Full B2 off-chain cluster + B3 contract batch before credible "audit-ready" claim. **F-01** UUPS `_disableInitializers` (B4 line-item).

### 3. Authentication / access controls — **3.5/5**

17 distinct roles per S2-2 §16; UUPS `_authorizeUpgrade` gated by UPGRADER_ROLE; 7-day timelock on admin. M8 v3-demo tests exercise role-restricted ingest/reveal/shred paths. **Critical gap on live contract:** **C2** — `src/challenge/ChallengeRegistry.sol` stores `eligibleChallengersRoot` and NatSpec describes merkle enforcement, but `openChallenge()` never verifies membership → permissionless challenge-open. B3 also flags ShredRegistry OPERATOR→Timelock conflation, recordRevealCompleted no refusal-recheck, G4RefusalRegistry OPERATOR-grant, MultiPartySignal/ConsentGate signer-set-never-cleared.

- **Open backlog (B3):** **C2**, ChallengeRegistry bond-permanently-locked, MultiParty/Consent signer-set, ShredRegistry authority conflation, `_evaluateAxis` module-whitelist, recordRevealCompleted refusal-recheck, **F-02** chainId, SC-F-05/06, BR-F/H/D, G4RefusalRegistry OPERATOR-grant. **F-01** (B4): UUPS `_disableInitializers` + ERC1967Proxy test-fixture migration.

### 4. Complexity management — **3.5/5**

42 `.sol` files; ConditionEngine ~18,680 bytes (76% EIP-170); ClaimDSL + FSMInterpreter + 9 condition modules + AttestationGate composition. Deliberate full-engine architecture (Rule 31), not scope creep. 2026-05-14 doc lift (22-contract NatSpec, ARCHITECTURE.md 8 diagrams, SPEC-COMPLIANCE.md) makes the surface navigable — but an external auditor still faces substantial composition depth.

- **Open backlog:** Complexity is accepted trade-off; no synthesis item downgrades architecture. B3 module-whitelist (`_evaluateAxis`) reduces misuse risk within existing complexity.

### 5. Decentralization — **3.5/5**

V3 stack deployed Base Sepolia 2026-05-14: UUPS proxies, TimelockController, 17-role governance, addresses in `deployments/base-sepolia.json`. V3 custody design rents G2 Lit V3 + G3 dcipher/drand; Cealis holds no master DEK. DECENTRALIZATION-POSTURE.md documents progressive roadmap (Phases G→M). **Operational gap:** off-chain reveal-coordinator / combiner / vault runtime is mock-backed (B1) — decentralization posture is architecturally sound but not yet operationally demonstrated end-to-end.

- **Open backlog (B1):** LBU-1…10 mock→real seams, Rule-25 per-step revalidation in live coordinator, Art.18 freeze wiring, real BullMQ/Redis/Postgres. Mainnet promotion deferred.

### 6. Documentation — **4.0/5**

8 Stage-2 specs + WP (S2-1..S2-8, `docs/specs/`), GLOSSARY.md, ARCHITECTURE.md, TRIAGE.md, INCIDENT-RESPONSE.md, MEV-EXPOSURE.md, DECENTRALIZATION-POSTURE.md. NatSpec on 22 major contracts. Documentation quality is genuinely high for grant/diligence readers. **Credibility gap:** prior 5/5 treated doc completeness as code maturity; at least one live contract behavior diverges from documented enforcement (**C2** eligibleChallengersRoot).

- **Open backlog (B4):** the internal project rulebook (§0) corrected 2026-05-19; this scorecard rewritten 2026-05-25. Remaining: align NatSpec with post-B3 contract fixes; **F-01** migration documented in or explicitly deferred.

### 7. Front-running resistance — **4.0/5**

No AMM/swap/auction/liquidation surfaces. Pre-reveal on-chain state is commitment-only (`hCommit`). Shred-vs-reveal race guarded by mandatory `NOT post_challenge_reveal_in_progress`. MEV-EXPOSURE.md: 9 categories eliminated, 1 LIMITED (challenge-bond front-run — mitigated by `eligibleCaller` PDA when configured), 1 LOW (inclusion-censorship). **C2** weakens the challenge-window allowlist story that MEV-EXPOSURE.md assumes is enforced.

- **Open backlog (B3):** **C2** fix restores allowlist enforcement credibility for challenge surface.

### 8. Low-level manipulation — **4.0/5**

Minimal assembly: 2 blocks in `AttestationGate._oracleAddress` (length-gated, NatSpec-documented). OZ ReentrancyGuardTransient via audited OZ v5.5. `abi.encode` post Task#13 in PasskeyRotationLog; TAG_*_V3 domain separation. Verified crypto-core fixes: TS-CRYPTO-F-06 (fail-closed), F-07, F-09, F-03, BR-G.

- **Open backlog (B2):** **C1** commitAAD round-trip (`combiner/pre-verify-pipeline.ts:55`, `profile-dispatch.ts:130`). TS-CRYPTO-F-05 re-key SCALE-preimage. TS-CRYPTO-F-08 canonicalAddressPin enforced inside pipeline. TS-API-F-03/06/07 opt-in→enforced cluster. F-05 `timingSafeEqual`.

### 9. Testing & verification — **3.5/5**

Independently re-verified green: **forge 274/274 at this document's May-2026 HEAD (330 at retirement)**, vitest pass, **typecheck 9/9**, live-smoke **9/9** on Base Sepolia. 56 Foundry fuzz tests + 3 invariant suites (UniversalTripwireInvariant). M8 v3-demo: 266 tests. **Material gap:** off-chain runtime (host server, reveal-coordinator, V3 vault, DB/Redis/queue) never built — all in-memory mocks (B1). **C3a** Rule-25 snapshot-once in `combiner-orchestrator/index.ts:94` — live coordinator must re-validate per-step by construction. Forge coverage blocked (Tags.sol stack-too-deep).

- **Open backlog (B1):** Real runtime + Rule-25 per-step revalidation closes C3a by construction. **B2:** C1, TS-CRYPTO-F-05/F-08, TS-API-F-05 (Stage-3 PDA validation no-op), verify-sdk real sigma-verification, TS-API-F-09 Pino sanitizer. **C3b** TEE stub marked + NODE_ENV=production guard — **FIXED 2026-05-19** (B4).

## Open Backlog

Enumerated from [docs/audits/live-system-audit-synthesis.md](../docs/audits/live-system-audit-synthesis.md) B1–B4 buckets:

### B1 — R2 BUILD-SCOPE (closed by authoring R2 to corrected spec)

- LBU-1…10 mock→real seams (repo/vault/chain-anchor/queue/schema)
- **C3a** Rule-25 per-step revalidation in live `processRevealAuthorizedEvent` (`combiner-orchestrator/index.ts:94`) — shred-race + Art.18 bypass if snapshot-once
- Art.18 freeze wiring
- Real BullMQ/Redis durability
- Real Postgres schema + migrations

### B2 — FIX-NOW off-chain (required for "everything green")

- **C1** commitAAD round-trip integrity check silently skipped for historical/re-keyed commits (`combiner/pre-verify-pipeline.ts:55` + `profile-dispatch.ts:130`)
- TS-CRYPTO-F-05 re-key SCALE-preimage
- TS-API-F-05 Stage-3 PDA validation no-op
- verify-sdk real crypto sigma-verification + freshness-default
- TS-CRYPTO-F-08 canonicalAddressPin enforced *inside* pipeline
- k_conditional from commitAAD not sigma-metadata
- TS-API-F-03 / F-06 / F-07 opt-in→enforced cluster
- TS-API-F-09 Pino sanitizer wiring
- F-05 `timingSafeEqual`

### B3 — CONTRACT, IN-SCOPE-NOW (single batched go-live redeploy per Rule 44)

- **C2** ChallengeRegistry `eligibleChallengersRoot` never verified in `openChallenge()` — permissionless challenge-open on live contract
- ChallengeRegistry bond-permanently-locked
- MultiPartySignal / ConsentGate signer-set-never-cleared
- ShredRegistry OPERATOR→Timelock conflation
- `_evaluateAxis` no module-whitelist
- recordRevealCompleted no refusal-recheck
- **F-02** chainId
- SC-F-05 / SC-F-06
- BR-F / BR-H / BR-D
- G4RefusalRegistry OPERATOR-grant

### B4 — HONESTY / DOC

- Internal project rulebook (§0) corrected 5.00/5 → ~3.5/5 (2026-05-19)
- **C3b** TEE stub `sealPlaintextForVault` marked + NODE_ENV=production guard — **FIXED 2026-05-19**
- This scorecard rewritten 2026-05-25
- **F-01** UUPS `_disableInitializers` — needs documented 1–2-day ERC1967Proxy test-fixture migration (in scope or explicitly out)

## Path forward (post-rewrite)

| Priority | Action | Bucket |
|---|---|---|
| Credibility | Do not cite 5.00/5 in grants, diligence, or outreach | B4 |
| Live contract | Batch B3 fixes into single go-live redeploy (Simon approval required) | B3 |
| Off-chain security | Close B2 cluster before claiming runtime-ready | B2 |
| Runtime | Author R2 with B1 seams + Rule-25 per-step revalidation | B1 |
| External audit | PRO-44 third-party review when funded | Auditing |

**Recommendation:** Present **≈3.5/5** with explicit open backlog to grant reviewers. On-chain crypto core is defensible; maturity inflation is not.
