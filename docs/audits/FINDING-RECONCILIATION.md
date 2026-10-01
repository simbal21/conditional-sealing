# Audit-Finding Reconciliation

*Written 2026-09-26 during pre-push preparation. This note reconciles the
shorthand finding counts used in the repository's top-level documents with
the actual audit corpus in `docs/audits/`.*

## Why this file exists

Top-level documents in this repository previously summarized the internal
security record as **"2 CRITICAL and 8 HIGH"** findings. That shorthand
conflated numbers from different passes and undercounted the corpus. This
file is the authoritative reconciliation: what each pass found, which
findings are the same ones under different names, and what was still open
at retirement (2026-06-10).

## The passes

| # | Date | Artifact | Scope |
|---|---|---|---|
| 1 | 2026-05-14 | `security-audit-2026-05-14/` | Manual + adversarial review of contracts and the TS off-chain pipeline |
| 2 | 2026-05-19 | `live-system-audit-synthesis.md` | Consolidated synthesis of pass 1 + backlog reconciliation (supersedes pass 1's headline) |
| 3 | 2026-06-02 | `security-audit-2026-06-02/` (`LEDGER.md`, `OPEN-FIXLIST.md`) | Post-R2b re-audit at HEAD `e87c108`; authoritative for current state |
| 4 | 2026-06-03 | `honest-audit-2026-06-03.md` | Four-lens adversarial rewrite; the "truth-base" narrative |

**None of these was an external or independent audit.** The system was never
externally audited. For the honest overall maturity read, see
`MATURITY-SCORECARD.md` (~3.5/5, Auditing axis ~2/5).

## The CRITICALs — four distinct findings over time

| ID | Severity | First found | What | Status at retirement |
|---|---|---|---|---|
| **C1** | CRITICAL | Pass 2 (net-new) | Off-chain commit-AAD round-trip integrity check silently skipped for historical and re-keyed commits | **FIXED in source** (R2b sweep; verified in pass 3) |
| **C2** | CRITICAL | Pass 2 (in-scope-now) | Deployed `ChallengeRegistry` stores the `eligibleChallengersRoot` allowlist and documents merkle enforcement in NatSpec, but `openChallenge()` never verifies membership → **permissionless challenge-open on the live Base Sepolia contract** | **FIXED in source only** — the live testnet contract was never redeployed, so the deployed contract remained challenge-open |
| **C3** | CRITICAL | Pass 2 | (a) Rule-25 snapshot-once preconditions in the reveal coordinator (shred-race / bypass); (b) unmarked fake-success TEE stub `sealPlaintextForVault` | Split: C3a → **PARTIAL** (closed by construction in the coordinator, but live `LiveStateReaderPorts` have zero production implementations); C3b → **FIXED** (stub marked + production-guarded) |
| **F-1** | CRITICAL | Pass 3 (net-new) | Mode-F FSM conditions not enforced — the engine fabricates a trivially-terminal transition and `FSMInterpreter` performs no edge-table validation, so any Mode-F reveal/shred PDA fires on the first anonymous call; defeats the Universal Tripwire for every Mode-F PDA | **Fixed in source 2026-06-02** (commit in the 2026-06-02 re-audit fix batch; `ConditionEngine._evaluateAxis` no longer fabricates the terminal transition, `FSMInterpreter` validates edges) — **never redeployed; live testnet contract still vulnerable** |

## The HIGHs — where "8 HIGH" came from

- **Pass 1** found **8 HIGH** findings (the `security-audit-2026-05-14/` backlog). The pass-2 synthesis records 5 of those 8 as still open at 2026-05-19.
- **Pass 3** (`LEDGER.md` §A, "the fix queue") lists **13 HIGH** findings at its HEAD: 6 on-chain (F-2, F-3, B3b, SC-F-06, F-02, B3-bond) and 7 off-chain/build (SC-1, SC-2, F-CRYPTO-1/F-COMBINER-1, TS-API-F-05, TS-CRYPTO-F-05, S2-7 D1, WebAuthn F-1). Several overlap the pass-1/2 backlog under renamed IDs; several are net-new (broken CI lockfile drift, 24 vulnerable dependencies including a drizzle-orm SQLi and a fastify content-type bypass, fake-success WebAuthn verifier).
- The pass-2 synthesis reconciles the whole backlog as **29 findings: 10 FIXED · 6 PARTIAL · 12 DEFERRED-OPEN · 1 net-new CRITICAL (C1)**.

## What the old shorthand got wrong

The old "2 CRITICAL and 8 HIGH" combined the pass-1 HIGH count (8) with the
C1/C2 CRITICAL naming from the honest-audit rewrite, and thereby:

1. **Missed C3** (pass 2's third CRITICAL, partially fixed).
2. **Missed F-1** (pass 3's net-new on-chain CRITICAL; fixed in source 2026-06-02, never redeployed).
3. **Missed the net-new pass-3 HIGHs** (CI broken, vulnerable dependencies, fake-success WebAuthn, combiner self-attestation tautology, and others).
4. **Omitted fix dispositions** — most importantly that the fixes that landed
   landed in source only and were never deployed, so the live testnet
   contracts carry the pre-fix vulnerabilities.

## Retirement-state summary (the honest headline)

At retirement on 2026-06-10: **two CRITICALs live on the testnet deploy** (C2 and
F-1 — both fixed in source on 2026-06-02, never redeployed), one
CRITICAL fixed in source (C1), one split fixed/partial (C3), plus a HIGH
backlog of which the June ledger's fix queue alone lists 13. The live Base
Sepolia deployment predates every source-level fix. Full inventory with
fix classes (`source-now` / `redeploy` / `build-wiring`) is in
`security-audit-2026-06-02/OPEN-FIXLIST.md`.
