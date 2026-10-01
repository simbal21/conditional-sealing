# Kill-Test Results

### The aggregate data behind "157 companies, 0 clean fits"

*Companion to [the Fundability Fingerprint](./fundability-fingerprint.md), which defines the six conditions, the strict-AND logic, and the kill-test procedure. This file publishes the data: the segment-level aggregate of the population run of 2026-06-06. Cealis was retired four days later, on 2026-06-10; project context and limits are in the repository README.*

---

## 1. What this is, and is not

In June 2026 I ran the six-condition Fingerprint across **157 candidate companies/use cases**: 100 in fields Cealis already knew or bordered (lending, inheritance, whistleblowing, escrow, bug bounty, and so on) and 57 in field clusters I had never examined before (clinical trials, biometrics, defense technical data, energy markets, and others). Each candidate got an independent devil's-advocate pass whose job was to kill it against all six conditions and to record the first hard failure.

The raw material is three internal boards from that run. **The per-company sheets are not being published**, and the reason is plain: they name specific private companies and founders, describe their incidents and weaknesses, and contain outreach plans. None of that is mine to publish, and none of the finding depends on the names. What this file publishes instead is everything aggregate: the segments tested, the verdict counts per segment, and which of the six conditions did the killing in each. Where large public infrastructure projects appear below (Safe, Sablier, Zama), they appear as *market context* — the recurring trustless incumbents — not as identified test subjects.

Verdict vocabulary (defined in the Fingerprint, §3): **survived** = clears all six conditions cleanly; **wounded** = one or two conditions shaky but a narrow, honest, forward-only slice survives; **dead** = at least one hard failure, no honest fit.

---

## 2. Headline, and what is hard vs. soft in it

| Verdict | Count |
| --- | --- |
| **Survived (clears all 6 cleanly)** | **0** |
| Wounded (narrow honest slice survives) | ~25–26 |
| Dead (≥1 hard failure) | ~131–132 |
| **Total tested** | **157** |

**The hard number is the zero.** Across 157 candidates, not one cleared all six conditions head-on, and that result is identical in every file that recorded the run.

**The wounded/dead split is soft.** The three internal files do not agree on it: the two component boards' own headline lines report 0 / 18 / 139; the master summary reports 0 / 26 / 131, folding borderline entries into "wounded"; and counting the verdict column row by row across both boards — which is what the segment table below does — gives 0 / 25 / 132. The 157 total is consistent everywhere; the wounded/dead split is not. The disagreement is purely about where to draw the wounded/dead line on marginal cases. So read the wounded and dead columns below as classification-at-row-level, accurate to a few borderline entries either way — and treat only **0 clean fits out of 157** as asserted hard.

---

## 2b. Reproducibility — what can and cannot be re-checked

**Internally consistent:** the 157 total and the 0 clean fits are identical in every internal file that recorded the run. The instrument (`fundability-fingerprint.md` — the six conditions, the strict-AND logic, the kill-test procedure) is published in full, and the segment-level aggregates below are published with per-segment verdict counts and killing conditions.

**Not independently reproducible from this repository alone:** the per-candidate sheets are not published — they name private companies and founders — so an outside researcher cannot re-run the exact pass on the exact population. Treat this file as internal research data, not a peer-reviewed study: a single analyst (me) defined the conditions, directed the agent-run desk evaluations over public information, and adjudicated every verdict, all on a single date (2026-06-06). No company was contacted; no primary research was conducted.

The transferable result is the method and the structural scissor it exposes (trigger objectivity vs. ability to pay) — not the number 157. If you rerun the instrument, expect your own population and your own zero-or-not.

---

## 3. The segment table

Condition shorthand (full definitions in the Fingerprint, §1): **C1** data is dark until trigger · **C2** objective machine-verifiable trigger · **C3** no standing legal duty to produce early · **C4** non-custody is the actual requirement · **C5** a paying, motivated check-writer · **C6** no trustless/cheap incumbent.

### Known and adjacent fields (100 tested — 0 survived, 15 wounded, 85 dead)

| Segment | Tested | Clean | Wounded | Dead | What did the killing |
| --- | ---: | ---: | ---: | ---: | --- |
| On-chain credit / RWA lending (the flagship thesis) | 7 | 0 | 0 | 7 | C6 (confidential-compute and credit-oracle incumbents own the sealed-reveal-on-default slot) + the recovery thesis itself is dead: defaults fail on insolvency, not missing identity; regulated flows also hit C1/C3 |
| AI-agent payment rails | 7 | 0 | 1 | 6 | C1 (credentials/tokens validated live on every transaction), C6 (in-house escrow/MPC stacks); money custody out of scope. Wounded sliver: sealed payload released on a chain-verifiable predicate |
| Prediction-market settlement / oracles | 7 | 0 | 0 | 7 | C2 (outcome resolution is human/semantic judgment), C6 (oracle feeds + commit-reveal are commodity) |
| Consumer genomics | 7 | 0 | 1 | 6 | C1 (genomes read live for research/clinical use), C2 (consent validity is a legal judgment), C3 (clinical access duties), one defunct entity (C5) |
| Corporate whistleblowing | 7 | 0 | 1 | 6 | C2 (release fires on investigator/triage judgment), C6 (E2EE/ZK reporting incumbents), C3 (duty to investigate/produce) |
| DAO treasury, key succession + digital inheritance | 11 | 0 | 4 | 7 | C6 (multisig + delay-module + recovery stacks and vesting/streaming protocols of the Safe/Sablier genre own on-chain succession), C2 (death certification is off-chain human attestation). All 4 wounded are the liveness-lapse/timelock payload variant |
| M&A, trade-secret, source-code / SaaS escrow | 13 | 0 | 1 | 12 | C1 (the counterparty must read the secret; escrowed code must be synced/runnable), C2 ("misuse" / "best efforts" are court judgments), C6 (software-escrow incumbents), plus money-custody misfits and defunct payers (C5) |
| Bug bounty / coordinated disclosure | 7 | 0 | 1 | 6 | C2 (validity/severity is human triage), C3 (mandated reporting duties), C6 (~$0 timestamping kills the "prove I submitted first" wedge). Wounded sliver: researcher-side sealed-PoC-against-payment — the keystone shape |
| AI training-data licensing / data DAOs | 6 | 0 | 2 | 4 | Downstream *use* of legitimately decrypted data is out of scope; C2 (license-scope disputes are judgments); C1. Wounded slivers: payment-plus-license-gated release for distrustful data holders |
| Parametric insurance | 5 | 0 | 0 | 5 | C1 (payouts are live computations over public feeds), C6 (oracle settlement stacks already own it) |
| Journalism source-protection / embargo | 7 | 0 | 2 | 5 | C2 (publish/release is editorial judgment), C5 (grant-gated non-profits). Wounded slivers: multi-party sealed custody and timelock archival variants |
| Healthcare / EHR custody | 5 | 0 | 1 | 4 | C1 (records read at every care episode), C2 (consent/clinician judgment), C3 |
| Confidential compute (TEE/FHE/MPC platforms) | 5 | 0 | 1 | 4 | C6 (category peers build conditional release in-house), C1 (state is live-computed). Wounded sliver: independent tripwire gating a compute-result handoff |
| RegTech / KYC verification | 6 | 0 | 0 | 6 | C2 (data-access events are regulator/human requests), C3 (standing AML retention-and-production duty) |

### Never-explored frontier clusters (57 tested — 0 survived, 10 wounded, 47 dead)

| Segment | Tested | Clean | Wounded | Dead | What did the killing |
| --- | ---: | ---: | ---: | ---: | --- |
| Clinical-trial data sealing | 4 | 0 | 1 | 3 | C1 (breached assets were live operational systems), C5 (the motivated payer is the upstream sponsor, not the data-handler). Wounded sliver: pre-database-lock interim package with a calendar/lock trigger |
| Biometric template custody | 3 | 0 | 3 | 0 | Nothing survived clean: C6/C1 blunt the core (in-house non-custodial stacks; delete-don't-store is cheaper; live re-verification isn't dark). The shared honest sliver: regulator-auditable attested deletion / cold-archive sealing |
| Music-rights royalty escrow | 4 | 0 | 1 | 3 | C2 (ownership/attribution is human adjudication), money-not-data scope, C5 (captured or insolvent collecting societies). Wounded sliver: settlement rail for already-signed splits only |
| Trade-finance dedup + cross-border commodity escrow | 5 | 0 | 2 | 3 | C6 (a confidential-computing dedup incumbent owns the registry half). Both wounded are shaky on C2: physical delivery needs a trusted inspection oracle |
| Sports & esports integrity (incl. prize custody) | 6 | 0 | 1 | 5 | C2 (disclosure/investigation triggers are discretionary judgments), C5 (broke non-profits; conflicted custodians), money custody. Wounded sliver: pre-commitment sealing until an official embargo lift |
| Property escrow (off-plan, title, closing) | 5 | 0 | 1 | 4 | C2 (construction milestones are architect/engineer-certified), C3 (record-production duties), regulator-mandated bank escrow as incumbent. Wounded sliver: closing-fund release on the machine-verifiable deed-recorded event |
| Alt-asset custody (whisky/wine/watches/art) | 5 | 0 | 0 | 5 | Category mismatch: physical assets, not dark data (C1/scope); several post-collapse estates (C5); registries and warehouse records already the fix (C6) |
| Energy-market data integrity | 5 | 0 | 1 | 4 | C2/C1 (the abuses were forecasts, conduct, or data already streamed to the regulator — no sealed datum in the loop). Wounded sliver: sealed draft rulings until gazette publication |
| Defense / export-controlled technical data | 5 | 0 | 0 | 5 | C1 (technical data in live engineering use), C3 (standing production duty; anchoring controlled data to a public chain is off-limits), C6 (certified DRM vendors own the slot) |
| Marital / probate disclosure | 5 | 0 | 0 | 5 | C1 (disclosure exists to be read by the other side), C3 (full-and-frank-disclosure duties), C5 (some professional parties profit from disputes existing), C2 (court/consent triggers) |
| Ransomware negotiation / breach forensics | 5 | 0 | 0 | 5 | C1 (negotiation strategy must be read live), C2 (litigation triggers), C4 inverted (evidence holders *want* privileged control — the opposite of non-custody) |
| Private-secondary equity / cap-table / LP data | 4 | 0 | 0 | 4 | C1 (the data is the platform's live working set), C6 (the transfer-agent/registry regime owns title-of-record); fabricated-inputs fraud is garbage-in that no seal fixes |
| National-ID infrastructure | 1 | 0 | 0 | 1 | C1 (authentication data read live on every login; a perpetual flow with no discrete release trigger) |

---

## 4. Which conditions did the killing — the scissor in the data

The Fingerprint (§4–5) gives the ranked failure distribution and the structural finding; the segment table is where you can see it happen. The two blades sort the segments almost cleanly:

- **Blade A — crypto-native segments (objective triggers, no payer).** On-chain credit, DAO succession/inheritance, prediction markets, AI-agent rails, confidential compute: the triggers are genuinely machine-verifiable, and the rows die on **C6 and C5** — a trustless incumbent already owns the slot (multisig-plus-delay stacks, vesting/streaming protocols, FHE/MPC platforms such as Zama shipping conditional decryption as a commodity substrate) and the would-be buyers are thin-budget teams that build in-house.
- **Blade B — enterprise segments (payers, no objective trigger).** Genomics, healthcare, KYC, defense, clinical, marital/forensics, whistleblowing, journalism: the budgets are real, and the rows die on **C2, C1, and C3** — the release event is a human/legal/governance judgment, the data is read live, and a standing duty to produce makes self-disablement non-compliance.

Where the trigger is clean, the money isn't; where the money is, the trigger isn't. That negative correlation — visible segment by segment above — is why the zero is not bad luck, and why I concluded it could not be out-built.

The wounded slivers confirm the same pattern from the other side: every one of them sits where an objective trigger *already exists in the customer's world* — a database-lock date, a deed-recorded event, an embargo lift, an already-signed split, a liveness lapse, a pre-funded payment — and every one is a narrow partner-fit layer, never a head-on product (Fingerprint §6 describes the surviving shapes).

---

## 5. Rerunning this on your own market

The method is fully specified in [the Fundability Fingerprint](./fundability-fingerprint.md): six binary conditions (§1), a strict AND (§2), an adversarial population procedure (§3).

Build a broad candidate population including your favorite ideas, assign each to a devil's-advocate whose job is to kill it, and record the first failing condition. Then read the death distribution — not just the verdicts — as a map of your market's structure.

It costs an afternoon on paper. Run it before the build, not after.
