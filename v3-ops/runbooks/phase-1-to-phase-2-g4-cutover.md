# Phase 1 → Phase 2 G4 cutover (§15)

**Spec:** S2-6 §15 + §4.2.1
**Authority:** Registry admin proposes; TimelockController executes; §4.2.1 DCAP acceptance gate fires immediately before execute.
**On-chain role:** `REGISTRY_ADMIN_ROLE`.
**Governance path:** `timelock-7d-addition`.
**Expected on-chain events:** `EntryAdded` (Phase 2 G4 entry).
**Failure modes:** `TRIPWIRE_BYPASS` (DCAP gate failure), reproducibility mismatch, registry collision, timelock expiry, Phase 2 DCAP acceptance stale or ambiguous.

> M7 ships this as a runbook + dry-run only. Actual cutover is an operational decision triggered when partner signing/funding makes Phase 2 operationally available. Partner-ready and legal-effect PDAs MUST use Phase 2 (§15.4).

## §15.4 partner-ready guardrail (NORMATIVE)

Configurator and contract validation REJECT legal-effect or partner-ready commits under Phase 1. A Phase 1 dev commit that needs partner readiness MUST be recommitted under Phase 2 with fresh σ_subject over the new commit.

## Prerequisites

- Phase 2 G4 authority key prepared (TEE measurement, DCAP verifier ref, vendor family classification).
- §4.2.1 DCAP acceptance packet pre-prepared with: `g4AuthorityRef`, `phase=2`, `authorityPubkey`, `teeMeasurement`, `dcapVerifierRef`, `effectiveBlock`, `metadataHash`, admission-authoritative mode (`snark-backed` OR `on-chain-verifier`), accepted TCB statuses, vendor-family classification (unambiguous), `litG4DisjointnessVerified` = true, collateral freshness ≤24h.
- Phase 1 historical-verification policy hash drafted (§15.3).
- §15.5 announcement metadata prepared: effective block, Phase 2 authority ref, Phase 1 historical-verification policy.

## Step 1 — Proposal

Payload fields:
- `newPhase2AuthorityRef`
- `authorityPubkey`
- `teeMeasurement`
- `dcapVerifierRef`
- `dcapAcceptancePacket` (full §4.2.1 structure)
- `metadataHash`
- `cutoverEffectiveBlock`
- `phase1HistoricalPolicyHash`

## Step 2 — Queue

`TimelockController.schedule(target=G4AuthorityRegistry, data=addEntry(phase=2, ...), delay=7d)`.

## Step 3 — Observation (7 days)

External auditors verify:
- TEE attestation chain,
- DCAP verifier config,
- vendor-family disjointness from Lit (cross-vendor),
- accepted TCB statuses are still acceptable.

If TCB or collateral aged during the 7-day window, re-issue the acceptance packet immediately before execute.

## Step 4 — Execute (DCAP gate FIRST)

The §4.2.1 DCAP acceptance gate fires before `TimelockController.execute(...)`. Any of the following → `CEREMONY_ERR_TRIPWIRE_BYPASS` and abort:
- `g4_authority_ref` mismatch with proposal
- `phase !== 2`
- admission-authoritative mode not in `{snark-backed, on-chain-verifier}`
- vendor-family classification empty or `ambiguous`
- `litG4DisjointnessVerified === false`
- accepted TCB statuses empty
- collateral freshness > 24h before `block.timestamp`

Gate passes → `TimelockController.execute(...)`. Receipt emits `EntryAdded` for the Phase 2 G4 entry.

## Step 5 — Verify

- `getEntryAt(newPhase2AuthorityRef, cutoverEffectiveBlock)` returns the Phase 2 entry with `phase=2`.
- §15.3: Phase 1 entries remain valid for Phase 1 dev commits AFTER cutover. They are NOT upgraded into legal-effect Phase 2 commits.
- §15.4 partner-ready guardrail active in the configurator: legal-effect / partner-ready commits under Phase 1 rejected (Phase F integration test enforces).
- §15.5 announcement published with `effectiveBlock`, Phase 2 authority ref, Phase 1 historical-verification policy.
- S2-5 verification API surface exposes metadata sufficient for clients to distinguish Phase 1 vs Phase 2 artefacts.

## Abort discipline (§20)

A failure leaves Phase 1 canonical. Phase 1 dev commits remain verifiable; Phase 2-bound commits cannot be recommitted until a successful cutover. Queued op cancellable via `TimelockController.cancel(opId)`.

## Cross-references

- WP §N (Phase 1 to Phase 2 discipline).
- S2-1 §9 (σ_G4 construction).
- S2-2 §18.4 (G4 authority update event surface).
- S2-3 §7.5 (G4 adapter Phase 1 vs Phase 2).
