# G4 authority key rotation (§4)

**Spec:** S2-6 §4 + §4.2.1
**Authority:** Registry admin proposes; TimelockController executes. Phase 2 requires a DCAP acceptance gate immediately before execution.
**On-chain role:** `REGISTRY_ADMIN_ROLE`.
**Governance path:** `timelock-7d-addition` for additions; emergency deprecation paths apply separately.
**Expected on-chain events:** `EntryAdded`, `EntryTombstoned` (old entry).
**Failure modes:** unauthorized actor, registry collision, timelock expiry, tombstone conflict, Phase 2 DCAP acceptance stale or ambiguous, `TRIPWIRE_BYPASS` on the §4.2.1 gate.

> This rotates σ_G4-producing authority. It does NOT rotate DEK. σ-as-authorization invariant holds.

## Prerequisites

- New authority pubkey OR TEE measurement (Phase 2).
- For Phase 2: full DCAP acceptance packet (§4.2.1).
- `effective_block` AND `tombstone_block` for the old entry (forward-looking only — historical commits keep using the old entry per §4.6).
- Vendor-family classification unambiguous (Phase 2). Ambiguous = fail-closed, abort proposal.
- Lit/G4 cross-vendor disjointness verified (Phase 2).

## Step 1 — Proposal

Build the proposal packet:
- `phase` (1 or 2)
- `g4_authority_ref`
- `authority_pubkey`
- `tee_measurement` (Phase 2 only)
- `dcap_verifier_ref` (Phase 2 only)
- `metadata_hash`
- `effective_block`
- `tombstone_block_for_old`
- `old_entry_ref`

Compute deterministic proposal hash.

## Step 2 — Queue

`TimelockController.schedule(...)` with 7-day delay.

## Step 3 — Observation (7 days)

Security review of identity, hardware attestation chain, TCB freshness, and (Phase 2) DCAP verifier config. If TCB or collateral aged out during the 7-day window, re-issue the acceptance packet immediately before execute.

## Step 4 — Execute (Phase 2 only: DCAP gate FIRST)

For Phase 2 rotations, the ceremony's `preExecuteHook` enforces:
- `g4_authority_ref` matches the proposal,
- `phase === 2`,
- `tee_measurement` non-null,
- `dcap_verifier_ref` non-null,
- admission-authoritative mode is `snark-backed` OR `on-chain-verifier`,
- vendor-family classification is NOT empty AND NOT `ambiguous` (fail-closed),
- Lit/G4 cross-vendor disjointness verified (`true`),
- accepted TCB statuses list non-empty,
- collateral freshness within 24h of `block.timestamp`.

Any failure → `CEREMONY_ERR_TRIPWIRE_BYPASS` raised; execute aborts.

After the gate passes, submit `TimelockController.execute(...)`. Receipt emits `EntryAdded` for the new entry AND `EntryTombstoned` for the old entry (single tx executes both effects).

## Step 5 — Verify

- New entry resolves at `getEntryAt(new_g4_authority_ref, current_block)`.
- Old entry resolves at `getEntryAt(old_entry_ref, commit_block_pre_tombstone)`; same call AT or AFTER `tombstone_block` MUST fail with `TOMBSTONE_CONFLICT` (verified by reading historical commits).
- Deprecation flag NOT set on the new entry.
- Combiner verification reads `G4AuthorityRegistry` at `commit_block`; a current key cannot validate an old commit unless that key was effective at the commit's block.

## Abort discipline (§20)

If the DCAP gate fails: no state change. The old entry remains canonical. Log the proposal hash, packet digest, failure reason, and block context. Re-run requires correcting the packet (which means a new ceremony or new commit per §20.2).

## Phase 1 → Phase 2 cutover (§15)

Separate `phase-1-to-phase-2-g4-cutover` runbook. The cutover is registered as a Phase 2 G4 authority rotation through this ceremony (via the §15 runbook) with the §4.2.1 acceptance gate active. Phase 1 entries remain valid for Phase 1 dev commits after cutover; they are NOT upgraded into legal-effect Phase 2 commits.

## Cross-references

- S2-1 §12.3 (G4AuthorityRegistry verification), §11 (endpoint attestation), §9 (σ_G4 construction).
- S2-2 §9.6 (contract entry shape), §18.4 (events).
- S2-3 §7.5 (G4 adapter Phase 1 vs Phase 2).
- WP §N (Phase 1 to Phase 2 discipline).
