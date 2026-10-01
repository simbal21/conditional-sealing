# QTSP signing-root rotation (§7A)

**Spec:** S2-6 §7A.3
**Authority:** Registry admin + counsel/commercial vetter; TimelockController executes.
**On-chain role:** `REGISTRY_ADMIN_ROLE`.
**Governance path:** `timelock-7d-addition` + tombstone old entry.
**Expected on-chain events:** `EntryAdded`, `EntryTombstoned`.
**Failure modes:** counsel/commercial vetting missing, eIDAS status evidence stale, root hash mismatch, tombstone conflict.

> Historical QES-bound σ_subject signatures verify against QTSPRegistry state at `commit_block`; a later root rotation, Trusted List removal, or tombstone CANNOT retroactively degrade a commit that was QES-valid at signing time.

## Prerequisites

- Counsel-reviewed root rotation: new root pubkey hash, fresh eIDAS evidence, current Trusted List membership.
- `effective_block` and `tombstone_block_for_old`.
- Subject migration path documented (existing subjects keep old root validity for their historical commits).

## Step 1 — Proposal

Payload fields:
- `old_entry_ref`
- `qtsp_provider_ref`
- `qtsp_root_pubkey_hash` (new)
- `trust_list_evidence_hash` (fresh)
- `e_idas_status_url_hash` (fresh)
- `metadata_hash`
- `counsel_review_digest`
- `effective_block`
- `tombstone_block_for_old`

## Step 2 — Queue

`TimelockController.schedule(target=QTSPRegistry, data=addEntry+tombstoneOldEntry, delay=7d)`.

## Step 3 — Observation (7 days)

Counsel re-verifies new root + Trusted List membership. Partner archetype admin reviews allow-list continuity (no archetypes silently dropped).

## Step 4 — Execute

`TimelockController.execute(...)`. Receipt emits `EntryAdded` (new entry) and `EntryTombstoned` (old entry).

## Step 5 — Verify

- New entry resolves at `getEntryAt(qtsp_provider_ref, effective_block)`.
- Old root remains valid for historical commits — `getEntryAt(old_entry_ref, commit_block_pre_tombstone)` returns the old root.
- `getEntryAt(old_entry_ref, current_block)` AT or AFTER tombstone fails with `TOMBSTONE_CONFLICT`.
- No deprecation flag on the new entry.

## Abort discipline (§20)

A failure leaves the existing root canonical. Cancel queued op via `TimelockController.cancel(opId)`. Historical QES signatures unaffected either way.

## Cross-references

- S2-1 §5.5, §12.7.
- S2-2 §9.9, §9.15.
- WP §K, §N.
