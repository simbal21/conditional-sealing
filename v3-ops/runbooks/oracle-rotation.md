# Oracle rotation (§7)

**Spec:** S2-6 §7
**Authority:** Registry admin + oracle vetter; TimelockController executes.
**On-chain role:** `REGISTRY_ADMIN_ROLE`.
**Governance path:** `timelock-7d-addition` (new entry) + tombstone (old entry).
**Expected on-chain events:** `OracleAdded`, `EntryTombstoned`.
**Failure modes:** schema replay failure, key compromise mid-flight, tombstone conflict, replacement not staged.

## Prerequisites

- Trigger reason recorded: signing-key rotation, schema change, operator reorganization, trust-tier change, compromise, deprecated oracle type, or operational SLA failure.
- New pubkey AND/OR new schema vetted off-chain. Replay tests on the queued schema against current PDA Claim expressions if schema is changing.
- `effective_block` and `tombstone_block_for_old` chosen (forward-looking only).
- Active and pre-authorization flows accounted for: a tombstone AFTER `RevealAuthorized` does NOT retroactively break the in-flight ceremony (§7.3).

## Step 1 — Proposal

Payload fields:
- `old_entry_ref`
- `new_oracle_id`
- `oracle_type_hash`
- `operator_pubkey_hash`
- `schema_hash`
- `valid_examples_hash` / `invalid_examples_hash`
- `metadata_hash`
- `trust_tier`
- `vetting_digest`
- `effective_block`
- `tombstone_block_for_old`

## Step 2 — Queue

`TimelockController.schedule(target=OracleRegistry, data=addEntry+tombstoneOldEntry, delay=7d)`.

## Step 3 — Observation (7 days)

Replay tests on new schema (if changing). Operator coordination on cutover. Watchdogs confirm the tombstone block is forward-looking (no historical erasure).

## Step 4 — Execute

`TimelockController.execute(...)`. Receipt emits `OracleAdded` (new entry) and `EntryTombstoned` (old entry).

## Step 5 — Verify

- New entry resolves at `getEntryAt(new_oracle_id, effective_block)`.
- Old pubkey/schema remain valid for commitments whose `commit_block` predates the tombstone — verified by historical lookup.
- No deprecation flag on the new entry.
- Schema migration: existing PDAs retain old schema semantics; new PDAs may bind the new schema after `effective_block`.

## Abort discipline (§20)

A failure between steps 1–4 leaves the old oracle entry as canonical. Cancel queued op via `TimelockController.cancel(opId)` if needed.

## Cross-references

- S2-2 §8.4, §8.8 (rotation contract surface).
- S2-1 §12.5 (at-commit-block verification).
- S2-4 §6.1, §6.2 (PDA binding to oracle).
- WP §F.
