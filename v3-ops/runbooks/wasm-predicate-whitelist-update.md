# WASM predicate whitelist update (§10)

**Spec:** S2-6 §10
**Authority:** PDA+ governance admin; TimelockController executes.
**On-chain role:** PDA+ governance admin, granted by TimelockController.
**Governance path:** `timelock-7d-addition` (sub-class 1 of §10A).
**Expected on-chain events:** `EntryAdded`.
**Failure modes:** binary hash mismatch, audit digest missing, simulation vector mismatch, gas/time bound failure, predicate nondeterminism.

> Selected predicate binary hashes are bound in `wasm_predicate_hashes_root` inside `pda_root`. Historical PDAs keep their bound hashes — a later whitelist update DOES NOT rewrite existing roots. Gas/time cap changes are sub-class 4; adding new predicate class rules is sub-class 5 (codepath-bound, design-locked).

## Prerequisites

- Audited WASM binary, reproducibly built. Binary hash recorded.
- Source commit digest, audit digest, simulation vector hash.
- Gas/time bounds (`gas_bound`, `time_bound_ms`).
- Allowed input schema ref (deterministic).
- Affected PDA template classes documented.

## Step 1 — Proposal

Payload fields:
- `predicate_binary_hash`
- `source_commit_digest`
- `audit_digest`
- `simulation_vector_hash`
- `gas_bound`
- `time_bound_ms`
- `allowed_input_schema_ref`
- `metadata_hash`
- `effective_block`

## Step 2 — Queue

`TimelockController.schedule(...)` per §10A.2 sub-class 1 timelocked addition.

## Step 3 — Observation (7 days)

Partners run simulation vectors against the candidate predicate. Watchdogs verify gas/time bounds are honored.

## Step 4 — Execute

`TimelockController.execute(...)`. Receipt emits `EntryAdded`. Future-emitted PDAs may bind this predicate hash in `wasm_predicate_hashes_root`.

## Step 5 — Verify

- `getEntryAt(predicate_binary_hash, current_block)` returns the new entry.
- Existing `pda_root` values remain historically valid (their bound hashes resolve to the originally-effective predicate entry).
- No deprecation flag on the new entry.

## Abort discipline (§20)

A failure leaves the prior whitelist canonical. Existing PDAs unaffected. Cancel queued op via `TimelockController.cancel(opId)`.

## Cross-references

- S2-4 §6 + §9.3 (PDA+ governance + WASM whitelist).
- Stage-0 Q-0-5.
- S2-2 (ClaimDSL + DSLVersionRegistry adjacency).
- S2-1 (`pda_root` construction).
