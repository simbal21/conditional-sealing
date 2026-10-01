# DSL version update (§9)

**Spec:** S2-6 §9
**Authority:** Registry admin + upgrader (where contract deployed); TimelockController executes.
**On-chain role:** `REGISTRY_ADMIN_ROLE`, `UPGRADER_ROLE` (interpreter contract deploy).
**Governance path:** `timelock-7d-addition`.
**Expected on-chain events:** `EntryAdded`, `DSLVersionUsed`.
**Failure modes:** interpreter bytecode mismatch, cap-set unsafe, predicate nondeterminism, gas/time bound failure, backward-compatibility break.

> Existing PDAs continue evaluating under the DSL version bound in their `pda_root` and `commit_AAD`. A new interpreter CANNOT reinterpret old Claim ASTs unless the old PDA explicitly binds the new version through a future supported update ceremony.

## Prerequisites

- New interpreter contract deployed (testnet first). Bytecode hash recorded.
- AST version + cap-set hash + test vector digest + compatibility statement hash all prepared.
- Determinism evaluation passed: no nondeterministic operations introduced, gas/time bounds enforced.
- Backward-compatibility test: replay every Claim AST shape against the new interpreter using existing canonical test vectors; outputs must match the old interpreter's outputs.

## Step 1 — Proposal

Payload fields:
- `interpreter_bytecode_hash`
- `interpreter_contract_address`
- `ast_version`
- `cap_set_hash`
- `test_vector_digest`
- `compatibility_statement_hash`
- `metadata_hash`
- `effective_block`

## Step 2 — Queue

`TimelockController.schedule(target=DSLVersionRegistry, data=addEntry(...), delay=7d)`.

## Step 3 — Observation (7 days)

External auditors replay canonical Claim ASTs against the queued interpreter. Combiner SDK reviewers verify the new entry is referenced by the next plugin version's `min_combiner_sdk_version`.

## Step 4 — Execute

`TimelockController.execute(...)`. Receipt emits `EntryAdded` and the inaugural `DSLVersionUsed` event when the first new-binding PDA registers.

## Step 5 — Verify

- `getEntryAt(ast_version, current_block)` returns the new interpreter entry.
- Existing PDAs continue resolving their bound DSL version via `getEntryAt(..., old_pda_commit_block)`.
- No deprecation flag on the new entry.

## Abort discipline (§20)

A failure leaves the prior DSL version canonical. Cancel queued op via `TimelockController.cancel(opId)`.

## Cross-references

- S2-1 §12.4 (class-CATALOG rule for DSL registry).
- S2-2 §9.7 (DSLVersionRegistry contract surface).
- S2-4 §6.1, §6.6 (PDA binding to DSL).
