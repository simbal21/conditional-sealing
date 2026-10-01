# Oracle onboarding (§6)

**Spec:** S2-6 §6
**Authority:** Registry admin + oracle vetter; TimelockController executes.
**On-chain role:** `REGISTRY_ADMIN_ROLE`; `ORACLE_SUBMITTER_ROLE` granted after registry entries are effective.
**Governance path:** `timelock-7d-addition`.
**Expected on-chain events:** `OracleAdded`, `OracleSchemaAdded`.
**Failure modes:** schema replay failure, operator vetting failure, trust-tier mismatch, examples hash mismatch, submitter role missing or over-scoped, tombstone conflict.

> No PDA may bind the oracle until BOTH OracleRegistry and OracleSchemaRegistry entries are effective. `ORACLE_SUBMITTER_ROLE` grants are scoped to a specific oracle id and PDA scope; over-broad scope is a failure mode.

## Prerequisites

- Operator publishes: signing pubkey OR contract address, oracle type, schema hash, valid example set hash, invalid example set hash, metadata hash, operational contact hash, trust-tier proposal, uptime/reputation evidence, intended PDA template classes.
- Cealis off-chain vetting completes: identity, operating history, legal basis, jurisdiction, trust tier, schema determinism, canonical examples, replay tests against Claim expressions, key custody posture, monitoring endpoint, deprecation contact path.
- Vetting digest archived (CID) and included in proposal metadata.
- Submitter set named in same proposal if oracle path requires on-chain attestation submission.

## Step 1 — Proposal

Payload fields:
- `oracle_id`
- `oracle_type_hash`
- `operator_pubkey_hash`
- `schema_hash`
- `valid_examples_hash` / `invalid_examples_hash`
- `metadata_hash`
- `operator_contact_hash`
- `trust_tier`
- `uptime_reputation_hash`
- `vetting_digest`
- `submitter_role_scope` (or null)
- `effective_block`

Compute deterministic proposal hash. Queue includes BOTH OracleRegistry and OracleSchemaRegistry entries.

## Step 2 — Queue

`TimelockController.schedule(...)`.

## Step 3 — Observation (7 days)

Recipients run replay tests of the queued schema against canonical valid + invalid example sets. Watchdogs confirm submitter scope matches the oracle id and PDA template classes.

## Step 4 — Execute

`TimelockController.execute(...)`. Receipt emits `OracleAdded` and `OracleSchemaAdded`. Submitter role grant follows via TimelockController or the OracleRegistry-governed role path AFTER both entries are effective.

## Step 5 — Verify

- `getEntryAt(oracle_id, current_block)` returns the new entry with the expected `effective_block`.
- `getEntrySchemaAt(schema_id, current_block)` returns the matching schema.
- Submitter is authorized only for the queued oracle id and PDA scope.
- No deprecation flag on the new entries.

## First-oracle launch (§6.7)

Launch set is **Chainlink Automation for time** + **SubjectInitiated self-oracle**. These are normal registry entries, NOT hardcoded paths:
- Chainlink time uses a schema covering valid timestamp reach, stale timestamp, wrong chain id, replayed automation report, out-of-window report.
- SubjectInitiated uses a schema covering valid subject action digest, wrong `authorizationId`, stale nonce, wrong ceremony axis, authenticator mismatch.
- Chain-native block timestamp TimeLock can remain Tier A without oracle signature; SubjectInitiated verifies through subject-authenticator path.

Both publish valid + invalid example set hashes BEFORE the 7-day queue. `ORACLE_SUBMITTER_ROLE` is scoped to the specific oracle id and launch PDA classes.

## Abort discipline (§20)

A failure between steps 1–4 leaves the oracle un-onboarded. The abort path records proposal hash, vetting digest, failure reason code, block context. Cancellable queued op via `TimelockController.cancel(opId)`.

## Disaster path (§14.5)

Compromised oracle: `setDeprecationFlag(...)` per asymmetric governance (24h canonical-in-use OR 0h non-canonical). Pending and pre-authorization flows halt. Replacement uses this §6 standard 7-day onboarding.

## Cross-references

- S2-2 §8 (OracleRegistry contract surface).
- S2-1 §12.5 (oracle registry verification at commit_block).
- S2-4 §6.1 (PDA template binding to oracle).
- Stage-0 Q-0-8 (launch oracle set lock).
- WP §F (oracle discipline).
