# PDA+ governance update (§10A)

**Spec:** S2-6 §10A
**Authority:** depends on sub-class (see table).
**Governance path:** depends on sub-class.
**Failure modes:** `DEPRECATION_DISCLOSURE_MISSING` (sub-class 2 without disclosure), `TRIPWIRE_BYPASS` (sub-class 3 with invalid emergency bounds).

> §10A.4 halt-only invariant: emergency circuit breaker cannot grant reveal, change recipients, alter `pda_root`, delete ciphertext, or bypass `post_challenge_reveal_in_progress == false`.

## Sub-class table

| Sub-class | Authority | Role | Delay | Output |
|---|---|---|---|---|
| 1 — TimelockController-7d additions | Cealis operator + TimelockController | `REGISTRY_ADMIN_ROLE` or PDA+ governance admin | 7 days | `EntryAdded` |
| 2 — CealisSecurityMultisig deprecations | CealisSecurityMultisig | `SECURITY_COUNCIL_ROLE` | 0h non-canonical / 24h canonical-in-use | `DeprecationFlagSet`, `DisclosurePublished` |
| 3 — Emergency circuit breaker | CealisSecurityMultisig + EmergencyGovernance | `SECURITY_COUNCIL_ROLE`, `EMERGENCY_GOVERNANCE_ROLE` | bounded (≤30 days) | `SecurityCouncilSuspended` |
| 4 — Constraint adjustment | Cealis operator + TimelockController | PDA+ governance admin | 7 days | `EntryAdded` |
| 5 — Rule addition (codepath-bound) | Cealis operator + code owner | `UPGRADER_ROLE` if code changes; PDA+ governance admin | 7 days after evidence lock | `EntryAdded`, `RoleGranted` |

## Sub-class 1 — Timelocked addition

Expands platform capacity without altering historical PDA semantics. Proposal lists added content-addressed artefact, affected archetypes, validation stage, source/audit/test digests, effective block, partner inspection rendering. Mutates only future-eligible PDA+ allow-lists or registry entries; existing `pda_root` and `pda_version` remain historically valid.

## Sub-class 2 — Deprecation

Deprecates an existing PDA+ or registry entry through asymmetric DeprecationFlag discipline:
- Non-canonical entries deprecate instantly.
- Canonical-in-use entries use 24h expedited delay + disclosure hash/CID + 72h permissionless auto-clear if disclosure missing + 30-day cooldown before same-entry re-deprecation without TimelockController.

Proposal MUST include `disclosure_cid` AND `disclosure_commit_hash`. Missing either → `CEREMONY_ERR_DEPRECATION_DISCLOSURE_MISSING` at construct time.

## Sub-class 3 — Emergency circuit breaker

Halt-only, bounded duration. Covers class-wide safety failures, suspected Security Multisig compromise, or emergency disablement of an unsafe PDA+ surface. EmergencyGovernance may suspend Security Multisig deprecation authority for the bounded duration.

Proposal MUST include `emergency_duration_seconds` (>0, ≤30 days) AND `emergency_scope_hash`. Invalid bounds → `CEREMONY_ERR_TRIPWIRE_BYPASS` at construct time.

Halt-only constraint: emergency circuit breaker CANNOT
- grant reveal
- change recipients
- alter `pda_root`
- delete ciphertext
- bypass `post_challenge_reveal_in_progress == false`.

## Sub-class 4 — Constraint adjustment

Changes data inside an existing cross-field validator rule WITHOUT changing the validator code shape. Required proposal packet: parameter diff, compatibility check, simulation vector digest, impacted default-table diff, affected archetypes, effective block.

7-day timelock. Executes only if the existing validator still accepts historical PDAs under their original `pda_root` while applying the new bound to future PDA emissions.

## Sub-class 5 — Rule addition

Codepath-bound. Requires design lock, source/code release, test evidence, simulation vectors, partner-inspection rendering update, activation block, and author-lock review for S2-1/S2-2 impact. Does NOT require a `commit_version` bump UNLESS the new rule changes byte layout, commit semantics, cryptographic construction, or historical verification.

Rollout is staged through TimelockController. MUST include rollback/disable semantics before first activation.

## Step-by-step (all sub-classes)

1. **Proposal** — payload includes sub-class, `addedContentRef`, `affectedArchetypes`, `templateId`, `defaultRowHash`, `diffHash`, `auditDigest`, `testDigest`, `simulationVectorHash`, `inspectionRenderingHash`, `authorLockReviewHash`, `metadataHash`, `effectiveBlock` + sub-class-specific fields.
2. **Queue** — via TimelockController (sub-classes 1, 4, 5) OR CealisSecurityMultisig Safe execTransaction (2, 3).
3. **Observation** — partner inspection rendering published. Affected archetype notice circulated.
4. **Execute** — depends on sub-class:
   - 1: `TimelockController.execute(...)` emits `EntryAdded`.
   - 2: Safe execTransaction emits `DeprecationFlagSet` + `DisclosurePublished`.
   - 3: Safe execTransaction emits `SecurityCouncilSuspended`; restoration is a separate Safe call.
   - 4: `TimelockController.execute(...)` emits `EntryAdded`.
   - 5: Code release + `TimelockController.execute(...)` emits `EntryAdded` + `RoleGranted` (if upgrader role granted).
5. **Verify** — partner inspection output shows the new row, deprecated row, or emergency scope. No tripwire bypass.

## Abort discipline (§20)

A failure leaves the prior PDA+ state canonical. Partner inspection output reflects the abort. Queued op cancellable via `TimelockController.cancel(opId)` for sub-classes 1/4/5. Safe-multisig proposals fail closed (signatures not collected → no execution).

## Cross-references

- S2-4 §6.1-§6.7, §14.3 (PDA+ governance sub-class boundary decisions).
- S2-5 (partner inspection output surface).
- S2-2 (registry / upgrader role surfaces).
- S3-1 (PDA+ governance runbooks for partner notification).
