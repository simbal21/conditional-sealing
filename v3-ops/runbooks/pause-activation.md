# Pause activation (§12)

**Spec:** S2-6 §12 + §12.2 + §12.3 + §12.4
**Authority:** Per-PDA `pause_authority_mode` (Partner / Joint / None).
**On-chain role:** `PAUSER_ROLE` scoped by PDA/config.
**Governance path:** `instant-non-canonical-deprecation` (per-PDA, no 7-day delay).
**Expected on-chain events:** `PauseActivated`.
**Failure modes:** `QUORUM_MISSING` (None mode rejected), `TRIPWIRE_BYPASS` (duration ≤0 or > 90 days).

> Pause is reversible and bounded. It NEVER deletes ciphertext, destroys keys, grants release, alters reveal content, or resets historical state. §12.3 auto-lift cap: duration ≤ 90 days. Extension is a new pause action subject to the same cap.

## Authority modes (§12.2)

- `Partner` — partner or configured partner operator may request bounded pause.
- `Joint` — requires configured joint authority set.
- `None` — discretionary pause DISABLED for this PDA (rejected at construct with `QUORUM_MISSING`). Registry-level emergency halts governed elsewhere (sub-class 3 emergency circuit breaker).

## Prerequisites

- PDA `pause_authority_mode` is Partner or Joint.
- Authority proof prepared (per-mode signature).
- Reason digest archived off-chain; reason text or digest/encrypted, no sensitive refusal text.
- Duration ≤ 90 days (90 * 24 * 60 * 60 seconds).

## Step 1 — Proposal

Payload:
- `hCommit`
- `pauseAuthorityMode` (Partner / Joint)
- `pauseAuthorityId`
- `authorityProof`
- `reasonDigest`
- `durationSeconds` (0 < x ≤ 90 days)

Construct-time validation:
- `pauseAuthorityMode === None` → `CEREMONY_ERR_QUORUM_MISSING`.
- `durationSeconds <= 0 || durationSeconds > MAX_PAUSE_SECONDS` → `CEREMONY_ERR_TRIPWIRE_BYPASS`.

## Step 2 — Queue

No timelock delay; pause is immediate per §12.2. Emit `PauseActivated` on `TimelockController.execute` (delay 0).

## Step 3 — Observation

— skipped (immediate).

## Step 4 — Execute

`PauseActivated` emitted on chain with `pauseAuthorityMode`, `pauseAuthorityId`, `reasonDigest`, `startBlock`, `expiryBlock`.

## Step 5 — Verify

- `PauseActivated` observed.
- Pause state visible on ConditionEngine; FSM advancement / new auth blocked per PDA config.
- No `RevealAuthorized` event can be emitted while paused; `RevealAuthorized` events ALREADY emitted remain part of chain-of-custody.
- G4 cannot be forced to sign by the pause.

## Abort discipline

A failed pause request leaves the system unpaused. Authority error / invalid duration / mode mismatch all fail before any on-chain state change.

## Auto-lift (§12.3)

Pause auto-lifts at `expiryBlock`. Any extension is a NEW pause activation subject to the same 90-day cap and same authority.

## Cross-references

- WP P24.
- S2-2 §14 (pause/halt contract surface).
- legal Art. 18 90-day freeze constraints (internal legal-constraints rules (not exported)).
