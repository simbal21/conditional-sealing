# Pause deactivation (§12)

**Spec:** S2-6 §12
**Authority:** Per-PDA `pause_authority_mode` (Partner / Joint).
**On-chain role:** `PAUSER_ROLE` scoped by PDA/config.
**Governance path:** instant.
**Expected on-chain events:** `PauseDeactivated`.
**Failure modes:** `QUORUM_MISSING` (None mode).

> Manual unpause, separate from §12.3 auto-lift. Resumes FSM advancement and new auth emissions.

## Prerequisites

- Active pause on the PDA.
- Authority matches `pause_authority_mode` (same authority that activated, or joint authority).
- Unpause reason digest archived off-chain.

## Step 1 — Proposal

Payload:
- `hCommit`
- `pauseAuthorityMode` (Partner / Joint)
- `pauseAuthorityId`
- `authorityProof`
- `unpauseReasonDigest`

`None` mode rejected at construct with `CEREMONY_ERR_QUORUM_MISSING`.

## Step 2 — Queue / Step 3 — Observation / Step 4 — Execute

Immediate (no timelock delay). `PauseDeactivated` emitted on chain.

## Step 5 — Verify

- `PauseDeactivated` observed.
- ConditionEngine pause state cleared.
- FSM advancement / new auth emissions resume per PDA config.
- Already-emitted historical events (e.g. `RevealAuthorized`) remain unchanged.

## Abort discipline

A failure leaves the pause active until auto-lift at `expiryBlock`.

## Cross-references

- WP P24.
- S2-2 §14.
