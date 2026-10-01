# ChallengeRegistry pause/resolution (§12.7)

**Spec:** S2-6 §12.7
**Authority:** PDA-scoped `CHALLENGE_RESOLVER_ROLE`. Cannot act outside its PDA scope.
**Governance path:** instant per-PDA (no 7-day delay).
**Expected on-chain events:** `ChallengeResolved` (confirm/halt) OR `ChallengeExtended` (extend). Intake-side events `ChallengeOpened` and `ChallengeWithdrawn` are NOT resolver actions.
**Failure modes:** `TRIPWIRE_BYPASS` (invalid resolver action, missing `resolverActionRef`, extension > 90 days).

> Halt-only. The resolver CANNOT alter reveal content, emit release, force G4 to sign, delete state, or bypass refusal.

## Three resolver actions (§12.7)

| Action | Result | Effect |
|---|---|---|
| `confirmNoIntervention` | sets `ConfirmedNoIntervention` | only allows gate signing through normal `canGatesSign` path |
| `haltCeremony` | sets `Halted` | MUST route through G4 refusal/artifact path; does NOT erase `RevealAuthorized` |
| `extendChallenge` | bounded extension | for legal or G4 evidence collection only; MUST respect extension caps + 90-day pause/freeze ceiling for the registry surface lifetime |

`resolverActionRef` (hash/CID) is MANDATORY on all three actions per §12.7.

## Four event surface (§12.7)

- `ChallengeOpened` — intake-side, NOT a resolver action.
- `ChallengeResolved` — resolver emits for `confirmNoIntervention` AND `haltCeremony`.
- `ChallengeExtended` — resolver emits for `extendChallenge`.
- `ChallengeWithdrawn` — intake-side withdrawal, NOT a resolver action.

## Prerequisites

- Open challenge with `challengeId` in ChallengeRegistry.
- Resolver holds `CHALLENGE_RESOLVER_ROLE` scoped to the PDA in question.
- `resolverActionRef` artefact archived off-chain (counsel evidence, partner counter-attestation, etc.).
- For `extendChallenge`: extension duration ≤ 90 days × 24 × 60 × 60 seconds; current registry-surface ceiling not yet hit.

## Step 1 — Proposal

Payload:
- `challengeId`
- `resolverAction` (one of the three)
- `resolverActionRef` (mandatory)
- `hCommit`
- `pdaScope`
- `extensionSeconds` (extendChallenge only; null otherwise)

Construct-time validation:
- Invalid `resolverAction` → `CEREMONY_ERR_TRIPWIRE_BYPASS`.
- Empty `resolverActionRef` → `CEREMONY_ERR_TRIPWIRE_BYPASS`.
- `extendChallenge` with `extensionSeconds <= 0` or `> 90d` → `CEREMONY_ERR_TRIPWIRE_BYPASS`.

## Step 2 — Queue / Step 3 — Observation / Step 4 — Execute

Immediate (no timelock delay). Emit `ChallengeResolved` for confirm/halt OR `ChallengeExtended` for extend.

## Step 5 — Verify

- Expected event emitted (`ChallengeResolved` or `ChallengeExtended`).
- **Halt-only invariant check**: `RevealAuthorized` MUST NOT appear in the audit log for this ceremony. If it does, the ceremony aborts with `CEREMONY_ERR_TRIPWIRE_BYPASS` — this means the resolution path leaked into a release event, which is forbidden by §12.7.

## Abort discipline

A failure leaves the challenge in its prior state. Counsel evidence not consumed. `resolverActionRef` artefact remains archived for re-attempt.

## S3-1 ownership (off-chain)

S3-1 owns:
- resolver evidence packets,
- counter-attestation review,
- bond workflow,
- G4 refusal coordination,
- timer tracking,
- partner/recipient notices.

S2-6 fixes that challenge resolution CANNOT become a hidden reveal approval or deletion path.

## Cross-references

- WP §N (G4 refusal path coordination).
- S2-2 (ChallengeRegistry interface + role surfaces).
- legal Art. 18 90-day freeze constraints.
