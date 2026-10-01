# Shred trigger (§11)

**Spec:** S2-6 §11
**Authority:** PDA-bound per `shred_authority_mode` (Subject / Joint / Operator / Timelock / Disabled).
**Governance path:** instant for Subject/Joint/Operator (per-PDA min latency); `timelock-7d-addition` for Timelock mode.
**Expected on-chain events:** `ShredRequested`, `ShredFinalized`.
**Failure modes:** `TRIPWIRE_BYPASS` (Disabled mode, mandatory guardrail violation, condition false), `QUORUM_MISSING` (Operator without legal basis), `TIMELOCK_NOT_EXPIRED` (challenge window incomplete or min latency not elapsed).

> §11.4 MANDATORY guardrail: every shred condition AND-composes `post_challenge_reveal_in_progress == false`. PDA+ guardrail; NOT partner-configurable. Check fires BEFORE the authority check so the tripwire is unbypassable.

> §11.5: `proof_shred` is a PUBLIC verification token, NOT σ / share / DEK / reveal authorization. Safe to surface in audit logs and partner-facing surfaces.

## Authority modes (§11.1 + §11.2)

| Mode | Trigger surface | Proof | M7 ceremony behavior |
|---|---|---|---|
| `Subject` | subject-authenticated request | σ_subject-equivalent action digest | runs straight through with min latency |
| `Joint` | subject + partner co-sign over same `authorizationId`, `h_commit`, reason | both sigs | runs straight through with min latency |
| `Operator` | Cealis operator action | PDA-defined legal basis digest + reason digest | requires `legal_basis_digest` non-null at construct; otherwise `QUORUM_MISSING` |
| `Timelock` | scheduled block/timestamp + condition truth | no discretionary signer | uses TIMELOCK_7D_ADDITION path |
| `Disabled` | — | — | rejected at proposal with `TRIPWIRE_BYPASS` |

## Prerequisites

- PDA's `shred_authority_mode` configured (per-PDA, frozen at onboarding per an internal design note, not in this export).
- Shred condition (Mode P predicate or Mode F FSM) evaluates true on ConditionEngine.
- ChallengeRegistry NOT in `post_challenge_reveal_in_progress == true` state — the mandatory guardrail.
- Challenge window completed (if non-zero on this PDA).
- Minimum shred latency elapsed since trigger.
- For Operator mode: PDA-bound legal-basis digest archived (CID), digest hashed into input.
- M5 vault API available (interface stub at M7 — production wiring at M8 wires `vaultClient.deleteCiphertext(hCommit)`).

## Step 1 — Proposal

Payload includes:
- `hCommit`
- `authorityMode`
- `authorityProof`
- `conditionEvaluatedTrue` (must be `true`)
- `postChallengeRevealInProgress` (must be `false`)
- `challengeWindowCompleted` (must be `true`)
- `minLatencyBlocksElapsed` (must be `true`)
- `reasonDigest`
- `legalBasisDigest` (Operator only; null otherwise)

The ceremony checks at proposal:
1. **Disabled mode** rejected immediately with `CEREMONY_ERR_TRIPWIRE_BYPASS`.
2. **§11.4 mandatory guardrail**: `postChallengeRevealInProgress === true` → `CEREMONY_ERR_TRIPWIRE_BYPASS`. Fires BEFORE step 3 so authority-correct requests cannot bypass it.
3. **Operator without `legalBasisDigest`** → `CEREMONY_ERR_QUORUM_MISSING`.

## Step 2 — Queue

Additional preconditions check at queue:
- `conditionEvaluatedTrue === true` (else `TRIPWIRE_BYPASS`)
- `challengeWindowCompleted === true` (else `TIMELOCK_NOT_EXPIRED`)
- `minLatencyBlocksElapsed === true` (else `TIMELOCK_NOT_EXPIRED`)

Emit `ShredRequested` on chain. Timelock delay is per-PDA min latency, NOT the standard 7-day path (except Timelock mode which uses 7d).

## Step 3 — Observation (per-PDA latency)

Per-PDA min latency window enforced on chain. No discretionary signing; if mode is `Subject` or `Joint`, the authority proof was bundled at trigger.

## Step 4 — Execute (§11.3 triple block)

The triple block:
1. **G1 refuses future reveal authorization** — ShredRegistry state on chain.
2. **G4 refuses σ_G4** — registry state mirrored to G4 via event listener (M8 wiring).
3. **Vault deletes ciphertext** — `vaultClient.deleteCiphertext(hCommit)` returns `{ deletionProof, timestampUnix }` (interface stub at M7).

`ShredFinalized` emitted on chain.

## Step 5 — Verify

- Both `ShredRequested` and `ShredFinalized` emitted.
- `proofShred` available via `ceremony.getProofShred()`.
- ShredRegistry `currentShredState(hCommit) === Finalized` on chain.
- Vault `exists(hCommit) === false` after deletion.

## Abort discipline (§20)

A failure leaves state unshredded (§20.2). The original `RevealAuthorized` / commitment / vault entries remain. Abort path records proposal hash, authority mode, failure reason. Queued op cancellable via `TimelockController.cancel(opId)` for Timelock mode; Subject/Joint/Operator/Disabled abort is immediate (no queue).

## §11.6 Shred-first lifecycle bias

For PDAs whose use case permits early erasure, shred fires as soon as retention windows close. Retention floors still apply:
- vault ciphertext + wrapped shares: obligation duration + 3 years unless PDA/legal posture permits earlier
- access logs, delivery logs, on-chain commitments: their own retention rules

## Cross-references

- WP §E.
- S2-2 §10 (ShredRegistry contract surface).
- S2-4 (shred guardrails on PDA+).
- internal legal-constraints rules (not exported) (retention table).
- internal shred-condition design note (not in this export).
