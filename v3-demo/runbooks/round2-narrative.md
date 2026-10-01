# Round 2 — Shred → G1 Chain-Block (Absence-of-Event)

**Round 2 demonstrates that no release path exists once a subject has
exercised right-to-erasure.** The crypto-enforced halt happens at the G1
chain emit layer: after `ShredFinalized`, the on-chain `ConditionEngine`
REFUSES to emit `RevealAuthorized` — verified by ABSENCE-OF-EVENT, not by
event-then-negation. The combiner is NEVER invoked.

This round is the executable form of the internal rulebook's universal tripwire:

> *No release path exists that bypasses the on-chain-verified predefined
> condition.*

## Axis

Subject-initiated right-to-erasure CRYPTO-ENFORCED at G1 chain emit layer.

| Concern | How Round 2 enforces it |
|---|---|
| Subject's GDPR Art. 17 right | Subject signs a passkey assertion; M7 `ShredTriggerCeremony` accepts authority mode `Subject` |
| Chain refusal to emit | After `ShredFinalized`, `ConditionEngine.evaluate(authorizationId)` may revert OR may execute and skip emission per S2-2 §10.4 #1 + §12.5 #4 — either way, no `RevealAuthorized` for this hCommit |
| Vault deletion | M7 ceremony's `execute()` stage calls `vaultClient.deleteCiphertext(hCommit)`; `vault.exists(hCommit)` returns `false` after |
| G4 future refusal | G4 Phase 1 mock state shifts to `isShredded(hCommit) === true`; any future σ_G4 request for this hCommit would fail-closed |
| Combiner blast radius | The combiner is NEVER REACHED. Spy count stays at 0 |

## Normative Success Criterion

```
assertNoEventInRange("RevealAuthorized", shredBlock, latestBlock, { hCommit })
```

Zero matching events MUST be observed in the block range from the shred
block onward. Throws `DEMO_ERR_UNEXPECTED_EVENT` on any violation.

This is the entire success criterion for Round 2.

## Flow

| Step | Action | Verification |
|---|---|---|
| 1 | M5 ingest produces (authorizationId, hCommit) for fresh subjectId | response 201, capture identifiers |
| 2 | T+12h: subject signs passkey shred request | `ShredTriggerCeremony({authorityMode: Subject})` |
| 3 | Ceremony emits `ShredRequested` → `ShredFinalized` | `chainState.shredRequestedEmitted && chainState.shredFinalizedEmitted` |
| 4 | Vault ciphertext deleted | `vault.exists(hCommit) === false` |
| 5 | G4 Phase 1 mock marks subject shredded | `g4Phase1Mock.isShredded(hCommit) === true` |
| 6 | T+24h: TimeLock predicate evaluates true on-chain | `ConditionEngine.evaluate(authorizationId)` may revert or skip |
| 7 | **NORMATIVE:** `assertNoEventInRange("RevealAuthorized", shredBlock, latestBlock, {hCommit})` | Zero matching events |
| 8 | Combiner NEVER invoked | `combinerSpy.invocationCount === 0` |
| 9 | Repeatability cleanup | vault rows = 0, BullMQ pending = 0, on-chain state = `Shredded` (terminal) |

## How to Run

```bash
# CI dry-run (no infra required)
DEMO_MODE=ci-anvil pnpm exec demo round2

# Live mode against Base Sepolia (testnet only; deployed bytecode may lag/diverge
# from this source snapshot — see deployments/README.md)
DEMO_MODE=live-base-sepolia \
  BASE_SEPOLIA_RPC_URL=https://... \
  CONDITION_ENGINE_ADDRESS=0x... \
  SHRED_REGISTRY_ADDRESS=0x... \
  pnpm exec demo round2
```

## What Could Go Wrong

**Symptom: `DEMO_ERR_UNEXPECTED_EVENT` thrown.**
A `RevealAuthorized` event fired for the shredded hCommit. This is a S2-2
§12.5 #4 violation — the chain emitted a reveal authorization after the
shred was finalized. Causes to investigate:

1. **Race: `RevealAuthorized` emitted in the same block as `ShredFinalized`.**
   S2-2 §10.4 + §12.5 #4 mandates that ConditionEngine reads ShredRegistry
   state BEFORE emitting. If a block reorder or ordering bug causes the
   ConditionEngine to read stale shred state, this can fire. Look for
   ConditionEngine.evaluate calls that don't re-check the ShredRegistry.
2. **ShredRegistry state-write missing in the same tx as ShredFinalized.**
   The shred-trigger ceremony writes the `Shredded` terminal state atomically
   with emitting `ShredFinalized`. If the write is split across txs, an
   intervening reveal-authorization tx could slip through.
3. **The mandatory PDA+ guardrail `NOT post_challenge_reveal_in_progress`
   was bypassed.** Per S2-6 §11.4, the guardrail fires BEFORE the authority
   check. If a custom PDA configuration disables this guardrail, a shred
   request during a post-challenge reveal could land mid-flight.

**Symptom: combiner spy count > 0.**
The combiner facade was called. This implies either (a) a phantom
`RevealAuthorized` event slipped past the chain refusal (see above), or
(b) round code accidentally invoked `combineAndDecrypt` in a code path it
shouldn't have reached. Round 2's flow MUST NOT touch the combiner.

**Symptom: vault.exists(hCommit) === true after run.**
The vault delete didn't happen. Either the M7 ceremony's `execute()` stage
threw before calling `vaultClient.deleteCiphertext`, OR the vault client
silently swallowed the request. Inspect ceremony stagesReached: if `execute`
is present but `vault.exists` is still true, the issue is at the vault
adapter; if `execute` is absent, the issue is upstream in the ceremony
proposal/queue stages.

## Defensive Tests Layered on Top

- `round2-shred-absence-of-event.test.ts` — Step 7 normative assertion.
- `round2-shred-triple-block-axes.test.ts` — all 3 axes per S2-2 §10.4 + S2-6 §11.3.
- `round2-vault-delete-before-sd-revoc.test.ts` — Step 4 ordering invariant.
- `round2-combiner-never-invoked.test.ts` — Step 8 spy assertion.
- `round2-shred-finalized-terminal-state.test.ts` — terminal state + event ordering.
- `round2-clean-state.test.ts` — repeatability cleanup data.

## Relation to Round 2b

Round 2 and Round 2b are TWO DISTINCT FIXTURES exercising TWO DISTINCT
axes of refusal/halt. See `round2b-narrative.md` for the G4 mid-flight
refusal axis (where RevealAuthorized DOES fire, then the combiner aborts
fail-closed). The two MUST NOT be conflated.

| | Round 2 | Round 2b |
|---|---|---|
| Subject triggered shred? | YES | NO |
| `RevealAuthorized` emitted? | NO (absence-of-event) | YES |
| Combiner invoked? | NEVER | Yes, then aborts fail-closed |
| Failure layer | G1 chain emit | G4 gate-signing |
| Recipient outcome | No bundle, no refusal artifact (no auth fired) | Signed refusal payload via webhook |
