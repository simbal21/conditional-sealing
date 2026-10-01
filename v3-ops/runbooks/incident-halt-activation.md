# Incident response — Halt activation

**Scope:** Bounded-duration halt per S2-2 §14 + S2-6 §12. Pause-authority enum (Partner / Joint / None), ≤90 days, no deletion, halt-only.
**Spec:** S2-6 §12; cross-ref `pause-activation.md` for the per-PDA ceremony.
**Triggers:** GDPR Art. 18 restriction (Class A 0x03 refusal), operational vulnerability response, suspected attack, pending counsel review.
**Discipline:** Pause is REVERSIBLE. Does NOT delete ciphertext, destroy keys, grant release, alter reveal content, or reset historical state.

## Difference from shred + disaster recovery

| Action | Reversible | Deletes ciphertext | Time bound | Authority |
|---|---|---|---|---|
| **Pause** (this runbook) | ✅ yes (auto-lift at expiry OR manual unpause) | ❌ no | ≤90 days hard cap (§12.3) | per-PDA Partner / Joint |
| **Shred** | ❌ no (permanent triple block) | ✅ yes | per-PDA min latency | per-PDA Subject / Joint / Operator / Timelock |
| **Disaster recovery deprecation** | ✅ yes (DeprecationFlag clearable via auto-clear OR re-deprecation) | ❌ no | 72h disclosure deadline + 30-day cooldown | CealisSecurityMultisig |

## When to choose pause vs shred vs disaster recovery

- **Art. 18 restriction** (subject right to restrict processing): pause-activation, ≤90 days, encrypted-reason mode default. Auto-lift required after 90 days unless renewed with new pause.
- **Art. 17 erasure** (subject right to be forgotten): shred-trigger (permanent, irreversible). Routes through `incident-shred-ceremony.md`.
- **Registry compromise**: registry-deprecation via `disaster-recovery-bundle.md` (asymmetric governance, 24h/0h/72h auto-clear).
- **Operational vulnerability requiring bounded halt while patching**: pause-activation.
- **Suspected attack on specific commit**: pause-activation while counsel + ops investigate. If confirmed compromise of a registry entry → escalate to disaster-recovery-bundle.

## Authority mode dispatch (§12.2)

| Mode | Trigger source | Proof | Per-PDA frozen at onboarding |
|---|---|---|---|
| Partner | Partner-facing API (M5) | Partner HMAC + reason | yes |
| Joint | Subject + partner co-sign | both sigs over same reason | yes |
| None | (rejected at ceremony construct) | — | yes — pause-disabled PDAs |

## Routing protocol

1. **Receive halt trigger.** Source determines authority mode:
   - subject Art. 18 request → routes via partner; partner triggers Partner mode (with subject co-sign for Joint mode if PDA configured).
   - operational vulnerability → ops triggers Partner mode with reason digest.
2. **Pre-check authority mode**: if PDA's `pause_authority_mode === None`, this PDA disabled discretionary pause. Registry-level emergency halt (sub-class 3 emergency circuit breaker) is the only path.
3. **Pre-check duration bound**: `0 < durationSeconds ≤ 90 × 24 × 60 × 60`. Outside → TRIPWIRE_BYPASS at ceremony construct.
4. **Build pause-activation input**: see `pause-activation.md`. For 0x03 art18 cases, `reasonDigest` is the CID-hash of the encrypted reason blob; reason text stays encrypted.
5. **Run pause-activation ceremony**: emits `PauseActivated` with `pauseAuthorityMode`, `pauseAuthorityId`, `reasonDigest`, `startBlock`, `expiryBlock`.
6. **Verify**: ConditionEngine pause state on chain; FSM advancement / new auth blocked per PDA config.

## Auto-lift (§12.3)

`PauseActivated` carries `expiryBlock`. Pause auto-lifts at expiry without further on-chain action. ANY extension is a NEW pause activation subject to the same 90-day cap from its own start.

## Manual unpause

Use `pause-deactivation.md`. Same authority mode (Partner / Joint) required. Emits `PauseDeactivated`. Resumes FSM advancement and new auth emissions immediately.

## Halt-only invariant (§13.8)

Pause:
- ❌ does NOT grant reveal,
- ❌ does NOT change recipient set,
- ❌ does NOT alter reveal content,
- ❌ does NOT bypass G1,
- ❌ does NOT force G4 to sign,
- ❌ does NOT erase already-emitted `RevealAuthorized` events (chain-of-custody preserved),
- ✅ blocks FSM advancement / new auth emissions per PDA config.

## Art. 18 specific notes

- §12.3 90-day cap aligns with internal legal-constraints rules (not exported) Art. 18 freeze constraint: 90-day maximum + auto-expiry after deadline.
- PDA may abuse-resist: operator may deny freeze if obligation is in `Defaulted` state and Art. 6(1)(b) legitimate interest outweighs (subject's Art. 18 claim balanced against partner's enforcement need).
- Encrypted-reason mode default per §0.9 — reason text MUST NOT appear on-chain or in audit logs in plaintext.

## Cross-references

- `pause-activation.md` (ceremony script).
- `pause-deactivation.md` (manual unpause).
- `incident-refusal-escalation.md` (Class A 0x03 art18 routing).
- `incident-shred-ceremony.md` (Class A 0x02 art17 — permanent erasure path).
- `incident-registry-deprecation.md` (registry-level halt path).
- S2-2 §14 (pause/halt contract surface).
- legal Art. 18 90-day freeze constraints (internal legal-constraints rules (not exported)).
