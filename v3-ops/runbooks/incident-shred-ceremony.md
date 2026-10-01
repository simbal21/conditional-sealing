# Incident response — Shred ceremony

**Scope:** Emergency / right-to-erasure flows. Routes by `shred_authority_mode` per §11.2 + §11.7.
**Spec:** S2-6 §11; cross-ref `shred-trigger.md` for the per-mode ceremony.
**Triggers:** Art. 17 GDPR right to erasure (Class A 0x02 refusal), Subject self-initiated shred, Joint subject+partner shred, Operator-initiated with PDA-bound legal basis, Timelock-triggered retention-window close.
**Discipline:** §11.4 MANDATORY guardrail — `post_challenge_reveal_in_progress == false` AND-composed; PDA+ guardrail, NOT partner-configurable.

## Authority mode dispatch (§11.2)

| Mode | Trigger source | Proof | Latency |
|---|---|---|---|
| Subject | Art. 17 request via partner-facing surface | σ_subject equivalent | Per-PDA min latency |
| Joint | Co-signed request (subject + partner) | both sigs over same `authorizationId`, `h_commit`, reason | Per-PDA min latency |
| Operator | Cealis ops action with legal basis | PDA-bound legal_basis_digest + reason_digest | Per-PDA min latency |
| Timelock | Scheduled retention-window close | No discretionary signer | block/timestamp condition |
| Disabled | (rejected at ceremony proposal) | — | — |

## Per-PDA configuration

`shred_authority_mode` is FROZEN at PDA onboarding (per an internal design note, not in this export). Use cases:
- KYC lending → typically Subject or Operator with legal basis.
- Testament → typically Disabled (permanent archival).
- Evidence escrow → typically Operator with legal basis.
- Medical records → typically Subject (Art. 17 critical).

## Routing protocol

1. **Receive shred trigger.** Source determines authority mode:
   - subject-facing API → Subject mode.
   - dashboard co-sign → Joint mode.
   - ops action with court order / counsel review → Operator mode.
   - scheduled job → Timelock mode.
2. **Pre-check mandatory guardrail (§11.4)**: query ChallengeRegistry for `post_challenge_reveal_in_progress == false`. If TRUE, refuse the shred — escalate to pause-activation instead while the challenge resolves.
3. **Pre-check authority mode**: if PDA's `shred_authority_mode === Disabled`, refuse (this is intentional — permanent retention use cases).
4. **Pre-check condition**: ConditionEngine confirms the shred condition (predicate Mode P OR FSM Mode F) evaluates true.
5. **Pre-check timing**: challenge window completed (if non-zero) + min latency elapsed.
6. **Build shred-trigger input**: see `shred-trigger.md`. For Operator mode, attach PDA-bound legal_basis_digest (omit → QUORUM_MISSING).
7. **Run shred-trigger ceremony**: see `shred-trigger.md` for the per-step protocol.
8. **§11.3 triple block executes**:
   - G1 refuses future reveal authorization (ShredRegistry on chain).
   - G4 refuses σ_G4 (event listener mirrors registry state to G4).
   - Vault deletes ciphertext (`vaultClient.deleteCiphertext`).
9. **Verify `proof_shred`**: returned via `ceremony.getProofShred()`. Public verification token — partner-facing surface may publish it.

## Special case — Art. 17 erasure (0x02 + Subject)

1. Subject submits Art. 17 request via partner-facing API (M5).
2. Partner forwards to Cealis with subject signature.
3. Class A 0x02 `art17` refusal emitted on chain (`RefusalReasonEncrypted` — encrypted-reason mode default per §0.9).
4. Subject ceremony invokes shred-trigger with Subject authority.
5. Mandatory guardrail check: ChallengeRegistry must be clear.
6. Triple block executes.
7. Subject receives `proof_shred` via partner-facing API as cryptographic erasure receipt.

## Special case — Operator-initiated (court order / legal compel / 0x01)

1. Court order / regulatory demand received.
2. Counsel reviews + archives legal-basis evidence (CID hash).
3. Class A 0x01 `legal_compel` refusal emitted (`RefusalReasonPublic` bounded summary).
4. Operator ceremony invokes shred-trigger with Operator authority + `legal_basis_digest`.
5. Mandatory guardrail check.
6. Triple block executes.
7. Partner-facing notice published per S3-1.

## §11.6 Shred-first lifecycle bias

For PDAs whose use case permits early erasure, shred fires as soon as retention windows close. Retention floors still apply per internal legal-constraints rules (not exported):
- vault ciphertext + wrapped shares: obligation duration + 3 years (§195 BGB) unless PDA/legal posture permits earlier crypto-shred.
- access logs, delivery logs, on-chain commitments: own retention rules.

## Cross-references

- `shred-trigger.md` (per-mode ceremony script).
- `incident-refusal-escalation.md` (Class A 0x02 art17 routing).
- WP §E (crypto-shredding semantics).
- S2-2 §10 (ShredRegistry contract).
- S2-4 (PDA+ shred guardrails).
- internal legal-constraints rules (not exported) (retention table).
- internal shred-condition and shredding-authority design notes (not in this export).
