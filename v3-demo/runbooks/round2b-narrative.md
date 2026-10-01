# Round 2b — G4 Mid-Flight Refusal (0x02 art_17_erasure)

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

**Round 2b demonstrates that even when the chain authorizes a reveal, the
combiner aborts fail-closed if any gate refuses.** Subject has NOT
triggered shred. ConditionEngine emits `RevealAuthorized` NORMALLY. G4
returns refusal `0x02 art_17_erasure` during gate-signing. The combiner
observes the refusal in the AuthorizationRegistrySnapshot → aborts
fail-closed (CUSTODY_ERR_G4_REFUSED). The recipient receives a signed
refusal payload via the webhook + Problem+JSON delivery surface.

## Axis (distinct from Round 2)

G4 mid-flight refusal as a DISTINCT axis from Round 2's G1 chain-block
axis. This separation matters:

| | Round 2 (G1 axis) | Round 2b (G4 axis) |
|---|---|---|
| Subject triggered shred? | YES | NO |
| `RevealAuthorized` emitted? | **NO** (universal tripwire) | **YES** (chain authorizes) |
| Combiner invoked? | NEVER | Yes (snapshot-verifier checks refusal state) |
| Combiner outcome | n/a | `{ok: false, code: CUSTODY_ERR_G4_REFUSED, subCodes: [REASON_0x02]}` |
| Recipient outcome | No bundle, no refusal (no auth fired) | Signed refusal payload via webhook |
| Vault state after | `exists === false` | `exists === true` (refusal ≠ erasure of ciphertext at vault layer for mid-flight code 0x02) |

## Normative Success Criterion

```
recipientVerify === {
  verified: true,
  kind: "refusal",
  reasonCode: 0x02,
  reasonLabel: "art_17_erasure",
  reasonVisibility: "encrypted",
  encryptedReasonRef: <ipfs://...>,
  blocking: true,
}
```

And `combinerResult.ok === false` with `code === "CUSTODY_ERR_G4_REFUSED"`.

## Flow

| Step | Action | Verification |
|---|---|---|
| 1 | Onboard fresh subject (NO shred) | (authorizationId, hCommit) captured |
| 2 | T+24h: TimeLock fires → `RevealAuthorized` emitted | `revealAuthorizedEmitted === true` |
| 3 | Combiner collects σ; σ_Lit + σ_G3 succeed; σ_G4 returns refusal 0x02 | `g4Phase1Mock.hasReceivedRequest(hCommit) === true` |
| 4 | Combiner fail-closed abort (S2-1 §1.7 + §14) — NO Shamir.combine, NO AEAD | `combinerResult.ok === false`, `subCodes = [REASON_0x02]`, `shamirCombineCount === 0`, `aeadDecryptCount === 0` |
| 5 | M5 `handleG4Refusal` produces G4RefusalEntry + webhook event | `refusalEntry.reason_code === 0x02`, `webhookEvent.event_type === "g4.refused"` |
| 6 | Recipient verifies refusal payload format | `recipientVerify.verified === true && kind === "refusal" && reasonCode === 0x02` |
| 7 | Cleanup: authorization terminal state + vault row count + BullMQ pending | vault row count = 1 (NOT shredded), BullMQ pending = 0 |

## Encrypted-Reason Mode for 0x02

Per S2-2 §14.3 / S2-5 §10.4:

- Codes 0x02 (Art. 17 erasure) and 0x03 (Art. 18 restriction) MUST carry
  an `encrypted_reason_ref` and MUST be marked
  `reason_visibility === "encrypted"`.
- Plaintext disclosure of the reason would be a GDPR violation.
- The reason payload is decryptable ONLY by the authorized recipient.

`handleG4Refusal` throws if `isEncryptedReason(code) && encrypted_reason_ref === undefined`.

## How to Run

```bash
# CI dry-run (no infra required)
DEMO_MODE=ci-anvil pnpm exec demo round2b

# Live mode (requires real G4 mock with refusal config + Base Sepolia)
DEMO_MODE=live-base-sepolia \
  BASE_SEPOLIA_RPC_URL=https://... \
  G4_PHASE1_MOCK_URL=https://... \
  G4_PHASE1_AUTHORITY_PUBKEY_HEX=0x... \
  pnpm exec demo round2b
```

## Brief vs Upstream Surface

The brief mentions:
- `revealDeliveryAssembler.assembleRefusal({ authorizationId, refusalReason, refusalArtifactSig })`
- `verifyRefusalArtifact` returning `{ verified, kind: 'refusal', reasonCode }`

Neither exists upstream in M5/verify-sdk. See the internal integration-gap log.

The actual upstream surface per S2-5 §3.6 is:
- `handleG4Refusal` → `G4RefusalEntry` persisted + emitted via webhook.
- Webhook is HMAC-signed; partners verify with `@cealis/verify-sdk/verifyWebhook`.
- The Problem+JSON refusal body carries reason_code + reason_label +
  reason_visibility + encrypted_reason_ref (when applicable).

Round 2b implements `verifyRecipientRefusalPayload` LOCALLY (in
`round2b.ts`) to wrap this surface in the brief-conceptual
`{ verified, kind, reasonCode }` shape — but this is v3-demo-local
approximation, not a verify-sdk export. The back-prop targets are
documented in the internal integration-gap log.

## What Could Go Wrong

**Symptom: `combinerResult.ok === true`.**
The combiner reconstructed the file key despite the refusal. This is a
fail-closed violation per S2-1 §1.7 + §14. Causes to investigate:

1. **`snapshot-verifier.ts` skipped the refusal check.** The conditional
   `refusalState.refused && reasonCode >= 0x01 && reasonCode <= 0x09`
   should throw `CUSTODY_ERR_G4_REFUSED`. If reason code is in range but
   the throw didn't fire, the boolean was wrong.
2. **The AuthorizationRegistrySnapshot was stale.** The combiner reads
   the snapshot at `authorizationBlock`. If the snapshot was taken BEFORE
   the refusal was recorded on-chain, the check would falsely pass.
3. **Round code accidentally invoked `combineAndDecrypt` with a
   refusal-clean snapshot.** Check the input `AuthorizationRegistrySnapshot.refusalState` —
   if it's `{refused: false}`, the combiner correctly proceeds. Round 2b
   simulates the refusal-set case.

**Symptom: `shamirCombineCount > 0` or `aeadDecryptCount > 0`.**
The fail-closed contract was violated. Even one Shamir.combine call on a
refusal-set snapshot is a S2-3 §9.7 violation ("NO partial plaintext is
returned on failure"). Inspect the combiner call chain — the throw must
happen in `snapshot-verifier.ts` BEFORE `reconstructFileKey` /
`decryptAeadPayload`.

**Symptom: `recipientVerify.verified === false`.**
The refusal payload shape is invalid. The local verifier checks:
- webhook `event_type === "g4.refused"`
- reason_code in 0x01..0x0A
- 0x02/0x03 → `encrypted_reason_ref` MUST be present
- reason_visibility matches the encrypted-reason class
- blocking flag matches the code's blocking class
- reason_code_hex format matches numeric code

If `verified === false`, walk the 6 checks above; the failing one points
at the upstream M5 surface that drifted.

**Symptom: plaintext reason text appeared in logs / output.**
0x02 / 0x03 are encrypted-reason mode by spec. Any plaintext leakage is
a GDPR violation. Inspect the M5 `handleG4Refusal` path — only
`encrypted_reason_ref` should appear; the actual reason content lives
encrypted off-chain.

## Relation to Round 2

See `round2-narrative.md` "Relation to Round 2b" comparison table. The
critical separation: Round 2 = G1 axis (chain refusal, absence-of-event).
Round 2b = G4 axis (combiner fail-closed mid-flight). Conflating them
loses signal about WHICH layer enforced the halt.
