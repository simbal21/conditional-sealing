# Round 1 — Escrow Tripwire Happy Path

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

End-to-end narrative for the Cealis V3 Internal E2E Demo's Round 1. This
round exercises the 4-gate AND-composition (3-of-3 over {Lit, G3, G4})
on a TimeLock fixture (testament archetype, drand G3, G4 Phase 1).

Authoritative spec: internal M8 build brief (not in this export).

## Composition

| Gate | Source | Role in Round 1 |
|---|---|---|
| G1 — Chain | M2 `ConditionEngine` on Base | Fires `RevealAuthorized` after TimeLock condition module evaluates |
| G2 — Lit V3 | rented commodity TEE attestation | Signs σ_Lit over `(authorizationId, hCommit, block_hash)` |
| G3 — drand | League of Entropy threshold-randomness beacon | Signs σ_G3 at the bound drand round |
| G4 — Cealis verification | Phase 1 sealed-code server (mock in CI) | Signs σ_G4 over the attestation context |

PDA fixture: testament archetype (M4 `testamentSubmittedPda`).
Recipient profile: FIXED_ONLY → 3-of-3 Shamir over {Lit, G3, G4}.
σ_subject is COMMIT-TIME consent (passkey assertion bound into commit_AAD), NOT a Shamir share per S2-1 §6.3.1.

## Ten-step flow

### Step 1 — Subject onboarding (commit)

The subject generates a fresh WebAuthn passkey assertion. The runner POSTs
to the M5 Mode A ingestion endpoint:

- **Endpoint:** `POST /v1/ingestions` (in-process via `createModeAIngestion`)
- **Payload:** `{"document": "Round 1 demo payload"}` (small plaintext)
- **PDA:** testament with TimeLock 24h delay (300s in live mode)
- **Mode:** `A` (TEE-ingest)
- **Idempotency-Key:** `idem-r1-<runId>-1`
- **σ_subject:** WebAuthn assertion bytes bound into commit_AAD

**On-chain expectation:** ConditionEngine emits `PDARegistered(authorizationId, hCommit, pdaRoot, partnerId)`.

**Off-chain artifact:** `output/round-1/<runId>/00-commit-request.json` + `01-commit-response.json`.

### Step 2 — Idempotency replay (S2-5 §1.5)

Re-POST the SAME request with the SAME Idempotency-Key. The repository
must return BYTE-IDENTICAL response. No vault double-write, no chain
double-anchor.

**Asserted via:** `assertIdempotencyByteIdentical({firstResponse, secondResponse})`.
**Artifact:** `01b-idem-replay-response.json` (must be byte-equal to `01-commit-response.json`).

### Step 3 — Chain anchor verification

The synthetic anchor returns `commit_tx_hash` echoing `hCommit` byte-for-byte
and `commit_block_hash` populated. In live mode, viem `watchContractEvent`
against the partner-RPC observes M2's `PDARegistered` log.

**Artifact:** `02-chain-anchor-tx.json`.

### Step 4 — TimeLock fire

- **CI:** `evm_increaseTime` advances anvil by 86,400s simulated.
- **Live:** `setTimeout(300_000)` — 5-minute wall delay per Phase A
  `getTimelockDelay('live-base-sepolia')`.

The TimeLock condition module evaluates and unconditionally schedules a
`RevealAuthorized` emission.

### Step 5 — ConditionEngine emits `RevealAuthorized`

**Event signature:** `RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)`

**Decoded params:**

- `authorizationId` (bytes32, indexed) — matches commit-time value
- `hCommit` (bytes32, indexed) — matches commit-time anchor
- `pdaRoot` (bytes32, indexed) — PDA template root
- `authorizationBlock` (uint64)
- `authorizationTimestamp` (uint64)
- `challengeWindow` (uint32)
- `conditionRef` (bytes32)

**Captured:** `block_hash` for σ binding at the at-commit-block reading
discipline (S2-1 §11.4).

**Artifact:** `03-condition-engine-event.json`.

### Step 6 — Combiner collects σ + reconstructs file_key (σ-as-authorization)

The combiner orchestrates:

1. **σ_Lit request** — Lit V3 mock signs over `(authorizationId, hCommit, block_hash)`.
2. **σ_G3 request** — drand mock at the bound drand round.
3. **σ_G4 request** — G4 Phase 1 mock server signs the endpoint attestation.

Each σ is verified at the at-commit-block reading discipline. For each
verified σ, the combiner releases the per-stanza wrap-decap material
(NOT HKDF over σ — σ is the AUTHORIZATION, not the IKM). With all three
shares released, `Shamir.combine([share_Lit, share_G3, share_G4]) → file_key`.

**Discipline:** σ-as-AUTHORIZATION (locked 2026-05-05). The combiner facade
is `combineAndDecrypt` from `@cealis/v3-custody`. There is NO HKDF-over-σ
surface anywhere; the foundation test
`sigma-as-authorization-discipline.test.ts` greps src/ for any regression.

**Artifacts:** `04-sigma-bundle.json` (σ values + verification result),
`05-recovered-shares.json` (redacted; profile + gate count only).

### Step 7 — AEAD decrypt

`XChaCha20-Poly1305.decrypt({ key: file_key, aad: commit_AAD, ciphertext })`
returns plaintext byte-equal to the onboarding payload. This is M1's
`decryptPayload` primitive consuming a 32-byte DEK + the encoded
commit_AAD as additional authenticated data.

**Artifact:** `06-aead-plaintext.json` (redacted — only payload digest
written to disk; raw plaintext stays in-memory).

### Step 8 — M5 reveal-delivery assembles bundle (S2-5 §4)

`processRevealAuthorizedEvent` orchestrates the M5 reveal pipeline:

- Builds `combinerManifest` from the event payload.
- Applies the recipient selector to the full plaintext.
- Calls `assembleRevealArtifactBundle` which composes the 15-key
  `RevealArtifactBundle`.
- Persists via `InMemoryRevealArtifactRepository` (or DB-backed repo in live).

**Bundle 15-key catalog:** bundle_version, canonicalization,
authorization, pda, recipient, plaintext, issuer_attestation, provenance,
sigma_block, chain_proofs, registry_snapshots, shred_state, sd_refs,
verification, pii_statement.

**Canonicalization:** JCS per RFC 8785. Bundle digest = keccak256(utf8(JCS(bundle))).

**Artifact:** `07-reveal-artifact-bundle.json`.

### Step 9 — Recipient verify-sdk verifies OFFLINE (S2-5 §4.7)

The recipient runs `@cealis/verify-sdk`'s `verifyArtifactBundle` against
the bundle. The SDK runs OFFLINE — independence is a normative property.
Partner-controlled RPC is the only chain-read surface; no Cealis URL is
contacted.

verify-sdk runs 15 named checks (App. B): canonicalization, chainProof,
pdaRoot, registrySnapshots, endpointAttestation, issuerAttestation,
provenance, sigmaSubject, sigmaLit, sigmaG3, sigmaG4, sigmaConditional,
shredState, recipientSelector, sdRefs. Happy path returns `overall: "pass"`.

**Artifact:** `08-verify-sdk-result.json`.

### Step 10 — Repeatability cleanup verifier

After the round, no orphan state for the subject's `subjectId` remains:

- Vault rows for subjectId = 0
- BullMQ pending jobs for subjectId = 0
- On-chain Authorization state terminal (`Finalized` for Round 1; `Shredded`
  would apply to Round 2)

**Asserted via:** `assertCleanState({subjectId, postgres, redis, client})`.
**Artifact:** `09-clean-state-report.json`.

## Live demo timing notes

The 24-hour TimeLock is simulated in CI via `evm_increaseTime`. For live
demonstrations, a 300-second (5-minute) wall delay is the fixture default
per PHASE-PLAN §0 drift #7. This is short enough to keep the demo
audience engaged + long enough that the TimeLock is unambiguously real
(not a JIT bypass).

## What could go wrong (troubleshooting)

| Symptom | Likely cause | Fix |
|---|---|---|
| `DEMO_ERR_IDEMPOTENCY_VIOLATION` on Step 2 | M5 repository didn't echo the previously-saved response | Check `IngestionRepository.getByIdempotencyKey` implementation |
| Verify-sdk `overall: "fail"` on chain_proofs | Bundle's chain_proofs hash fields not 32-byte hex OR challenge window not yet expired by `now` | Inspect `08-verify-sdk-result.json` for the specific check.code; re-time the assertion |
| Verify-sdk `overall: "fail"` on sigmaLit/g3/g4 | σ evidence missing `public_after_reveal: true` OR malformed authority_ref | Inspect `04-sigma-bundle.json`; σ values must be hex prefixed and ≥ 1 byte payload |
| Verify-sdk `overall: "fail"` on recipientSelector | `expectedRecipientRef` option does not match bundle's `recipient.recipient_ref` | Adjust caller; in CI we use `round1-heir` |
| `DEMO_ERR_BUNDLE_VERIFY_FAIL` general | Any of the 15 checks failed | Read `08-verify-sdk-result.json` `checks` map for the failing check.code |
| `DEMO_ERR_REPEATABILITY_LEAK` on Step 10 | Live mode: vault row didn't clear; BullMQ job didn't process | Inspect Postgres `vault*blob*` tables for `subject_id` rows; check Redis SCAN under `bull:webhook-delivery:*` |
| Round-internal `DEMO_ERR_INTEGRATION_GAP` | Upstream surface gap surfaced in the internal integration-gap log | Read `safeRefs.gapDescription`; back-prop to responsible milestone |

## CLI invocation

```bash
DEMO_MODE=ci-anvil \
  DEMO_POSTGRES_URL=postgres://localhost/cealis_v3 \
  DEMO_REDIS_URL=redis://localhost:6379 \
  G4_PHASE1_AUTHORITY_PUBKEY_HEX=0x<authority-pubkey> \
  CONDITION_ENGINE_ADDRESS=0x<addr> \
  pnpm exec demo round1
```

## CI/test invocation

```bash
pnpm --filter @cealis/v3-demo test tests/round1/
```

All 7 Round 1 step-isolated tests + 1 CLI dispatch test run against in-
process synthetic adapters. No infra required.
