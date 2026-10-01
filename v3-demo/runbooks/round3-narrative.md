# Round 3 — SD On (Parallel Pipelines, Day-One Delivery)

**Mission file:** internal M8 build brief (not in this export)
**Spec anchors:** S2-7 §1.5 (asymmetric isolation) · §4.4 (cleartext modes) · §11.1 (verifyAndCommitDisclosure) · §14 (Mode B incompatibility) · §15 (one-way edge) · S2-1 §4 (BP-SD-1 sdMerkleRoot at fixed commit_AAD position) · S2-2 §9.15 (IDisclosureRegistry expansion).
**Linear:** PRO-496 (Round 3 + cross-round).

## What Round 3 demonstrates

Round 3 is the **parallel-pipeline demo**. Same setup as Round 1 (testament fixture, FIXED_ONLY 3-of-3 over {Lit, G3=drand, G4 Phase 1}, Mode A), with one addition: `sd_enabled: true` + one M6 predicate (`age_over_18` → `range` circuit).

Two pipelines run **in parallel**, neither blocking the other:

1. **Escrow pipeline.** Ingest plaintext, derive DEK, AEAD-encrypt to vault, anchor h_commit on chain. Wait for TimeLock to fire (24h CI sim / 5 min live). When it fires: ConditionEngine emits `RevealAuthorized`, combiner collects σ_Lit + σ_G3 + σ_G4, Shamir.combine reconstructs file_key, AEAD-decrypt, M5 assembles `RevealArtifactBundle`, recipient receives it.
2. **SD pipeline (inside the same TEE at ingestion).** Per-field Poseidon commitments computed for the SD attributes. PLONK proof generated for the `range` predicate proving `birthdate ⇒ age >= 18`. Cleartext fields delivered in **`cleartext_zk_opened`** mode (the §4.4 default for regulated partner integrations). SD bundle assembled and **delivered DAY-ONE** — at onboarding completion, NOT at TimeLock fire.

The recipient ends up with **BOTH** bundles, verifiable independently.

## ASCII timing diagram

```
                    T=0                              T+24h
                     │                                 │
   ┌─────────────────┴─────────────────────────────────┴────────────┐
   │                                                                 │
   │  ESCROW PIPELINE                                                │
   │    [TEE ingest] → [AEAD wrap] → [h_commit anchored] → ─ ─ ─ ─ ─ ─ → [σ_Lit·σ_G3·σ_G4]
   │                                                       waiting          │
   │                                                       on TimeLock      ▼
   │                                                                    [Shamir.combine]
   │                                                                        │
   │                                                                        ▼
   │                                                                    [AEAD decrypt]
   │                                                                        │
   │                                                                        ▼
   │                                                                    [RevealArtifactBundle]
   │                                                                        │
   │                                                                        ▼
   │                                                                   ▲▲▲ recipient
   │                                                                       (escrow bundle)
   │                                                                        │
   │                                                                        │
   │  SD PIPELINE                                                           │
   │    [TEE ingest]                                                        │
   │       │                                                                │
   │       ├─ DEK ─→ HKDF ─→ sd_master_salt   (one-way edge per §15)        │
   │       │                                                                │
   │       ▼                                                                │
   │    [per-field Poseidon commitments]                                    │
   │       │                                                                │
   │       ▼                                                                │
   │    [PLONK range proof: age >= 18]                                      │
   │       │                                                                │
   │       ▼                                                                │
   │    [cleartext_zk_opened bundle]                                        │
   │       │                                                                │
   │       ▼                                                                │
   │    ▲▲▲ recipient                                                       │
   │       (SD bundle, DAY-ONE delivery)                                    │
   │                                                                        │
   └────────────────────────────────────────────────────────────────────────┘
   T=0                                              T+24h
```

## Comparison: Round 1 (escrow only) vs Round 3 (escrow + SD parallel)

| Property | Round 1 | Round 3 |
|---|---|---|
| Fixture | testament | testament (same) |
| sd_enabled | false | **true** |
| Predicates | — | **age_over_18 → range circuit** |
| Bundles delivered | 1 (escrow at T+24h) | **2 (SD at T=0, escrow at T+24h)** |
| Cleartext-opening mode | n/a | **cleartext_zk_opened (DEFAULT §4.4)** |
| sdMerkleRoot in commit_AAD | absent | **fixed position (BP-SD-1)** |
| On-chain verify path | — | **verifyAndCommitDisclosure (S2-2 §9.15)** |
| One-way edge enforced | n/a | **DEK → HKDF → sd_master_salt** |
| Partner SDK calls | verify-sdk (escrow only) | verify-sdk + **@cealis/v3-sd-verify** |
| Independence-normative | — | **SD pipeline asymmetrically isolated (§15.2)** |

## Step-by-step (per the internal build brief)

1. **Onboarding with SD payload (Mode A TEE ingest).** Subject onboards via M5 ingest with `sd_enabled: true` and SD attributes including birthdate. M5 → M6 invocation within the TEE: per-field Poseidon BN254 commitments + PLONK `range` proof + cleartext_zk_opened bundle. M5 ingestion persists ciphertext to vault (escrow side) AND records the SD bundle for delivery. Captures: `authorizationId`, `hCommit`, `sdBundleId`, `sdMerkleRoot`.
2. **sdMerkleRoot at fixed commit_AAD position (BP-SD-1).** Read commit_AAD via Phase A `decodeCommitAAD`; assert sdMerkleRoot bound at the fixed position normative for `commit_version = 0x0302`.
3. **DAY-ONE delivery.** M5 reveal-delivery sends SD bundle to recipient endpoint IMMEDIATELY at onboarding completion. NOT at TimeLock fire. Format per S2-7 §4 + §11.1 (PLONK proof bytes, public inputs, sdMerkleRoot, expiry, mode=cleartext_zk_opened).
4. **Recipient verifies via partner SDK.** Phase A `verify.ts` → `@cealis/v3-sd-verify` `verifySdBundle()`. SDK calls M2 `IDisclosureRegistry.verifyAndCommitDisclosure` on-chain via partner-controlled RPC. Verifies PLONK proof + expiry check + revocation check (DisclosureRevocationRegistry). Result: `{ status: "valid", predicate: "age_over_18", age_over_18: true }`.
5. **TimeLock fires.** CI: `setNextBlockTimestamp(currentTs + 86400)`. Live: 300s wall.
6. **Escrow reveal proceeds.** Same path as Round 1 (Phase A facades). ConditionEngine emits `RevealAuthorized` → combiner collects σ → Shamir.combine → AEAD decrypt → M5 reveal-delivery assembles bundle.
7. **Recipient has BOTH bundles.** SD bundle (T=0) + escrow bundle (T+24h). `assertBundleVerifiable` runs for both independently.
8. **One-way edge architectural smoke.** No SD-to-escrow backflow. Property enforced by `DefaultSdBoundary.executeIfEscrowOk` — SD failure cannot mutate the escrow result. Static check: `@cealis/v3-sd` source MUST NOT import from `@cealis/v3-custody`'s DEK-handling surface. Full 7-stage parameterized table is Phase E's responsibility.
9. **Repeatability cleanup.** `assertCleanState(subjectId)`: vault rows = 0, BullMQ pending = 0, on-chain Authorization state terminal.

## Round 3 in @cealis/v3-demo

- **Orchestration:** `src/rounds/round3.ts` → `runRound3Structural()` (vitest CI) / `runRound3Live()` (Phase G smoke).
- **Test files:** `tests/round3/` — 9 files per the internal build brief table.
- **CLI dispatch:** `src/cli.ts` `ROUND_DISPATCH.round3` slot — honors `DEMO_DRY_RUN=1` for the structural CI gate.
- **Bundle types:** `SdBundle` from `@cealis/v3-sd/types` (re-exported via `m6-imports`).
- **Partner SDK:** `verifySdBundle` from `@cealis/v3-sd-verify` (re-exported via `m6-sdk-imports`).

## Caveats + integration bounds

- **PLONK proving in tests is mocked.** Real `range` circuit proving via snarkjs is heavy (~10s per proof). Vitest CI uses a stub `VerifierRegistryClient.verifyProof = () => true`. The PLONK setup artifacts (zkey, vkey, wasm) ship with `@cealis/v3-sd` and are exercised in M6's own test suite + Phase G live smoke. See the internal integration-gap log if any change to this is required.
- **DEMO_DRY_RUN=1** routes through `runRound3Structural()` — no infra required. Without it (and with a valid `DEMO_MODE`), the CLI dispatches `runRound3Live()` which in this Phase D iteration still composes via the structural path (Phase G owns the live-deploy wiring).
- **σ-as-AUTHORIZATION** is the locked doctrine; the foundation test `sigma-as-authorization-discipline.test.ts` greps the demo source for any HKDF-over-σ regression. Round 3 source does NOT introduce one.
- **No Mode B in Round 3.** Mode B + SD is structurally forbidden per S2-7 §14; Phase E exercises the rejection path. Round 3 happy-path is Mode A.

## Open carry-over to Phase E

- 7-stage asymmetric-isolation parameterized table (per S2-7 §15.2) is **Phase E**, not Round 3.
- Mode B + SD defense-in-depth (M5 + M6 + bare Mode B) is **Phase E**.
- 10-code G4 refusal escalation table (Round 2b covers one code, Phase E parameterizes the others) is **Phase E**.
