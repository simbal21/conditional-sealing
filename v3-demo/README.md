# @cealis/v3-demo

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `../deployments/README.md`.

**Cealis V3 Internal End-to-End Demo (M8).**

Wires every prior Stage-3 milestone (M0–M7) into a runnable 4-round
demonstration of the full V3 system:

| Round | Demonstrates |
|---|---|
| `round1`   | Escrow tripwire happy path (TimeLock + drand + G4 Phase 1 + Mode A + FIXED_ONLY) |
| `round2`   | Subject-initiated shred → G1 chain-block at emit layer (absence-of-event) |
| `round2b`  | G4 mid-flight refusal 0x02 art_17_erasure (fail-closed combiner) |
| `round3`   | SD on (parallel pipelines, day-one + escrow) |

Plus cross-round invariants: 7-stage asymmetric isolation table, Mode B + SD
defense-in-depth, halt-activation blocks ingestion, 10 G4 refusal codes
parameterized.

## Status (at retirement, June 2026)

**Illustrative only.** The demo runtime used in-memory mocks; do not read a
passing round as evidence of a working end-to-end system.

All four rounds (`round1`, `round2`, `round2b`, `round3`) and the cross-round
invariants are implemented in `src/rounds/` and dispatched from `src/cli.ts`.
They run over in-process synthetic adapters — a mocked chain anchor and
synthetic gate signatures — so a demo run exercises orchestration and byte
paths, not a live chain. The live Anvil-fork integration never shipped: the
`ci-anvil` mode plumbing exists in `src/setup.ts`, but the rounds were only
ever validated over the synthetic adapters.

The Phase G live-deploy smoke ran 9/9 against Base Sepolia on 2026-05-14
(testnet; see `../deployments/README.md`). An earlier phase table in this
file, dated 2026-05-14, listed most phases as pending; it was superseded by
the source and has been removed.

See `SPEC-COMPLIANCE-GUARD-M8.md` for the spec-grounded drift sheet and
the internal integration-gap log (not published) for integration gaps surfaced at Phase A.

## Run

```bash
# ci-anvil mode (rounds run over in-process synthetic adapters; see Status)
DEMO_MODE=ci-anvil pnpm exec demo round1

# Live Base Sepolia smoke (Phase G only)
DEMO_MODE=live-base-sepolia pnpm exec demo round1
```

Required environment for all modes:

- `DEMO_MODE` = `ci-anvil` or `live-base-sepolia`
- `DEMO_POSTGRES_URL` (Postgres connection)
- `DEMO_REDIS_URL` (Redis connection)
- `G4_PHASE1_MOCK_URL` + `G4_PHASE1_AUTHORITY_PUBKEY_HEX`
- 10 M2 contract-address env vars: `CONDITION_ENGINE_ADDRESS`, `SHRED_REGISTRY_ADDRESS`, ...

Live mode additionally requires:

- `BASE_SEPOLIA_RPC_URL`
- `DEPLOYER_PRIVATE_KEY` + `DEPLOYER_ADDRESS`

## Architecture

`@cealis/v3-demo` is a **pure consumer** of M0–M7. It re-exports the upstream
surface via 7 typed facades (`src/m{1..7}-imports.ts` + `m6-sdk-imports.ts`)
so round code never reaches into another workspace directly.

`src/setup.ts` handles infra bootstrap + mode switch + contract address
resolution + PDA fixture loading.

`src/assert.ts` provides 6 assertion primitives shared by all rounds:
`assertEvent`, `assertNoEventInRange`, `assertBundleVerifiable`,
`assertRefusalReasonCode`, `assertCleanState`, `assertIdempotencyByteIdentical`.

`src/verify.ts` wraps `@cealis/verify-sdk` for offline bundle + webhook
verification using partner-controlled RPC (independence is normative per
S2-5 §4.7 + §9.1).

`src/errors/demo-error.ts` declares the frozen `DemoError` class with 14
pre-declared codes and 30+ pre-declared `DemoSafeRefs` fields (Rule 47 + M7
lesson — adding fields mid-build burns a Phase-A re-pass).

`src/cli.ts` dispatches the 4 round entry points. (An earlier Phase-A design
left the slots as throwing stubs; all four are filled in the shipped source —
see Status above.)

## Normative invariants

See `SPEC-COMPLIANCE-GUARD-M8.md` §0 for all 20 invariants. Highlights:

- **σ-as-AUTHORIZATION** (locked 2026-05-05). NO HKDF over σ values anywhere.
- **FIXED_ONLY = 3-of-3 Shamir over {Lit, G3, G4}**. σ_subject is
  commit-time consent bound into commit_AAD, NOT a Shamir share.
- **G3 = drand** (NOT dcipher) for M8 per Q-0-1.
- **G4 = Phase 1** sealed-code server for M8. Phase 2 HSM TEE deferred to
  post-M8 partner pilot.
- **Round 2 = ABSENCE-OF-EVENT** per S2-2 §12.5 #4. Combiner never invoked.
- **Asymmetric isolation = 7-stage table** per S2-7 §15.2. Single-failure-mode
  tests are non-conformant.
- **REPEATABILITY + IDEMPOTENCY** are distinct, both binding (S2-5 §1.5).

## Workspace dependencies

- `@cealis/v3-crypto` (M0+M1) — byte-exact cryptographic primitives
- `@cealis/v3-custody` (M3) — combiner + gate adapters
- `@cealis/v3-configurator` (M4) — 5 archetype PDA fixtures
- `@cealis/v3-api` (M5) — ingestion + reveal delivery
- `@cealis/v3-sd` (M6) — SD pipeline (Round 3 + Phase E only)
- `@cealis/v3-sd-verify` (M6 SDK) — partner SD verification
- `@cealis/v3-ops` (M7) — operational ceremony classes
- `@cealis/verify-sdk` — partner bundle verification

## License

Apache-2.0 (see the repository root `LICENSE`).
