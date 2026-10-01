# Conditional Sealing — Architecture Overview

Status: archived reference implementation — see the "Read this first" note and the "What this is not" section in the README.

This is the repo-level map: how the system fits together, which parts were real at retirement, which were stubs, and where to start reading. The verdict from the project's own state-at-retirement assessment holds throughout: **cryptographically real, operationally unfinished.**

---

## 1. The system in one screen

The system implements conditional sealing: encrypt data once, split the key across independent gates, and let a public blockchain — not a person — decide when the gates may cooperate to reopen it. That is the design goal; by construction the architecture intends that no single party, the operator included, holds a working key. The unfinished operational layer never demonstrated this end-to-end against live external networks, so read the property as the design's promise, not a demonstrated capability.

```
SEAL (commit)
  plaintext
     │  ChaCha20-Poly1305 AEAD under a fresh DEK          [REAL — golden-vector tested]
     ▼
  ciphertext ──► off-chain vault                          [MOCKED — in-memory stores only]
     │
  DEK ──► GF(2^8) Shamir split (constant-time: see §3)    [REAL — golden-vector tested]
     │      (FIXED_ONLY profile: 3-of-3 over G2/G3/G4;
     │       G1, the chain, is the trigger, not a shareholder)
     ▼
  per-gate shares, each wrapped hybrid X25519 + ML-KEM-768 [REAL]
  to that gate's recipient pubkey, carried in a custom
  age-plugin envelope with per-stanza keccak MACs;
  subject consent (σ_subject) bound into commit_AAD        [REAL as crypto; ingestion
                                                            transport/auth UNWIRED]

REVEAL
  on-chain condition FSM advances on ConditionEngine       [REAL in source; live testnet
     │                                                      deploy DRIFTED — see below]
     ▼
  RevealAuthorized event fires (G1)                        [REAL in source — the sole
     │                                                      emit site, invariant-tested;
     ▼                                                      live emission not demonstrated]
  gates G2/G3/G4 each verify and sign (σ-as-authorization) [STUBBED — live signing
     │                                                      transports never finished]
     ▼
  combiner: multi-step pre-verify pipeline → share unwrap → [REAL — adversarially tested,
  Shamir reconstruction → AEAD decrypt                       fail-closed on any missing gate]
     │
     ▼
  RevealArtifactBundle assembled and delivered             [ASSEMBLY REAL; delivery ran
                                                            on mocks; offline verifier STUB]
```

Miss any one gate and the threshold is not met — there is no decryption path that routes around the chain. The combiner enforcing that AND-composition is real code with adversarial tests. The wiring that would have connected it to the actual external gate operators was stubbed when the project was retired.

One doctrine worth knowing before reading the code: **σ-as-authorization** (locked 2026-05-05). Gate signatures are authorization evidence gating share release — they are never piped through HKDF, never treated as key material, never used as Shamir share values. Earlier design documents in `docs/designs/` describe a superseded HKDF-over-σ construction; the specs and the implemented code follow the Shamir + σ-as-authorization model. The spec-compliance guard files in each package exist to catch exactly this kind of drift.

## 2. The four gates

- **G1 — the chain.** The `ConditionEngine` contract (deployed only to Base Sepolia testnet) evaluates the sealed data's condition as a finite state machine over `AttestationGate` checks and emits `RevealAuthorized` when it reaches a terminal firing state. G1 is not a Shamir shareholder; it is the objective trigger every other gate requires. The source is real and covered by the reproduced contract test suite (see `GETTING-STARTED.md`); the live deployment drifted from it — see the disclaimer below.
- **G2 — Lit Protocol.** A rented threshold/TEE network intended to sign once its release evidence is present. Adapter code exists; the live transport was a stub.
- **G3 — dcipher or drand.** Rented threshold networks, with an important scope difference: drand attests **time only** (tlock-style timelock encryption), while Randamu's dcipher is the path for richer condition attestation. The choice is made per deployment and frozen at commit. Same status as G2: adapters real, live transport stubbed.
- **G4 — a refusal-only operator verifier.** The one gate the project itself operated. It can *refuse* to sign on narrow legal, GDPR, or integrity grounds (10 closed reason codes); it cannot open anything, and its signature alone is below the reconstruction threshold. Phase 1 was a sealed-code Ed25519 server with a reproducible-build scaffold; Phase 2 (a rented, remotely attested TEE) was designed, never built.

Because G4 is refusal-capable and the off-chain runtime was operator-run, this repository deliberately never claims the system is "non-custodial" or "decentralized" without qualification, and never claims it cannot be compelled or blocked. Those phrasings were on the project's internal banned list and stay banned here.

**Live-deployment drift disclaimer.** The contract stack runs on Base Sepolia behind UUPS proxies (entry point: the `ConditionEngine` proxy); the implementation contracts are Sourcify-verified, the proxies themselves are not (addresses: `deployments/base-sepolia-verification.json`), but the deployed bytecode predates the later source-level security fixes, it is testnet-only, and you must not send value to or build on it. The canonical disclaimer is `deployments/README.md`; every mention of the live deployment in this repo defers to it.

## 3. Package map

States match the root `README.md` status table: real & tested / partial / simulated (stubbed) / not built.

**`contracts/` (partial).** The Foundry workspace: `ConditionEngine`, 9 condition modules, the FSM interpreter and Claim DSL, attestation/shred/challenge/gate-recipient registries, and UUPS governance. Test discipline was the strongest in the repo (reproduced post-retirement; see `GETTING-STARTED.md`). Two internal audit passes found real CRITICAL/HIGH issues; the fixes that landed, landed in source only and were never redeployed — that is the drift above — and part of the finding backlog was still open at retirement. Contracts-local detail (component diagrams, module walkthroughs, ceremony flows) lives in [`contracts/ARCHITECTURE.md`](contracts/ARCHITECTURE.md) — read that there rather than here.

**`v3-crypto/` (real & tested).** The most finished layer and the reason to read this repo: sealing primitives, the age-plugin envelope, GF(2^8) Shamir, the hybrid X25519 + ML-KEM-768 share wrap, four signature verifiers (WebAuthn P-256, EIP-712, BLS12-381, Ed25519), and locked golden test fixtures with a checked-in spec-compliance guard. Real, byte-exact, internally adversarially reviewed. The Shamir field math is constant-time by construction in the field arithmetic; a JIT'd, garbage-collected JavaScript runtime makes any constant-time claim best-effort. Boundary honesty: three internal verifiers remain fail-closed stubs — they throw rather than implement — and are marked as such in code and in `v3-crypto/README.md`: dcipher-verify (sigma-g3), G4 Phase-2 DCAP-verify (sigma-g4), and QES-verify (sigma-subject).

**`v3-custody/` (partial).** The 4-gate AND combiner: gate adapters for G2/G3/G4, an at-commit-block chain reader for the registries, and `combineAndDecrypt` — a multi-step pre-verify pipeline (canonical-address pinning, plugin integrity, commit-AAD round-trip, registry-snapshot and gate-pubkey verification, shred state, supersession lineage, cross-vendor TEE disjointness, per-stanza MACs) before Shamir reconstruction and AEAD decrypt. The combiner and its fail-closed behavior are real and tested; the external gate signing transports were stubs at retirement.

**`v3-sd/` (partial).** Selective disclosure: Poseidon commitments and PLONK circuits for revealing proven predicates without opening the seal. Real cryptography, but a disconnected island — never wired into the API.

**`v3-api/` (partial).** The Fastify ingestion/delivery server (29 OpenAPI operations, webhook taxonomy, the `RevealArtifactBundle` format). It boots end-to-end exactly once — on in-memory stores with unwired auth. This is where "operationally unfinished" is most visible.

**`v3-configurator/` (partial).** Per-partner policy (PDA) validation. The validation logic exists; a barrel export shipped a no-op validator, which is exactly the kind of defect the status table exists to flag.

**`v3-ops/` (illustrative only).** 17 operational ceremonies and 19 CLI commands for key and registry management. Skeleton and catalogs only; nothing here ever ran against real infrastructure.

**`v3-demo/` (illustrative only).** The end-to-end demo harness wiring every package into 4 scripted rounds. The rounds are scripted and run against in-memory mocks; no live integration. Do not read it as evidence of a working system.

**`verify-sdk/` (not built).** The offline independent verifier — the package that would let a partner check a reveal without trusting the operator. Check scaffolding exists in the source, but the real cryptographic σ-verification behind it was never implemented and the package was never functional. The independence property is asserted in the spec, not delivered in code.

**`deployments/`.** `base-sepolia.json` (the addresses of the live contracts, plus a few deploy-time admin entries and one never-deployed placeholder) plus the canonical drift disclaimer.

The tracked build ran roughly three months (March–June 2026), retired 2026-06-10.

## 4. Where the documentation lives

- `docs/specs/` — the specification corpus: the whitepaper plus 8 Stage-2 specs (cryptography, contracts, custody integration, configurator, ingestion/delivery, ceremonies, selective disclosure, controlled use).
- `docs/designs/` — upstream design documents (primitives, threat model, trust framing, flows); note some predate the σ-as-authorization lock.
- `docs/audits/` — the internal adversarial review artifacts and `MATURITY-SCORECARD.md` (~3.5/5; an earlier 5.00/5 self-grade was withdrawn).
- `docs/research/` — the Fundability Fingerprint market kill-test that retired the project.
- `docs/state-at-retirement/` — the target state the project was building toward, explicitly marked as aspirational, not achieved.

## 5. If you're reading the code, start here

1. **`v3-crypto/test/fixtures/`** — the golden vectors (`shamir-positive`, `hybrid-wrap`, `envelope`, `e2e`). They pin the cryptography byte-exactly and are the fastest way to see what the primitives actually do.
2. **`v3-custody/src/combiner/`** — the AND-composition enforcement: pre-verify pipeline, share reconstruction, fail-closed paths. This is the system's load-bearing claim expressed as code.
3. **`contracts/src/engine/`** — `ConditionEngine` and the FSM machinery, with `contracts/ARCHITECTURE.md` beside you for the component map, then the modules and registries.
4. **`v3-api/`** — last, and with calibrated expectations: it shows the intended operational shape on top of mocks, not a finished runtime.

That order goes from strongest to weakest deliberately. The cryptographic core is worth studying on its own terms; the operational shell is a record of where the project stopped when it was killed on demand-side evidence.

— Simon Baltes, July 2026
