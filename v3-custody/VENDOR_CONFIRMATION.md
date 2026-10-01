# VENDOR_CONFIRMATION — M3 Custody SDK

**Per S2-3 §11.4 — release-blocking vendor confirmation checklist.**

Each item below aggregates the captured fixtures from `tests/fixtures/vendor/`. Status `READY` = pinned + fixture-backed at M3 ship; `DEFERRED` = vendor-blocked at M3, must resolve before partner-pilot (G4 Phase 2) deployment. None of the items are M3-blocking — drand-only ship + Lit fixture-backed transport satisfies the M3 internal-demo gate.

---

## 1. VENDOR_CONFIRMATION_LIT_CORE_API — DEFERRED-PROD

**Source:** `tests/fixtures/vendor/lit/api-version.json`

| Field | Value |
|---|---|
| Base URL | `https://chipotle.lit.mock` (fixture; live endpoint TBC at production transport) |
| API version | `chipotle-core-rest-v1-fixture` |
| `@lit-protocol/lit-node-client` | `7.3.0` (locked in `package.json`) |
| `@lit-protocol/contracts-sdk` | `7.4.0` (locked in `package.json`) |
| Cert pin SHA-256 | `1111…` (placeholder; live pin needed before enabling production transport) |
| Captured | 2026-05-11 |

**M3 status:** transport wrapper accepts fixture; production transport must supply σ bytes, DCAP quote bytes, assignment id, quote digest, version, and pinned channel identity separately. Live cert pin extraction is a deployment-time op.

---

## 2. VENDOR_CONFIRMATION_LIT_BLS_VARIANT — READY (interface-confirmed)

**Source:** `tests/fixtures/vendor/lit/sigma-vector.json` + S2-3 §11.3 (G1 pubkey 48 bytes, G2 signature 96 bytes)

Adapter delegates byte-exact verification to M1's `verifySigmaLit` via `src/m1-imports.ts`. Fixture vector validates against the M1-locked variant. `tests/integration/g2-lit-happy-path.test.ts` PASS.

---

## 3. VENDOR_CONFIRMATION_DCIPHER_SDK — DEFERRED

**Source:** `tests/fixtures/vendor/dcipher/sdk-status.json`

> Randamu dcipher SDK package/version, registry endpoint, vendor signature/source archive hash, and sigma vector are not pinnable in this workspace; drand-only build ships and dcipher-committed PDAs return `CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED` without fallback.

Expected package: `@randamu/dcipher-sdk`. Build-time exclusion enforced; runtime fallback to drand is FORBIDDEN per S2-3 §6.2 + §13.3 (verified by `tests/integration/g3-dispatch-no-runtime-fallback.test.ts`).

**M3 status:** internal-demo (M8) ships drand-only. dcipher hardens later when Randamu SDK is GA.

---

## 4. VENDOR_CONFIRMATION_DCIPHER_BLS_VARIANT — DEFERRED

**Source:** `tests/fixtures/vendor/dcipher/bls-variant.json` (deferred per item 3).

Threshold-BLS ciphersuite, committee pubkey length, signature length, threshold-not-met fixture, tombstoned-entry fixture all gated on Randamu SDK pin. Adapter signature verifier reserved at `src/g3-dcipher/sigma-verify.ts` — calls M1 once SDK is pinned.

---

## 5. VENDOR_CONFIRMATION_AUTOMATA_DCAP_CONTRACTS — DEFERRED (Phase 2)

**Source:** `tests/fixtures/vendor/g4-phase2/dcap-quote-stub.json`

Phase 2 DCAP P-256 attestation surface architected in `src/g4-phase2/` — `IS_DEFERRED === true` in `deferred-marker.ts`. Chain id, verifier contract address, bytecode hash, release tag, verifier type, quote-version support, zkVM program id, governance owner all placeholder. Phase 2 daemon NOT deployed at M3; partner-pilot phase deliverable per `project_g4_phase_pilot_decision.md`.

---

## 6. VENDOR_CONFIRMATION_AUTOMATA_GO_DCAP_SDK — DEFERRED (Phase 2)

**Source:** `tests/fixtures/vendor/g4-phase2/p256-chain-stub.json`

Go module path, immutable version/commit, sumdb checksum, supported quote types, callback/proof fixture all placeholder. Same Phase 2 deferred status as item 5.

---

## drand baseline (NOT a §11.4 numbered item but vendor-relevant)

**Source:** `tests/fixtures/vendor/drand/chain-info.json` + `round-vector.json`

| Field | Value |
|---|---|
| `drand-client` | `1.4.2` (locked in `package.json`) |
| Endpoints | `https://api.drand.sh`, `https://api2.drand.sh` |
| Transport | TLS 1.3 enforced; SHA-256 cert pin (placeholder; live pin extraction at deployment) |
| σ_G3 vector | reuses M1-valid vector from `v3-crypto/test/fixtures/sigma-g3.golden.json` |
| Long-lived committee KEM caveat | documented per `dek-lifecycle.md` line 35 — compromise exposes at most `TopShare(G3)`, NOT DEK |

Adapter passes all 4 drand integration tests (`g3-drand-round-vector`, `tlock-decap`, `chain-mismatch`, `round-mismatch`).

---

## G4 Phase 1 (sealed-code Ed25519, dev/pre-funding scaffold)

**Source:** `tests/fixtures/vendor/g4-phase1/{ed25519-vector,attestation-fixture}.json`

Ed25519 signing verified end-to-end. 10-code refusal enum (0x01-0x0A) tested. Encrypted-reason mode for 0x02/0x03. Split-key enforcement: σ_G4 alone does NOT admit `TopShare(G4)`. PDA-type eligibility guard rejects partner-ready / legal-effect with `CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE`. Reproducible build deterministic locally (hash `0542ac3b8a81801b8f3656c0a06904ddcbb1b0f8011f4f2550b6c4870ecb8c14`); `USE_DOCKER=1` host path needed for digest-pinned Docker validation (sandbox lacks Docker daemon access).

---

## Summary

| # | Item | M3 Status | Production-pilot Status |
|---|---|---|---|
| 1 | LIT_CORE_API | Fixture-backed | Live cert pin + endpoint required |
| 2 | LIT_BLS_VARIANT | READY (M1-delegated) | READY |
| 3 | DCIPHER_SDK | DEFERRED (build-excluded) | Required if any partner picks dcipher |
| 4 | DCIPHER_BLS_VARIANT | DEFERRED (gated on #3) | Required with #3 |
| 5 | AUTOMATA_DCAP_CONTRACTS | DEFERRED (Phase 2 surface) | Required for G4 Phase 2 deploy |
| 6 | AUTOMATA_GO_DCAP_SDK | DEFERRED (Phase 2 surface) | Required for G4 Phase 2 deploy |

**M3 ship gate satisfied:** drand-only + Lit fixture-backed + G4 Phase 1 sealed-code is the M8 internal-demo configuration. dcipher + Phase 2 hardening land before partner pilot.
