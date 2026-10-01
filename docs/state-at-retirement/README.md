# State at Retirement — Target State & Roadmap

> **TARGET-STATE-NOT-CURRENT.** This document describes the goal/roadmap state the project was building toward when it was retired (June 2026) — NOT what was achieved. For achieved state see the README status table and docs/audits/MATURITY-SCORECARD.md.

This is a sanitized summary of an internal "done state and roadmap" document generated on 2026-06-06 by an 11-subsystem discovery sweep of the repository, four days before the project was retired (2026-06-10). Everything under "Intended end-state" below is **aspirational**: it describes what a finished Cealis would have looked like. The scorecard and risk sections reflect the honest state at retirement.

## Audit status — correction

The original internal document's target-state section described an independent third-party security audit as "complete with all findings resolved." **That was a goal, not a fact, and it never happened. Cealis was never externally audited.** The contracts and runtime received internal adversarial review only (multi-lens internal audits and automated static analysis). An external paid audit was planned (est. €50–100K, targeting ≥ 4/5 maturity) and was cost-blocked; the honest self-assessed maturity at retirement was ~3.5/5 (see docs/audits/MATURITY-SCORECARD.md). Likewise, planned legal-counsel sign-off, penetration testing, and a bug bounty were never engaged.

## Intended end-state (aspirational)

Cealis was designed as a configurable conditional-sealing / data-escrow platform: data sealed under an on-chain-verified condition, with the design goal that no single party — partner, subject, gate operators, or Cealis itself — could open it outside that condition. These are **design goals as internally reviewed, not certified properties**; the system was never externally audited and the legal positions were never confirmed by counsel.

The finished system was intended to have:

- **Escrow → reveal → shred lifecycle** on real infrastructure. The decryption key for a sealed payload exists only as the AND-composition of four independent gate signatures (Chain · Lit V3 · dcipher/drand · Cealis G4), each share wrapped to that gate's own recipient pubkey; a database CHECK forbids storing a raw share.
- **Reveal only on-chain-authorized.** Reveal fires when, and only when, the PDA's on-chain condition module emits `RevealAuthorized` ("universal tripwire": no release path bypasses the on-chain condition).
- **Refusal-capable G4 gate** with 10 closed reason codes (legal compel, GDPR Art. 17/18, integrity failure, chain mismatch, deprecations, opt-out) — a crypto-enforced halt with no ability to *force* a reveal.
- **GDPR erasure as crypto-shredding** (DEK-share destruction + vault ciphertext deletion + on-chain shred state + G4 refusal), per-PDA configurable.
- **Court-oriented reveal artifacts**: every reveal produces a `RevealArtifactBundle` designed toward §371a ZPO evidentiary use (this admissibility claim was never reviewed by counsel).
- **Custody-minimizing design**: Cealis holds no master key anywhere by design (a Phase-2 TEE was intended to strengthen that into an attestable claim; the design was exercised by internal adversarial tests only).
- **Platform-shaped**: every use case is a PDA configuration artifact on one shared crypto-and-custody core — adding a use case means config rows, never code.

### Intended per-subsystem done-states (condensed)

1. **Crypto core (`v3-crypto`)** — byte-exact primitives locked for commit versions 0x0302/0x0303: constant-time GF(2⁸) Shamir, A1+Shamir DEK lifecycle (3 access profiles), hybrid X25519 + ML-KEM-768 post-quantum share wrap, keccak stanza MACs, SCALE envelope + CommitAAD codec with version dispatch, four σ verifiers (WebAuthn P-256, EIP-712 secp256k1, BLS12-381, Ed25519), 38 golden-tested TAG constants.
2. **Custody / 4-gate AND (`v3-custody`)** — `combineAndDecrypt` runs an 8-step pre-verify pipeline (address pin, policy digest, plugin integrity, envelope MAC, AAD round-trip, registry snapshot check, gate-pubkey resolution, shred/supersession checks) before σ orchestration, Shamir combine, and AEAD decrypt. Missing any single gate signature → no decryption, including mid-reveal shred.
3. **On-chain contracts** (`contracts/`) — `ConditionEngine` + 10 condition modules (PaymentObligation, TimeLock, SubjectInitiated, HeartbeatMissed, OracleAttestation, MultiPartySignal, DeadManSwitch, ConsentGate, Composed, PresentedTokenCondition), FSMInterpreter, ChallengeRegistry, AttestationGate, ClaimDSL, PasskeyRotationLog, two-axis ShredRegistry, and the full registry set — all UUPS-upgradeable behind a 7-day timelock, with the batched security-fix redeploy landed and Slither clean.
4. **Off-chain runtime & API (`v3-api`)** — Fastify v5 on real Postgres serving all 29 canonical endpoints from persistent stores; HMAC partner auth, WebAuthn subject auth, real registry reads, shred cascade, BullMQ workers, hardened HTTP boundary.
5. **Selective disclosure (`v3-sd` + `verify-sdk`)** — live dual pipeline parallel to escrow: Poseidon5 field commitments, snarkjs PLONK proofs (14-slot public-input set), Poseidon3 depth-16 Merkle tree, 16-check partner verify SDK, revocation auto-firing on shred.
6. **Configurator / PDA platform (`v3-configurator`)** — any implemented use case composed by configuration alone: 5-stage validation gate, boundary cascade, content-addressed templates, simulation harness, archetype defaults for ~20 niches including controlled-use (S2-8).
7. **Condition modules off-chain** — PDA-driven configure-at-ingest dispatch for all 10 modules plus 6 trigger relay routes, keeping the reveal path module-agnostic.
8. **Apps / UX** — four browser apps (Partner Dashboard, Subject Onboarding, Configurator UI, Operator Console) over a typed HTTP client, all PDA-driven.
9. **Ops, security & legal** — real ceremony tooling, CI-enforced static analysis and fuzzing, external audit and counsel sign-off (never reached — see the correction above).

### Deliberate infra stubs (by design, even in the end-state)

A finished Cealis was defined as a system where every remaining stub is a genuine external dependency behind a clean injection seam, honestly reported and env-swappable: vendor gate transports (Lit / dcipher / drand / G4), TEE sealer and cloud KMS, Base mainnet deploy, vault backends (IPFS/S3-class storage), eIDAS QTSP trust-list data, Lit operator roster data, a production ptau ceremony, KYC-vendor integration, external oracles, and EUDI relying-party registration.

## State at retirement (honest scorecard)

Overall completeness ≈ 50% — "cryptographically real, operationally unfinished." The crypto cores were nearly done; the bottleneck was wiring, persistence, auth, the SD-into-API seam, and the app layer, not cryptography.

| Subsystem | % done | One-line status at retirement |
|---|---|---|
| V3 crypto core (v3-crypto) | 88% | Byte-exact primitives real and tested; controlled-use TAG constants and vendor-boundary QES/Lit verify still open |
| V3 custody / 4-gate AND (v3-custody) | 80% | `combineAndDecrypt` fully real; non-custody design exercised by internal adversarial tests; 2 composition-root wiring gaps |
| On-chain contracts (ConditionEngine) | 72% | 9 modules + engine + registries real in source with internal-audit fixes applied; live testnet contracts predate the fixes (batched redeploy never executed); 10th module + 3 controlled-use registries absent |
| Configurator + PDA platform | 63% | Validation/boundary/use-cases production-shaped; barrel exported a placeholder `classifySurface`; controlled-use/monetary profiles absent |
| Spec stack + open designs | 57% | 6/9 Stage-2 specs authored; 3 specs and all 4 Stage-3 artifacts unwritten; propagation debts open |
| sd-pipeline | 55% | Crypto machinery real and tested but a disconnected island — not imported by the API; ZKP proof still a placeholder on the wired path |
| Off-chain runtime & API (v3-api) | 52% | Boots on real Postgres with a proven E2E cycle; 5 in-memory stores broke auth across restarts; HMAC implemented but unwired |
| Audits, security, legal & ops | 28% | Honest ~3.5/5 maturity; 2 CRITICAL + 8 HIGH open on the live testnet contracts; **no external audit; no counsel sign-off** |
| Full vision / feature catalog | 28% | Phases 0–4 merged and E2E green; later phases not started |
| Condition modules off-chain + use-case coverage | 22% | Modules deployed on-chain but nothing off-chain drove them yet; ~10/20 use-case keys |
| Apps & UX | 8% | Zero browser UI; no HTTP client layer existed |

### Open-work headline counts (internal, de-duplicated per domain; heavy overlap)

| Category | Open count |
|---|---|
| Open designs | 46 |
| Open build items | 115 |
| Open wiring seams | 69 |
| Audits / checks | 100 |

### Corrected repository metrics

- Solidity: 42 contract source files; the forge suite (unit, fuzz and invariant tests) passed in full — reproduction record in `GETTING-STARTED.md`.
- TypeScript: nine workspace packages, each with its own test suite.
- Live deployment: **32 contracts on Base Sepolia** (testnet only), implementation contracts Sourcify-verified (proxies not), deployed 2026-05-14 — **before** the internally-found security fixes were applied in source.

> **Deployment drift disclaimer:** the deployed Base Sepolia bytecode lags and diverges from this source tree (the batched fix redeploy never happened); it is testnet only and must not be treated as a reference deployment — see deployments/README.md.

## Top risks recorded at retirement

1. **Load-bearing stub clusters**: 5 in-memory stores meant subject auth did not survive a restart; the HMAC preHandler existed but was never wired, so ingest was effectively unauthenticated.
2. **SD pipeline disconnected**: zero `v3-sd` imports in the API; `sdMerkleRoot` not yet bound into `commit_AAD`, so post-hoc field alteration was not yet cryptographically detectable in the running system.
3. **Condition-module activation missing**: all deployed modules, but no ingest-time configure calls and no trigger relay routes — only `SubjectInitiated` was E2E-tested.
4. **Live on-chain security debt**: 2 CRITICAL + 8 HIGH findings from the internal 2026-06-02 review were fixed in source only; the live testnet contracts predate every fix. No external audit, no counsel sign-off.
5. **Spec drift**: 3 specs unauthored, propagation debts open; code had become the source of truth.
6. **Apps at 8%** were the longest pole to anything user-facing.
7. **A one-line barrel-export bug** silently disabled configurator validation for all external callers.
8. **Tooling/CI gaps** (crypto package never linted; static-analysis baseline stale) masked regressions.

> **Correction (2026-09-26, pre-push review):** the "2 CRITICAL + 8 HIGH" shorthand used above and in the table conflates numbers from different audit passes and undercounts the corpus — the 2026-05-19 synthesis names three distinct CRITICALs (C1, C2, C3) and the 2026-06-02 ledger adds a fourth net-new CRITICAL (F-1, Mode-F FSM tripwire defeat), plus 13 HIGH in its fix queue alone. At retirement, two CRITICALs were still live on the testnet deploy (C2 and F-1 — both fixed in source on 2026-06-02, never redeployed). The historical table above is preserved as written; the authoritative reconciliation is [`docs/audits/FINDING-RECONCILIATION.md`](../audits/FINDING-RECONCILIATION.md).

## Roadmap that was planned (never executed past its start)

- **Phase A** — ~30 design decisions unblocking build (HTTP client architecture, WebAuthn registration, operator auth, DB schema consolidation, module relay authorization, Composed-module scaffold, controlled-use contract designs, spec-alignment decisions).
- **Phase B** — the core runtime spine: persistence, auth wiring, SD-into-API, real attestation and registry reads, shred triple-block (~3 weeks estimated).
- **Phase C** — platform completeness: 10th condition module + controlled-use registries and profile, trigger relays, remaining use-case archetypes.
- **Phase D** — the four browser apps over a typed HTTP client.
- **Phase E** — hardening, observability, crash recovery, GDPR retention, legal guardrails in the configurator.
- **Phase F** — internal audit-and-check gauntlet (static analysis, fuzz/invariant suites, adversarial review loops, spec conformance).
- **Phase G** — externally gated items: vendor contracts, mainnet deploy decision, counsel engagement, the external paid audit, penetration test, bug bounty, entity formation. **None of Phase G was reached.**

The honest critical path to "first partner can run on it" was A → B → the subject and partner apps → a testnet smoke pass of the batched contract fixes. The project was retired before Phase B completed.

---

*Derived from an internal discovery-sweep document (11-agent fan-out, 3-way synthesis, deterministic render) dated 2026-06-06. Sanitized for public release: internal paths, tracking IDs, commit hashes, and named vendor candidates removed; audit claims corrected.*
