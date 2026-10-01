# Conditional Sealing

[![CI](https://github.com/simbal21/conditional-sealing/actions/workflows/ci.yml/badge.svg)](https://github.com/simbal21/conditional-sealing/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue.svg)](LICENSE) [![Docs: CC BY 4.0](https://img.shields.io/badge/docs-CC%20BY%204.0-lightgrey.svg)](docs/LICENSE)

**Escrow with no escrow agent — sealed data that unlocks only when an agreed, chain-verified condition is met.**

**What this is:** a case study in building and then killing a system. I spent three months designing and building *conditional sealing* — data encrypted once, reopenable only when a public blockchain confirms a pre-agreed rule has come true, with no master key anywhere. Before launch I wrote down a falsifiable demand test — the Fundability Fingerprint, six conditions that must all hold, fixed before I ran it — then applied it to 157 candidate companies and use cases. It returned **zero clean fits**. I retired the project on that evidence (2026-06-10). The [post-mortem essay](docs/postmortem.md) — also published at [simonbaltes.com/conditional-sealing](https://simonbaltes.com/conditional-sealing/) — is the primary artifact of this release; this repository is its evidence and archive: the design record, the tested cryptographic core, and the demand-study data.

> **A note on the name:** Cealis was the internal working title during development only — this system was designed and built March–June 2026 under that name. It is released as **conditional-sealing**; the working name is preserved unchanged throughout the specifications, audit records, smart-contract sources, and cryptographic domain-separation tags, because those are the factual record of the system as built and as deployed on-chain. This includes the `@cealis/*` package names inside the monorepo, which are internal workspace names kept deliberately (renaming them would break the build graph) and are not published to npm. The Cealis name and domain remain with the author for future, unrelated projects.

> **Snapshot, June 2026:** everything here reflects the state at retirement on 2026-06-10. The external networks this design depends on (Lit Protocol, drand/dcipher, Base Sepolia) have evolved since and were never live-integrated; configuration names, network identifiers, and endpoints in the code may no longer exist. The hosting used for the pilot was deleted after retirement.

> **Read this first:** this repository is published with its limitations stated up front. It was never externally audited, never run in production, and never held real user data. The on-chain components live on a public testnet only. See [What this is not](#what-this-is-not) before drawing any conclusion about security or completeness.

## What this is not

- **Never externally audited.** Two internal adversarial audit passes (2026-05-14, 2026-06-02), a 2026-05-19 synthesis and a 2026-06-03 honest-audit rewrite found multiple CRITICAL and HIGH findings; the corpus names four distinct CRITICAL findings over time (C1, C2, C3, F-1) — see the [finding reconciliation](docs/audits/FINDING-RECONCILIATION.md). Two of them, C2 (permissionless challenge-open) and F-1 (Mode-F FSM tripwire defeat), were fixed in source on 2026-06-02 but never redeployed: the live testnet contracts still contain both. No third party has reviewed this code.
- **Never production.** The runtime ran on in-memory mocks; the apps were never built.
- **No real data, ever.** Zero users, zero customers.
- **Retired 2026-06-10.** Not maintained; accepts no production use.

### Live-contract drift disclaimer

The Base Sepolia deployment is a **testnet-only historical proof-of-deployment**, made **before** the 2026-06-02 source-level fixes: the live contracts contain at least one CRITICAL finding fixed only in source, and deployed bytecode and this repository are not in sync. Administrative keys are not under secure management. Treat the on-chain contracts purely as a record of deployment and verification — never as secure, current, maintained, or a basis for real-value use. Deployment references repo-wide point back here (canonical copy: `deployments/README.md`).

## What is safe to reuse

| You want | Go to | Terms |
|---|---|---|
| The strongest code (sealing primitives, envelope, key split) | [`v3-crypto/`](v3-crypto/README.md) | Apache-2.0; review before use |
| The specification and design corpus | `docs/specs/`, `docs/designs/` | CC BY 4.0 |
| The methodology and kill-test | `docs/research/` | CC BY 4.0 |

## How to read this repository

- **60 seconds:** the [status table](#status-cryptographically-real-operationally-unfinished) and [What this is not](#what-this-is-not) — what is real, what is stubbed, what was never audited.
- **The design, one sitting:** [`WHITEPAPER.md`](WHITEPAPER.md).
- **The design and evaluation note:** [`docs/paper.md`](docs/paper.md) — construction, verification record, and the 0/157 demand study.
- **The strongest code:** [`v3-crypto/`](v3-crypto/README.md) — golden-fixture-tested sealing primitives.
- **The story and the kill:** [`docs/evolution.md`](docs/evolution.md), then the [post-mortem essay](docs/postmortem.md).
- **What a successor should build:** [`FUTURE-WORK.md`](FUTURE-WORK.md).
- **What we got wrong:** [`ERRATA.md`](ERRATA.md) — corrections found by adversarial review before publication, including one in the cryptographic core.
- **Run it:** [`GETTING-STARTED.md`](GETTING-STARTED.md).

---

## What it is

Conditional Sealing encrypts a payload once, then splits the decryption key across three independent signing "gates", all locked behind a fourth — the chain — in strict AND logic (the code's own mode name: `FULL_4GATE`): no single party — including the operator, the entity that would have run the service — holds a working key, and no decryption path routes around the chain. At retirement, all "independent" parties were in fact simulated inside one process on one machine. Each seal carries a machine-checkable condition (a date passing, an oracle attesting an event, a holder going silent, a contract reaching a state); a public blockchain, not a human, decides whether it is true. When it fires, the gates sign, the key reassembles, and the data is delivered with an on-chain custody record. That flow — and the no-working-key-anywhere property it rests on — is the architecture's intent, not a demonstrated capability: the gate signing transports were stubbed at retirement ([Status](#status-cryptographically-real-operationally-unfinished)).

- **G1 — the chain.** A `ConditionEngine` contract (Base Sepolia testnet only) evaluates the condition.
- **G2 — Lit Protocol,** a rented threshold/TEE network, signs once release evidence is present. The design binds it to the contract's `RevealAuthorized` event and adapter code exists; the live connection to the external network was simulated — designed and partly coded, never connected.
- **G3 — drand or dcipher** (fixed per deployment at commit): drand attests time (tlock-style), not arbitrary events; dcipher (Randamu) is the path to richer condition attestation. Live transport simulated, as with G2.
- **G4 — a refusal-only operator verifier:** may refuse on narrow legal, GDPR, or integrity grounds; cannot open anything; alone, below the reconstruction threshold. Because G4 holds one of the three required shares, its refusal blocks any release — even when G1, G2 and G3 agree. That veto is the intended design, not a flaw.

**Cryptographic core:** ChaCha20-Poly1305 AEAD payload; GF(2⁸) Shamir split of the data-encryption key; hybrid post-quantum share wrap (X25519 + ML-KEM-768); a custom `age`-plugin envelope with per-stanza MACs.

### Custody claims

Non-custody by design — no operator-held master key for the fixed gates — with two qualifications: the AND combiner is real and adversarially tested, but the live transports to external gate operators were never finished; and the organizationally, jurisdictionally, and TEE-vendor-disjoint operator posture was designed, never demonstrated against live networks. This README therefore avoids "decentralized," unqualified "non-custodial," and any cannot-be-compelled-or-blocked claim — G4 is refusal-capable and the runtime was operator-run (banned list: [Self-audit record](#self-audit-record)).

---

## Status: cryptographically real, operationally unfinished

Verdict verbatim from the state-at-retirement assessment; subsystem descriptions in [Repository layout](#repository-layout).

| Subsystem | State | Reality at retirement |
|---|---|---|
| `v3-crypto` | **real & tested** | Golden-vector tested against locked fixtures (catalog: [`v3-crypto/README.md`](v3-crypto/README.md)); constant-time by construction in the field arithmetic — best-effort under a JIT'd, garbage-collected JavaScript runtime. Three internal stubs remain fail-closed (they throw rather than implement): dcipher-verify, G4 Phase-2 DCAP-verify, and QES-verify |
| `v3-custody` | **partial** | Combiner real, adversarially tested; external signing transports stubbed (simulated) |
| `contracts` | **partial** | Strong test discipline; live testnet deploy predates the security fixes |
| `v3-configurator` | **partial** | Logic present; a barrel export shipped a no-op validator (exact defect + safe import: [`v3-configurator/README.md`](v3-configurator/README.md)) |
| `v3-sd` | **partial** | Real cryptography, not wired into the API |
| `v3-api` / runtime | **partial** | Boots once, on in-memory stores with unwired auth |
| apps / UI (partner console, onboarding, proof-check — never scaffolded in this repository) | **not built** | No browser UI; nothing calls the API over HTTP |
| `verify-sdk` | **not built** | Independence asserted, not delivered (stub) |

---

## Scale, and what it does not mean

These figures exist so that specific claims here can be checked. They are **not** a measure of personal effort or skill: the code and the specification corpus were produced by AI agents working under my direction. Volume measures generated output. What is mine is the design, the sequencing, the verification discipline, and the decision to stop.

- **Live on-chain:** 32 contracts on Base Sepolia, entry point the `ConditionEngine` proxy `0xb09a8300423CA3BD0E028bAB6A6245A248520D02`. The implementation contracts are Sourcify-verified (exact_match); the proxies are not — to check, look up the implementation address in [`deployments/base-sepolia-verification.json`](deployments/base-sepolia-verification.json). Testnet only — see the [drift disclaimer](#live-contract-drift-disclaimer).
- **Demand study:** 0 clean fits out of 157 candidates — the load-bearing number, identical across every internal record (methodology and aggregates: `docs/research/`).

The build ran ~3 months (2026-03-13 → 2026-06-10) as a pipeline of specification-first work packages with staged verification between phases. **This repository is published with a fresh, single-commit history.** The original history is not included and cannot be — it contains live credentials and personal data. Any claim about the build process therefore rests on the source tree and the test record, not on a commit log you can inspect. Corrections found before publication are recorded in [`ERRATA.md`](ERRATA.md).

---

## Where this sits

Conditional sealing is a committee-based, practical relative of witness encryption (Garg–Gentry–Sahai–Waters, 2013): rented threshold committees bound to an on-chain condition. It differs from pure timelock encryption (drand tlock), which attests only time, by supporting arbitrary on-chain conditions; from Lit Protocol alone by AND-composing multiple independent networks plus a refusal-only gate, so no single threshold network is trusted; and it sits adjacent to Safe/Zodiac-style programmable custody and to Zama-style FHE, which computes on ciphertext — a different primitive. Full comparison: Related Work in [`WHITEPAPER.md`](WHITEPAPER.md).

The design and evaluation note — construction, verification record, and the 0/157 demand study in one document — is [`docs/paper.md`](docs/paper.md).

How the design got here — the guardian-committee V1, the rent-don't-run reset, and the two mid-build reversals — is traced in [`docs/evolution.md`](docs/evolution.md).

---

## Self-audit record

- **A withdrawn 5.00/5 self-grade.** An early self-assessment scored the contracts 5.00/5 on the Trail-of-Bits 9-category framework; a later rewrite withdrew it to **≈3.5/5** — the original had counted self-authored documentation as audit maturity — and instructed: never cite the 5.00/5. See `docs/audits/MATURITY-SCORECARD.md`.
- **Internal adversarial self-review** over contracts and crypto (the two audit passes, the synthesis and the honest-audit rewrite above); findings, including the CRITICAL/HIGH set, in `docs/audits/`.
- **A banned-phrasings list:** "non-custodial" (unqualified), "decentralized," "a subpoena can't open it," "no one can block it." This README inherits it.
- **A kill-test:** a falsifiable, paper-only demand filter (the "Fundability Fingerprint," a strict 6-condition AND test) run over 157 companies found **0 clean fits.** The six conditions, all mandatory at once: the data stays dark until trigger; the trigger is objective and machine-verifiable; no standing legal duty to produce the data early; non-custody is the hard requirement, not a nice-to-have; a paying, motivated check-writer exists; no cheap trustless incumbent already owns the slot. I killed the project on that evidence.

---

## Why it was retired

A **demand-side scissor, not technology.** Trigger objectivity and willingness to pay are negatively correlated: where the trigger is objective (on-chain), customers are small, unpaying, and already served by trustless incumbents (Safe/Zodiac, Sablier); where customers pay (regulated enterprises), the trigger is subjective *and* a standing legal duty requires live access to their own data. Meanwhile the far better-funded confidential-compute category (Zama: FHE + threshold KMS, mainnet Dec 2025) shipped the commodity version of the primitive.

**Post-mortem essay:** [`docs/postmortem.md`](docs/postmortem.md). Methodology and aggregates: `docs/research/`. What survived the kill test and what a successor should build: [`FUTURE-WORK.md`](FUTURE-WORK.md).

---

## Repository layout

```
.
├── contracts/          # Foundry — ConditionEngine + 9 modules + registries + governance
├── v3-crypto/          # Sealing primitives, age-plugin envelope, Shamir + hybrid-PQ wrap
├── v3-custody/         # The 4-gate AND combiner
├── v3-sd/              # Selective disclosure (Poseidon + PLONK)
├── v3-api/             # Fastify ingestion / delivery server
├── v3-configurator/    # Per-partner policy (PDA) validation
├── v3-ops/             # Key-ceremony procedures
├── v3-demo/            # End-to-end demo harness
├── verify-sdk/         # Offline independent verifier (stub)
├── deployments/        # base-sepolia.json + verification map + drift disclaimer
├── docs/               # specs/ (whitepaper + 8 Stage-2 specs), designs/ (ADRs),
│                       # audits/, research/, state-at-retirement/,
│                       # paper.md, evolution.md, postmortem.md
├── WHITEPAPER.md       # One-sitting edition of the spec corpus
├── ARCHITECTURE.md     # Repo-level map (explicit about stubs)
├── FUTURE-WORK.md      # What survived the kill test; directions for a successor
├── ERRATA.md           # Pre-publication corrections (crypto claim, drand path, disclosure)
├── SECURITY.md
├── CITATION.cff
├── LICENSE
└── NOTICE
```

Run it: `GETTING-STARTED.md`. Contributions: `CONTRIBUTING.md` (short version: fork it). Reading paths: [How to read this repository](#how-to-read-this-repository).

---

## How to cite

Use [`CITATION.cff`](CITATION.cff) (GitHub renders a "Cite this repository" button), or cite the design via `WHITEPAPER.md` (full corpus: `docs/specs/`). Copy-paste forms:

> Baltes, S. (2026). *Conditional Sealing: a reference implementation* (version 1.0.0-archive) [Software, archived]. https://github.com/simbal21/conditional-sealing — developed under the working name Cealis.

> Baltes, S. (2026). *Conditional Sealing: Threshold-Gated Data Escrow with an On-Chain Release Trigger — Design and Evaluation Note.* In `docs/paper.md` of the conditional-sealing repository. https://github.com/simbal21/conditional-sealing

---

## License

**Code:** Apache-2.0, chosen for its explicit patent grant over the cryptographic implementation. **Docs and specs:** CC BY 4.0. See `LICENSE` and `NOTICE`. This is an archived reference release, not a maintained project.
