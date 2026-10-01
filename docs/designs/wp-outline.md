# Cealis V2 Whitepaper — Outline

**Date:** 2026-04-22 (reshaped from 2026-04-21 §1-§12 version; prior structure superseded).
**Status:** Drafting-mode outline. Updated iteratively as sections land.
**Audience:** us (internal project vision doc for own understanding, not external pitch artifact).
**Examples:** zero (avoids scope-lock on which use cases readers visualize).
**Naming:** V2 = system version. V3 = custody subsystem within V2. Never bare "V3" for the system.
**Voice target:** Simon's. Short declarative + "because" causal + claim→mechanism. No polish, no triples-of-three, no marketing superlatives. Lead (main context) voice-passes after drafting.
**Working file:** prose accumulates in `docs/specs/wp.md`.
**Length target:** ~45-55 pages total. Dense, honest, scannable.

---

## Organizing principle

Describe the system first. Features fall out as consequences. Pattern: *"X, because [the system is designed this way]."* Part 1 is descriptive. Part 2 is derivative. Never mix.

## Tripwire claim — every section defends this

**"No release path exists that bypasses the on-chain-verified predefined condition."**

Universal claim. NE/TP/CR all fall out of it — do not structure the WP around those three lenses. If any section implies a release bypass, it's wrong. The WP is one argument at multiple altitudes.

## Anti-patterns (hard blocks)

1. NE/TP/CR as structural triplet — simplification trap (stops looking for more views + enables misuse).
2. "Primary value prop per use case" categorization.
3. V1 framing leak: Cealis-operated committee, identity-escrow as system identity, 3-of-5 guardians as core, Reveal Manager as primary component, Tier 0/1/2 language, IBE master key.
4. Pitch-deck tone / compliance-brochure tone.
5. Marketing superlatives ("best," "most secure," "fully decentralized") or balanced-clause cadence or triples-of-three.
6. On-chain storage language (only commitment hashes on-chain; ciphertext off-chain).
7. Closed-system presentation (system has depth beyond what's articulated — §P closes with this).
8. Cealis-as-pure-open-source or Cealis-as-no-operator (correct: commercial operator of a protocol with named survival path).
9. Bare "V3" as system version (V2 system, V3 custody subsystem).
10. SD-as-mandatory (SD is parallel add-on, Mode A only, optional per PDA).

## Key framings locked 2026-04-22

- **Cealis's identity as company:** Cealis's protocol. Cealis charges for it. Commercial, not open-source software. "Platform" = PDA+ configurability claim (one system, many use cases via config) — NOT an open-source claim, NOT a decentralization claim. Worst-case: open-source possible. Vanish-path: if Cealis disappears, data already in the system can still be operated.
- **V3 custody property cluster ("web3-native"):** zero Cealis-held custody + disjoint-operator composition + on-chain-first orchestration + portable artifacts. "Simpler" = rent > build. Don't bloat simplicity into multiple dimensions.
- **Open-ended depth is explicit:** the WP states directly that more views/use cases/compositional expressions surface as thinking deepens. §P closes with this; §A acknowledges it; no section implies the system is fully enumerated.
- **Subject identity design:** per-partner namespace (cross-partner unlinkable), registration_nonce (destroyed on shred), σ_subject off-chain (AEAD-bound into commit_AAD), WebAuthn P-256 or EIP-712 wallet. Subject key recovery/rotation/multi-device is known-open, acknowledged as future work in-WP.

---

# Part 1 — The System

Describe the machine fully. No property claims — those live in Part 2.

## §A — System at a glance

Cealis as commercial protocol. Data escrow system. 4-gate AND-composition (Chain + Lit + dcipher/drand + Cealis G4). Age envelope ciphertext. Chain as authoritative coordinator.

Commercial identity: Cealis's protocol, Cealis charges for it, platform-as-PDA+ claim, survival path named (if Cealis vanishes, existing-data deployments continue).

Open-ended acknowledged: "the longer you think about Cealis the more views surface. This document is a current snapshot, not an exhaustive articulation."

Naming: V2 system with V3 custody as of 2026-04-22.

**Source:** primitives.md preamble + flows-spec-final.md §0 overview + session 2026-04-22 decisions.
**Length:** ~1 page.

## §B — Primitives

Full enumeration P0-P22 with dispositions (P12 DELETED, P16 PARKED, P17 NOT CARRIED FORWARD). Each primitive 2-4 sentences, stated as a commitment (what the system does — not a selling point).

Not a taxonomy. The set of commitments that compose to produce the system's behavior. New primitives from V3 integration flagged: P18 zero-custody, P19 disjoint-composition, P20 ingestion mode, P21 crypto-aging discipline, P22 σ-secrecy.

**Source:** primitives.md.
**Length:** ~5-7 pages.

## §C — Commit ceremony

Subject or partner initiates → G4 ingestion endpoint → Mode A (TEE-ingest, plaintext enters boundary and is encrypted; Phase 1 server with sealed-code + on-chain binary-hash registry OR Phase 2 rented TEE with DCAP) or Mode B (device-encrypt, subject's client constructs envelope locally) → age envelope with 4 recipient stanzas (Lit ACC + G3 + G4 + optional heir) → σ_subject signs over h_commit_preimage + PDA terms digest (AEAD-bound into commit_AAD, off-chain, cross-partner-unlinkable) → h_commit anchored on Base L1.

Ciphertext format: composite identity via SCALE-encoded HKDF IKM tuple, stanza-level MACs (combiner-bypass defense), ChaCha20-Poly1305 AEAD.

subject_commitment_v3 with per-partner namespace. authorizationId with client-generated nonce.

**Source:** flows-spec-final.md §0.1-§0.6, §1.1 + primitives P1, P18, P19, P20.
**Length:** ~3-4 pages.

## §D — Reveal ceremony

Lifecycle: PDA's ConditionEngine module fires → G1 emits `RevealAuthorized(authorizationId, h_commit, block#, ts)` + Base L1 finality (~13 min) → G2 Lit V3 Chipotle serving TEE signs σ_Lit → G3 (dcipher OR drand per PDA) signs σ_G3 → G4 independently reads chain + verifies ShredRegistry state + signs σ_G4 → recipient's combiner derives DEK via HKDF over SCALE-encoded signature tuple → age envelope decrypted → payload delivered to named recipient(s).

σ_G4 IS in HKDF IKM — G4 refusal is cryptographic halt (not procedural). Distinction: halt-capable, not alter-capable. Recipient-side combiner runs in hardened context; σ values are key material (not public verification tokens).

Challenge window (per-PDA, mechanically gated timeouts, not operator-overrideable).

Multi-recipient delivery via per-recipient stanzas with Merkle-rooted recipients[] in commit_AAD.

**Source:** flows-spec-final.md §0.1, §0.5, §1.2 + primitives P3, P8, P10, P22.
**Length:** ~4-5 pages.

## §E — Shred ceremony

On-chain shred is a contract state change on ShredRegistry. Triple block: (a) G1 `ConditionEngine.isConditionMet` returns false post-shred — no future `RevealAuthorized` events, (b) G4 reads ShredRegistry pre-attestation and refuses to sign σ_G4 — crypto-halts in-flight reveals because σ_G4 is in HKDF IKM, (c) vault physically deletes ciphertext after on-chain confirmation.

PDA-parametric shred authority: `shred_authority_id` ∈ {Subject, Joint, Operator, Timelock, Disabled}. Who can trigger shred is a per-PDA policy, not a system-wide guarantee.

Shred-first lifecycle bias where use case permits (minimizes ciphertext lifetime for future-crypto-break defense).

**Source:** flows-spec-final.md §0.8 + primitives P11, P21 + session 2026-04-17 (shred-authority is policy param).
**Length:** ~2-3 pages.

## §F — Configurability — PDA+ and PDA

Two-level configurability.

**Platform-level (PDA+):** ingestion mode availability (Mode A, Mode B, or both), condition module set supported, schema library, retention policies, shred guardrails, vault backend choices. Set by Cealis; what the platform offers.

**Per-partner (PDA):** schema, G3 choice (dcipher for regulated/KYC/M&A; drand for time-native/long-retention), phase (1 or 2 G4), recipients[], shred authority, challenge window duration, condition module selection. Set per partner; what the partner configures within what the platform offers.

ConditionEngine modules (pluggable, first-class): PaymentObligation, TimeLock, SubjectInitiated, HeartbeatMissed, OracleAttestation, MultiPartySignal, DeadManSwitch, ConsentGate, Composed. Named in §F; specs live in Interface-Closure v3 (blocked, out of WP scope).

Data-agnostic by construction. No enumerated catalog of supported schemas.

**Source:** primitives P4, P6, P7, P14, P15, P20 + flows-spec-final.md §0.2.
**Length:** ~2-3 pages.

## §G — Ingestion modes

Two ingestion modes are architected into the platform. One ships; the other is built-for but not currently enabled.

**Mode A — TEE-ingest (shipping default).** Plaintext uploaded to G4 endpoint. Phase 1: server with sealed-code + on-chain binary-hash registry + 7-day timelock on updates. Phase 2: rented AWS Nitro or equivalent TEE with DCAP verification. Plaintext processed inside boundary, encrypted into age envelope, destroyed post-processing. Supports SD pipeline (§H). Trust model: institutional attestation chain (§K).

**Mode B — Device-encrypt (architected as PDA+ capability, not currently enabled).** Platform is built to turn this on as a PDA+ option without protocol rework. When enabled, subject's client generates DEK locally, constructs full age envelope with Lit + G3 + G4 recipient stanzas on device, uploads ciphertext only — Cealis never sees plaintext. Trust model: cryptographic non-custody. Requires a crypto-capable client application (not a webform). Structurally incompatible with SD and with anything else that requires TEE-side plaintext access. When enabled, partner or subject picks via PDA or user UI.

**Why Mode A defaults in current deployment:** B2B partners send raw data through the API (backend-to-backend — no client-side crypto step available in that workflow) and the consumer-facing flow needs a webform-grade UX rather than a full app. Mode B requires an app and cannot serve either need. Mode B's architecture is preserved so privacy-primary use cases can enable it later as a PDA+ capability.

No hybrid mode.

**Source:** primitives P20 (to be restated with clarified Mode A shipping / Mode B architected-not-enabled scope) + flows-spec-final.md §0.1 + trust-framing.md §1 + session 2026-04-22 clarification on Mode B status.
**Length:** ~2-3 pages.

## §H — Selective disclosure (parallel pipeline)

Under Mode A, inside TEE at commit-time, SD pipeline emits cleartext + ZKP outputs for pre-specified fields or proven predicates. Parallel to escrow pipeline — does NOT extract from escrow. Shares DEK only for salt-derivation (never for decryption).

Incompatible with Mode B (plaintext never enters Cealis TEE under Mode B; client-side SD is future extension, not in scope).

Brief treatment here. Technical detail lives in SD-Closure v3 (pending; current SD-Closure is a V1-era internal doc, not in this export).

**Source:** primitives P5 + SD-Closure (current version, flagged as V1-era pending v3 revision).
**Length:** ~1-2 pages.

## §I — Provenance + attestation

**P14 Issuer modes.** Mode A external (KYC provider signs attestation; personKey = provider ID + per-subject nonce). Mode B self-sovereign (subject IS issuer; personKey = wallet + registration nonce). Mode C asset-not-person (depositor role; personKey = content hash + depositor nonce).

**P15 attestation-as-input.** Externally-attested data composes with self-declared data in a single PDA. Attestation travels as part of AAD. Per-PDA: which fields require which attestations.

Chain-of-custody extends backwards to data provenance — external attestor's trust chain becomes part of the commit record.

**Source:** primitives P14, P15 + flows-spec-final.md §0.6, §0.9.
**Length:** ~1-2 pages.

---

# Part 2 — What Follows

Abstractions. Properties derivable from Part 1. Trust framing. Threats. Storage and operational commitments. Limits. Depth.

## §J — Features derivable from the system

Each feature stated as *"X, because [Part 1 section reference]."* Comprehensive catalog from 2026-04-22 (43 items) curated during drafting. No "primary" features. No categorization. No NE/TP/CR triplet.

**Core properties (first altitude):** non-existence-until-condition · no-single-party-release-including-Cealis · on-chain-conditions-cannot-be-faked · tamper-proof · verifiable-deletion · subject-cryptographic-consent · cross-partner-privacy · inherent-chain-of-custody · named-recipient-delivery · halt-without-release · cryptographically-determined-reveal · data-agnostic · two-ingestion-modes · portable-artifacts.

**Derivable/operational (second altitude):** zero-Cealis-held-custody · disjoint-operator-composition · per-PDA-G3-choice · PDA-parametric-shred · configurable-conditions · PDA+/PDA-two-level · multi-recipient-delivery · mechanically-gated-dispute · provenance-extends-backwards · hybrid-PQ-at-commit · stanza-addition-re-key · phase-swappable-G4 · rental-cost-structure · different-reveal-paths-per-condition · structured-artifact-output · parallel-day-one-disclosure · delegated-identity-verification.

**Implicit/structural (third altitude — may be prose-inline, not listed):** σ_G4-crypto-enforced-halt · σ-as-key-material · architecturally-distributed-controller-relationship · composability (artifact as input to other obligation).

Open-ended markers (cross-reference to §P): additional compositional possibilities the primitives support but this WP doesn't enumerate.

**Source:** session 2026-04-22 feature catalog + cross-references to Part 1 sections.
**Length:** ~5-7 pages.

## §K — Trust framing

Mode A institutional attestation chain — 7 links named explicitly per `trust-framing.md §1`:
1. Trust Cealis's source-code claim
2. Trust reproducible-build process
3. Trust on-chain binary-hash registry (+ 7-day timelock)
4. Trust TEE attestation (DCAP)
5. Trust hardware vendor
6. Trust compiler toolchain
7. Trust external audit

For crypto-literate users: every link is verifiable — chain collapses to mathematical trust if verified.
For consumer users: chain collapses to institutional trust.

Mode B cryptographic non-custody — 2 links only:
1. Trust subject's own device + SDK
2. Trust gate attestations fetched pre-encryption

Honest posture per `trust-framing.md §3`: no blanket "V2 is cryptographically secure" claim; no "TEE = cryptographic proof" claim; no "we are GDPR-compliant" blanket; no "decentralized / no single point of control" claim without naming Cealis's halt + vault-availability capabilities; no "your data is safe forever" claim. Replace each with specific claims stating what's actually true.

**Source:** trust-framing.md.
**Length:** ~3-4 pages.

## §L — Threat catalog

**Defenses (10 items from threat-model.md §1):** single-party compromise · single-org compromise across gates · operator discretion errors · data tampering post-commit · classical cryptographic aging · user-initiated erasure · cross-partner linkability · quantum attack on single primitive · dormant/staggered single-gate key compromise · legal compulsion on single operator.

**Non-defenses (10 items from §2):** simultaneous multi-gate operator compromise · fundamental symmetric-break + long-retention exfiltration · compromised reveal-side combiner · TEE compromise at commit (Mode A) · subject-device compromise at commit (Mode B) · chain-level attack on Base L1 · side-channel/hardware attacks on TEEs · covert staged compromise over years · legal compulsion to SHRED (policy matter per PDA) · vault availability (Cealis shutdown).

**Out of scope (§3):** identity verification itself · eIDAS-QES · general predicate disclosure · subject device key recovery · content-level disputes ("is the data correct" — not Cealis's role).

Mapping: for each defense, which primitive carries it; for each non-defense, what mitigation exists and what residual remains. No hand-waving; no compliance-blanket claims.

**Source:** threat-model.md.
**Length:** ~5-7 pages. Heaviest section of the WP.

## §M — Storage + crypto-aging

**Off-chain vault** — Cealis-operated, hardened access control, append-only audit logs (§371a ZPO integrity), crypto-shred support, closed-source by explicit commit (not reflex transparency; interrogated against threat model).

**On-chain footprint** — h_commit, ConditionEngine state, G4AuthorityRegistry, PluginHashRegistry, LitV3Assignment records, ShredRegistry, event log. No plaintext, no ciphertext, no identifying data on-chain.

**Crypto-aging three-part commitment (P21):** hybrid post-quantum wrapping at commit (ML-KEM-768 + X25519) · periodic stanza-addition re-key ceremony adding new stanzas under fresh primitives (payload bytes never touched) · shred-first lifecycle bias.

**Considered-and-rejected:** on-chain vault (strictly worse on future-crypto-break axis) · open-source-vault-as-default (doesn't address the threats the vault actually faces) · information-theoretic security (not operationally realistic).

Honest closing: long-horizon safety is operational commitment to re-keying + aggressive shredding. Not a silver bullet.

**Source:** storage-discipline.md.
**Length:** ~3-4 pages.

## §N — Operational posture

**Phase 1 → Phase 2 swap discipline.** Phase 1 (launch, pre-funding): Cealis-hosted server with sealed-code + on-chain binary-hash registry + 7-day timelock on updates. Phase 2 (post-funding ~€250/mo): rented AWS Nitro or equivalent TEE. API-compatible drop-in. Commits made in Phase 1 remain valid under Phase 1 attestation post-cutover.

**Commodity-rental economic argument.** Staking a custody network to absorb $20M partner obligations requires $40-80M economic-security floor per partner. Unbootstrappable pre-funding. Commodity rental (Lit V3 ~$0.01/op + dcipher/drand per-tier + G4 ~€250/mo + vault ops) dissolves this constraint. Zero Cealis-operated staked network at any point.

**Minimum-viable launch: 3 gates (Chain + Lit V3 + G4).** G3 (dcipher OR drand) is extend-later if pricing/support blocks pilot. age-plugin-cealis-v3 HKDF SCALE tuple supports 2-4 signatures; 3-gate commits remain valid under 3-gate verification post-expansion to 4.

**Cealis's identity as company.** Commercial operator of the protocol. Charges for the service. "Platform" means PDA+ configurability — one system, many use cases via configuration — NOT an open-source commitment, NOT a decentralization claim. Worst-case: open-source is possible. Vanish-path is named explicitly: if Cealis disappears, data already in the system can still be operated (protocol composes rented commodities + chain + age envelope + plugin; existing deployments survive).

**Source:** flows-spec-final.md §0.7, §3.1, §3.2 + session 2026-04-22 company-identity lock.
**Length:** ~3-4 pages.

## §O — Limits

Structural limits. Not bugs. Naming them is the honest posture.

- Cannot operate without the chain (chain halt = system halt).
- Cannot gate on conditions not expressible on-chain or via signed oracle input.
- Cannot protect against TEE compromise at commit-time (Mode A).
- Cannot protect against subject-device compromise at commit-time (Mode B).
- Cannot generate new proofs about committed data post-commit (plaintext destroyed).
- Cannot verify identity itself (delegated to attestor/KYC provider — P14).
- Cannot issue eIDAS qualified electronic signatures (evidentiary only).
- Cannot offer fully general partial disclosure (each predicate needs a circuit; Mode B has no SD).
- Cannot fully erase if commitment format itself leaks information.
- Cannot protect against simultaneous compromise of Lit + G3 + G4 operator sets.
- Cannot protect against fundamental symmetric-cipher break + long-retention ciphertext exfiltration (mitigated by P21 stacking re-key, not eliminated).
- Cannot protect against compromised reveal-side combiner (mitigated by P22 σ-secrecy discipline, not eliminated).

**Source:** primitives.md LIMITS section.
**Length:** ~2 pages.

## §P — Open-ended depth

The system has more in it than this document articulates. Views surface as thinking deepens. Use cases grow without protocol change. Compositional possibilities visible in the primitives but not exhaustively enumerated here.

Named examples (non-exhaustive): time-locked reveals · subject-initiated reveals · compositional enforcement chains (artifact-as-input to another obligation) · threat-activated reveals · dead-man's-switch at primitive level · progressive/multi-stage reveals · configuration transparency (trigger-abuse visibility) · TEE boundary hardening variants.

Closed: primitives · ceremonies · threat model.
Open: use cases · views · compositional expressions.

This document is a snapshot, not a closed specification. It is expected to grow.

**Source:** session 2026-04-22 open-ended-explicit decision + a working note (not included in this export).
**Length:** ~1-2 pages.

---

## Back matter

- Glossary (brief).
- References: flows-spec-final.md, primitives.md, threat-model.md, trust-framing.md, storage-discipline.md, SD-Closure.md (not included in this export).
- Version note: V2 system with V3 custody as of 2026-04-22. Living document — gaps flagged as open items are designed later and baked in.

---

## Drafting sequence

1. §A (system at a glance) — altitude-setter
2. §B (primitives) — mechanical, source doc exists
3. §C (commit ceremony)
4. §D (reveal ceremony)
5. §E (shred ceremony)
6. §F (configurability)
7. §G (ingestion modes)
8. §H (SD parallel pipeline)
9. §I (provenance + attestation)
10. §J (features derivable) — requires Part 1 complete
11. §K (trust framing)
12. §L (threat catalog)
13. §M (storage + crypto-aging)
14. §N (operational posture)
15. §O (limits)
16. §P (open-ended depth)

Integration pass after §P. Voice-pass by Simon last.

## Team

- **Lead:** Claude main-context — briefs builder, routes to challenger, integrates, coordinates.
- **wp-builder:** drafts sections on brief. Opus. Plan-mode. Writes to `wp.md`.
- **wp-challenger:** stress-tests drafted sections against 12-test anti-drift framework. Opus. Plan-mode. Read-only. Returns structured findings.

## Living history

Prior outline (2026-04-21 §1-§12 structure with dense-but-single-flat-pass organization) is superseded by this Part 1 / Part 2 reshape. The earlier version and the session logs that capture the V2 design journey are preserved in the private archive (not included in this export).
