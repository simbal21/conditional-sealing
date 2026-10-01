# V2 Primitives — V2-WP Draft (with V3 custody integrated)

**Status:** Draft for V2 WP. V3 custody architecture (Apr 21) integrated. P16/P17 dispositioned, P12 deleted, new primitives P18-P22 added. Pending Simon's final framing-voice pass on any primitive.
**Origination:** 2026-04-17 (initial draft P0-P15) · **Revision:** 2026-04-21 (V3 custody integration + new primitives)
**Context:** Internal session transcript + system-audit synthesis (not included in this export). V3 custody decisions in `flows-spec-final.md` + the p16-p17 alignment working file (not included in this export). Session-log captures in the v2-state working file §7 (not included in this export).
**Naming note:** V2 = system version. V3 = custody/key-holding subsystem within V2. When this doc says "V3 custody" it means the key-holding architecture; when it says "V2 WP" it means the whole system.

---

## P0. Chain as orchestrator.
The system IS on-chain, calling off-chain components. Every primitive below is coordinated, gated, or verified through the chain. Remove chain → nothing functions.

## P1. TEE-bounded commit with subject-assent.
Default ingestion mode (TEE-ingest, per P20 mode A): plaintext enters Cealis TEE via authenticated upload — Phase 1 server (sealed-code + on-chain binary-hash registry) / Phase 2 rented TEE (DCAP-verifiable). Inside: plaintext processed + encrypted into DEK-sealed age envelope with gate-recipient stanzas (Lit + G3 + G4 + optional heir). Plaintext destroyed after TEE processing. Subject signs σ_subject (WebAuthn passkey P-256 or EIP-712 wallet) over `h_commit_preimage + PDA terms digest`; σ_subject stays off-chain, AEAD-bound into commit_AAD, cross-partner-unlinkable by construction. Alternative ingestion mode B (device-encrypt, per P20): subject's client constructs the envelope locally, Cealis never sees plaintext — subject-assent signature applies identically.

## P2. Off-chain sealed vault.
Ciphertext leaves TEE (or leaves subject device under mode B), stored off-chain. Off-chain because on-chain permanence combined with future-crypto-break risk makes public-by-default storage strictly worse for long-retention data (see A6 future-crypto-break threat pairing). Vault operator runs hardened infrastructure with access control; vault code is closed-source by explicit commit (not a transparency reflex — see storage-discipline.md for threat-model reasoning).

## P3. Chain-gated custody — crypto-enforced via 4-gate AND-composition.
DEK is derived via `age-plugin-cealis-v3` from SCALE-encoded tuple of signatures from 4 disjoint-operator gates:
- **G1 Chain** — Cealis ConditionEngine SC on Base L1. Event `RevealAuthorized(authorizationId, h_commit, block#, ts)` emitted when PDA's condition module fires. Gate status is event-visible, not a signature input.
- **G2 Lit V3 Chipotle** — rented commodity, ~30 permissionless operators, per-request TEE signs σ_Lit.
- **G3 dcipher OR drand** — rented commodity, per-PDA choice; threshold signature σ_G3.
- **G4 Cealis verification component** — Phase 1 server (Ed25519 sealed-code) / Phase 2 rented TEE (DCAP); signs σ_G4 in HKDF IKM.

`DEK = HKDF(salt=TAG_COMPOSITE_IDENTITY_V3‖authorizationId‖h_commit, ikm=SCALE{σ_Lit, σ_G3, σ_G4[, σ_heir]})`. All signatures required; no 3-of-4 subset derives DEK. Crypto-enforced against any single-party compromise. Full bypass requires compromising Lit + G3 + G4 operators simultaneously. Authoritative spec: `flows-spec-final.md` §0.5.

## P4. Parameterizable gate condition via ConditionEngine (attestation-universal primitive + FSM orchestration).
On-chain condition authorizing reconstruction is a single primitive: `AttestationGate`. Verifies a signed attestation from a PDA-designated oracle against a frozen Claim expression (small DSL of comparison, boolean, path-access, and time-window operators). Each PDA's condition is a finite state machine orchestrating which AttestationGate the PDA is waiting on next; the FSM reaches a terminal firing state and ConditionEngine emits `RevealAuthorized`. Evaluation is permissionless-push — authorized submitters (default: the oracle itself) advance the FSM by submitting attestations on-chain. New condition domains extend the palette by onboarding new oracles to `OracleRegistry`, not by forking the system. Three trust tiers per condition class — chain-native facts, commodity-oracle facts, bespoke-oracle facts — declared per PDA and carried in the artifact bundle. Full architecture in WP §F.

## P5. Optional independent side-channel disclosure.
At commit-time, inside TEE, specific fields or proven predicates emitted — cleartext or ZK proofs — via pipeline running independently from sealed-core. Off by default per partner. Shares DEK for salt-derivation only, never decryption. Predicate menu extensible. **Compatible with ingestion mode A (TEE-ingest). INCOMPATIBLE with mode B (device-encrypt)** — plaintext never enters Cealis TEE under mode B, so TEE-side SD cannot run. Client-side SD (on-device ZK proof generation) is a future extension, not in current scope.

## P6. Two-level platform configurability.
Cealis configures the system for a deployment (schema, condition module set, retention, side-channel defaults, shred guardrails, ingestion mode availability). Partner configures PDA within that deployment (schema, G3 choice, phase, recipients, shred authority, challenge window, condition module). **No enumerated catalog of use cases** — new configurations happen by config, not by registry. Some configurations are platform-level (PDA+, see P20) and sit above per-PDA config.

## P7. Schema-polymorphic payload.
System makes zero assumptions about what data is being committed. Each PDA declares its own schema, AAD construction, attestation requirements. **No registry of "supported schemas."** Data-agnostic by construction.

## P8. Multi-recipient delivery.
On gate-fire, reconstructed payload delivered to N recipients via N re-encryptions under N distinct recipient keys. `recipients[]` Merkle-rooted in commit_AAD, first-class in artifact bundle. Per-recipient schema-selector for partial delivery. Single-recipient is length-1.

## P9. On-chain chain-of-custody (inherent).
Because chain orchestrates lifecycle, every event is inherently on-chain — commit, disclose, gate-fire, challenge-open, challenge-resolve, release, deliver, shred. Not logged to chain; happens on chain. Reveal artifact composes from on-chain events + decrypted payload.

## P10. Optional challenge window.
Between gate-firing and release-executing, a configurable window lets a party dispute. Resolution on-chain and mechanically gated — timeouts/dismissals are deterministic, not operator-overrideable. Per-PDA: default case = 14-day window + bond; testament = no window; archival = no window.

## P11. On-chain shred event with PDA-configured guardrails.
Shred is a contract state change that permanently blocks decryption-key issuance for a commitment. Triple block: (a) G1 `ConditionEngine.isConditionMet` returns false post-shred (no future `RevealAuthorized`), (b) G4 reads `ShredRegistry` pre-attestation and refuses to sign σ_G4 — **crypto-halts in-flight reveals via σ_G4-in-IKM**, (c) vault physically deletes ciphertext after on-chain confirmation. PDA defines guardrails: who can trigger (subject by default, or Joint / Operator / Timelock / Disabled), under what constraints, jurisdictional overrides. Privacy-first framing.

## P12 (DELETED under V3 — 2026-04-21). ~~Custodian-topology independence.~~
V3 has no Cealis-operated committee. Substrate-independence is now carried by **P19** (Disjoint-operator composition). Original V2 framing: see archived disposition notes (not included in this export).

## P13. No operator discretion over reveal content or outcome.
All administrative work (configure PDAs, manage onboarding, monitor) is dashboard + API-key — normal SaaS admin. **Reveal-content operations are cryptographically determined** by chain events + gate signatures + subject's commitment data. Operator powers that do exist — G4 refusal (crypto-enforced halt on legal / GDPR / integrity grounds) and vault availability (Cealis runs the vault; can go down or be legally compelled to stop serving) — are bounded to halt-or-allow. They never alter what a valid reveal contains; they only stop-or-allow the reveal from completing. No human decides whether a default is real; no human overrides a gate to grant or deny a specific party; no human redacts reveal output. Availability is a separate axis from correctness.

## P14. Optional Issuer role.
Mode A (KYC-flagship): external Issuer signs attestation; personKey from provider ID + per-subject nonce. Mode B (subject-self): subject IS issuer; personKey from wallet + registration nonce. Mode C (asset, not person): depositor role; key from content hash + depositor nonce.

## P15. Attestation-as-input.
Data going into commit can be self-declared (trust = subject only) or externally attested (trust = signer's audit trail). Attestation travels as part of AAD. Per-PDA: which fields require which attestations. Extends chain-of-custody to data provenance.

## P16 (PARKED FOR REDESIGN under V3 — 2026-04-21). ~~Auditable committee.~~
Not a V2-WP primitive. Original V2 framing assumed a Cealis-operated committee V3 custody eliminated. Proposed G4-liveness-beacon redesign dropped 2026-04-21 (Simon: V3 as-specified is enough; client-side fail-closed on stale attestation already absorbs the threat without a separate primitive). File stays for potential future redesign. Full disposition: archived working notes (not included in this export).

## P17 (NOT CARRIED FORWARD under V3 — 2026-04-21). ~~Tamper-responsive custody.~~
Not a V2-WP primitive. Was V2's Cealis-committee-defense descriptive package; V3 eliminated the target. Defense-in-depth carried natively by P3 (4-gate AND) + P11 (shred cascade) + P19 (disjoint-operator composition). Full disposition: archived working notes (not included in this export).

## P18. Zero Cealis-operated custody.
Cealis holds no decryption-capable key material at any point in the commit, reveal, or storage lifecycle. No Cealis-operated staked custody network. No Cealis-held master key, threshold share, or long-lived decryption key. The only Cealis-controlled signing capability is the G4 authority key (Ed25519 Phase 1 / TEE-sealed Phase 2), which signs σ_G4 — one of four required HKDF IKM inputs. σ_G4 alone does NOT yield DEK; reveal also requires σ_Lit from Lit operators (disjoint) and σ_G3 from dcipher/drand operators (disjoint). Cealis cannot unilaterally decrypt any commitment. Economic rationale: staking a custody network to absorb $20M partner obligations requires a $40-80M economic-security floor per partner — unbootstrappable pre-funding. Commodity-rental substrate dissolves this constraint.

## P19. Disjoint-operator composition.
Gate operators are selected so the cost of compromising the substrate scales multiplicatively, not additively. Specifically: (a) **organizationally disjoint** — Lit Protocol operators, Randamu Threshold Association (dcipher) or League of Entropy (drand) nodes, Cealis (G4) are separate legal entities; (b) **jurisdictionally disjoint** — permissionless global pool for Lit, Swiss association or international public good for G3, Cealis entity for G4; (c) **TEE-vendor disjoint** — spec-mandated cross-vendor between G2 Lit's serving TEE and G4 Phase 2 TEE (A11 fix per `flows-spec-final.md` §0.7). Compromise of any single organization yields no decryption capability (enforced by P3's AND-composition math). Compromise across organizations requires visible multi-party coordination, cross-jurisdictional legal processes, and multi-vendor hardware attacks simultaneously. Defense-in-depth via substrate composition, not hardware layering.

## P20. Ingestion mode as platform-configuration (PDA+).
Platform supports two ingestion modes, selected per PDA at deployment:
- **Mode A (TEE-ingest).** Plaintext uploaded to G4 endpoint (Phase 1 server / Phase 2 TEE), Cealis encrypts inside boundary, plaintext destroyed post-processing. Trust model: institutional attestation chain (see A5 trust-framing) — for crypto-literate users the chain is verifiable, for consumer users it's institutional trust. Supports P5 SD. Simpler client.
- **Mode B (device-encrypt).** Subject's client generates DEK, constructs full age envelope with Lit + G3 + G4 recipient stanzas locally, uploads ciphertext only. Cealis never sees plaintext. Trust model: cryptographic non-custody — a one-step proof that Cealis mathematically cannot see plaintext. Incompatible with P5 SD. Requires crypto-capable client SDK; device must verify gate attestations before encrypting.

Partner or subject selects mode at PDA onboarding. Mode is platform-level configuration (the platform either supports B or doesn't); PDA parameter selects between supported modes. Privacy-primary use cases (testament, journalism, medical, whistleblowing) default to mode B; B2B KYC / field-extraction / SD-dependent use cases default to mode A. No hybrid mode.

## P21. Crypto-aging operational discipline.
Cryptographic primitives age; long-retention ciphertext must outlive any single primitive. Platform commits to three-part discipline:
- **Hybrid post-quantum wrapping at commit.** All asymmetric stanza encryption uses ML-KEM-768 + X25519 hybrid (per `flows-spec-final.md` §0.12). Attacker needs BOTH primitives to fail to extract DEK from stanzas.
- **Periodic stanza-addition re-key ceremony.** As primitives weaken, gate operators participate in a ceremony that adds a new stanza under fresh primitives to existing commitments. Payload stays encrypted under original DEK + symmetric primitive (ChaCha20-Poly1305, believed-secure for decades including against Grover speedup). Only key-wrapping is re-done; data bytes never re-encrypted.
- **Shred-first lifecycle bias.** For PDAs where early shredding is compatible with the use case, shred ASAP to minimize the window during which ciphertext exists. Shortest-lived ciphertext has the smallest attack surface against future crypto breaks.

Addresses the future-crypto-break + prior-breach threat pairing (A6). Operational commitment in the WP, not a silver-bullet claim.

## P22. Reveal-side signature secrecy.
Under V3 custody's HKDF construction, gate signatures σ_Lit / σ_G3 / σ_G4 are key material, not traditional public verification tokens. Anyone observing all three σ values can derive DEK via HKDF. Platform discipline: σ values are delivered confidentially to the recipient's combiner over authenticated encrypted channels (mutual TLS, Noise, or equivalent); never published on-chain; never logged in transit; never cached in intermediate systems. Recipient's combiner runs in a hardened execution context appropriate to the use case (TEE or HSM for regulated-compliance recipients; audited process memory with explicit risk statement for consumer recipients). Reveal operation is a one-shot exposure inside the hardened context; DEK does not persist post-decryption.

## P23. Finite state machine as condition-orchestration primitive.
A PDA's condition is a finite state machine with states, transitions (each gated by a specific AttestationGate), and terminal firing states. FSM spec is public-by-design, lives on IPFS with multi-pin redundancy (Cealis primary + partner mirror + optional Filecoin deal), and its hash is bound into `pda_root` → `h_commit`, so any post-commit FSM swap fails both the advance-time hash check and the reveal-time AEAD. Per-transition submitter authorization is declared at commit — default oracle-self-only, optionally widened to a PDA-declared relayer set — bounding permissionless-push griefing. Multi-stage conditions (dispute windows, cures, grace periods, M&A milestones) are native; boolean trees collapse into degenerate single-state FSMs. Reachability + gas-budget analysis at configurator-emission time, authorized by the Cealis-internal configurator before deploy.

## P24. Per-PDA pause as bounded bug-response primitive.
Distinct from shred. A PDA declares `pause_authority` (partner, joint subject+partner, or none). The authorized party calls `pausePDA(authId, reason, duration_max_90d)` to block FSM advancement without altering reveal content. On-chain visible; auto-lifts after duration or explicit unpause. Purpose: respond to discovered vulnerabilities in AttestationGate, OracleRegistry entries, or oracle operator compromises before full shred becomes warranted. Does not alter reveal correctness — only halts, per P13's halt-or-allow bound on operator powers.

---

## LIMITS — what the system cannot do

- Operate without the chain (chain halt = system halt).
- Gate on conditions not expressible on-chain or via signed oracle input.
- Protect against TEE compromise at commit-time (under mode A).
- Protect against subject-device compromise at commit-time (under mode B).
- Generate new proofs about committed data post-commit (plaintext destroyed).
- Verify identity itself — delegated to attestor / KYC provider.
- Issue eIDAS qualified electronic signatures (evidentiary only).
- Offer fully general partial disclosure — each predicate needs a circuit; mode B has no SD.
- Fully erase if commitment format itself leaks information.
- Protect against simultaneous compromise of Lit + G3 + G4 operator sets (full bypass).
- Protect against fundamental break in symmetric cipher + long-retention ciphertext exfiltration (mitigated by P21 stacking re-key, not eliminated).
- Protect against compromised reveal-side combiner (mitigated by P22 secrecy discipline, not eliminated).

---

## Notes

- Naming of "ConditionEngine" may change (Interface-Closure v3 decision).
- Attack model catalog: `threat-model.md` (Phase D1, to be written).
- Trust-framing doc: `trust-framing.md` (Phase D2, to be written).
- Storage discipline doc: `storage-discipline.md` (Phase D4, to be written).
- IBE design brief (archived working file, not included in this export) — historical V2-era context for why V2 → V3 custody pivot happened.
- Source corpus for WP voice: archived working file (not included in this export).
- WP example strategy: **zero examples** (Simon 2026-04-21 — avoids scope-lock on which use cases readers visualize).
- WP audience: **us** (internal project vision doc for own understanding, not external pitch artifact).
