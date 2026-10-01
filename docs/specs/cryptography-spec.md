# Cealis V2 System, V3 Custody — Cryptography Specification (S2-1)

**Version:** 1.0 (Phase B5 Wave-2 backprop applied; locks at Phase 3 Simon greenlight)
**Status:** Stage-2 mandatory specification. Implementable.
**Audience:** Cealis-internal crypto engineer implementing `age-plugin-cealis-v3`; external cryptographic auditor (top-tier audit-firm caliber); future Cealis engineers. Note: this specification has never been externally audited; adversarial review was internal only.
**Relationship to other Stage-2 specs:** Foundational. Unblocks S2-2 (smart-contracts), S2-3 (custody-integration), S2-4 (configurator-PDA), S2-5 (ingestion-delivery-API), S2-6 (operational-ceremonies), S2-7 (SD v2). Consumed by all of them; consumes none of them.
**Relationship to WP:** WP §C / §D / §E / §F (current 2026-04-25 post-legal-conform-pass) gives prose framing; this spec gives byte-exact constructions.
**Deployment note:** chain-ID references in this spec (Base mainnet 8453 / Base Sepolia 84532) are specification values; any live Base Sepolia deployment is testnet-only and its deployed bytecode may lag or diverge from this source — see `deployments/README.md`.
**Naming discipline:** V2 is the system version; V3 is the custody subsystem within V2 (per internal Rule 29). This spec uses "V3 custody" or "V2 system, V3 custody" — never bare "V3" as system version. The `_V3` suffix on TAG constants and primitive names refers to the custody subsystem version, not to a hypothetical V3 system.

---

## §0 — Front matter

### §0.1 Document identity

**Title:** Cealis V2 System, V3 Custody — Cryptography Specification (S2-1)

**Stage:** Stage-2 mandatory specification, foundational tier. The seven Stage-2 specs (S2-1 through S2-7) compose the byte-exact engineering contract for the V2 system, V3 custody architecture. S2-1 sits at the root of the dependency graph: it spec'd ALL Stage-2 docs — S2-2 smart-contracts-spec, S2-3 custody-integration-spec, S2-4 configurator-pda-spec, S2-5 ingestion-delivery-api-spec, S2-6 operational-ceremonies-spec, S2-7 sd-spec-v2 — consume cryptographic constructions enumerated normatively in S2-1, and none of them feed back into S2-1.

**Version field semantics:** the `Version: 1.0` line in the doc header reflects S2-1's own document version, not the protocol version. The protocol version this spec normatively encodes is `commit_version = 0x0302` (V3 custody backprop release per §2.8: A1+Shamir DEK lifecycle, `sdMerkleRoot` AAD binding, σ-as-authorization doctrine, and the IB-1/IB-2/IB-3/IB-4 repair batch — typed hierarchical Shamir access structure (IB-2), acyclic h_commit schedule (IB-1), re-key AEAD invariant (IB-3), and SD salt cycle break (IB-4)); the previous version `0x0301` (flat-Shamir, broken under 4-gate AND for surplus conditional-recipient access structures) is historical/invalid for new partner-ready commits unless explicitly migrated. The next protocol version requires the discipline at §2.8 (TAG-registry version bump + coordinated rollout).

**Stage:** Phase B5 Wave-2 + Phase D regression-cleanup backprop applied 2026-05-06. All 18 normative sections + 3 appendices are canonical enough for coordinated Stage-2 cross-review; Phase 3 voice-pass + final integration review open after the consumer-spec sweep confirms the 2026-05-06 IB-1/IB-2/IB-3/IB-4 repair batch + the `commit_version` bump to `0x0302`.

### §0.2 Audience and reading order

**Three primary audiences:**

1. **Cealis-internal crypto engineer** implementing `age-plugin-cealis-v3` and the combiner library. Reads §1 (conventions) → §6 (envelope spec) → §14 (combiner protocol) → §6.4 (AEAD payload) as the implementation core; uses §7 + §8 + §9 + §10 (gate signatures) + §11 (endpoint attestation) + §12 (registry verification) as primitive references when building gate-side handlers. §13 (PasskeyRotationLog ABI) + §15 (re-key ceremony) are operational-discipline annexes consumed at integration with rotation infrastructure.

2. **External cryptographic auditor** at top-tier audit-firm caliber. Reads §1 (conventions) → §2 (TAG registry — domain separation completeness) → §3 (composite identifiers — h_commit derivation) → §4 (commit_AAD — what is bound) → §6.3 (Shamir reconstruction) → §6.4 (AEAD payload + tag verification) → §14 (combiner protocol — fail-closed discipline + σ-as-authorization) → §16 (error model + abort discipline). §3.6 + every §X.N PII content statement establishes auditor-grade legal-cryptographic cross-domain framing per §13.10.1's Breyer C-582/14 GDPR Recital 26 strict-interpretation precedent.

3. **Future Cealis engineers** maintaining the spec across protocol-version bumps. §2.8 (TAG addition/retirement discipline) + §15 (re-key ceremony for primitive aging) + §17 (cross-references) anchor the operational framework for forward-evolution under the §2.8 commit_version coordination protocol. The §2.6 retired-tag enumeration documents history; the §2.10 active-tag count + the §3.3.4 D1 expansion document the current canonical state.

**Recommended reading order for first-time readers:** §0 (this section) → §1 (conventions, MUST read first) → §2 (TAG registry, scan by topic) → §6 envelope-spec parent intro at line 1267 (architectural lay-of-the-land) → topic-specific deep-dives. §17 cross-references and §3 composite identifiers are reference-grade rather than narrative; skim on first pass, return when implementing specific surfaces.

### §0.3 Terminology discipline

**V2 vs V3 — strict naming per internal Rule 29:**
- **V2** is the *system version*. The V2 system encompasses the configurable data escrow platform (PDA configurator, ConditionEngine modules, age-plugin-cealis-v3 envelope, recipient delivery surfaces, all 7 Stage-2 specs).
- **V3** is the *custody subsystem* within V2 (locked 2026-04-21 per project_tier_cost_model_apr21.md memory). The V3 custody subsystem is the 4-gate AND-composition: G1 Chain + G2 Lit V3 + G3 dcipher/drand + G4 Cealis verification component.
- This spec uses **"V3 custody"** or **"V2 system, V3 custody"** at the document scope — never bare "V3" as a system-version label.
- The **`_V3` suffix** on TAG constants (TAG_COMMIT_V3, TAG_AAD_V3, etc.) and primitive names refers to the custody subsystem version, not to a hypothetical V3 system. Symbol-level `_V3` reads as "the V3 custody version of this primitive."

**σ as authorization (P22 doctrine, revisited 2026-05-05):** Throughout this spec, σ values (σ_Lit, σ_G3, σ_G4, σ_conditional) are conventional verification signatures or attestation outputs over `(authorizationId, h_commit, block_hash)` under the gate authority state that was valid at the commit block. They are **authorization evidence**, not DEK material. A valid σ authorizes that gate's per-stanza wrap-decap path to release one Shamir share to the recipient combiner. σ bytes MAY be public after reveal in the recipient artifact or audit trail; secrecy attaches to the released Shamir share, decap material, DEK, and plaintext, not to σ itself. This discipline is normative across §7.1 + §8.1 + §9.1 + §10.1 and the combiner protocol in §14.

**A1+Shamir lifecycle LOCKED, access-structure repaired (dek-lifecycle design 2026-05-05 + IB-2 4-gate AND repair 2026-05-06):** The commit-time TEE generates a fresh random DEK, encrypts the payload once under §6.4, then shares the DEK according to `access_structure_profile`. `FIXED_ONLY` uses top-level `3-of-3` over Lit, G3, and G4. `RECIPIENT_1_OF_1` uses top-level `4-of-4` over Lit, G3, G4, and one recipient branch. `RECIPIENT_K_OF_N` uses top-level `4-of-4` over Lit, G3, G4, and a recipient aggregate share; that recipient aggregate is separately split as `k_conditional-of-n_conditional`. At reveal, verified σ values authorize per-stanza decap and typed share admission; §6.3 reconstructs `file_key` through the profile-specific access structure. There is no σ-derived HKDF/DEK construction in `commit_version = 0x0302`.

**Access-structure discipline:** Ordinary flat `3 + k_conditional` Shamir reconstruction is forbidden. Conditional-recipient surplus may satisfy only the recipient branch and MUST NOT substitute for Lit, G3, or G4. Missing any configured mandatory top-level branch makes DEK reconstruction mathematically impossible. For this B5 backprop, `access_structure_profile` is derived from the committed conditional-recipient policy and bound through `conditional_recipients_policy_digest`; if Stage 3 elects an explicit top-level profile field, that is a `commit_version` bump.

**Phase 1 vs Phase 2 (G4 only):** The G4 Cealis verification component has two phases per Stage-0 Q-0-2 closure. **Phase 1** is dev-scaffold-only (sealed-code Ed25519 server signature; non-partner-use). **Phase 2** is partner-ready (DCAP TEE attestation envelope per §9.3 + §11.2 cross-vendor mandate). Phase 1 commits stay valid under §9.6 Phase-swap discipline post-Phase-2 cutover. This phasing is G4-internal and does NOT propagate to G1 (always on-chain) / G2 (always Lit V3 attested TEE) / G3 (always rented commodity threshold network — dcipher or drand per `g3_choice`).

### §0.4 What this spec does NOT cover (cross-ref App. C)

S2-1 is the cryptographic spec — byte-exact constructions for the V3 custody composition and the age-plugin-cealis-v3 envelope. It does NOT cover:
- **Smart-contract surfaces:** ConditionEngine modules, RevealAuthorized event emission, on-chain registry contracts (PluginHashRegistry, G4AuthorityRegistry, DSLVersionRegistry, OracleRegistry, QTSPRegistry, SupersededCommitRegistry) — see **S2-2**.
- **Custody-integration:** Lit V3 SDK + Randamu dcipher SDK + drand client + Automata zkDCAP verifier + library version pins per §1.8 deferral — see **S2-3**.
- **PDA configurator:** PDA configuration surface, role_tag/delivery_hint enums, qes_subject_required policy, g3_choice enum, Mode 3 RESERVED enforcement at PDA-config layer (§10.4.3 3-layer defense-in-depth), cealis_class_wide_halt_opt_out — see **S2-4** + designs/conditional-recipient.md.
- **Ingestion + delivery API:** RevealAuthorized → API delivery surfaces, recipient artifact bundle structure, crypto-shred coordination — see **S2-5**.
- **Operational ceremonies:** DKG ceremonies for gate authority keys, key rotation orchestration, re-key ceremony triggering (S2-1 §15 specifies the cryptographic mechanics; S2-6 specifies the operational protocols), plugin distribution channel — see **S2-6**.
- **Selective Disclosure pipeline:** SD-specific TAG_SD_* tags, SD field commitment construction, ZKP / PLONK / Poseidon — see **S2-7** (disjoint TAG namespace per §2.7).
- **Library version pins:** specific `@noble/curves`, `@noble/hashes`, `filippo.io/age`, `@simplewebauthn/server` versions per §1.8 deferral — see **S2-3**.

App. C enumerates the scope-out matrix in detail.

### §0.5 Status of this document

**Phase B5 status (2026-05-06 Wave-2 backprop):** IB-1 (`h_commit` acyclic schedule), IB-2 (typed hierarchical Shamir access structure), IB-3 (re-key AEAD invariant), and IB-4 (SD salt cycle break) are back-propagated into this spec. Phase 3 (final integration + voice-pass + Simon greenlight) opens after the remaining consumer-spec sweep confirms no downstream drift.

**Architectural locks (NOT subject to relitigation absent Tier-1 escalation):**
- A1+Shamir DEK lifecycle (dek-lifecycle design, 2026-05-05)
- σ-as-authorization doctrine (P22 revisited 2026-05-05; supersedes the earlier σ-as-IKM framing)
- BP-2 / BP-3 / BP-4 / BP-5 / BP-6 / BP-9 / BP-10 / BP-11 / BP-12 LOCKED (9 back-propagations integrated; BP-1 / BP-7 / BP-8 are tracking-state slots without LOCKED status; BP-13 REJECT / BP-14 ACCEPT / BP-15 REJECT per `designs/v3-registry-class-discipline.md`).

**Open architectural questions (deferred to later Stage-2 docs or Phase 3):**
- Lit V3 + dcipher BLS variant assignments (deferred to S2-3 SDK confirmation per §1.1.4)
- DCAP user_data 64-byte vs 32-byte keccak-compress final byte budget (deferred to S2-3 + Simon Decision D11)
- QTSP Phase 2 σ_subject QES Path D specifics (deferred to S2-3 SDK + Phase 2 Path D finalization)
- Lit / G4 / conditional gate-recipient-pubkey publication SDK details, consumed from S2-2 + S2-3 after the §6.2 share-wrap primitive

These are normatively enumerated forward-references at §1.8 + §3.4.3 + §5.5 + §17 and resolve at the named downstream stage. Phase 3 trigger condition: Simon clears the first-canonical-section checkpoint after the `0x0302` backprop patches land.

### §0.6 Source-of-truth ordering (per internal Rule 0)

Per internal Rule 0, when this spec disagrees with reference docs (Closure-Doks, docs/specs/wp.md, docs/designs/flows-spec-final.md, designs/*.md):
- **For canonical byte-exact constructions:** S2-1 (this spec) is the source of truth.
- **For project-level architectural framing:** docs/specs/wp.md §A-§P takes precedence over reference-only Closure-Doks.
- **For Phase 1 build state:** historical pilot reference material documented the V1 pilot; V3 custody architecture (per project_tier_cost_model_apr21.md memory) supersedes V1 build-own-custody framing.

When an implementer reads a discrepancy, this spec's normative text wins; the discrepancy should be reported back via the back-propagation discipline at §2.8 + Rule 33 propagation.

### §0.7 Document discipline anchors

- **Encoding rules (§1.3):** Every byte-exact construction follows the SF-3 normative encoding rule discipline. SCALE encoding for SCALE structs; fixed-width byte concatenation (BE per §1.2) for keccak preimages with TAG_*_V3 prefix per generalized D6 V3 TAG-prefix discipline.
- **No SDK version pins (§1.8):** Wire-format identifiers (RFC, FIPS, EIP, IRTF draft, W3C) are normative; library version pins are S2-3 territory.
- **PII content discipline:** Every §X.N PII content statement establishes which fields are personally identifiable, under which controllership scope. The §3.6 ¶3 template (canonical PII-NONE pattern) extends through §4.9 + §13.10 + §10.10 + §11.8 + §12.12 + §16.15 + §16.19 per §17.9's **5 substrate-distinguishing PII-NONE consolidations**: 2 Breyer-applies (§10.10 Mode 2 wallet_address + §13.10.1 PasskeyRotationLog account_id) + 3 inverse-Breyer-NOT-APPLICABLE (§11.8 endpoint attestation 4-check + §12.12 5 V3 registries + §16.15+§16.19 ERR codes joint anchor as single 3rd inverse instance). §13.10.1's Breyer C-582/14 strict-interpretation precedent anchors the cross-partner-stable identifier framework. Per-section PII statements (§5.11 etc.) extend this template at section level.
- **Architectural-truth-template multi-substrate-variant pattern:** Per §17.8, **5 INSTANCEs** of the multi-layer-defense architectural-truth-template enforce cross-substrate consistency: §14.7.4 (combiner per-generation σ authorization-evidence verification) + §13.6 (Cealis-as-infrastructure-not-authority) + §10.9 (Mode 3 RESERVED enforcement chain) + §11.4 (endpoint attestation 6-substrate enumeration) + §12.6 (5-registry historical-lookup). Consumer-spec implementations (S2-2 + S2-3 + S2-4 + S2-5 + S2-6 + S2-7) MUST honor the multi-layer-defense pattern at the substrate-variant layer per §17.8 organizational anchor.
- **σ-as-authorization + AEAD orthogonality:** σ values authorize per-stanza share release. They are not DEK material and may appear in the reveal artifact after verification. PII protection is via AEAD and Shamir threshold reconstruction: the protected materials are Shamir shares, decap material, DEK, and plaintext.
- **Typed Shamir access structure:** σ values authorize release of typed Shamir shares, and share combination follows `access_structure_profile`, not a flat threshold. Top-level mandatory branches are mathematical: Lit, G3, and G4 are always required; recipient material is either absent (`FIXED_ONLY`), one top-level branch (`RECIPIENT_1_OF_1`), or a nested `k-of-n` branch (`RECIPIENT_K_OF_N`). Consumer specs MUST NOT expose raw flat `Shamir.combine` over commit shares.

### §0.8 Cross-reference index

- §1 conventions establishes encoding rules + primitives consumed throughout
- §2 TAG_*_V3 registry establishes domain-separation tags consumed at every keccak preimage in §3 + §4 + §5 + §6 + §7 + §9 + §10 + §13 + §15
- §17 cross-references enumerates all S2-N consumption surfaces from this spec

### §0.9 PII content statement

§0 carries no PII. The front matter establishes meta-architectural framing only; specific data flows and field-level PII statements live in §3.6 + §4.9 + §5.11 + §6 PII statements + §7-§14 per-section PII content statements + §15 + §16.

---

## §1 — Conventions

This section fixes the vocabulary, primitives, encoding rules, and notation used throughout this specification. Every byte-exact construction in §3 through §16 reads against the conventions established here. Non-conforming implementations are conforming neither to S2-1 nor to the larger V2 system, V3 custody specification family.

### 1.1 Cryptographic primitives — wire-format identifiers

The cryptographic primitives below are referenced normatively across this specification. Each is identified by its public wire-format specification (RFC, FIPS, EIP, IRTF draft, or equivalent), not by any specific library. Library version pins for each primitive live in S2-3 (custody-integration-spec); S2-1 specs the wire format only.

#### 1.1.1 Hash functions

- **keccak-256** — canonical hash function for all `bytes32` digests in this specification (commit-side derivations, AAD digests, TAG_*_V3 preimages, Merkle leaves). Output length 32 bytes. The "keccak-256" name in this spec refers to the original Keccak submission with rate `r = 1088` and capacity `c = 512`, NOT NIST FIPS 202 SHA3-256 (which uses different padding); both produce 256-bit output but the digests differ. Implementations MUST use the keccak-256 variant — this matches the Solidity `keccak256` opcode and the Ethereum ecosystem default.
- **HKDF-SHA256** — RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function with SHA-256 as the underlying hash. Used for payload AEAD nonce derivation (§6.4) and per-stanza wrap key derivation (§6.2). It is NOT used to derive the DEK from σ values in `commit_version = 0x0302`; §6.3 reconstructs the DEK by Shamir threshold combination. The HKDF call signature throughout this spec is `HKDF(salt, ikm, info, L)` where `L` defaults to 32 bytes when omitted; deviations from the default `L` are stated explicitly at the call site.
- **SHA-256** — RFC 6234 / FIPS 180-4. Used as the HMAC underlying hash in HKDF-SHA256 above; not directly invoked in any standalone keccak preimage. Where this spec writes `HKDF(...)` without further qualification it means HKDF-SHA256.

#### 1.1.2 Authenticated encryption

- **ChaCha20-Poly1305 AEAD** — RFC 8439 (formerly RFC 7539) authenticated encryption with associated data. 256-bit key, 96-bit nonce, 128-bit authentication tag. Used for the payload layer of the age envelope (§6.4); the DEK serves as the key, the nonce is HKDF-derived per §6.4, and `commit_AAD` is the AEAD's associated-data input.

#### 1.1.3 Asymmetric primitives

- **BLS12-381** — IRTF draft-irtf-cfrg-pairing-friendly-curves and draft-irtf-cfrg-bls-signature. The BLS-signature draft specifies two ciphersuite variants distinguished by which group carries the public key vs the signature: **minimum-pubkey-size** (G1 pubkey 48 bytes + G2 signature 96 bytes) and **minimum-signature-size** (G2 pubkey 96 bytes + G1 signature 48 bytes). The variant choice is per-gate, fixed by the gate operator's protocol implementation. **drand** uses minimum-pubkey-size (G1 pubkey + G2 sig) per the League of Entropy production deployment; this is normative for σ_G3 verification on the drand path (§8.3). **dcipher** + **Lit V3** variant assignments are deferred to S2-3 SDK confirmation (Randamu dcipher SDK + Lit V3 Chipotle SDK pin the concrete variant per their reference implementations); §7 (σ_Lit) and §8.2 (σ_G3 dcipher) cite the variant once S2-3 confirms. Implementations MUST verify σ values under the variant the gate operator's published protocol uses; mismatching the variant produces a signature-verification failure but no security degradation. Byte widths follow the variant: drand σ_G3 is 96 bytes (G2 sig); drand committee pubkey is 48 bytes (G1 point).
- **P-256** — FIPS 186-5 / NIST P-256 (also called secp256r1). Used by WebAuthn passkey σ_subject (§5.2) and by σ_conditional Mode 1 PASSKEY_ACCOUNT (§10.1). WebAuthn assertions are minimum 64 bytes (raw r ‖ s) but typically delivered in CBOR-encoded WebAuthn assertion format; this spec verifies the signature value extracted from the assertion. The PasskeyRotationLog (§13) similarly carries P-256 WebAuthn assertions per entry.
- **Ed25519** — RFC 8032 EdDSA over Curve25519. Used by gate G4 Phase 1 σ_G4 (§9.2) — sealed-code server signature, 64 bytes. Phase 1 is dev-scaffold-only per Stage-0 Q-0-2 LOCKED; partner-facing commits land under Phase 2 (DCAP attestation, §9.3) where Ed25519 does not appear.
- **secp256k1** — Standards for Efficient Cryptography 2 (SEC 2) curve. Used by σ_subject EIP-712 wallet path (§5.3) and σ_conditional Mode 2 WALLET_EOA (§10.2). EIP-712 wallet signatures are exactly 65 bytes (`r ‖ s ‖ v`). Recovery semantics per EIP-2 normalized `v` ∈ {0, 1} or legacy `v` ∈ {27, 28}; combiners SHOULD canonicalize before recovery.

#### 1.1.4 Post-quantum primitives

- **ML-KEM-768** — FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (also called Kyber-768 in pre-FIPS literature). NIST PQC standardization round 3 winner. Key encapsulation only (NOT signature). Public key 1184 bytes, ciphertext 1088 bytes, shared secret 32 bytes. Used in hybrid construction with X25519 for stanza wrapping per Simon Decision D2 (per-stanza hybrid PQ wrap) — exact construction pending Δ12 architecture arbitration.
- **X25519** — RFC 7748 Diffie-Hellman key agreement over Curve25519. Public key 32 bytes, shared secret 32 bytes. Used in hybrid PQ wrap construction alongside ML-KEM-768 per Simon Decision D2: the hybrid construction requires breaking BOTH ML-KEM-768 and X25519 to extract the wrapped DEK, providing post-quantum security via the lattice layer and classical-backstop security via the elliptic-curve layer. Also used as the recipient-key family in age envelope X25519 recipient stanzas (the standard age scheme for non-Cealis-plugin recipients, e.g., the conditional_recipient Mode 2 delivery wrap to `delivery_x25519_pubkey` per §10.2).

#### 1.1.5 Other wire formats

- **EIP-712** — Ethereum Improvement Proposal 712 typed-data signing. Used for σ_subject EIP-712 wallet path (§5.3, domain `"CealisSubjectAssent"` per Simon Decision D5) and σ_conditional Mode 2 WALLET_EOA (§10.2, domain `"CealisConditionalRecipient"` per D5). Mode 3 WALLET_EIP1271 (§10.3, RESERVED at V2 launch) wraps an EIP-712 digest into the EIP-1271 `isValidSignature` call.
- **WebAuthn / FIDO2** — W3C WebAuthn Level 2 + CTAP2 for the assertion structure. Used at σ_subject WebAuthn path (§5.2), σ_conditional Mode 1 PASSKEY_ACCOUNT (§10.1), and PasskeyRotationLog entry signing (§13).
- **DCAP attestation** — Intel Data Center Attestation Primitives. Used at σ_G4 Phase 2 (§9.3) and at the Lit V3 per-op TEE attestation (§11.2). On-chain verification via Automata zkDCAP (or equivalent verifier circuit). Commit-time endpoint-attestation quotes bind the acyclic `attestation_context_digest_N` (§3.4.3) inside DCAP `user_data`; reveal-time per-op quotes bind `(authorizationId, h_commit_N, block_hash)` at 96 bytes raw, keccak-compressed to 32 bytes if the report-data budget requires compression (final byte budget pending S2-3 cross-check per Simon Decision D11).
- **JCS canonicalization** — RFC 8785 JSON Canonicalization Scheme. Used for the RevealArtifactBundle output per Simon Decision D4b (per-recipient bundles).
- **SCALE codec** — Polkadot SCALE Codec specification. Used for `commit_AAD` (§4), conditional_recipients_policy (§4 + §10), endpoint-attestation sum types (§3.4 per Simon Decision D10), and deterministic share/stanza metadata. §6.3 uses Shamir reconstruction over recovered 32-byte shares rather than a SCALE-encoded HKDF input. See §1.3 for the SCALE encoding rules normative to this spec.

### 1.2 Endianness convention

Multi-byte integer fields appear in two distinct contexts in this specification: as direct concatenated inputs to keccak preimages, and as primitive fields inside SCALE-encoded structures.

- **Direct keccak preimages — big-endian.** Multi-byte integer fields concatenated into a keccak preimage use big-endian (network byte order) encoding. This matches the Solidity `abi.encodePacked` convention used at chain-side verification sites (`PluginHashRegistry`, `G4AuthorityRegistry`, `ConditionEngine`) and matches V1 Cealis convention. Examples: `block_hash_at_attestation` (32 bytes, native byte order from `eth_getBlockByHash`); `authorizationId` (32 bytes, native from keccak output); fixed-width counters and timestamps (`uint64`, `uint32`, `uint16`) in BE.
- **SCALE-encoded structures — SCALE-native little-endian.** Per the Polkadot SCALE codec specification, primitive integer types (`u8`, `u16`, `u32`, `u64`, `u128`) inside SCALE structs encode as little-endian fixed-width bytes. Compact length prefixes for `Vec<T>` and `String` follow SCALE compact-encoding rules. This applies to every field inside `commit_AAD` (§4), inside the conditional_recipients_policy struct, inside endpoint-attestation sum types, and inside any other SCALE-encoded structure in this spec.

The mixing pattern at construction sites where a TAG-prefixed keccak wraps a SCALE-encoded body (e.g., `aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD))`) preserves both conventions: the TAG prefix concatenates as raw bytes (no integer fields to endian), the SCALE-encoded body internally carries little-endian primitive fields, and the keccak step ingests the concatenated byte stream verbatim. No endianness flip occurs at the boundary.

**Q-W2-2 LOCKED 2026-04-25** by dw-lead per default-applied position in the internal S2-1 writers' questions log; tracked at BP-5 in the internal S2-1 back-propagation log for back-propagation on Simon ack at first-canonical-section checkpoint. The endianness convention specified in this section (BE for direct keccak preimages, SCALE-native LE for SCALE-encoded structures) is the dw-lead default-applied disposition. Source corpus does not explicitly enumerate this convention; dw-lead applied the discipline based on (a) Solidity `abi.encodePacked` / chain-side verification convention (BE), and (b) Polkadot SCALE codec specification (SCALE-native LE for primitive ints). Override path: if Simon picks LE-only or BE-only convention at first-canonical-section checkpoint, every keccak preimage carrying multi-byte integer fields in §3 / §6 / §10 / §11 / §13 / §14 receives a coordinated patch.

### 1.3 Encoding rules (SF-3 normative)

The byte-concatenation operator `‖` and SCALE encoding play distinct, non-interchangeable roles in this specification. The choice between them is normative and load-bearing for security: cross-using them where the spec requires the other introduces boundary-malleability vulnerabilities (the A07 attack class identified in worker-4's delta-audit Δ4 cross-reference).

#### 1.3.1 Byte concatenation with TAG_*_V3 prefix — for FIXED-WIDTH hash inputs

Byte concatenation with a TAG_*_V3 prefix is the canonical encoding for keccak preimages where every concatenated field is fixed-width. Examples (full normative specs in the named sections):

- `h_commit = keccak256(TAG_COMMIT_V3 ‖ <15 fixed-width fields>)` — §3.4
- `authorizationId = keccak256(TAG_AUTHID_V3 ‖ <5 fixed-width fields>)` — §3.2
- `subject_commitment_v3 = keccak256(TAG_SUBJECT_V3 ‖ <3 fixed-width fields>)` — §3.1
- `pda_root = keccak256(TAG_PDA_ROOT_V3 ‖ <29 fixed-width fields>)` — §3.3
- σ_conditional reveal-challenge digest per Mode 1/2 — §10.1, §10.2
- σ_G4 Phase 1 attestation preimage — §9.2
- Per-stanza MAC preimage under `TAG_STANZA_MAC_V3` — §6.1

The fixed-width requirement is not optional. If any field in the proposed concatenation is variable-length (a string, a `Vec<T>`, a length-prefixed payload), byte concatenation MUST NOT be used; SCALE encoding is required per §1.3.2 below.

#### 1.3.2 SCALE encoding — for VARIABLE-LENGTH or STRUCTURED payloads

SCALE encoding is the canonical encoding for any payload that contains variable-length fields or that benefits from self-describing struct framing. The Polkadot SCALE codec specification is the normative reference; the compact-length-prefix convention for `Vec<T>` and the position-deterministic struct encoding are the load-bearing properties this spec depends on.

Examples in this specification (full normative specs in the named sections):

- `commit_AAD` SCALE struct — §4 (22 mandatory fields including BP-2 supersession lineage Group 4 and `sdMerkleRoot`, fixed-width but encoded under SCALE for codec consistency and forward-compat)
- `conditional_recipients_policy` struct — §4 + §10 (variable n + k + recipient stanza set)
- Conditional recipient stanza payloads — §6.1 + §10.1 / §10.2 / §10.3 (variable-length fields like `delivery_url`, `account_id` metadata)
- `endpoint_attestation_digest` SCALE sum-type per Simon Decision D10 — §3.4 cross-reference (variant-tagged across Phase 1 / Phase 2)
- RevealArtifactBundle structured content — §13 (also JCS-canonicalized for downstream consumption per D4b)

#### 1.3.3 The mixed pattern — TAG-prefix wrapping SCALE-encoded body

A small number of construction sites wrap a SCALE-encoded variable-length body inside a TAG-prefixed keccak. The canonical example is `aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD))` per Simon Decision D6: the `SCALE(commit_AAD)` step encodes the 19-field structured payload deterministically; the keccak step then ingests the concatenation of the TAG (32 bytes, fixed) plus the SCALE byte stream (deterministic length per the encoded fields). This mixed pattern is permitted ONLY where the SCALE-encoded body is itself a deterministically-encoded structure (i.e., SCALE's own framing provides the boundary discipline that fixed-width concatenation would otherwise require). It MUST NOT be used to wrap an arbitrary variable-length payload that lacks SCALE structure.

#### 1.3.4 Anti-pattern — raw concatenation of variable-length fields

Raw byte concatenation of variable-length fields without length-prefixing or SCALE encoding is a specification defect. Such constructions admit boundary-malleability: an attacker can shift bytes across the implied field boundaries and produce a different field-tuple that hashes to the same digest. The A07 attack class identified in flows-spec-final.md §0.5 explicitly rejects raw concatenation in the verified share set; this rejection generalizes to every keccak preimage in this specification. Implementations MUST use either the fixed-width concatenation pattern of §1.3.1 (where fixed-width is genuine, not assumed) or the SCALE pattern of §1.3.2; the mixed pattern of §1.3.3 only where its specific preconditions are met.

This rule maps to the Cealis Protocol Checklist Item 2 spec-form: `abi.encode` (or SCALE) for variable-length / security-critical hashes; `abi.encodePacked` / byte-concat ONLY for fixed-width Merkle leaves and TAG-prefixed hash inputs with rationale. The §2 cross-reference in §2.5 cites this rule as the encoding-rule authority.

### 1.4 SCALE codec — referenced primitives

The Polkadot SCALE codec is the normative encoding for variable-length and structured payloads in this specification. Implementations consume the canonical SCALE codec specification directly; this subsection enumerates the SCALE primitives this spec references so an implementer can map them to the codec's type catalog.

- **Primitive integers:** `u8`, `u16`, `u32`, `u64`, `u128` — SCALE-native little-endian fixed-width encoding.
- **Booleans:** `bool` — single byte, `0x00` for false, `0x01` for true.
- **Fixed-size byte arrays:** `[u8; N]` — exactly N raw bytes, no length prefix.
- **Variable-length byte arrays:** `Bytes` (alias for `Vec<u8>`) — SCALE compact-length prefix followed by the bytes.
- **Vectors:** `Vec<T>` — SCALE compact-length prefix (number of elements), followed by each element's SCALE encoding in order.
- **Optional values:** `Option<T>` — single discriminant byte (`0x00` for None, `0x01` for Some), followed by the wrapped value's SCALE encoding when Some.
- **Sum types (variant-tagged enums):** SCALE encodes a variant index byte followed by the variant's payload's SCALE encoding. Used at `endpoint_attestation_digest` (§3.4 cross-reference per Simon Decision D10) where Phase 1 and Phase 2 carry different payload shapes.
- **Structs:** SCALE encodes each field in declaration order using each field's own SCALE encoding. No field name, no field-position metadata; the order is purely positional and is the wire-normative ordering.

The compact-length encoding for `Vec<T>` and `Bytes` length prefixes is per the SCALE codec specification: 1-byte for lengths < 64, 2-byte for lengths < 16384, 4-byte for lengths < 2^30, and 5-to-68-byte (1-byte mode discriminator + 4-to-67 bytes of big-integer payload) for lengths up to approximately 2^536. Practical Cealis V3 payloads fall in the 1-byte or 2-byte range.

### 1.5 Pseudocode notation

Pseudocode in this specification follows these conventions:

- **Function call notation:** `keccak256(x)`, `HKDF(salt, ikm, info, L)`, `SCALE_encode(x)`, `SCALE_decode(x)`, `chacha20poly1305_encrypt(key, nonce, aad, plaintext)`, `chacha20poly1305_decrypt(key, nonce, aad, ciphertext)`, `bls_verify(pubkey, message, signature)`, `ed25519_verify(pubkey, message, signature)`, `ecdsa_recover(digest, signature)`. The function names are wire-format identifiers; library bindings live in S2-3.
- **Concatenation operator:** `‖` denotes byte concatenation per §1.3.1 / §1.3.3 (TAG-prefix-or-fixed-width context). Use of `‖` always implies the §1.3.1 fixed-width discipline OR the §1.3.3 mixed pattern, never the §1.3.4 anti-pattern.
- **Field reference:** `commit_AAD.field_name` denotes a struct-field access against a SCALE-encoded struct. Implementers SCALE-decode the struct then access the named field; the field's byte position is determined by SCALE struct declaration order per §1.4.
- **Hash digest:** `digest = keccak256(...)` returns a 32-byte value. `[:N]` notation slices a byte sequence to its first N bytes — used for HKDF-derived nonces (e.g., `nonce = HKDF(...)[:12]` for the 96-bit ChaCha20-Poly1305 nonce per §6.4).
- **Constant references:** TAG_*_V3 constants per §2 are referenced by name; their `bytes32` values are computed per §2.1 and consumed at construction sites per the no-raw-strings discipline of §2.1.
- **Semantic abbreviations:** `σ_X` denotes a signature value produced by gate / authenticator X; `pk_X` denotes X's public key; `sk_X` denotes X's secret key. σ values authorize release of Shamir shares; the shares and decap outputs are the confidential reconstruction material.

### 1.6 Byte-width notation

Byte widths in this specification are stated explicitly at first reference and follow these conventions:

- Hash digests: 32 bytes (keccak-256, SHA-256 derivative).
- Curve-point public keys: 32 bytes (Ed25519, X25519, P-256 compressed); 33 bytes (secp256k1 compressed); 48 bytes (BLS12-381 G1 compressed); 65 bytes (P-256 uncompressed `0x04 ‖ x ‖ y` per WebAuthn convention); 96 bytes (BLS12-381 G2 compressed).
- Signatures: 64 bytes (Ed25519, P-256 raw r ‖ s); 65 bytes (secp256k1 EIP-712 raw r ‖ s ‖ v); 96 bytes (BLS12-381 G2 signature compressed); WebAuthn assertion bytes are minimum 64 (raw P-256 sig) but typically delivered in CBOR-encoded form 100-300 bytes.
- ML-KEM-768: 1184 bytes public key, 1088 bytes ciphertext, 32 bytes shared secret.
- AEAD: 32 bytes ChaCha20-Poly1305 key, 12 bytes nonce, 16 bytes authentication tag.
- DCAP quote: variable, typically 4-6 KiB depending on TEE quote structure; `user_data` field is exactly 64 bytes (Intel SGX limit) per §1.1.5 above.
- Addresses: 20 bytes (Ethereum / EIP-55 wallet addresses).

The fixed widths above are the wire-format byte counts; on-chain Solidity types map naturally (`bytes32` for 32-byte digests, `bytes20` for addresses, etc.).

### 1.7 Error model

This specification adopts a fail-closed error model throughout. Any verification check failure in a combiner pre-verify chain (§14.1), any AEAD authentication failure (§6.4), any registry-state mismatch (§12), any MAC failure (§6.1, §6.2), and any signature verification failure (§7, §8, §9, §10) MUST cause the combiner to abort BEFORE any downstream cryptographic step (file_key reconstruction, plaintext production, or delivery). The combiner returns a typed error to the caller; it does NOT return partial decryption output, partial plaintext, or any state that depends on the failed step's success.

Error codes are not normatively enumerated in S2-1 itself — implementations choose a typed-error scheme appropriate to their language (Rust `Result<T, CombinerError>`, Go's typed errors, TypeScript discriminated unions). The only normative requirement is the fail-closed behavior: no error path produces a release path that bypasses the on-chain-verified condition. This is the universal-tripwire discipline (per WP §A "no release path bypasses the predefined condition") restated at the spec level.

The G4RefusalRegistry reason-code enum per §9.4 is the on-chain-visible counterpart to the combiner's internal error model. Codes 0x01-0x09 enumerate the structured refusal causes G4 emits when it declines to sign σ_G4 (legal compulsion, GDPR Art. 17 / 18, integrity fail, chain mismatch, plugin / authority / DSL / oracle deprecation per Simon Decision D9). Code 0x0A is structurally distinct: it is an **opt-out informational signal** emitted when a PDA's `cealis_class_wide_halt_opt_out = true` causes G4 to PROCEED with signing despite an ostensibly-applicable deprecation event — G4 does not refuse, but logs the opt-out fact for downstream auditability. The combiner's error response to a G4 refusal (codes 0x01-0x09) is to abort per the fail-closed rule above; combiner response to a 0x0A informational signal is to record the signal in the recipient's attestation chain and continue normal verification.

### 1.8 No SDK version pins — wire-format only

This specification carries wire-format identifiers (RFC, FIPS, EIP, IRTF draft, W3C standard) for every primitive but does NOT carry library version pins. Specific library choices — `@noble/curves` for elliptic-curve operations, `filippo.io/age` for the age envelope baseline, `@simplewebauthn/server` for WebAuthn assertion verification, `@noble/hashes` for keccak / SHA-256 / HKDF, `@polkadot/util` for SCALE codec, `tiny-keccak` or `keccak` for keccak-256 in non-TypeScript implementations, `drand/kyber` for drand BLS verification, the Randamu dcipher SDK for dcipher threshold IBE, the Lit V3 SDK for Lit operator interaction, Automata zkDCAP for on-chain DCAP verification — live in S2-3 (custody-integration-spec). S2-3 is responsible for tracking library version compatibility against the wire-format identifiers in this section.

The deliberate split between wire format and library binding lets S2-1 stay stable while S2-3 absorbs library-ecosystem churn (vendor SDK upgrades, new minor versions, CVE patches). An implementer reading S2-1 without S2-3 has enough wire-format detail to produce a compliant implementation against any conforming library; S2-3 then narrows the choice to the specific libraries Cealis pilot deployments use.

### 1.9 Cross-reference index

Other sections in this specification refer back to §1 conventions at the following points:

- §2.1: TAG_*_V3 construction rule references §1.1.1 keccak-256 + §2.1 own discipline.
- §2.5: encoding rule reference points to §1.3 (SF-3 normative encoding-rule distinction) and §1.4 (SCALE codec primitives).
- §3.4: h_commit byte layout consumes §1.2 endianness convention and §1.3.1 fixed-width concatenation discipline.
- §4: commit_AAD SCALE struct consumes §1.3.2 + §1.4.
- §5: σ_subject WebAuthn / EIP-712 / QES paths consume §1.1.3 (P-256, secp256k1).
- §6.1: stanza format consumes §1.1.1 + §1.3.1 + §1.4.
- §6.2: hybrid PQ wrap consumes §1.1.4 (ML-KEM-768 + X25519) — A1+Shamir locked by Δ12 and dek-lifecycle backprop.
- §6.3: Shamir reconstruction consumes the per-stanza shares recovered through §6.2 after σ authorization.
- §6.4: ChaCha20-Poly1305 AEAD consumes §1.1.2.
- §7 / §8 / §9: gate signatures consume §1.1.3 (BLS12-381, Ed25519) and §1.1.5 (DCAP).
- §10: σ_conditional Modes 1 / 2 / 3 consume §1.1.3 + §1.1.5 (EIP-712, EIP-1271, WebAuthn).
- §11: endpoint attestation consumes §1.1.5 (DCAP, EIP-712).
- §13: PasskeyRotationLog consumes §1.1.3 (P-256, WebAuthn).
- §14: combiner protocol consumes §1.7 (error model).
- §16: error model + abort discipline restates §1.7 in the fail-closed combiner context.

---

## §2 — TAG_*_V3 Registry

This section enumerates every domain-separation constant the Cealis V2 system, V3 custody depends on. Every keccak-256, HMAC, and HKDF construction in this specification consumes one or more of these constants as a domain separator. The registry is closed at protocol-version `0x0302` (V3 custody backprop release): adding a new tag requires a `commit_version` bump and a coordinated rollout. Retiring a tag requires the same bump plus the deprecation discipline in §2.6.

### 2.1 Construction rule

Every TAG in this registry is a precomputed `bytes32` value defined as:

```
TAG_<NAME>_V3 = keccak256(bytes(<LABEL>))
```

where `<LABEL>` is the canonical ASCII label string enumerated for that TAG in §2.3. The label-string convention follows the `CEALIS_V3_*_V3` namespace — every label begins with `CEALIS_V3_` and ends with `_V3` — but the middle portion is **not mechanically derived from the symbol's `<NAME>`**. Three V3 labels diverge from a strict symbol-derived form: `TAG_COMMIT_V3` uses the historical preimage `"CEALIS_V3_COMMITMENT_HASH_V3"` per `flows-spec-final.md:59`; `TAG_AUTHID_V3` uses `"CEALIS_V3_AUTH_ID_V3"` per `flows-spec-final.md:76`; `TAG_SUBJECT_V3` uses `"CEALIS_V3_SUBJECT_V3"` per direct application of the namespace rule to the symbol. These labels are pre-locked: they were committed when the V3 cryptographic preimages were defined and cannot change without a `commit_version` bump per §2.8. §2.3 carries the normative label authority for every TAG, and any divergence between a symbol-derived form and the historical label is enumerated there with explicit citation.

The label string MUST be valid 7-bit ASCII per RFC 20. UTF-8 encoding of any 7-bit-ASCII string is bit-identical to ASCII, so `bytes("...")` in Solidity, `Buffer.from("...", "utf8")` in TypeScript, and `b"..."` in Rust all produce the same preimage. Non-ASCII characters in a TAG label are rejected at registry-time and MUST NOT appear in any conforming implementation.

Implementations MUST treat each TAG as a precomputed `bytes32` constant. Embedding the label string as a literal at a hash-input construction site is forbidden in production code: it forfeits the static-analysis guarantee that every tag in use is registered here, and it permits silent label-string drift across reimplementations. The same rule applies in TypeScript, Rust, Go, and any other implementation language; the language-specific binding for "precomputed `bytes32` constant" is whatever that language's idiomatic equivalent of a `const`-declared 32-byte array is. The Cealis Protocol Checklist Item 1 (TAG_* domain separation) binds this rule on Solidity and is restated here for the off-chain combiner / plugin / API surfaces.

### 2.2 Universal property — collision-resistance under keccak-256

Distinct labels produce distinct `bytes32` values under the collision-resistance of keccak-256. The single `<NAME>` element distinguishing two TAGs is sufficient: an attacker who could find two labels `CEALIS_V3_<NAME_A>_V3` and `CEALIS_V3_<NAME_B>_V3` with the same keccak-256 digest would have broken keccak's collision resistance. No two tags share a label; no implementation may add a tag whose label collides with an existing entry by case-insensitive comparison (the spec uses case-sensitive matching, but case-insensitive uniqueness avoids subtle confusion).

The shared `CEALIS_V3_` / `_V3` framing is structural, not security-critical: it provides human-readable scoping (every Cealis V3 tag is unambiguously identifiable) and protects against accidental cross-protocol reuse with hypothetical V1, V2, or other-system tags whose label conventions differ. Cross-protocol collision (a Cealis V3 tag colliding with a non-Cealis V3 hash domain) is implausible at keccak-256 collision-resistance levels regardless of label discipline; the framing is defense-in-naming, not defense-in-cryptography.

### 2.3 Active TAG_*_V3 constants (30 entries)

The following table enumerates every TAG_*_V3 constant in active use across this specification. Each row gives: the constant symbol name; the exact ASCII label string passed to `keccak256(bytes(...))`; the construction context (the section where the tag's primary use is defined); the source-of-truth pointer in the working corpus.

Implementations MUST precompute the `bytes32` digest at compile-time or initialization-time and use the precomputed value at every hash-input construction site.

#### 2.3.1 Commit and authorization tags

| TAG | Label string for keccak | Construction context | Source-of-truth |
|---|---|---|---|
| `TAG_COMMIT_V3` | `"CEALIS_V3_COMMITMENT_HASH_V3"` | First field of `h_commit` keccak preimage (§3.4). Anchors the envelope's chain-of-custody on Base L1. | flows-spec-final.md:59; WP §C wp.md:289 |
| `TAG_AUTHID_V3` | `"CEALIS_V3_AUTH_ID_V3"` | First field of `authorizationId` keccak preimage (§3.2). Per-commit identifier threading every ceremony event. | flows-spec-final.md:76; WP §C wp.md:244 |
| `TAG_SUBJECT_V3` | `"CEALIS_V3_SUBJECT_V3"` | First field of `subject_commitment_v3` keccak preimage (§3.1). Per-partner-namespaced subject identifier; PRO-226 cross-partner-unlinkability fix. Label per direct application of the §2.1 namespace rule (no normative source pre-locks a longer form; brief-01's reconstruction `"CEALIS_V3_SUBJECT_COMMITMENT_V3"` was V1-cargo-cult from `TAG_SUBJECT_V1 = "CEALIS_SUBJECT_COMMITMENT_V1"` per the internal V1 Solidity rules doc and is not adopted). | flows-spec-final.md:84,226 (symbol only); WP §C wp.md:231 (symbol only) |
| `TAG_SIGMA_SUBJECT_V3` | `"CEALIS_V3_SIGMA_SUBJECT_V3"` | Domain separator for σ_subject preimage (§5.2). σ_subject is WebAuthn P-256, EIP-712 wallet, or QTSP-issued QES depending on `subject_authenticator_class`; `keccak256(σ_subject)` lands in commit_AAD as `sigma_subject_digest` (§4). | flows-spec-final.md:221; WP §C wp.md:315 |
| `TAG_PDA_ROOT_V3` | `"CEALIS_V3_PDA_ROOT_V3"` | First field of `pda_root` keccak preimage (§3.3). Anchors the 29-field PDA configuration (§3.3) into `h_commit`, surviving any post-commit PDA mutation attempt. | WP §C wp.md:262 |

#### 2.3.2 commit_AAD and AEAD tags

| TAG | Label string for keccak | Construction context | Source-of-truth |
|---|---|---|---|
| `TAG_AAD_V3` | `"CEALIS_V3_AAD_V3"` | Domain separator for `aad_digest`: `aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD))`. Per Simon Decision D6 the keccak-prefix interpretation is normative; `aad_digest` lands as one of the 15 inputs to `h_commit` (§3.4). | flows-spec-final.md:226; D6 |
| `TAG_AEAD_V3` | `"CEALIS_V3_AEAD_V3"` | ChaCha20-Poly1305 nonce derivation for the payload AEAD: `nonce = HKDF(DEK, TAG_AEAD_V3 ‖ commit_context_digest_0)[:12]` (§6.4). Final `h_commit_N` is not available at payload-encryption time. | flows-spec-final.md:108; WP §C wp.md:200; h-commit-acyclic-schedule.md §7 |
| `TAG_COMMIT_CONTEXT_V3` | `"CEALIS_V3_COMMIT_CONTEXT_V3"` | Domain separator for `commit_context_digest_N`, the pre-payload acyclic context used by §6.2 stanza-wrap KDFs and §6.4 payload AEAD nonce/AAD discipline before final `ciphertext_digest_N` and `h_commit_N` exist. Same fixed-width field order as §3.4.1 with `ciphertext_digest = 0x00…00`. | h-commit-acyclic-schedule.md §4.2 / §7 |
| `TAG_ATTESTATION_CONTEXT_V3` | `"CEALIS_V3_ATTESTATION_CONTEXT_V3"` | Domain separator for `attestation_context_digest_N`, the pre-quote context bound inside commit-time endpoint-attestation evidence to break the `h_commit ↔ endpoint_attestation_digest` recursion. | h-commit-acyclic-schedule.md §4.2 / §7 |

#### 2.3.3 Gate-binding tags

| TAG | Label string for keccak | Construction context | Source-of-truth |
|---|---|---|---|
| `TAG_LIT_ACC_BINDING_V3` | `"CEALIS_V3_LIT_ACC_BINDING_V3"` | Stanza-format binding tag for the LIT_ACC recipient stanza (gate G2). Bound into the per-stanza MAC of stanza[0] under `TAG_STANZA_MAC_V3` (§6.1). | flows-spec-final.md:227 |
| `TAG_DCIPHER_IBE_BINDING_V3` | `"CEALIS_V3_DCIPHER_IBE_BINDING_V3"` | Binding tag for the G3 stanza when `g3_choice = 0` (dcipher threshold IBE; §8.2). Bound into the per-stanza MAC of stanza[1] under `TAG_STANZA_MAC_V3`. Exactly one of `TAG_DCIPHER_IBE_BINDING_V3` or `TAG_DRAND_ROUND_BINDING_V3` appears per commit, selected by `g3_choice` (§3.3 pda_root field); the unselected binding-tag is absent from the commit's stanza set. | flows-spec-final.md:227 |
| `TAG_DRAND_ROUND_BINDING_V3` | `"CEALIS_V3_DRAND_ROUND_BINDING_V3"` | Binding tag for the G3 stanza when `g3_choice = 1` (drand BLS12-381 round signature; §8.3). | flows-spec-final.md:227 |
| `TAG_G3_BINDING_V3` | `"CEALIS_V3_G3_BINDING_V3"` | Generic G3 parent binding tag, used when the spec abstracts over both dcipher and drand at structural-equality positions (e.g., the binding-tag field in §6.1 stanza MACs is referred to as the G3 binding tag generically). At construction time the implementation substitutes the concrete g3_choice-derived tag (`TAG_DCIPHER_IBE_BINDING_V3` or `TAG_DRAND_ROUND_BINDING_V3`); `TAG_G3_BINDING_V3` itself is not consumed in any keccak preimage. | flows-spec-final.md:228 |
| `TAG_G4_ATTESTATION_V3` | `"CEALIS_V3_G4_ATTESTATION_V3"` | Domain separator for σ_G4 attestation field-bind. Commit-time endpoint attestations bind `attestation_context_digest_N`, not final `h_commit_N`, because the endpoint-attestation digest is itself an input to final `h_commit_N`. Reveal-time per-op gate signatures still bind final `h_commit_N` as their authorization target. | flows-spec-final.md:228; h-commit-acyclic-schedule.md §7 |
| `TAG_G4_ATTESTATION_AUTHORITY_V3` | `"CEALIS_V3_G4_ATTESTATION_AUTHORITY_V3"` | Binding tag for stanza[2] G4 recipient. Binds to the G4 authority root key (the registered key in `G4AuthorityRegistry`), not to the per-instance signing key. Supports key rotation without invalidating historical commits. A04 fix per `flows-spec-final.md:230`. | flows-spec-final.md:230 |
| `TAG_COMPOSITE_IDENTITY_V3` | `"CEALIS_V3_COMPOSITE_IDENTITY_V3"` | Historical `0x0300` HKDF salt prefix for the retired σ-derived DEK construction. `commit_version = 0x0302` no longer consumes this tag for DEK derivation; §6.3 reconstructs from Shamir shares. The tag remains registered for multi-version historical verification per §2.8. | flows-spec-final.md:127; WP §C wp.md:218; WP §D wp.md:355; dek-lifecycle design 2026-05-05 |

#### 2.3.4 Stanza, recipient, and artifact tags

| TAG | Label string for keccak | Construction context | Source-of-truth |
|---|---|---|---|
| `TAG_STANZA_MAC_V3` | `"CEALIS_V3_STANZA_MAC_V3"` | Per-stanza MAC over `(stanza_index, binding_tag, plugin_version_digest)` for every stanza in the age envelope header. Crypto-enforces combiner discipline against an altered plugin that ignores or reorders stanzas. The plugin MUST verify every stanza's MAC under `TAG_STANZA_MAC_V3` BEFORE parsing the stanza payload; any MAC failure aborts the combiner before HKDF derivation (§14.1). A02 fix. | flows-spec-final.md:230; WP §C wp.md:191 |
| `TAG_STANZA_WRAP_V3` | `"CEALIS_V3_STANZA_WRAP_V3"` | Domain separator for the per-stanza hybrid PQ wrap derivation per §6.2.3. Used with `commit_context_digest_N`, not final `h_commit_N`, because stanza wrapping happens before `ciphertext_digest_N` exists. In `commit_version = 0x0302`, the wrapped content is a 32-byte Shamir share of the commit-time DEK, not a raw DEK and not a stanza-local seed. Domain-separates the per-stanza wrap derivation from any other HKDF call in the system. | flows-spec-final.md (Δ12); §6.2; dek-lifecycle design 2026-05-05; h-commit-acyclic-schedule.md §7. |
| `TAG_STANZA_WRAP_NONCE_V3` | `"CEALIS_V3_STANZA_WRAP_NONCE_V3"` | Domain separator for the AEAD nonce wrapping the Shamir share under the hybrid KEM shared secret per §6.2.3. Domain-separates the wrap-step nonce derivation from `TAG_AEAD_V3` (payload nonce). Used in the per-stanza ML-KEM-768 + X25519 wrap construction. | flows-spec-final.md (Δ12); §6.2; dek-lifecycle design 2026-05-05. |
| `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` | `"CEALIS_V3_CONDITIONAL_RECIPIENT_BINDING_V3"` | Additional MAC on each `CONDITIONAL_RECIPIENT_*` stanza over `variant_tag (1 byte) ‖ stanza_index (u32 big-endian) ‖ plugin_version_digest (bytes32) ‖ SCALE-length-prefixed(payload)`. Cross-variant substitution defense: prevents a `WALLET_EOA` payload from being silently reinterpreted as a `PASSKEY_ACCOUNT` payload via byte reinterpretation. The conditional_recipient MAC is independent of and additional to the gate `TAG_STANZA_MAC_V3` MAC; the plugin verifies BOTH MACs before parsing payload. | WP §C wp.md:191; conditional-recipient.md:56-58 |
| `TAG_REVEAL_CHALLENGE_V3` | `"CEALIS_V3_REVEAL_CHALLENGE_V3"` | Domain separator for the σ_conditional reveal-challenge digest at reveal: `keccak256(TAG_REVEAL_CHALLENGE_V3 ‖ authorizationId ‖ h_commit ‖ <mode-specific binding> ‖ role_tag ‖ stanza_index ‖ reveal_block_hash)`. Mode-specific binding is `account_id` for variant 0x01 (PASSKEY_ACCOUNT, §10.1) and `wallet_address` for variant 0x02 (WALLET_EOA, §10.2). Variant 0x03 (WALLET_EIP1271) consumes the same digest as input to `isValidSignature` per §10.3 — **but variant 0x03 is RESERVED at V2 launch per Reconfirm B; the configurator rejects Mode 3 selection at PDA-config time.** The TAG_REVEAL_CHALLENGE_V3 preimage form is spec'd architected for post-V2 enable; no V2 commits will produce a Mode 3 σ_conditional reveal-challenge digest. | WP §D wp.md:371,378; conditional-recipient.md:87,138 |
| `TAG_RECIPIENT_LEAF_V3` | `"CEALIS_V3_RECIPIENT_LEAF_V3"` | Domain separator for the leaves of the `recipients_root` Merkle tree (P8 multi-recipient delivery). Per Simon Decision D7, `recipients_root` leaves are sorted by recipient_pubkey lexicographic before hashing; this tag prefixes each leaf preimage to prevent cross-tree leaf-substitution. Leaf-format byte layout is in §3.4 cross-reference. | flows-spec-final.md:229 |
| `TAG_P15_ATTESTATION_V3` | `"CEALIS_V3_P15_ATTESTATION_V3"` | Domain separator for P15 attestation-as-input leaves under `p15_attestations_root` in commit_AAD (§4). Per-field attestation leaves prefixed with this tag prevent cross-attestation collision. | flows-spec-final.md:229 |
| `TAG_ARTIFACT_V3` | `"CEALIS_V3_ARTIFACT_V3"` | Domain separator for `RevealArtifactBundle` content digests (per-recipient bundles per Simon Decision D4b). Used wherever the artifact bundle's content is hashed for delivery confirmation, audit reference, or downstream verification. | flows-spec-final.md:229 |
| `TAG_PLUGIN_VERSION_V3` | `"CEALIS_V3_PLUGIN_VERSION_V3"` | Binds the `age-plugin-cealis-v3` build to commit_AAD via the `plugin_version_digest` field (§4). The preimage form is `plugin_version_digest = keccak256(TAG_PLUGIN_VERSION_V3 ‖ canonical_binary_hash)` where `canonical_binary_hash = keccak256(<canonical binary bytes>)` — the recipient combiner content-addresses its loaded `age-plugin-cealis-v3` binary, then TAG-prefixes and hashes again. **Q-W2-30 LOCKED 2026-04-25** by dw-lead per generalized D6 V3 TAG-prefix discipline; `flows-spec-final.md:172` raw-bytes formula (`plugin_version_digest = keccak256(<canonical binary bytes>)`, no TAG prefix) is V1-cargo-cult, tracked at BP-3 in the internal S2-1 back-propagation log for back-propagation. Simon ack at first-canonical-section checkpoint; if Simon overrides, §2 + §4 + §14.1 receive a coordinated patch. A12 fix: the recipient combiner MUST match its loaded binary's content-addressed hash against the commit_AAD's `plugin_version_digest`, verified against `PluginHashRegistry` state at the commit's block. | `flows-spec-final.md:230` (TAG name + binding intent); WP §C `wp.md:317` + §M `wp.md:1006` (`plugin_version_digest` field semantics, NOT TAG preimage form). Preimage formula locked per dw-lead Q-W2-30 resolution 2026-04-25 + BP-3. |
| `TAG_ROTATION_LOG_ANCHOR_V3` | `"CEALIS_V3_ROTATION_LOG_ANCHOR_V3"` | Domain separator for `rotation_log_anchor` derivation in the PASSKEY_ACCOUNT (variant 0x01) conditional_recipient stanza (§6.1) and PasskeyRotationLog walk-from-anchor verification (§13). Preimage form: `rotation_log_anchor = keccak256(TAG_ROTATION_LOG_ANCHOR_V3 ‖ contract_address ‖ account_id ‖ entry_index_at_commit ‖ entry_pubkey_at_commit ‖ entry_delivery_pubkey_x25519_at_commit ‖ entry_mlkem_pubkey_at_commit)`. The anchor snapshots the atomic Mode 1 identity tuple: P-256 passkey for WebAuthn authorization plus explicit X25519 + ML-KEM delivery/wrap keys. No P-256-to-X25519 conversion is defined or permitted. **BP-4 LOCKED 2026-04-25** by dw-lead per generalized D6 V3 TAG-prefix discipline (same authority as Q-W2-30); `designs/conditional-recipient.md:§2 line 51` raw-concat formula receives a Rule 33 propagation patch on Simon ack at first-canonical-section checkpoint. | `designs/conditional-recipient.md:§2` (PasskeyRotationLog spec — raw-concat baseline; BP-4 propagation patch pending); §6.1.5 stanza format; §13 PasskeyRotationLog ABI; worker-4 §6.1 cycle-2 review BP-N flag → dw-lead resolved as BP-4 in the internal S2-1 back-propagation log; B5 HARD-5 repair. |
| `TAG_CONDITIONAL_RECIPIENTS_POLICY_V3` | `"CEALIS_V3_CONDITIONAL_RECIPIENTS_POLICY_V3"` | Domain separator for `conditional_recipients_policy_digest` derivation per §4.6.3. Preimage form (mixed-pattern §1.3.3): `conditional_recipients_policy_digest = keccak256(TAG_CONDITIONAL_RECIPIENTS_POLICY_V3 ‖ SCALE(conditional_recipients_policy))` where `conditional_recipients_policy = {n, k, recipients[], recipient_stanza_merkle_root}` per `designs/conditional-recipient.md §11`. The digest binds the FULL conditional_recipients policy into commit_AAD; subject-side verifier re-derives at σ_subject signing per §4.7; G4 re-derives at reveal per §4.7.3; mismatch causes σ_G4 refusal (crypto-enforced halt). **BP-10 LOCKED 2026-04-26** by dw-lead per generalized D6 V3 TAG-prefix discipline (same authority as Q-W2-30 + BP-4); `designs/conditional-recipient.md §11` raw-keccak formula (`keccak256(SCALE(conditional_recipients_policy))`, no TAG prefix) receives a Rule 33 propagation patch on Simon ack at first-canonical-section checkpoint. Worker-4 §4 cycle-1 review finding-2 surfaced the gap; dw-lead resolved as BP-10 in the internal S2-1 back-propagation log. | `designs/conditional-recipient.md §11` (conditional_recipients_policy struct definition — raw-keccak baseline; BP-10 propagation patch pending); WP §C `wp.md:332` (`conditional_recipients_policy_digest` field semantics in commit_AAD). |
| `TAG_SUPERSEDED_COMMIT_REGISTRY_V3` | `"CEALIS_V3_SUPERSEDED_COMMIT_REGISTRY_V3"` | Domain separator for the on-chain `SupersededCommitRegistry` lookup hash discipline per §15 (re-key ceremony, BP-2 LOCKED). Construction per §15.6.3: `keccak256(TAG_SUPERSEDED_COMMIT_REGISTRY_V3 ‖ superseded_commit_ref ‖ commit_generation)`. The registry maps `superseded_commit_ref → h_commit_v2` so any recipient given an `h_commit` can walk the registry to find any successor `h_commit_vN` and confirm the supersession is governance-authorized (registry write gated by 7-day TimelockController per S2-2). **BP-11 LOCKED 2026-04-26** by dw-lead per generalized D6 V3 TAG-prefix discipline (same authority as Q-W2-30 + BP-4 + BP-10); flows-spec-final.md §SupersededCommitRegistry receives Rule 33 propagation patch on Simon ack at first-canonical-section checkpoint. Worker-3 §15 cycle-1 spec surfaced the requirement; dw-lead resolved as BP-11 in the internal S2-1 back-propagation log. | Worker-3 internal S2-1 drafting notes §15.6.3 (TAG construction + use-site); flows-spec-final.md §SupersededCommitRegistry (Rule 33 propagation patch pending). |
| `TAG_ROTATION_AUTHORIZATION_V3` | `"CEALIS_V3_ROTATION_AUTHORIZATION_V3"` | Domain separator for `rotation_authorization_digest` derivation per §13.3 (PasskeyRotationLog ABI). Use-site: per worker-3 §13 cycle-2 spec — the on-chain authorization preimage that binds a passkey/ML-KEM key rotation event to the subject's authenticated assent before the new entry is appended to the PasskeyRotationLog. **BP-12 LOCKED 2026-04-26** by dw-lead per generalized D6 V3 TAG-prefix discipline (same authority as Q-W2-30 + BP-4 + BP-10 + BP-11); `designs/conditional-recipient.md §2 line 72` receives Rule 33 propagation patch on Simon ack at first-canonical-section checkpoint. Worker-4 §13 cycle-1 review surfaced the requirement; dw-lead resolved as BP-12 in the internal S2-1 back-propagation log. | Worker-3 internal S2-1 drafting notes §13.3 (TAG construction + use-site, when shipped); `designs/conditional-recipient.md §2 line 72` (Rule 33 propagation patch pending). |
| `TAG_ORACLE_REGISTRY_V3` | `"CEALIS_V3_ORACLE_REGISTRY_V3"` | Domain separator for the per-leaf preimage of the `oracle_references_root` Merkle tree per §12.5. Construction: `oracle_id_i = keccak256(TAG_ORACLE_REGISTRY_V3 ‖ oracle_pubkey_or_addr)` for each leaf, then `oracle_references_root = MerkleRoot(SortedUnion({oracle_id_i}))`. **BP-14 LOCKED 2026-05-04** by /design pipeline (Phase 1–5; closes designs/v3-registry-class-discipline.md). Rationale: `oracle_id_i` participates as a Merkle-leaf preimage at construction time (unlike DSL/QTSP refs which are governance-opaque single-field entries inside `commit_AAD` and domain-separated by `TAG_AAD_V3` upstream wrap). Without per-leaf TAG-prefix, future Merkle trees in V3 would carry an inverted invariant ("must not collide with raw oracle_id"); per-leaf TAG-prefix forecloses cross-tree leaf substitution at the source. OracleRegistry is class-CRYPTO per §12.0 NORMATIVE rule; DSL + QTSP remain class-CATALOG (raw 32-byte ref). | `designs/v3-registry-class-discipline.md` (BP-14 ACCEPT decision + class rule); §12.5 (preimage form + Merkle-leaf use-site); `designs/v3-registry-class-discipline.md` Phase 4 stress-test H-2 (Merkle-leaf preimage threat model). |

#### 2.3.5 Controlled-use tags (commit_version = 0x0303 only)

The following eight TAG_*_V3 constants are added by the controlled-use access sessions profile per S2-8 §1.4. They become active when a PDA elects the controlled-use configuration profile (`token_policy_config.enabled = true`, equivalently `commit_version = 0x0303`). Partners running NE / TP / CR profiles without controlled-use do not consume these tags.

| TAG | Label string for keccak | Construction context | Source-of-truth |
|---|---|---|---|
| `TAG_CU_CREDENTIAL_V3` | `"CEALIS_V3_CU_CREDENTIAL_V3"` | Domain-separated hash for the off-chain master credential digest (S2-8 §2 token model). The credential digest binds the holder pubkey, scope set, master_id, and PDA root; the lazy-anchor first-presentation transaction commits the digest to `CredentialAnchorRegistry`. | S2-8 §1.4; `designs/controlled-use.md` |
| `TAG_CU_ANCHOR_V3` | `"CEALIS_V3_CU_ANCHOR_V3"` | Domain-separated hash for the on-chain credential anchor entry stored in `CredentialAnchorRegistry`. Anchor preimage binds credential digest + first-presentation block number + master credential anchor ref (S2-8 §2.6, A22 transaction-atomic discipline). | S2-8 §1.4 |
| `TAG_CU_SUB_TOKEN_V3` | `"CEALIS_V3_CU_SUB_TOKEN_V3"` | Domain-separated hash for sub-token derivation from a master credential. Derivation preimage binds master credential digest + sub-token scope subset + TTL + holder presentation context (S2-8 §2 master-vs-sub split, §8 TTL semantics). | S2-8 §1.4 |
| `TAG_CU_SLICE_COMMIT_V3` | `"CEALIS_V3_CU_SLICE_COMMIT_V3"` | First field of the per-slice sealed envelope hash construction (`h_envelope`) per S2-8 §1.7 and §5 controlled-use sealed-envelope chain. Anchors the per-slice append-only envelope chain into the existing `h_commit` lineage. | S2-8 §1.4, §1.7, §5 |
| `TAG_CU_SLICE_LAYOUT_V3` | `"CEALIS_V3_CU_SLICE_LAYOUT_V3"` | Domain separator for the `pda_slice_layout_anchor` Merkle root that commits cross-slice slice-id topology per PDA (S2-8 §5). The synthesis predecessor name `slice_topology_root` is retired per F-COS-4 rename. | S2-8 §1.4, §5 |
| `TAG_CU_WRITE_ATTEST_V3` | `"CEALIS_V3_CU_WRITE_ATTEST_V3"` | Domain separator for the G4 Phase 2 TEE write-validation attestation per S2-8 §4 (synthesis H-2 G4 TEE attestation + on-chain policy-hash replay). Binds the validated write commit to schema_hash, scope, policy-allow checks, and the slice's preceding envelope ref. | S2-8 §1.4, §4 |
| `TAG_CU_AUDIT_STREAM1_V3` | `"CEALIS_V3_CU_AUDIT_STREAM1_V3"` | Domain separator for Stream 1 (data-event) audit entries per S2-8 §1.8. Stream 1 entries are encrypted under the slice's PDA-bound DEK and shred with the data on Art. 17 fire (synthesis H-3, A23 two-stream retention). | S2-8 §1.4, §1.8, A23 |
| `TAG_CU_AUDIT_STREAM2_V3` | `"CEALIS_V3_CU_AUDIT_STREAM2_V3"` | Domain separator for Stream 2 (metadata-event) audit entries per S2-8 §1.8 and §1.9. Stream 2 entries carry `content_shape_digest` (HMAC under deployment-scoped audit-pepper), are signed by `K_G4_audit_stream2`, AND co-signed by the PDA-selected cosign-gate from `{G2_LIT, G3_DCIPHER, G3_DRAND}` per synthesis H-4. | S2-8 §1.4, §1.8, §1.9, H-4 |

Byte-exact construction details (input field set, ordering, fixed-width padding, length prefix discipline) inherit from the §2.1 construction rule. Specific field-set definitions for `h_envelope` per `TAG_CU_SLICE_COMMIT_V3` are normative at S2-8 §1.7 sketch and pending final byte-exact authoring in this spec's §6 cross-reference (App. C BP-CU-1).

### 2.4 Hex digests (precomputed, normative)

The `bytes32` digest of each TAG is reproducible from the label string by any implementation; the values below are normative and any implementation reading a different value indicates either a non-conforming label string, an incorrect keccak-256 implementation, or an encoding bug. Implementers SHOULD include unit tests that recompute each digest from its label string at compile-time and assert equality with the values below.

The hex digests are computed as `keccak256(bytes("<LABEL>"))` per §2.1. This specification carries the labels normatively; the digests are derivative and are reproducible by any conforming keccak-256 implementation (e.g., `@noble/hashes` for TypeScript, `tiny-keccak` for Rust, `keccak.NewLegacyKeccak256()` for Go, the `keccak256` opcode for Solidity).

A test-vector appendix at App. B carries the full digest table once Phase 3 implementation has produced verified values. App. B (Test vectors) MUST carry the precomputed `bytes32` hex digest for every TAG enumerated in §2.3 — one row per TAG, with the label-string preimage shown alongside the digest, plus a worked example computation for `TAG_COMMIT_V3` so implementers have a single canonical reference for keccak-256 input encoding (UTF-8 bytes, no NUL terminator, no trailing newline).

### 2.5 Encoding rule reference

The byte-concatenation operator `‖` used throughout this registry and in §3-§14 is defined in §1 SF-3. Briefly: byte-concatenation with a TAG_*_V3 prefix is permitted ONLY for hash-input layouts where every concatenated field is fixed-width. Variable-length payloads (commit_AAD, the σ_conditional vector inside the verified share set, the conditional_recipient stanza payload) MUST use SCALE encoding (Polkadot SCALE codec, length-prefixed). Mixing a TAG prefix with a SCALE-encoded body is the specific pattern used at construction sites where a domain separator wraps a structurally complex payload (e.g., `aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD))`). §1 contains the normative full statement; §2 cites it.

### 2.6 Retired and deprecated tags — DO NOT USE

This subsection enumerates every tag that an implementer or auditor might encounter in older Cealis source material but which is NOT part of V3 custody and MUST NOT be used in any conforming V3 implementation.

#### 2.6.1 V1-era tags (entirely retired under V3 custody)

The following tags belonged to V1 cryptographic constructions that no longer exist in V3. They MUST NOT appear in any V3 implementation. Their listing here is defense-against-confusion for engineers cross-referencing V1 documentation.

The five tags marked `*` below are normatively retired per `flows-spec-final.md:234`; the remaining four (`TAG_AAD_V1`, `TAG_COMMIT_V1`, `TAG_AUTHID_V1`, `TAG_SUBJECT_V1`) are listed for defense-against-confusion since they appear in V1-era reference docs (the internal V1 Solidity rules doc enumerates the V1 TAG set extensively) and an engineer cross-referencing V1 source might otherwise mistake them as still-active. None of these tags are part of any V3 cryptographic construction.

| Retired TAG | V1 use | Reason for retirement |
|---|---|---|
| `TAG_AAD_V1` | V1 AAD construction | V1 AAD format superseded by V3 commit_AAD (§4); structurally incompatible. |
| `TAG_COMMIT_V1` | V1 commitment hash | Superseded by `TAG_COMMIT_V3`. |
| `TAG_AUTHID_V1` | V1 authorization identifier | Superseded by `TAG_AUTHID_V3` with PRO-222 nonce fix. |
| `TAG_SUBJECT_V1` | V1 subject commitment | Superseded by `TAG_SUBJECT_V3` with PRO-226 per-partner-namespace fix. |
| `TAG_WRAPPED_DEK_V1` * | V1 Cealis-held wrapped DEK | V3 has no Cealis-held wrapped DEK; DEK is commit-time random, Shamir-split, and per-stanza wrapped (§6.2 + §6.3). |
| `TAG_CEREMONY_V1` * | V1 Cealis-side DKG ceremony | V3 has no Cealis-side DKG; gate operators are independent commodity networks (§7-§9). |
| `TAG_DLEQ_V1` * | V1 Cealis-side DLEQ proof | V3 has no Cealis-side DLEQ; gate signatures are verified via standard primitive verification (BLS / Ed25519 / DCAP). |
| `TAG_PARTIAL_EXTRACT_V2` * | V2-era partial-extract construction | V3 has no Cealis extract step. |
| `TAG_REENC_CTX_V2` * | V2-era proxy re-encryption context | V3 has no Umbral PRE / proxy re-encryption. |

#### 2.6.2 V3-era retirement — `TAG_HEIR_BINDING_V3`

`TAG_HEIR_BINDING_V3` was enumerated in earlier V3 working drafts (`flows-spec-final.md:227`, dated 2026-04-21) as the per-stanza MAC for the testament-heir stanza variant. The 2026-04-24 conditional-recipient design (`designs/conditional-recipient.md`, committed via /design pipeline closing PRO-429 + PRO-431) generalized "heir" beyond testament into the polymorphic `conditional_recipient` primitive (Mode 1 PASSKEY_ACCOUNT, Mode 2 WALLET_EOA shipping V2; Mode 3 WALLET_EIP1271 reserved). The MAC was renamed to `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` to track the primitive rename.

`TAG_HEIR_BINDING_V3` MUST NOT be used in any V3 conforming implementation. Conforming implementations MUST use `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` for the per-stanza MAC of every CONDITIONAL_RECIPIENT_* stanza variant including future variants beyond 0x01 / 0x02 / 0x03. Any code referencing the retired tag is by definition pre-2026-04-24 V3-draft material and predates the canonical primitive rename.

### 2.7 Selective Disclosure pipeline tags — out of scope

The Cealis Selective Disclosure (SD) pipeline (P5 per WP §B; §H pipeline architecture) operates parallel to the V3-custody escrow core and uses an independent `CEALIS_SD_*` TAG family with its own construction discipline. S2-7 owns the active `TAG_SD_*_V3` family (`TAG_SD_FIELD_COMMITMENT_V3`, `TAG_SD_MERKLE_LEAF_V3`, `TAG_SD_BUNDLE_V3`, `TAG_SD_NULLIFIER_V3`, and related SD-only tags). S2-1 does not enumerate SD tags inside the `CEALIS_V3_*` escrow registry; it binds the SD pipeline only through `commit_AAD.sdMerkleRoot` (§4).

This specification (S2-1) is the cryptography specification for the V3-custody escrow core. SD pipeline cryptographic constructions are normatively spec'd in S2-7 (sd-spec-v2). The escrow-side and SD-side tag namespaces are disjoint by construction: the V3-custody tags carry the `CEALIS_V3_` prefix (this section) and the SD-pipeline tags carry the `CEALIS_SD_` prefix (S2-7). No tag in either namespace shares a label with any tag in the other. Cross-namespace label collisions are a specification defect and MUST be flagged immediately if observed in any draft.

### 2.8 Adding or removing tags

Adding a new TAG_*_V3 constant requires:

1. A specification change to this section enumerating the new tag with its label string and construction context.
2. A `commit_version` bump in the `h_commit` and commit_AAD field set (currently `0x0302`; see §3.4 and §4 for the version field).
3. A coordinated rollout across all conforming implementations (off-chain combiner, on-chain registry verification, plugin distribution).
4. A backward-compatibility check: existing commits under the old `commit_version` MUST continue to verify under the old tag set; the new tag applies only to commits whose `commit_version` is the new value.

Removing a tag requires:

1. A specification change marking the tag as RETIRED in §2.6 (V3-era retirement subsection if the tag was V3-canonical, V1-era subsection if it predates V3).
2. A `commit_version` bump.
3. A retention discipline for legacy commits: the retired tag's value remains computable (the label string is preserved in §2.6) so that combiners verifying legacy commits under the old `commit_version` can still construct the correct preimage. Legacy commits do not become unverifiable on tag retirement.
4. A registry-deprecation discipline if the retirement is security-motivated: codes 0x06-0x09 in the G4 refusal enum (§9.4) cover plugin / authority / DSL / oracle deprecation. Tag retirement is NOT a deprecation event in the registry sense; it is a versioning event that triggers the next-`commit_version` discipline.

### 2.8.5 Initial Stage-2 drafting carve-out (NORMATIVE)

**Numerical boundary:** BP-N entries numbered **BP-3 through BP-15 inclusive** — the initial-Stage-2-drafting BP set — do not trigger the `commit_version` bump discipline of §2.8 above. This includes new TAG_*_V3 additions tied to architectural-coherence locks (e.g., BP-14's `TAG_ORACLE_REGISTRY_V3` added 2026-05-04 per `designs/v3-registry-class-discipline.md`). Any subsequent BP-N entry numbered BP-16 or later triggers §2.8.1 `commit_version` bump discipline normally.

**Rationale:** BP-3 through BP-15 are clarifications + architectural-coherence locks of the V3-initial-release tag set, surfaced during initial drafting of the seven Stage-2 specs (S2-1 through S2-7). Treating each individually as a `commit_version` bump would multiply protocol-version churn against the same initial-release tag set without any deployed consumers to coordinate against. The numerical BP-3..BP-15 boundary is precise and unambiguous — no reliance on time-event dating ("Stage-2 sealing window," "first-canonical-section checkpoint") that would create disposition ambiguity for entries landing close to a transition.

**Sign-off:** Simon ack on S2-1 SHIPPED status (2026-04-30 per the internal Phase-2 handoff record §I) + Simon ack on /design pipeline closure of BP-13/14/15 (2026-05-04 per `designs/v3-registry-class-discipline.md`) jointly close the initial-drafting BP cycle. BP-3 / BP-4 / BP-10 / BP-11 / BP-12 LOCKED dispositions and their Rule 33 propagation patches to `designs/conditional-recipient.md` + `flows-spec-final.md` carry under the same carve-out.

**Scope:** the carve-out covers TAG additions at the §2.3 enumeration table only. It does NOT relax any other §2.8 discipline (label uniqueness, ASCII rule, precomputation requirement, retirement procedure, etc.). It does NOT extend to Stage-3 implementation; Stage-3 reference implementations consume the post-BP-15 locked tag set.

#### 2.8.6 Controlled-use profile additions (commit_version 0x0302 → 0x0303)

The eight TAG_*_V3 constants in §2.3.5 and the three commit_AAD field additions in §4 (per controlled-use profile) bump the protocol version to `commit_version = 0x0303`. The bump is selective: it applies ONLY to PDAs that elect the controlled-use configuration profile (`token_policy_config.enabled = true`). PDAs running NE / TP / CR without controlled-use continue on `commit_version = 0x0302` unchanged; no migration is required for non-controlled-use commits.

Coordinated rollout discipline per §2.8: the S2-2 amendment adds the three new on-chain registries (`CredentialAnchorRegistry`, `SliceLayoutRegistry`, `MasterTokenRevocationRegistry`) plus opt-in `TokenRevocationRegistry`; the S2-3 amendment extends G4 Phase 2 TEE scope to include write-validation + Stream 2 cosign; the S2-4 amendment adds the `token_policy_config` PDA field family. Implementations consuming the controlled-use profile MUST coordinate across S2-1 / S2-2 / S2-3 / S2-4 at the `0x0303` version boundary.

Rule 33 propagation status: the eight tags in §2.3.5 are normative at this spec; the byte-exact construction details for `h_envelope` and the audit-event tuple structures are pending S2-1 §4 + §6 amendment authoring (App. C BP-CU-1). S2-8 source-of-truth for the controlled-use architecture; this spec source-of-truth for the byte-layouts once final authoring lands.

### 2.9 Cross-reference index

The following sections in this specification consume one or more TAG_*_V3 constants as keccak / HMAC / HKDF inputs. This index is the inverse of the per-row "Construction context" column in §2.3 and is provided for forward-search by implementers:

- §3.1 subject_commitment_v3: `TAG_SUBJECT_V3`
- §3.2 authorizationId: `TAG_AUTHID_V3`
- §3.3 pda_root: `TAG_PDA_ROOT_V3`
- §3.4 h_commit + acyclic contexts: `TAG_COMMIT_V3` (final `h_commit_N` preimage prefix); `TAG_COMMIT_CONTEXT_V3` (pre-payload context with zero ciphertext digest); `TAG_ATTESTATION_CONTEXT_V3` (commit-time endpoint-attestation context). Indirectly via field bindings: `TAG_AAD_V3` (in `aad_digest` derivation per §4, where `aad_digest` is one of the 15 h_commit inputs); `TAG_RECIPIENT_LEAF_V3` (in `recipients_root` Merkle leaves per §3.4 sub-section, where `recipients_root` is one of the 15 h_commit inputs).
- §4 commit_AAD: `TAG_AAD_V3` (in `aad_digest`); `TAG_PLUGIN_VERSION_V3` (in `plugin_version_digest`); `TAG_P15_ATTESTATION_V3` (in `p15_attestations_root` Merkle leaves)
- §5 σ_subject: `TAG_SIGMA_SUBJECT_V3`
- §6.1 stanza format: `TAG_STANZA_MAC_V3` (every stanza); `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` (every CONDITIONAL_RECIPIENT_* stanza); `TAG_LIT_ACC_BINDING_V3` (stanza[0]); `TAG_DCIPHER_IBE_BINDING_V3` or `TAG_DRAND_ROUND_BINDING_V3` per `g3_choice` (stanza[1]); `TAG_G4_ATTESTATION_AUTHORITY_V3` (stanza[2])
- §6.2 hybrid PQ wrapping: `TAG_STANZA_WRAP_V3` (per-stanza wrap derivation HKDF salt); `TAG_STANZA_WRAP_NONCE_V3` (AEAD nonce wrapping the Shamir share)
- §6.3 Shamir reconstruction: no TAG input; verified σ values authorize share decap and `Shamir.combine` reconstructs the DEK
- §6.4 ChaCha20-Poly1305 AEAD: `TAG_AEAD_V3`
- §12.5 OracleRegistry per-leaf: `TAG_ORACLE_REGISTRY_V3` (BP-14 LOCKED 2026-05-04 per `designs/v3-registry-class-discipline.md` + §12.0 NORMATIVE class rule)
- §9.2 σ_G4 Phase 1 attestation: `TAG_G4_ATTESTATION_V3`
- §9.3 σ_G4 Phase 2 attestation: `TAG_G4_ATTESTATION_V3`
- §10.1 σ_conditional Mode 1 PASSKEY_ACCOUNT: `TAG_REVEAL_CHALLENGE_V3`
- §10.2 σ_conditional Mode 2 WALLET_EOA: `TAG_REVEAL_CHALLENGE_V3`
- §10.3 σ_conditional Mode 3 WALLET_EIP1271 (reserved): `TAG_REVEAL_CHALLENGE_V3` (when enabled post-V2)
- §13 PasskeyRotationLog ABI: `TAG_ROTATION_LOG_ANCHOR_V3` (in `rotation_log_anchor` derivation per §6.1 stanza format and §13 walk-from-anchor verification — universally normative; preimage field-set varies per §6.1.5 architecture contingency)
- §14.1 combiner pre-verify checklist: cross-reference site for every TAG used at reveal-time

`TAG_G3_BINDING_V3` is enumerated in §2.3.3 as a generic parent tag; per its construction-context note, it is not directly consumed at any keccak preimage site but is referenced abstractly when the spec talks about "the G3 stanza binding" before specializing to `TAG_DCIPHER_IBE_BINDING_V3` or `TAG_DRAND_ROUND_BINDING_V3`.

### 2.10 Summary

This section establishes 30 active TAG_*_V3 constants under `commit_version = 0x0302` and eight additional TAG_*_V3 constants under `commit_version = 0x0303` (controlled-use deployments only; §2.3.5) — 38 total when controlled-use is active. TAG_STANZA_WRAP_V3 + TAG_STANZA_WRAP_NONCE_V3 are unconditional and wrap Shamir shares in `commit_version = 0x0302`; TAG_COMMIT_CONTEXT_V3 + TAG_ATTESTATION_CONTEXT_V3 are the IB-1 acyclic-schedule tags that keep commit-time attestation, stanza wrapping, and payload AEAD construction out of the final-`h_commit` recursion. TAG_ROTATION_LOG_ANCHOR_V3 carries a field-set-only contingency on downstream conditional-recipient implementation detail (NORMATIVE on TAG existence). TAG_CONDITIONAL_RECIPIENTS_POLICY_V3, TAG_SUPERSEDED_COMMIT_REGISTRY_V3, TAG_ROTATION_AUTHORIZATION_V3, and TAG_ORACLE_REGISTRY_V3 are fully NORMATIVE under their locked BP dispositions; BP-13 and BP-15 are rejected class-CATALOG cases. The remaining TAGs are fully unconditional or historical multi-version verification entries as noted inline. Plus one V3-era retirement (`TAG_HEIR_BINDING_V3`). See §2.3.4 for per-TAG status. The construction rule is `TAG_<NAME>_V3 = keccak256(bytes(<LABEL>))` per §2.1, with `<LABEL>` enumerated normatively in §2.3 and following the `CEALIS_V3_*_V3` namespace. Three pre-locked labels (`TAG_COMMIT_V3`, `TAG_AUTHID_V3`, `TAG_SUBJECT_V3`) diverge from a strict symbol-derived form and are documented inline. Labels are 7-bit ASCII per RFC 20. Implementations MUST precompute each TAG as a `bytes32` constant and consume the constant at construction sites; raw label strings at construction sites are forbidden in production code. SD pipeline tags are spec'd separately in S2-7 with the disjoint `CEALIS_SD_` prefix. Adding or removing tags requires a `commit_version` bump and coordinated rollout per §2.8.

Per Cealis Protocol Checklist Item 1: every keccak / HMAC / HKDF construction in §3 through §15 of this specification consumes a TAG from this registry. No construction in the V3-custody escrow core uses a raw string literal as a domain separator. Cross-checking implementation source code against this table is the primary mechanism by which implementers and external auditors verify that domain separation is consistently applied across the system. *(See §12.0 for the class-CATALOG carve-out at registry lookup-key sites where governance-assigned opaque keys derive domain separation from upstream `TAG_AAD_V3` wraps rather than per-key TAG-prefix. The carve-out applies to DSLVersionRegistry + QTSPRegistry only; class-CRYPTO registries — PluginHashRegistry, G4AuthorityRegistry, OracleRegistry — remain under per-key TAG-prefix discipline.)*

The eight controlled-use tags in §2.3.5 ride the same `TAG_<NAME>_V3 = keccak256(bytes(<LABEL>))` construction rule per §2.1; the `CEALIS_V3_CU_*` label namespace cleanly sub-namespaces the controlled-use additions inside the `CEALIS_V3_*_V3` master namespace.

---

## §3 — Composite identifiers

This section gives byte-exact constructions for the four composite identifiers that thread through the V3-custody escrow core: `subject_commitment_v3` (per-partner unlinkable subject identifier), `authorizationId` (per-commit identifier consumed by every gate signature and every ceremony event), `pda_root` (PDA-configuration anchor that survives PDA mutation defenses), and `h_commit` (the on-chain anchor hash binding the entire envelope to Base L1). All four are keccak-256 digests with a `TAG_*_V3` prefix per §1.3.1 fixed-width concatenation discipline; all multi-byte integer fields are big-endian per §1.2.

PII content of every construction in this section: NONE. Subject identity is bound only via per-partner-namespaced commitments and content-addressed hashes; no plaintext subject data, partner data, or PDA data appears in any keccak preimage.

### 3.1 subject_commitment_v3

#### 3.1.1 Construction

```
subject_commitment_v3 = keccak256(
  TAG_SUBJECT_V3                       // 32 bytes per §2.3.1
  ‖ person_key                         // 32 bytes (mode-derived, see §3.1.2)
  ‖ partner_namespace                  // 32 bytes = keccak256(partner_id ‖ pda_id)
  ‖ registration_nonce                 // 32 bytes (CSPRNG, vault-stored, destroyed on shred)
)
```

Total preimage length: 32 + 32 + 32 + 32 = 128 bytes (TAG + 3 fixed-width field bytes). Output: 32 bytes (keccak-256).

#### 3.1.2 person_key derivation per Issuer mode (P14)

`person_key` is itself a keccak-256 digest. Its preimage depends on the PDA's Issuer mode per WP §B P14. All three modes produce a 32-byte output, so `person_key` is uniformly 32 bytes regardless of mode.

| Issuer mode | `person_key` preimage | Width / type |
|---|---|---|
| **Mode A — external Issuer (KYC flagship)** | `person_key = keccak256(provider_id ‖ per_subject_nonce)` where `provider_id` is the external attestor's bytes32 identifier (e.g., KYC vendor namespace) and `per_subject_nonce` is a 32-byte CSPRNG value generated at onboarding. | bytes32 |
| **Mode B — subject-self-sovereign** | `person_key = keccak256(wallet_address ‖ registration_nonce)` where `wallet_address` is the subject's 20-byte EOA and `registration_nonce` is a 32-byte CSPRNG value. The same `registration_nonce` value used here is concatenated separately into `subject_commitment_v3` (§3.1.1) — two distinct domain-separated uses of one nonce per onboarding. | bytes32 |
| **Mode C — asset-not-person (depositor)** | `person_key = keccak256(content_hash ‖ depositor_nonce)` where `content_hash` is a 32-byte keccak of the asset content and `depositor_nonce` is a 32-byte CSPRNG value bound to the depositor role. | bytes32 |

#### 3.1.3 partner_namespace

`partner_namespace = keccak256(partner_id ‖ pda_id)` — a 32-byte digest concatenating two 32-byte identifiers and hashing them. `partner_id` is the per-partner identifier in `PartnerRegistry`; `pda_id` is the per-PDA identifier in `PDARegistry`. Both are 32-byte values frozen at registry-creation time.

The `partner_namespace` field exists to enforce per-partner unlinkability of the subject. The same subject onboarded under two distinct `(partner_id, pda_id)` pairs produces two distinct `subject_commitment_v3` values, even when `person_key` and `registration_nonce` would otherwise be identical. This closes V1 PRO-226: an observer correlating on-chain commitments across partners cannot identify the same subject.

#### 3.1.4 registration_nonce

`registration_nonce` is a 32-byte CSPRNG-generated value, fresh per onboarding. It is stored in vault metadata and destroyed when the commitment is shredded per WP §E shred ceremony.

The nonce closes V1 PRO-222: subjects whose `person_key` candidates are enumerable (e.g., known national-ID ranges under a Mode A KYC vendor) could be matched to on-chain commitments by brute-forcing the `person_key` preimage absent the nonce. With a 32-byte nonce, the search space exceeds 2^256, foreclosing the attack.

Re-use of `registration_nonce` across commits is forbidden. Implementations MUST generate a fresh nonce per onboarding from a CSPRNG rooted in the operating environment's standard randomness source (Mode A: inside the Cealis TEE boundary using the TEE's hardware RNG; Mode B: on the subject's device using the platform's `crypto.getRandomValues` or equivalent).

#### 3.1.5 Cross-partner unlinkability — proof sketch

Given two PDAs `(partner_A_id, pda_A_id)` and `(partner_B_id, pda_B_id)` with `(partner_A_id, pda_A_id) ≠ (partner_B_id, pda_B_id)`, the resulting `partner_namespace_A` and `partner_namespace_B` differ with overwhelming probability under keccak-256 collision-resistance. Therefore `subject_commitment_v3_A ≠ subject_commitment_v3_B` even when the underlying subject is identical and even when `person_key` and `registration_nonce` are reused (which they MUST NOT be, but the unlinkability claim does not depend on nonce-freshness — it depends on partner-namespace separation alone). Cross-partner correlation requires the observer to either (a) compromise the keccak-256 collision-resistance assumption, or (b) gain access to the off-chain mapping `subject ↔ (person_key, registration_nonce)` held by each partner separately. No on-chain artifact reveals this mapping.

### 3.2 authorizationId

#### 3.2.1 Construction

```
authorizationId = keccak256(
  TAG_AUTHID_V3                        // 32 bytes per §2.3.1
  ‖ subject_commitment_v3              // 32 bytes per §3.1
  ‖ pda_id                             // 32 bytes (PDARegistry identifier)
  ‖ pda_version                        // 8 bytes (uint64, big-endian per §1.2)
  ‖ epoch                              // 8 bytes (uint64 Unix seconds, big-endian per §1.2)
  ‖ nonce                              // 32 bytes (CSPRNG per onboarding)
)
```

Total preimage length: 32 + 32 + 32 + 8 + 8 + 32 = 144 bytes. Output: 32 bytes (keccak-256).

#### 3.2.2 Field details

| Field | Width | Discipline |
|---|---|---|
| `TAG_AUTHID_V3` | 32 bytes | Per §2.3.1; precomputed `keccak256(bytes("CEALIS_V3_AUTH_ID_V3"))`. |
| `subject_commitment_v3` | 32 bytes | Per §3.1. Threads the per-partner-namespaced subject identifier through every authorization. |
| `pda_id` | 32 bytes | PDARegistry identifier. The same `pda_id` value is used in `partner_namespace` (§3.1.3) and in `pda_root` (§3.3); it is also bound separately into `commit_AAD` (§4) for AEAD-layer redundancy. |
| `pda_version` | 8 bytes (uint64, big-endian) | Frozen at commit. Allows version-specific verification semantics if a PDA has multiple versions over its lifetime. The uint64 width matches `epoch` for codec consistency and accommodates monotonic growth past any realistic per-PDA version count. |
| `epoch` | 8 bytes (uint64, big-endian) | Unix seconds since 1970-01-01T00:00:00Z. Onboarding timestamp bucket — captures the "when" of the authorization for downstream auditability without exposing finer-grained timing than the commit ceremony itself reveals. uint64 supports timestamps far beyond Year 2106 (uint32 limit). |
| `nonce` | 32 bytes (CSPRNG) | Per-commit random. Distinct from `subject_commitment_v3.registration_nonce` (which is per-onboarding). The combination of `subject_commitment_v3` (per-onboarding), `pda_id` (per-PDA), `epoch` (per-bucket), and `nonce` (per-commit) makes deterministic-collision attacks against `authorizationId` infeasible: an attacker would need to find two distinct commits sharing all five fields, which under CSPRNG guarantees on `nonce` alone has collision probability bounded by 2^-256. |

#### 3.2.3 Uniqueness property

`authorizationId` is unique across all commits with overwhelming probability under keccak-256 collision-resistance and CSPRNG nonce-uniqueness. The composition `(subject_commitment_v3, pda_id, pda_version, epoch, nonce)` is injective up to keccak collisions: two distinct commits share an `authorizationId` only if their preimage tuples collide under keccak-256, an event with probability 2^-128 per birthday-bound (and 2^-256 per second-preimage-bound).

The uniqueness property is load-bearing for §6.3 Shamir reconstruction context and §6.4 nonce derivation — the AEAD nonce is a deterministic function of `(DEK, commit_context_digest_0)`, where `commit_context_digest_0` binds `authorizationId` (via `pda_root` and indirectly, through the same fixed-width field layout as final `h_commit_0` but with `ciphertext_digest = ZERO32` per §3.4), so collision of `authorizationId` would propagate to nonce collision in the AEAD layer, which would compromise ChaCha20-Poly1305 security. The CSPRNG `nonce` field is the workhorse preventing this.

### 3.3 pda_root

#### 3.3.1 Construction (29 fields per Simon Decision D1)

```
pda_root = keccak256(
  TAG_PDA_ROOT_V3                          // 32 bytes per §2.3.1
  ‖ pda_id                                 // 32 bytes
  ‖ pda_version                            // 8 bytes (uint64, BE)
  ‖ reveal_condition_mode                  // 1 byte (uint8 enum)
  ‖ reveal_condition_spec_hash             // 32 bytes
  ‖ shred_condition_mode                   // 1 byte (uint8 enum)
  ‖ shred_condition_spec_hash              // 32 bytes
  ‖ oracle_references_root                 // 32 bytes (Merkle root)
  ‖ dsl_version                            // 32 bytes (DSLVersionRegistry ref)
  ‖ wasm_predicate_hashes_root             // 32 bytes (Merkle root, zeroed when unused)
  ‖ submitter_sets_root                    // 32 bytes (Merkle root, Mode F only)
  ‖ pause_authority_id                     // 32 bytes
  ‖ ceremony_resolver_id                   // 32 bytes
  ‖ eligible_challengers_reveal_root       // 32 bytes (Merkle root)
  ‖ eligible_challengers_shred_root        // 32 bytes (Merkle root)
  ‖ template_id                            // 32 bytes
  ‖ partner_id                             // 32 bytes
  // 13 D1 additions (Simon ack first-canonical-section checkpoint, BP-tracked):
  ‖ subject_authenticator_class            // 1 byte (uint8 enum)
  ‖ qtsp_provider_ref                      // 32 bytes (zeroed when qes_subject_required = false)
  ‖ art_9_scoped                           // 1 byte (bool)
  ‖ art_9_basis_id                         // 1 byte (uint8 enum, zeroed when art_9_scoped = false)
  ‖ legal_effect_expected                  // 1 byte (bool)
  ‖ cealis_class_wide_halt_opt_out         // 1 byte (bool)
  ‖ minimum_shred_latency                  // 8 bytes (uint64 seconds, BE)
  ‖ applicable_jurisdiction                // 32 bytes (jurisdiction code or set-merkle-root)
  ‖ conditional_recipients_updatable       // 1 byte (bool)
  ‖ subject_liveness_required_at_fire      // 1 byte (bool)
  ‖ emergency_response_bricking_acknowledgment // 1 byte (bool)
  ‖ time_critical_pda_flag                 // 1 byte (bool)
  ‖ pda_updatable                          // 1 byte (bool)
)
```

Field count: **29 fields** after the `TAG_PDA_ROOT_V3` domain-separator (16 original + 13 added per Simon Decision D1, ack at first-canonical-section checkpoint). The original 16 fields are enumerated in §3.3.3; the 13 D1 additions in §3.3.4. Per BP-9 (applied 2026-04-26 by dw-lead), the WP §C narrative previously read "15 original" — that wording was off-by-one against the WP §C enumeration itself, which lists 16; the WP narrative has now been patched to 16 and S2-1 follows the enumeration count.

Computing the byte total: 13 × 32 (bytes32 fields: `pda_id`, `reveal_condition_spec_hash`, `shred_condition_spec_hash`, `oracle_references_root`, `dsl_version`, `wasm_predicate_hashes_root`, `submitter_sets_root`, `pause_authority_id`, `ceremony_resolver_id`, `eligible_challengers_reveal_root`, `eligible_challengers_shred_root`, `template_id`, `partner_id`) = 416 bytes. Plus 8 (`pda_version` uint64) + 2 × 1 (`reveal_condition_mode` + `shred_condition_mode`) = **426 bytes (16 original fields)**. Plus 1 (`subject_authenticator_class`) + 32 (`qtsp_provider_ref`) + 1 + 1 + 1 + 1 + 8 + 32 + 1 + 1 + 1 + 1 + 1 = **82 bytes (13 D1 additions)**. Plus 32 (TAG) = **540 bytes total preimage**. Output: 32 bytes (keccak-256).

#### 3.3.2 Conditional binding rule (D1 normative)

Per Simon Decision D1: every field in `pda_root` MUST appear in the canonical preimage byte-stream regardless of value. "Not applicable" semantics use the zero-value of each field's type:

- `qtsp_provider_ref = 0x00…00` (32 bytes of 0x00) when `qes_subject_required = false` per the partner-side PDA configuration in §F.
- `art_9_basis_id = 0x00` when `art_9_scoped = false`.
- `wasm_predicate_hashes_root = 0x00…00` when no WASM predicate is referenced by either reveal or shred specs.
- `submitter_sets_root = 0x00…00` for PDAs whose conditions are entirely Mode P (Mode F has no submitter layer, so the tree is empty and the root is the keccak of empty input — but per the conditional binding rule, the field still appears in the preimage at its 32-byte width).

The conditional binding rule is what makes the preimage layout deterministic per `pda_id`: an implementation can compute `pda_root` from a `pda_id` lookup against `PDARegistry` plus the per-PDA configuration without needing to know which subset of fields the PDA's policy "uses" — every field is present, and zero-values are domain-separated from real values by the field's semantic context.

**Encoding choice — byte-concat (NOT SCALE).** The WP §C narrative previously described the conditional binding rule as "canonical SCALE encoding" — that wording was loose pseudocode for the canonical preimage form, NOT a normative directive to use SCALE as the inner codec for `pda_root`. Per BP-9 (applied 2026-04-26 by dw-lead) the WP §C narrative was patched to "canonical preimage form (fixed-width byte concatenation per §1.3.1 of the S2-1 cryptography-spec)." S2-1 normatively pins byte-concat per §1.3.1 fixed-width discipline (every field in §3.3.1 is fixed-width, so SCALE's compact-length prefixes and sum-type variant tags provide no boundary-discipline value at this layer; byte-concat preserves consistency with the rest of the §3 family — `subject_commitment_v3`, `authorizationId`, `h_commit` — all of which use byte-concat with TAG prefix). The choice is consequential: SCALE would produce different keccak input bytes than byte-concat, so this discipline must be pinned to one form for cross-implementation interop.

#### 3.3.3 Original 16 fields (per WP §C lines 263-278 enumeration; WP narrative line 295 was patched per BP-9 from "15 original" to "16 original" 2026-04-26)

| Field | Width | Discipline |
|---|---|---|
| `pda_id` | 32 bytes | Same value as in `authorizationId` (§3.2) and as input to `partner_namespace` (§3.1.3). |
| `pda_version` | 8 bytes (uint64, BE) | Same width as in `authorizationId`. |
| `reveal_condition_mode` | 1 byte (uint8 enum) | `0x01 = Mode F (FSM)`, `0x02 = Mode P (predicate)` per WP §B P4. |
| `reveal_condition_spec_hash` | 32 bytes | keccak of canonicalized FSM JSON (Mode F) or Claim AST (Mode P). Spec stored on IPFS multi-pin per WP §B P23. |
| `shred_condition_mode` | 1 byte (uint8 enum) | Same enum. Default Mode P per WP §E for most archetypes. |
| `shred_condition_spec_hash` | 32 bytes | Every PDA carries one — every PDA must commit to when destruction is valid per WP §C. |
| `oracle_references_root` | 32 bytes | Merkle root over union of oracle IDs referenced by BOTH reveal and shred specs, each bound to its OracleRegistry entry at commit-time (registry pubkey rotation does not retroactively change condition evaluation). |
| `dsl_version` | 32 bytes | Reference to DSLVersionRegistry entry. Verified at reveal against registry state at the commit's block, not current state. |
| `wasm_predicate_hashes_root` | 32 bytes | Merkle root of WASM predicate binaries embedded via DSL `custom_predicate(wasm_hash, input_binding)` meta-operator across both specs. **Zeroed when unused** per §3.3.2. |
| `submitter_sets_root` | 32 bytes | Merkle root of per-transition authorized-submitter lists (Mode F only — Mode P has no submitter layer). **Zeroed for Mode-P-only PDAs.** |
| `pause_authority_id` | 32 bytes | Encodes P24 pause-authority mode (`partner / joint / none`) per WP §B P24. |
| `ceremony_resolver_id` | 32 bytes | On-chain address (EOA / multi-sig / contract) with halt-capability during challenge windows for both reveal and shred axes per WP §F. Frozen at commit; rotation only applies to future PDAs. |
| `eligible_challengers_reveal_root` | 32 bytes | Merkle root over per-axis declared challenger sets `{subject, partner, named_observers[], recipients}` per WP §F. |
| `eligible_challengers_shred_root` | 32 bytes | Same shape, shred-axis. |
| `template_id` | 32 bytes | References the PDA+ template selected from the platform-provided library. |
| `partner_id` | 32 bytes | Same value as in `subject_commitment_v3.partner_namespace` input (§3.1.3). |

#### 3.3.4 The 13 D1 additions (per Simon Decision D1, ack at first-canonical-section checkpoint)

These fields back-propagate from the §F legal-conform pass and the conditional-recipient + emergency-response committed designs. The Rule 33 propagation pass triggered by S2-1 cryptography-spec drafting (worker-4 delta-audit Δ3 + worker-2 Q-W2-17 jointly surfaced the gap) integrated them into pda_root per Simon's D1 ack. The Stage-2 audit `§4 S2-1` (per the 2026-04-25 audit text) still references the pre-D1 pda_root field set; per Rule 33 propagation, the audit text is stale and the S2-1 spec is the canonical source for the 29-field layout (16 original per BP-9 WP narrative correction + 13 D1 additions).

| Field | Width | Source / discipline |
|---|---|---|
| `subject_authenticator_class` | 1 byte (uint8 enum) | `0x01 = platform_authenticator`, `0x02 = qtsp_qes`, `0x03 = synced_passkey`. Per WP §F PDA+ guardrail: legal-effect PDAs must NOT use `synced_passkey`. Configurator-enforced. |
| `qtsp_provider_ref` | 32 bytes | Reference to QTSPRegistry entry (D-Trust, Bundesdruckerei, etc.). Zeroed when `qes_subject_required = false`. |
| `art_9_scoped` | 1 byte (bool) | `0x01 = true` if PDA handles Art. 9(1) GDPR special-category data; `0x00 = false`. |
| `art_9_basis_id` | 1 byte (uint8 enum) | One of the 10 Art. 9(2) bases per WP §F (`(2)(a) explicit_consent` through `(2)(j) archiving_research_statistics`). Zeroed when `art_9_scoped = false`. |
| `legal_effect_expected` | 1 byte (bool) | Triggers Art. 22 safeguard guardrails per WP §F. Configurator forces tier-conditional rules when true. |
| `cealis_class_wide_halt_opt_out` | 1 byte (bool) | Partner opt-out from emergency-response class-wide halt per emergency-response.md §10. **Forbidden on legal-effect PDAs** by configurator (Art. 22(3)(a) human-intervention surface). |
| `minimum_shred_latency` | 8 bytes (uint64, BE) | Floor on elapsed time between `ShredAuthorized` emission and shred cascade execution, in seconds. PDA+ archetype floors per WP §F. |
| `applicable_jurisdiction` | 32 bytes | Scalar (single jurisdiction code) by default; set-valued (Merkle root over jurisdiction codes) for joint-escrow archetypes per WP §F. |
| `conditional_recipients_updatable` | 1 byte (bool) | When true, subject can issue updates to `conditional_recipients_policy`. Per conditional-recipient.md §8. |
| `subject_liveness_required_at_fire` | 1 byte (bool) | Per conditional-recipient.md §10 — interlocks with `role_tag = SUBJECT_SELF` (which requires this field to be true). |
| `emergency_response_bricking_acknowledgment` | 1 byte (bool) | Required on long-TTL PDAs with `pda_updatable = false` per emergency-response.md §10. Subject-acknowledged trade-off. |
| `time_critical_pda_flag` | 1 byte (bool) | When true, configurator forces `pda_updatable = true` and surfaces affirmative-harm trade-off at config time per emergency-response.md §10. |
| `pda_updatable` | 1 byte (bool) | Whether the PDA accepts post-commit updates via subject-signed update transactions. Per emergency-response.md §10. |

#### 3.3.5 Tamper-detection layering

`pda_root` is the PDA-binding anchor for `h_commit` (§3.4) — any change to any of the 29 fields produces a different `pda_root`, which produces a different `h_commit`, which fails the AEAD check at reveal (§6.4.6 universal-tripwire enforcement). Tamper-detection extends through two layers per WP §C:

- **Advance-time:** the on-chain FSMInterpreter contract re-hashes the loaded FSM spec fetched from its multi-pin location and verifies the hash matches `reveal_condition_spec_hash` extracted from `pda_root` on-chain. Any post-commit swap of the FSM spec fails at the FSMInterpreter's transition step before any gate considers signing.
- **Reveal-time:** the `age-plugin-cealis-v3` combiner verifies the AEAD bind of `commit_AAD` (which carries `pda_root` indirectly via the commit_AAD's `pda_root` field per §4), so a tampered configuration path is caught redundantly.

The redundancy is load-bearing for the universal tripwire — the chain-side FSMInterpreter check catches advance-time tamper, and the AEAD layer catches reveal-time tamper. Either layer alone would be insufficient against an attacker who could compromise the other.

### 3.4 h_commit

#### 3.4.1 Final h_commit_N construction and pre-final contexts (15 inputs per WP §C, post-IB-1)

```
ZERO32 = 0x0000000000000000000000000000000000000000000000000000000000000000

commit_AAD_attestation_N =
  commit_AAD_N with endpoint_attestation_digest = ZERO32

attestation_context_digest_N = keccak256(
  TAG_ATTESTATION_CONTEXT_V3             // 32 bytes per §2.3.2
  ‖ keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD_attestation_N))
)

endpoint_attestation_digest_N = keccak256(
  SCALE_encode(EndpointAttestation binding attestation_context_digest_N)
)

commit_AAD_N =
  final CommitAAD with endpoint_attestation_digest_N

aad_digest_N = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD_N))

commit_context_digest_N = keccak256(
  TAG_COMMIT_CONTEXT_V3                  // 32 bytes per §2.3.2
  ‖ authorizationId                      // 32 bytes per §3.2
  ‖ pda_root                             // 32 bytes per §3.3
  ‖ schema_digest                        // 32 bytes
  ‖ ZERO32                               // ciphertext_digest slot before age_envelope_N exists
  ‖ aad_digest_N                         // 32 bytes
  ‖ composite_identity_digest            // 32 bytes
  ‖ endpoint_attestation_digest_N        // 32 bytes
  ‖ retention_window                     // 8 bytes (uint64 seconds, BE)
  ‖ shred_authority_id                   // 32 bytes
  ‖ recipients_root                      // 32 bytes
  ‖ reveal_challenge_window              // 4 bytes (uint32 seconds, BE; 0 = off)
  ‖ shred_challenge_window               // 4 bytes (uint32 seconds, BE; 0 = off)
  ‖ g3_choice                            // 1 byte
  ‖ phase                                // 1 byte
  ‖ commit_version                       // 2 bytes
)

h_commit_N = keccak256(
  TAG_COMMIT_V3                        // 32 bytes per §2.3.1
  ‖ authorizationId                    // 32 bytes per §3.2
  ‖ pda_root                           // 32 bytes per §3.3
  ‖ schema_digest                      // 32 bytes (keccak of PDA.schema, P7)
  ‖ ciphertext_digest_N                // 32 bytes = keccak256(age_envelope_N), after envelope serialization
  ‖ aad_digest_N                       // 32 bytes = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD_N)) per §4
  ‖ composite_identity_digest          // 32 bytes (see §3.4.2)
  ‖ endpoint_attestation_digest_N      // 32 bytes (phase-specific, see §3.4.3)
  ‖ retention_window                   // 8 bytes (uint64 seconds, BE)
  ‖ shred_authority_id                 // 32 bytes (per-PDA P11 enum encoded)
  ‖ recipients_root                    // 32 bytes (Merkle root of recipients[])
  ‖ reveal_challenge_window            // 4 bytes (uint32 seconds, BE; 0 = off)
  ‖ shred_challenge_window             // 4 bytes (uint32 seconds, BE; 0 = off)
  ‖ g3_choice                          // 1 byte (uint8: 0 = dcipher, 1 = drand)
  ‖ phase                              // 1 byte (uint8: 1 = Phase 1, 2 = Phase 2)
  ‖ commit_version                     // 2 bytes (uint16 = 0x0302, BE)
)
```

Total final `h_commit_N` preimage length: 32 (TAG) + 32 × 9 (nine bytes32 fields: `authorizationId`, `pda_root`, `schema_digest`, `ciphertext_digest_N`, `aad_digest_N`, `composite_identity_digest`, `endpoint_attestation_digest_N`, `shred_authority_id`, `recipients_root`) + 8 (`retention_window`) + 4 × 2 (`reveal_challenge_window` + `shred_challenge_window`) + 1 × 2 (`g3_choice` + `phase`) + 2 (`commit_version`) = 32 + 288 + 8 + 8 + 2 + 2 = **340 bytes**. Output: 32 bytes (keccak-256). `commit_context_digest_N` uses the same fixed-width field layout and byte count, with `TAG_COMMIT_CONTEXT_V3` and `ciphertext_digest_N = ZERO32`.

Final `h_commit_N` is computed only after `age_envelope_N` is serialized and `ciphertext_digest_N` exists. Pre-finalization crypto MUST use `commit_context_digest_N`, not final `h_commit_N`. Only final `h_commit_N` is anchored on-chain, emitted in `RevealAuthorized`, signed by σ gates, keyed in shred/reveal registries, and used in supersession pointers. `commit_context_digest_N` and `attestation_context_digest_N` are off-chain deterministic constructions for pre-finalization KDF/AAD/attestation scheduling and MUST NOT be signed by gates or used as registry keys.

#### 3.4.2 composite_identity_digest

```
composite_identity_digest = keccak256(
  keccak256(Lit_ACC_spec)              // 32 bytes — pre-hash of Lit V3 ACC canonical encoding
  ‖ keccak256(G3_identity_spec)        // 32 bytes — pre-hash of dcipher OR drand identity per g3_choice
  ‖ conditional_recipients_root        // 32 bytes (Merkle root over conditional_recipient stanza set; zero when n=0)
)
```

Three fixed-width inputs (32 bytes each), per §1.3.1 fixed-width concatenation discipline. The pre-hash of each variable-length subfield collapses to a fixed-width digest, providing boundary discipline at the keccak-preimage construction layer (rather than delegating boundary discipline to upstream protocol encodings). This closes the §1.3.4 anti-pattern violation that direct byte-concat of variable-length fields would introduce — the §1.3.4 rule requires that boundary discipline appear in the keccak preimage construction itself, and pre-hashing each variable-length subfield satisfies this requirement uniformly.

`Lit_ACC_spec` and `G3_identity_spec` are produced in their respective protocol's canonical wire form (Lit V3 ACC encoding for the former; dcipher IBE identity OR drand round encoding for the latter, per `g3_choice`). The protocols' canonical encodings are S2-3 territory; S2-1 normatively requires that each protocol's canonical bytes be the keccak input, then keccak-collapsed to a 32-byte digest before inclusion in `composite_identity_digest`.

`conditional_recipients_root` is the Merkle root over the ordered conditional_recipient stanza set (§6.1 + §10), zero-valued (`0x00…00`) when no conditional_recipient is configured (i.e., the 3-gate baseline with `conditional_recipients_policy.n = 0`).

The legacy framing in early draft material (`flows-spec-final.md:47`) describes this digest's third input as `[optional heir pubkey]` — that framing is RETIRED per the conditional-recipient design (committed 2026-04-24 per `designs/conditional-recipient.md`); the canonical form is `conditional_recipients_root` per WP §C.

#### 3.4.3 endpoint_attestation_digest_N (phase-specific per Simon Decision D10 + IB-1)

`endpoint_attestation_digest_N` is a SCALE sum-type per Simon Decision D10 (§1.4 sum-type variant tagging) that encodes phase-specific binding over `attestation_context_digest_N`, not final `h_commit_N`. This breaks the otherwise-cyclic dependency where final `h_commit_N` would include `endpoint_attestation_digest_N` while the endpoint attestation also tried to attest final `h_commit_N`.

```
endpoint_attestation_digest_N = keccak256(
  SCALE_encode(EndpointAttestation)     // SCALE sum-type variant
)

enum EndpointAttestation {
  Phase1 {                              // variant tag 0x01
    binary_hash: bytes32,
    effective_block: u64,
    g4_authority_ref: bytes32,
    attestation_context_digest_N: bytes32,
  },
  Phase2 {                              // variant tag 0x02
    dcap_quote_bytes: Bytes,
  }
}
```

Phase 1 is dev-scaffold-only per Stage-0 Q-0-2 LOCKED — partner-facing PDAs commit under Phase 2 (DCAP attestation). Phase 1 binding is preserved in the SCALE sum-type for spec-completeness and dev-environment commits, but the configurator (per §F PDA+ guardrail) rejects legal-effect PDAs under Phase 1. The `dcap_quote_bytes` field for Phase 2 carries the full DCAP quote; per Simon Decision D11, the DCAP `user_data` field within the quote carries the `(authorizationId, attestation_context_digest_N, block_hash_or_effective_block)` binding. It MUST NOT carry final `h_commit_N`, because `endpoint_attestation_digest_N` is itself an input to final `h_commit_N`.

The mixed pattern of `keccak256(SCALE_encode(...))` is permitted per §1.3.3 because `SCALE_encode(EndpointAttestation)` produces a deterministic byte stream with SCALE's positional struct + variant-tagged sum-type framing providing the boundary discipline.

#### 3.4.4 Field details for the remaining h_commit fields

| Field | Width | Discipline |
|---|---|---|
| `TAG_COMMIT_V3` | 32 bytes | Per §2.3.1; precomputed `keccak256(bytes("CEALIS_V3_COMMITMENT_HASH_V3"))`. Pre-locked label per §2.1. |
| `authorizationId` | 32 bytes | Per §3.2. |
| `pda_root` | 32 bytes | Per §3.3 (29 fields D1-locked). |
| `schema_digest` | 32 bytes | `keccak256(PDA.schema_canonicalized)` — pins the PDA's declared schema per WP §B P7. |
| `ciphertext_digest_N` | 32 bytes | `keccak256(age_envelope_N)` per §6.1 envelope structure. Used only in final `h_commit_N`; `commit_context_digest_N` uses `ZERO32` at this field position to keep pre-finalization crypto acyclic. Recipient combiner recomputes `keccak256(loaded_envelope_N_bytes)` at reveal and rejects if it doesn't match `ciphertext_digest_N` — closes the "was this the envelope the chain saw" question per WP §C. |
| `aad_digest_N` | 32 bytes | Per Simon Decision D6 + §2.3.2 `TAG_AAD_V3`: `aad_digest_N = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD_N))`. The mixed pattern of TAG-prefix wrapping a SCALE-encoded body is permitted per §1.3.3 because `SCALE(commit_AAD_N)` provides its own boundary discipline. commit_AAD is itself bound into the AEAD at §6.4.3 for generation 0 and into stanza-wrap/lineage contexts for generation N. |
| `retention_window` | 8 bytes (uint64 BE) | Frozen at commit. The vault enforces deletion after this window elapses per WP §M storage discipline; the shred-condition logic also reads it for retention-completion predicates. |
| `shred_authority_id` | 32 bytes | Encodes per-PDA P11 shred-authority enum: `0x01 Subject / 0x02 Joint / 0x03 Operator / 0x04 Timelock / 0x05 Disabled`. **Encoding is left-padded big-endian** (matching the Solidity `bytes32(uint256(enum_value))` cast convention): `Subject = 0x0000000000000000000000000000000000000000000000000000000000000001`, `Joint = 0x…0002`, `Operator = 0x…0003`, `Timelock = 0x…0004`, `Disabled = 0x…0005`. Implementations MUST use this exact form across commit and reveal — any deviation produces a different `h_commit` than the on-chain anchor and the combiner aborts at §3.4.5 / §6.4 universal-tripwire enforcement. |
| `recipients_root` | 32 bytes | Merkle root over the `recipients[]` list per WP §B P8. Per Simon Decision D7, leaves are sorted by recipient_pubkey lexicographic before hashing; leaf format per §2.3.4 `TAG_RECIPIENT_LEAF_V3`. |
| `reveal_challenge_window` | 4 bytes (uint32 BE) | Per-PDA challenge-window duration in seconds for the reveal axis. `0` indicates no window. Per WP §F PDA+ Tier-A-zero / Tier-B-C-required guardrail: 0 forced when all reveal-side condition modules are Tier A (chain-native); ≥ archetype floor when any Tier B/C. |
| `shred_challenge_window` | 4 bytes (uint32 BE) | Same rule, shred-axis. New field added 2026-04-25 legal-conform pass per WP §F — earlier `flows-spec-final.md` material shows a single `challenge_window` field and is superseded. |
| `g3_choice` | 1 byte (uint8) | `0 = dcipher` (Randamu Threshold Association), `1 = drand` (League of Entropy). Per-PDA. The combiner consumes this field at reveal to determine which σ_G3 protocol applies (§8.2 vs §8.3). |
| `phase` | 1 byte (uint8) | `1 = Phase 1 server (DEV-SCAFFOLD ONLY, NOT partner-ready)`, `2 = Phase 2 TEE (partner-runtime per Stage-0 Q-0-2 LOCKED)`. PDA+ guardrail at §F rejects legal-effect PDAs under Phase 1. |
| `commit_version` | 2 bytes (uint16 = 0x0302, BE) | V3 custody envelope marker. Adding new TAGs, removing TAGs, or changing commit-bound byte layouts requires bumping `commit_version` per §2.8, except for initial Stage-2 drafting carve-outs in §2.8.5. The current value `0x0302` corresponds to the A1+Shamir DEK lifecycle + `sdMerkleRoot` binding + IB-1/IB-2/IB-3/IB-4 backprop release. |

#### 3.4.5 Load-bearing claim: any change produces a different final h_commit_N

The 15 final inputs above are exhaustively load-bearing — any change to any of them produces a different final `h_commit_N` under keccak-256 collision-resistance. This includes:

- Single-bit flip in any bytes32 field: produces a different keccak preimage and therefore a different output with overwhelming probability.
- Endianness violation on any multi-byte integer field: produces a different preimage byte sequence under §1.2 (BE for keccak preimages); `h_commit` does not match the on-chain anchor, so AEAD verification at §6.4.5 fails.
- Substitution of `pda_root` (e.g., serving an envelope that references a different PDA): produces a different `h_commit_N` and fails AEAD / final-anchor verification.
- Substitution of `ciphertext_digest_N` (e.g., serving a tampered envelope and updating the digest): combiner recomputes `keccak256(loaded_envelope_N_bytes)` at reveal and detects the mismatch even before AEAD verification.

The recipient combiner re-derives `attestation_context_digest_N`, `endpoint_attestation_digest_N`, `aad_digest_N`, `commit_context_digest_N`, and final `h_commit_N` at reveal from the loaded envelope and the on-chain anchor; any drift produces an `ERR_ATTESTATION_CONTEXT_MISMATCH`, `ERR_COMMIT_CONTEXT_MISMATCH`, or final-`h_commit_N` mismatch and the combiner aborts per §1.7 fail-closed error model.

#### 3.4.6 ciphertext_digest_N and commit_context_digest_N recompute rule (normative)

The combiner MUST recompute the generation contexts in this order:

1. `commit_AAD_attestation_N` by replacing `endpoint_attestation_digest_N` with `ZERO32` in the loaded `commit_AAD_N`.
2. `attestation_context_digest_N`.
3. `endpoint_attestation_digest_N` from the endpoint attestation evidence and compare it to the value in final `commit_AAD_N`.
4. `aad_digest_N`.
5. `commit_context_digest_N`.
6. `ciphertext_digest_N = keccak256(loaded_envelope_N_bytes)`.
7. final `h_commit_N`.

If `attestation_context_digest_N` does not match the endpoint-attestation evidence, the combiner aborts with `ERR_ATTESTATION_CONTEXT_MISMATCH`. If `commit_context_digest_N` does not match the context used by generation-N stanza wrapping (or, for generation-0, the payload AEAD nonce schedule at §6.4 — unchanged payload AEAD always uses `commit_context_digest_0`, not the selected-generation context), the combiner aborts with `ERR_COMMIT_CONTEXT_MISMATCH`. If `ciphertext_digest_N` differs from the final `h_commit_N` input set, the combiner aborts with `ERR_CIPHERTEXT_DIGEST_MISMATCH` per §16 BEFORE AEAD verification or share reconstruction.

This recompute step is what closes the universal-tripwire claim against vault tampering: a malicious vault operator who substitutes a tampered envelope for the original commit's envelope would need to find a colliding envelope under keccak-256, which is computationally infeasible. Without this recompute step, the AEAD layer could in principle mask vault tampering through a combination of carefully-crafted commit_AAD drift and ciphertext drift; with the recompute step, the chain-anchored final `ciphertext_digest_N` is the ground truth and any envelope failing the recompute is rejected before any further crypto.

### 3.5 Cross-reference index

This section consumes the following primitives and registries from earlier sections:

- **§1.1.1** keccak-256 — every construction in §3 produces a keccak-256 digest.
- **§1.2** endianness convention — multi-byte integer fields (`pda_version`, `epoch`, `retention_window`, `reveal_challenge_window`, `shred_challenge_window`, `commit_version`) are big-endian per §1.2; SCALE-encoded structures (e.g., the `EndpointAttestation` sum-type at §3.4.3) use SCALE-native LE per §1.4.
- **§1.3.1** byte concatenation with TAG_*_V3 prefix — every keccak preimage in §3 follows this discipline; all four constructions (subject_commitment_v3, authorizationId, pda_root, h_commit) are TAG-prefixed.
- **§1.3.3** mixed pattern — used at §3.4.2 `composite_identity_digest` (concatenates variable-length protocol-encoded subfields) and §3.4.3 `endpoint_attestation_digest` (TAG-prefix wrapping a SCALE-encoded sum-type).
- **§2.3.1** TAG_SUBJECT_V3, TAG_AUTHID_V3, TAG_COMMIT_V3, TAG_PDA_ROOT_V3 — consumed as 32-byte fixed prefixes per §1.3.1.
- **§2.3.2** TAG_AAD_V3 — consumed in `aad_digest` derivation per §3.4.4 + Simon Decision D6.

Forward-references (consumed by later sections):

- **§4** commit_AAD SCALE structure consumes `pda_root` as a top-level field; `aad_digest` per §3.4.4 wraps `SCALE(commit_AAD)` per D6.
- **§6.1** age envelope stanza format consumes `pda_root` and `authorizationId` indirectly via commit_AAD.
- **§6.3** Shamir file_key reconstruction consumes the verified Shamir shares recovered through §6.2 after σ authorization.
- **§6.4** ChaCha20-Poly1305 AEAD nonce derivation consumes `commit_context_digest_0` (generation-0 pre-payload acyclic context per §3.4) per §6.4.3 nonce formula — NOT final `h_commit_N`, which does not exist at payload-encryption time.
- **§14.1** combiner pre-verify checklist runs the §3.4.6 ciphertext_digest recompute rule + the §3.4.5 h_commit-rederivation check before file_key reconstruction fires.

### 3.6 PII content statement

NONE of the four constructions in this section produces a keccak preimage containing plaintext subject data, plaintext partner data, or plaintext PDA configuration data. All inputs are either:

- Already-hashed digests (`person_key`, `partner_namespace`, `subject_commitment_v3`, `pda_root`, `schema_digest`, `ciphertext_digest`, `aad_digest`, `composite_identity_digest`, `endpoint_attestation_digest`, `oracle_references_root`, `dsl_version`, `wasm_predicate_hashes_root`, `submitter_sets_root`, `eligible_challengers_reveal_root`, `eligible_challengers_shred_root`, `recipients_root`, `conditional_recipients_root`, `reveal_condition_spec_hash`, `shred_condition_spec_hash`, all `_id` fields);
- Random nonces (`registration_nonce`, per-commit `nonce`, per-subject nonces inside `person_key` derivation);
- Configuration enum values, version numbers, and policy flags (`reveal_condition_mode`, `shred_condition_mode`, `g3_choice`, `phase`, `commit_version`, `pda_version`, `subject_authenticator_class`, `art_9_scoped`, `art_9_basis_id`, `legal_effect_expected`, `cealis_class_wide_halt_opt_out`, `conditional_recipients_updatable`, `subject_liveness_required_at_fire`, `emergency_response_bricking_acknowledgment`, `time_critical_pda_flag`, `pda_updatable`);
- Time-window scalars (`retention_window`, `reveal_challenge_window`, `shred_challenge_window`, `minimum_shred_latency`, `epoch`);
- Jurisdiction codes (`applicable_jurisdiction`).

None of these inputs contains personally-identifiable information about the subject. Cross-partner unlinkability of `subject_commitment_v3` (§3.1.5) is the load-bearing privacy property at this layer; the other three constructions inherit unlinkability transitively because they consume `subject_commitment_v3` (or constructions that consume it) without adding any subject-identifying data.

**PII candidates that appear in DERIVED inputs.** A small set of inputs to the `person_key` derivation (§3.1.2) — specifically `wallet_address` under Mode B (subject's EOA, 20 bytes) and `provider_id` under Mode A (KYC vendor namespace, 32 bytes) — qualify as pseudo-identifiers under EU GDPR Art. 4(1) for natural persons. These appear in the `person_key` keccak preimage but NOT directly in the `subject_commitment_v3` keccak preimage. The keccak abstraction (preimage-resistance assumption) means the `person_key` digest reveals nothing about `wallet_address` or `provider_id` without brute-force search; the per-onboarding nonces (`registration_nonce` per §3.1.4 and `per_subject_nonce` / `depositor_nonce` per §3.1.2) defeat brute-force per the V1 PRO-222 mitigation. The §3.6 PII-NONE claim therefore holds at the `subject_commitment_v3` keccak-preimage layer; pseudo-identifier inputs to the `person_key` derivation remain cryptographically protected via keccak-256 preimage-resistance plus per-onboarding nonce randomization.

---

## §4 — commit_AAD SCALE structure

This section defines the byte-exact SCALE-encoded structure of `commit_AAD`, the Additional Authenticated Data block bound into the ChaCha20-Poly1305 AEAD payload at §6.4 and digested into `h_commit` at §3.4.4 via `aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE_encode(commit_AAD))` per Simon Decision D6. `commit_AAD` carries every field the AEAD-bound consistency check needs at reveal: authorization identifiers, PDA-configuration anchors, subject-binding digests, recipient-set digests, SD root binding, attestation digests, on-chain registry references that make rotation-without-breakage possible, and supersession lineage (per BP-2 LOCKED 2026-04-26 supporting per-commit re-key tracking). The struct is 22 mandatory fields, all fixed-width, totaling 523 bytes per SCALE-encoded instance. SCALE encoding is normative — raw byte concatenation is rejected per A07 boundary-malleability (WP §C line 226). The TAG-prefix on `aad_digest` is the V3 D6 use-site of `TAG_AAD_V3` from §2.3.2.

PII content of every field in `commit_AAD`: NONE. All inputs are 32-byte digests of upstream constructions, configuration enum values, version markers, or per-PDA scalar policy fields. Pseudo-identifier protection inherits transitively from §3.6 (specifically `subject_commitment_v3` and the `_id` fields).

### 4.1 commit_AAD SCALE struct definition

The struct contains 22 mandatory fields organized into four semantic groups: three per WP §C line 332 (Auth+PDA refs / Binding digests / Configuration choices) plus a fourth supersession-lineage group added per BP-2 LOCKED 2026-04-26 (worker-3 §15 cycle-1 architectural decision). SCALE struct encoding is positional — the field order below is normative for cross-implementation interoperability.

```scale
struct CommitAAD {
  // Group 1 — Authorization and PDA references (5 fields, 130 bytes)
  authorizationId:                       [u8; 32],
  pda_root:                              [u8; 32],
  schema_digest:                         [u8; 32],
  partner_id:                            [u8; 32],
  commit_version:                        u16,           // = 0x0302 for V3 custody backprop release

  // Group 2 — Binding digests (7 fields, 224 bytes)
  subject_commitment_v3:                 [u8; 32],
  sigma_subject_digest:                  [u8; 32],
  recipients_root:                       [u8; 32],
  p15_attestations_root:                 [u8; 32],
  endpoint_attestation_digest:           [u8; 32],
  conditional_recipients_policy_digest:  [u8; 32],
  sdMerkleRoot:                          [u8; 32],      // 0x00…00 when SD pipeline is OFF for the PDA; non-zero Poseidon root when SD is enabled

  // Group 3 — Configuration choices and version references (8 fields, 135 bytes)
  g3_choice:                             u8,             // 0 = dcipher, 1 = drand
  phase:                                 u8,             // 1 = Phase 1, 2 = Phase 2
  composite_identity_type:               u8,             // 0 = age-plugin-cealis-v3; values 1-255 reserved for future composite-identity-type expansion via commit_version bump per §2.8
  conditional_recipients_stanza_count:   u32,            // = n from conditional_recipients_policy
  plugin_version_digest:                 [u8; 32],
  g4_authority_ref:                      [u8; 32],
  dsl_version_ref:                       [u8; 32],
  oracle_references_root:                [u8; 32],

  // Group 4 — Supersession lineage (2 fields, 34 bytes; BP-2 LOCKED 2026-04-26)
  superseded_commit_ref:                 [u8; 32],       // sentinel 0x00…00 for original commits (commit_generation = 0); chain-walked transitively for re-key generations
  commit_generation:                     u16,            // 0 = original; 1 = first re-key; etc.; bounded at 65535 per §15.6.2
}
```

Field count: **22 fields, all mandatory**. There is no conditional or optional field at the `commit_AAD` layer — the `qtsp_provider_ref` field (relevant when `qes_subject_required = true`) is bound transitively via the `pda_root` field per WP §F line 532 + worker-4 delta-audit Δ2 resolution; it does not appear at the top level of `commit_AAD`. `sdMerkleRoot` is mandatory even when SD is disabled: SD-OFF commits encode 32 zero bytes, and SD-enabled commits encode the non-zero Poseidon Merkle root defined by S2-7 §5. Earlier framings that included `heir_wrap_present` are retired per the conditional-recipient design (committed 2026-04-24); the role is subsumed by `conditional_recipients_stanza_count > 0` (`> 0` ⇒ at least one conditional_recipient stanza is present in the envelope; `= 0` ⇒ 3-gate baseline with no conditional recipients).

**BP-2 LOCKED 2026-04-26** by dw-lead per worker-3 §15 cycle-1 architectural decision: re-key supersession lineage tracked per-commit (in `commit_AAD`), not per-PDA-policy (in `pda_root`). The two new fields `superseded_commit_ref` + `commit_generation` form Group 4 (supersession lineage). For original commits, `superseded_commit_ref = 0x00…00` and `commit_generation = 0`; for re-key generation N, `superseded_commit_ref` points to generation N-1's `h_commit` and `commit_generation = N`. Per §15.2 + §15.6.2, the supersession chain is walked transitively on-chain via the `SupersededCommitRegistry` (§15 + S2-2). In-scope of original BP-2 owner-line authority; flows-spec-final.md §SupersededCommitRegistry receives Rule 33 propagation patch on Simon ack at first-canonical-section checkpoint.

#### 4.1.1 Controlled-use commit_AAD field additions (commit_version = 0x0303 only)

When `commit_version = 0x0303` (controlled-use profile active), the commit_AAD SCALE struct in §4.1 is extended with three additional fixed-width fields per S2-8 §5 controlled-use sealed-envelope chain:

| Field | SCALE type | Byte width | Semantic role |
|---|---|---|---|
| `slice_id` | `[u8; 32]` | 32 | Per-slice identifier from the PDA's `token_policy_config.slice_layout.slices[]` (S2-8 §1.5). The 32-byte identifier disambiguates which per-slice envelope chain this commit lands in. |
| `slice_preceding_envelope_ref` | `[u8; 32]` | 32 | The 32-byte `h_envelope` of the immediately-preceding sealed envelope in this slice's chain (or `bytes32(0)` for the slice-initial envelope). Names the parent in the chain per S2-8 §5 supersession-invariance rule (the value stored is the ORIGINAL h_envelope, not any re-key generation; consumers walk `SupersededCommitRegistry` forward at read time per H-2). |
| `slice_position` | `u64` | 8 (BE per §1.2) | The 0-indexed position of this commit in its slice's chain. Slice-initial = 0; each subsequent commit increments by 1. Used at write-validation time to verify no commits skip positions (history-immutability invariant per S2-8 §5). |

Encoding under SCALE per §1.3.2: the three fields append to the existing commit_AAD struct field set in declaration order. Total `commit_AAD` byte-count under `commit_version = 0x0303` is 72 bytes larger than under `0x0302` (32 + 32 + 8 = 72). The `aad_digest` per Decision D6 (`aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD))`) automatically incorporates the new fields via SCALE's deterministic struct encoding.

Backward compatibility: a `commit_version = 0x0302` commit MUST NOT include these three fields; SCALE deserializers reading `0x0302` commit_AAD MUST validate field-set conformance. A `commit_version = 0x0303` commit MUST include all three fields; missing fields produce a SCALE deserialization error.

The byte-count arithmetic in §4.5 receives a parallel `commit_version = 0x0303` row when this amendment is fully authored. App. C BP-CU-1 tracks the pending byte-count entry.

### 4.2 SCALE encoding rules application

`commit_AAD` is encoded under §1.3.2 SCALE primitives + §1.4 SCALE codec reference. All fields are fixed-width (no `Bytes` / `Vec<T>` compact-length-prefix headers needed at this struct layer), so the byte budget is deterministic and precisely 523 bytes per instance (post-BP-SD-1 backprop 2026-05-05).

#### 4.2.1 Per-primitive byte widths (per §1.4 SCALE codec table)

| SCALE type used in CommitAAD | Encoded byte width | Endianness | Field examples |
|---|---|---|---|
| `[u8; 32]` (fixed array) | exactly 32 bytes | byte-array (no endian semantics) | All bytes32 fields (16 total) |
| `u16` | exactly 2 bytes | little-endian per §1.2 SCALE-native LE | `commit_version` |
| `u32` | exactly 4 bytes | little-endian per §1.2 SCALE-native LE | `conditional_recipients_stanza_count` |
| `u8` | exactly 1 byte | (single byte; no endian) | `g3_choice`, `phase`, `composite_identity_type` |

No compact-length encoding (`Compact<u32>` per §1.4) is needed for any field in `commit_AAD` because every field has a statically-known byte width. This is a deliberate design choice — fixed-width encoding gives auditors a deterministic byte budget and forecloses one class of length-encoding attack on the AEAD's AAD parameter.

#### 4.2.2 Endianness — SCALE-native LE per §1.2 BP-5 LOCKED

Multi-byte primitive integer fields (`commit_version` u16, `conditional_recipients_stanza_count` u32) MUST be encoded little-endian per §1.2's SCALE-native LE convention (BP-5 LOCKED). This is opposite the keccak-preimage discipline at §3 (which uses big-endian for multi-byte integer fields per §1.2). The two conventions co-exist because:

- Inside SCALE-encoded structures (`commit_AAD`, `conditional_recipients_policy`, `endpoint_attestation`), SCALE's own canonical encoding rules apply — LE for primitive ints.
- Inside keccak preimages (`subject_commitment_v3`, `authorizationId`, `pda_root`, `h_commit`), the §1.3.1 byte-concat-with-TAG-prefix discipline applies — BE for multi-byte integer fields.

The split is normative per §1.2. An implementation that produces a SCALE encoding with BE primitive ints will not interoperate with a compliant SCALE decoder; an implementation that produces a keccak preimage with LE multi-byte fields will not produce the same `h_commit` as the canonical reference. Both invariants apply simultaneously and are enforced by the consuming layer (SCALE decoder rejects malformed encoding; keccak digest mismatch fails AEAD verification).

#### 4.2.3 Struct field ordering is wire-normative

SCALE struct encoding is positional — field order in §4.1 above determines byte positions in the encoded output. Implementations that re-order fields produce different `SCALE_encode(commit_AAD)` bytes, which produce a different `aad_digest`, which fails the on-chain `h_commit` rederivation check at §3.4.5 + the AEAD AAD bind at §6.4.5. Cross-implementation interop requires the order in §4.1 to be preserved exactly.

The three-group structure (Auth+PDA refs / Binding digests / Configuration choices) reflects WP §C line 332's narrative grouping. Within each group, the order matches WP §C's prose enumeration. This ordering is the V3 normative choice and is bumped via `commit_version` for any future re-ordering or field-set change per §2.8.

### 4.3 aad_digest construction (D6 use-site for TAG_AAD_V3)

`aad_digest` per §3.4.4 is the on-chain commitment to the SCALE-encoded `commit_AAD`. Its construction is the V3 normative use-site of `TAG_AAD_V3` (enumerated at §2.3.2; instantiated here per Simon Decision D6 generalized V3 TAG-prefix discipline):

```
aad_digest = keccak256(
  TAG_AAD_V3                     // 32 bytes per §2.3.2
  ‖ SCALE_encode(commit_AAD)     // 523 bytes per §4.5 (post-BP-SD-1 backprop 2026-05-05)
)
```

Total preimage length: 32 (TAG) + 523 (SCALE-encoded struct) = **555 bytes** (post-BP-SD-1 backprop 2026-05-05). Output: 32 bytes (keccak-256).

This is a §1.3.3 mixed-pattern construction: TAG-prefix wrapping a SCALE-encoded body. The pattern is permitted because `SCALE_encode(commit_AAD)` produces a deterministic byte stream with SCALE's positional struct framing providing the inner boundary discipline; the outer TAG-prefix domain-separates this digest from any other keccak-256 digest in the spec per §1.3.1 + §2.1.

The construction matches §3.4.4's citation exactly (D6 cross-section consistency per SF-P2-4): `aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD))`. The two formulas at §3.4.4 and §4.3 above are identical modulo whitespace — `SCALE` and `SCALE_encode` are notationally equivalent, both denoting the canonical SCALE encoding of the named struct per §1.4.

The legacy framing in early draft material (`flows-spec-final.md:46`) describes `aad_digest` simply as "keccak256 of commit_AAD" without the `TAG_AAD_V3` prefix — that wording predates the generalized D6 V3 TAG-prefix discipline (locked 2026-04-25) and is RETIRED. The canonical V3 form is the TAG-prefix mixed pattern above.

### 4.4 Conditional binding (no top-level optional fields; transitive binding through pda_root)

Unlike `pda_root` (§3.3) which has 13 D1-conditional fields with the "zeroed when not applicable" rule, `commit_AAD` has no conditional or optional fields at the top level. All 22 fields are mandatory and have well-defined values for every commit:

- `conditional_recipients_policy_digest`: when `conditional_recipients_policy.n = 0` (3-gate baseline, no conditional recipients), the digest is computed over the zero-cardinality policy struct and is therefore well-defined. The field is NOT zeroed; it carries the digest of the empty policy. This matches the discipline at §3.4.2 `conditional_recipients_root = 0x00…00` only at the Merkle-root layer (where Merkle of empty input is by convention 0); the SCALE-policy-digest at this layer is the keccak of the SCALE-encoded zero-cardinality struct.
- `sdMerkleRoot`: when the SD pipeline is OFF for the PDA, the field is exactly 32 zero bytes. When SD is enabled, the field is the S2-7 §5 Poseidon Merkle root over SD field commitments and MUST be non-zero. The root is produced by S2-7's pre-root `sd_salt_context_digest` schedule; SD salt derivation MUST NOT consume `h_commit_N`, `commit_context_digest_N`, `aad_digest_N`, or any digest that depends on `sdMerkleRoot`. This field closes BP-SD-1 by making the SD root AEAD-bound and final-`h_commit_N`-bound through the existing `commit_AAD_N → aad_digest_N → h_commit_N` path without making SD block escrow success.
- `conditional_recipients_stanza_count`: `0` when no conditional_recipient is configured; `n` (matching `conditional_recipients_policy.n`) otherwise. Both values are valid encodings.
- `g4_authority_ref`, `dsl_version_ref`, `oracle_references_root`: every commit pins the registry references valid at the commit's block. There is no "not applicable" semantics — every commit consumes a current entry from each registry, so every commit has a well-defined value for each field.
- `endpoint_attestation_digest`: per §3.4.3, this field carries either the Phase 1 binding (`Ed25519` over binary_hash + block_hash + authorizationId + `attestation_context_digest_N` + timestamp) or the Phase 2 binding (DCAP quote with bound user_data = keccak(`authorizationId` + `attestation_context_digest_N` + block_hash_or_effective_block)); both are well-defined values per the SCALE sum-type at §3.4.3. `attestation_context_digest_N` is the pre-quote acyclic context per §3.4, not final `h_commit_N`.

Fields that are PDA-policy-specific and may carry semantic "not applicable" interpretations (e.g., the legal-conform-pass D1 additions like `qtsp_provider_ref`, `art_9_basis_id`, etc.) live in `pda_root` (§3.3.4) where the D1 "zeroed when not applicable" rule applies. `commit_AAD` binds those fields transitively via the `pda_root` field — any change to a pda_root field changes `pda_root`'s 32-byte value, which changes the `pda_root` field in `commit_AAD`, which changes `SCALE_encode(commit_AAD)`, which changes `aad_digest`, which changes `h_commit`, which fails the AEAD bind at §6.4.5 universal-tripwire enforcement.

This separation — D1-conditional fields live in `pda_root`, top-level `commit_AAD` fields are all mandatory and well-defined — is a deliberate design choice. It keeps the SCALE-struct byte budget at `commit_AAD` deterministically 523 bytes (no conditional length-variation), and concentrates the "zeroed when not applicable" complexity at one anchor layer (`pda_root`) plus the SD-disabled all-zero sentinel for `sdMerkleRoot`. For original commits (no prior generation), `superseded_commit_ref = 0x00…00` and `commit_generation = 0` per §15.6.2 sentinel convention; both fields ALWAYS appear in the SCALE preimage at their fixed widths.

### 4.5 Byte-count arithmetic — independently verified

The SCALE-encoded `commit_AAD` is exactly 523 bytes per the per-field width arithmetic below (post-BP-SD-1 backprop 2026-05-05). This is the canonical byte budget for cross-implementation interop.

#### 4.5.1 Per-group byte budget

**Group 1 — Authorization and PDA references (5 fields):**

| Field | SCALE type | Encoded width |
|---|---|---|
| `authorizationId` | `[u8; 32]` | 32 bytes |
| `pda_root` | `[u8; 32]` | 32 bytes |
| `schema_digest` | `[u8; 32]` | 32 bytes |
| `partner_id` | `[u8; 32]` | 32 bytes |
| `commit_version` | `u16` | 2 bytes |
| **Group 1 subtotal** | | **130 bytes** |

Arithmetic: 4 × 32 + 2 = 128 + 2 = **130 bytes**.

**Group 2 — Binding digests (7 fields):**

| Field | SCALE type | Encoded width |
|---|---|---|
| `subject_commitment_v3` | `[u8; 32]` | 32 bytes |
| `sigma_subject_digest` | `[u8; 32]` | 32 bytes |
| `recipients_root` | `[u8; 32]` | 32 bytes |
| `p15_attestations_root` | `[u8; 32]` | 32 bytes |
| `endpoint_attestation_digest` | `[u8; 32]` | 32 bytes |
| `conditional_recipients_policy_digest` | `[u8; 32]` | 32 bytes |
| `sdMerkleRoot` | `[u8; 32]` | 32 bytes |
| **Group 2 subtotal** | | **224 bytes** |

Arithmetic: 7 × 32 = **224 bytes**.

**Group 3 — Configuration choices and version references (8 fields):**

| Field | SCALE type | Encoded width |
|---|---|---|
| `g3_choice` | `u8` | 1 byte |
| `phase` | `u8` | 1 byte |
| `composite_identity_type` | `u8` | 1 byte |
| `conditional_recipients_stanza_count` | `u32` | 4 bytes |
| `plugin_version_digest` | `[u8; 32]` | 32 bytes |
| `g4_authority_ref` | `[u8; 32]` | 32 bytes |
| `dsl_version_ref` | `[u8; 32]` | 32 bytes |
| `oracle_references_root` | `[u8; 32]` | 32 bytes |
| **Group 3 subtotal** | | **135 bytes** |

Arithmetic: 3 × 1 + 4 + 4 × 32 = 3 + 4 + 128 = **135 bytes**.

**Group 4 — Supersession lineage (2 fields, BP-2 LOCKED 2026-04-26):**

| Field | SCALE type | Encoded width |
|---|---|---|
| `superseded_commit_ref` | `[u8; 32]` | 32 bytes |
| `commit_generation` | `u16` | 2 bytes |
| **Group 4 subtotal** | | **34 bytes** |

Arithmetic: 32 + 2 = **34 bytes**.

#### 4.5.2 SCALE struct total

```
SCALE_encode(commit_AAD) total bytes
  = Group 1 (130 bytes)
  + Group 2 (224 bytes)
  + Group 3 (135 bytes)
  + Group 4 (34 bytes)
  = 523 bytes
```

**`SCALE_encode(commit_AAD)` total: 523 bytes** per encoded instance (post-BP-SD-1 backprop 2026-05-05).

#### 4.5.3 aad_digest preimage total

```
aad_digest preimage bytes
  = TAG_AAD_V3 (32 bytes)
  + SCALE_encode(commit_AAD) (523 bytes)
  = 555 bytes
```

**`aad_digest` preimage total: 555 bytes** per §4.3 mixed-pattern construction (post-BP-SD-1 backprop 2026-05-05). Output: 32 bytes (keccak-256).

#### 4.5.4 Note on byte-count arithmetic lineage (PRE-BP-2 → POST-BP-2-LOCKED)

**Current canonical figures (POST-BP-SD-1 2026-05-05):** SCALE struct = **523 bytes** per encoded instance; `aad_digest` preimage = **555 bytes** (32-byte TAG-prefix + 523-byte SCALE struct). These are the load-bearing values for cross-implementation interop and are reproduced verbatim at §4.5. Any source-corpus or implementation reading a different total indicates either a pre-`sdMerkleRoot` draft or an arithmetic error.

**Lineage (for auditor cross-walk against earlier drafts):** Pre-BP-2 baseline was 457 bytes SCALE struct / 489 bytes `aad_digest` preimage. BP-2 LOCKED 2026-04-26 added two mandatory fields (`superseded_commit_ref` + `commit_generation`) totaling +34 bytes. BP-SD-1 2026-05-05 added `sdMerkleRoot` totaling +32 bytes. Post-backprop arithmetic: 457 + 34 + 32 = **523 bytes** SCALE struct; 489 + 34 + 32 = **555 bytes** `aad_digest` preimage.

**Earlier arithmetic-correction history (informational, pre-Phase-2):** A pre-Phase-2 worker-2 idle output (an internal writer-A staging draft) reported the (then pre-BP-2) SCALE struct total as 489 bytes rather than the pre-BP-2 baseline of 457. That figure was an arithmetic error (double-counting `commit_version` as both a 32-byte field and a 2-byte field). The pre-BP-2 enumeration's corrected total of 457 bytes was subsequently superseded by BP-2's +34-byte addition, yielding the current 491-byte SCALE struct. The internal session-checkpoint addendum inherited the pre-BP-2 489-byte figure as the `aad_digest` preimage total, which is no longer current; the post-BP-2 `aad_digest` preimage total is 523 bytes. No source-corpus document drifted on the underlying field set (WP §C is silent on byte budget); arithmetic-only errors in the writer-A staging chain were corrected upstream and are LOCKED at §4.5 / §4.6.4 post-BP-2.

### 4.6 Three load-bearing fields (per WP §C line 332)

WP §C calls out three fields as specifically load-bearing for V3 custody. Each is a binding into a registry whose state is read at the commit's block, not at current state — supporting forward-compat key/version rotation without breaking old commits.

#### 4.6.1 plugin_version_digest

- **Type:** `[u8; 32]`
- **Construction:** `plugin_version_digest = keccak256(TAG_PLUGIN_VERSION_V3 ‖ canonical_binary_hash)` per §2.3.5 + BP-3 (Q-W2-30 LOCKED 2026-04-25, dw-lead default per generalized D6 V3 TAG-prefix discipline)
- **Binding semantics:** Pins the commit to the specific `age-plugin-cealis-v3` build registered on-chain in `PluginHashRegistry` at commit time. The recipient combiner MUST load a binary whose hash matches this digest, verified against `PluginHashRegistry` state at the commit's block (not current state) per the "registry state at commit's block" rule.
- **Threat closed:** A12 — combiner-cannot-bypass-via-modified-plugin. Without this binding, an attacker substituting a tampered combiner could process a different DEK derivation path while the AEAD AAD still validates.
- **Deprecation handling:** if `PluginHashRegistry` marks this plugin entry deprecated AFTER the commit's block, the in-flight reveal proceeds (the gate-signing window is an architectural halt-impossibility window per §B P11 + §E). If marked deprecated BEFORE the commit's block, G4 refuses σ_G4 with reason code `0x06 plugin_deprecated` per §9 G4 reason-code enum + §15 deprecation-snapshot mechanics.

#### 4.6.2 g4_authority_ref

- **Type:** `[u8; 32]`
- **Construction:** `g4_authority_ref = keccak256(TAG_G4_ATTESTATION_AUTHORITY_V3 ‖ authority_key_pubkey)` per §2.3.5 + the V3 TAG-prefix discipline (generalized D6 / BP-3 / BP-4 pattern). The `authority_key_pubkey` is the specific G4 attestation authority public key whose registration in `G4AuthorityRegistry` is valid at the commit's block. **Encoding author-locked at S2-1; the S2-2 G4AuthorityRegistry contract interface MUST honor this byte layout** — same cross-spec pattern as §6.1.3 stanza[2] `authority_pubkey_ref` lock.
- **Binding semantics:** Pins the commit to the specific G4 root key. Recipients verify σ_G4 against this registry entry, NOT against current G4 authority key state.
- **Threat closed:** A04 — registry-race attack. Supports key rotation in `G4AuthorityRegistry` (`(hash, effective_block, tombstone_block)` tuples per `flows-spec-final.md:199`) without breaking old commits — old commits verify under the registry entry that was valid at THEIR commit block.
- **Deprecation handling:** Same as §4.6.1 — deprecated AFTER commit's block does not halt in-flight; deprecated BEFORE causes σ_G4 refusal with reason code `0x07 authority_deprecated`.

#### 4.6.3 conditional_recipients_policy_digest

- **Type:** `[u8; 32]`
- **Construction:** `conditional_recipients_policy_digest = keccak256(TAG_CONDITIONAL_RECIPIENTS_POLICY_V3 ‖ SCALE(conditional_recipients_policy))` per §2.3.5 + the V3 TAG-prefix discipline (generalized D6). The `conditional_recipients_policy` is the struct enumerating `{n, k, recipients[], recipient_stanza_merkle_root}` per `designs/conditional-recipient.md` §11. Mixed-pattern §1.3.3 construction (TAG-prefix wrapping SCALE-encoded body, same as §4.3 `aad_digest` pattern). **BP-10 LOCKED 2026-04-26** by dw-lead per generalized D6 V3 TAG-prefix discipline (same authority as Q-W2-30 + BP-4); `designs/conditional-recipient.md §11` raw-keccak formula receives a Rule 33 propagation patch on Simon ack at first-canonical-section checkpoint.
- **Binding semantics:** Pins the FULL conditional_recipients policy — n, k, the ordered recipient stanza set, their delivery modes (PASSKEY_ACCOUNT / WALLET_EOA / WALLET_EIP1271 reserved), bindings, delivery hints — into the AEAD check. The subject-side verifier (§4.7) re-derives this digest BEFORE invoking σ_subject signing; G4 re-derives at reveal.
- **Threat closed:** Server-side post-display tampering with the stanza set. A compromised configurator server that displays one policy in the UI while serializing a different policy into the SCALE payload is detected at the plugin's parse-and-display step. G4's reveal-time re-derivation provides the back-end interlock.
- **Crypto-enforced halt:** Any drift between the σ_subject'd policy and the stanza set in the envelope at reveal causes G4 to refuse σ_G4. No σ_G4 → no DEK → no decryption.

### 4.7 Subject-side pre-σ verifier — parse-and-display sub-flow

Before σ_subject is produced, the `age-plugin-cealis-v3` client runs a mandatory pre-σ verification sub-flow on the subject's device per WP §C lines 336-338. This sub-flow is normative for §4 because it is the integrity check for what the σ_subject signature actually covers — without this sub-flow, the subject could sign over a maliciously-modified `commit_AAD` rendered by a compromised configurator server.

#### 4.7.1 Display contract (normative)

The plugin MUST present in human-readable form, BEFORE invoking the subject's authenticator (WebAuthn passkey or EIP-712 wallet):

- **Every conditional_recipient** in the stanza set: `role_tag` (per §6.1.5 locked enum, e.g., `SUBJECT_SELF` / `HEIR` / `BENEFICIARY` / `MEDICAL_PROXY` — full enum at §6.1.5), `delivery_mode` (PASSKEY_ACCOUNT / WALLET_EOA / WALLET_EIP1271-reserved), binding summary (sensitive fields like `wallet_address` MAY be masked per privacy convention), and `delivery_hint`.
- **Condition module reveal-side logic** in human-readable form (per §F predicate / FSM rendering).
- **Condition module shred-side logic** in human-readable form.
- **PDA+ policy surface visible to subject:** shred authority, retention window, reveal challenge window, shred challenge window, jurisdiction, Art. 9 scoping if applicable, legal-effect-expected flag if true.
- **Derivation of `h_commit` from the displayed inputs** — so the subject sees the hash they will sign over, AND can verify (via plugin output) that the hash matches what the configurator UI claimed.

#### 4.7.2 Per-recipient confirmation requirement

The plugin MUST require:

- **One explicit confirmation (e.g., checkbox) per conditional_recipient.** The subject acknowledges each recipient individually. Bulk-confirm semantics ("approve all") are forbidden — per-recipient confirmation is structurally what defeats the attack where N legitimate recipients are displayed but a malicious (N+1)-th is silently appended.
- **One overall confirmation on the condition spec digest.** The subject acknowledges the reveal- and shred-side condition logic.

The plugin MUST refuse to invoke WebAuthn / EIP-712 signing for σ_subject without ALL confirmations.

#### 4.7.3 G4 reveal-side interlock

WP §C line 338: "G4 reproduces the same check at reveal time — G4 parses `commit_AAD.conditional_recipients_policy_digest` and verifies it matches `keccak256(SCALE(conditional_recipients_policy))` of the stanza set in the envelope; any mismatch → σ_G4 refused."

This is the back-end of the binding the subject verified at commit. The forward direction (commit-time) and reverse direction (reveal-time) together form a cryptographic closed loop that survives configurator-server compromise: the subject saw the parsed policy and signed over its digest; G4 sees the stanza set in the envelope and verifies the same digest matches.

#### 4.7.4 Plugin is one binary — verifier is a sub-flow

The verifier is a sub-flow of the existing `age-plugin-cealis-v3`, NOT a separate executable. Its reproducible-build hash is part of `plugin_version_digest` per §4.6.1. This means: an attacker compromising the configurator server cannot replace the verifier without invalidating the plugin's `PluginHashRegistry` entry, which would cause the recipient combiner to abort at §14.1 pre-verify (plugin hash mismatch).

#### 4.7.5 Mode B specific note

Under Mode B device-encrypt ingestion (`flows-spec-final.md:190`, WP §G), the verifier runs on the subject's device pre-encryption. The same display + per-recipient confirmation contract applies. Mode B is incompatible with SD per P5; this dependency is stated at the top of any Mode B documentation.

### 4.8 Cross-reference index

This section consumes the following primitives and registries from earlier sections:

- **§1.2** endianness convention — `commit_version` u16 and `conditional_recipients_stanza_count` u32 are SCALE-native LE per §1.2 + BP-5 LOCKED. The 16 `[u8; 32]` fields are byte arrays (no endian semantics).
- **§1.3.2** SCALE encoding for variable-length and structured payloads — the canonical encoding rule for `commit_AAD`. Even though no field in `commit_AAD` is variable-length, SCALE provides the struct-positional framing that gives boundary discipline.
- **§1.3.3** mixed pattern — used at §4.3 `aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE_encode(commit_AAD))` (TAG-prefix wrapping a SCALE-encoded body).
- **§1.4** SCALE codec reference — primitive byte widths consumed at §4.2.1.
- **§2.3.2** TAG_AAD_V3 — consumed in `aad_digest` derivation at §4.3 per Simon Decision D6. §2 enumerates the TAG; §4.3 specifies the use-site.
- **§2.3.5** TAG_PLUGIN_VERSION_V3, TAG_G4_ATTESTATION_AUTHORITY_V3, TAG_CONDITIONAL_RECIPIENTS_POLICY_V3 — consumed in §4.6.1 + §4.6.2 + §4.6.3 per BP-3 / BP-4 / BP-10 + the generalized D6 TAG-prefix discipline.
- **§3.4.4** `aad_digest` is cited from §3 as `keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD))` per Simon Decision D6 — §4.3's construction matches this citation exactly (D6 cross-section consistency per SF-P2-4).
- **§3.3** `pda_root` is bound into `commit_AAD` as field #2; transitively binds the 29 D1-locked pda_root fields including the conditional fields per §3.3.4.

Forward-references (consumed by later sections):

- **§5** σ_subject construction consumes `commit_AAD.conditional_recipients_policy_digest` for the subject-side verifier check at §4.7.1 (subject signs over the digest of `h_commit_preimage + PDA_terms_digest`, which transitively includes `aad_digest` via `h_commit`).
- **§6.1** age envelope stanza format consumes `conditional_recipients_stanza_count` for the stanza-count check in conditional_recipient stanzas.
- **§6.4.3** ChaCha20-Poly1305 AEAD takes `aad = SCALE_encode(commit_AAD)` as the AAD parameter — the FULL SCALE-encoded struct (523 bytes post-BP-SD-1 backprop 2026-05-05), NOT the digest. The `aad_digest` lives in `h_commit`; the FULL `commit_AAD` lives in the AEAD.
- **§9** G4 verification component consumes `conditional_recipients_policy_digest` for the reveal-side interlock check at §4.7.3.
- **§14.1** combiner pre-verify checklist re-derives `aad_digest` from the loaded envelope's `commit_AAD` and compares against `h_commit`'s `aad_digest` field per §3.4.5.

### 4.9 PII content statement

NONE of the 22 fields in `commit_AAD` carries plaintext subject data, plaintext partner data, or plaintext PDA configuration data. All inputs (including the BP-2 supersession-lineage Group 4 fields `superseded_commit_ref` and `commit_generation`, and the BP-SD-1 `sdMerkleRoot` field) are either:

- **Already-hashed digests / Merkle roots** (`subject_commitment_v3`, `sigma_subject_digest`, `pda_root`, `schema_digest`, `recipients_root`, `p15_attestations_root`, `endpoint_attestation_digest`, `conditional_recipients_policy_digest`, `sdMerkleRoot`, `plugin_version_digest`, `oracle_references_root`, `authorizationId`, `g4_authority_ref`, `dsl_version_ref`);
- **Identifiers** (`partner_id`) — non-secret partner metadata, structurally distinct from subject identifiers;
- **Configuration enum values, version markers, and policy scalar fields** (`commit_version`, `g3_choice`, `phase`, `composite_identity_type`, `conditional_recipients_stanza_count`).

None of these inputs contains personally-identifiable information about the subject. Subject identity is bound through `subject_commitment_v3` per §3.1, which itself is per-partner-namespaced and unlinkable across partners (§3.1.5). The other binding digests (`sigma_subject_digest`, `recipients_root`, `conditional_recipients_policy_digest`, etc.) inherit unlinkability transitively because they are keccak-256 outputs of upstream constructions whose preimages were already PII-free at the §3 layer.

**PII candidates that appear in DERIVED inputs upstream.** As at §3.6 ¶3, a small set of inputs to upstream constructions consumed by `commit_AAD` qualifies as pseudo-identifiers under EU GDPR Art. 4(1) for natural persons — specifically `wallet_address` (Mode B subject EOA, 20 bytes) and `provider_id` (Mode A KYC vendor namespace, 32 bytes) inside `person_key` derivation per §3.1.2. These appear in the `person_key` keccak preimage but NOT directly in any `commit_AAD` field. The keccak abstraction (preimage-resistance assumption) means the digests in `commit_AAD` reveal nothing about these pseudo-identifiers without brute-force search; the per-onboarding nonces (`registration_nonce`, `per_subject_nonce`, `depositor_nonce` per §3.1) defeat brute-force per the V1 PRO-222 mitigation. The §4.9 PII-NONE claim therefore holds at the `commit_AAD` SCALE-encoding layer; pseudo-identifier protection inherits transitively from §3.6.

`partner_id` is partner-side metadata, structurally distinct from subject metadata. Cross-partner unlinkability of subjects (§3.1.5) is preserved despite `partner_id` appearing as a top-level `commit_AAD` field — `partner_id` identifies the PARTNER (not the subject), and the binding it provides defeats cross-partner substitution attacks at the AEAD layer without compromising subject unlinkability.

---

## §5 — σ_subject construction

This section defines the byte-exact construction of `σ_subject`, the subject's cryptographic assent over the commit's PDA terms, plus the storage discipline that keeps σ_subject's pubkey off-chain (cross-partner unlinkability) while binding the signature into the AEAD via `sigma_subject_digest` in `commit_AAD` (§4.1, Group 2). Three authenticator paths are normative: WebAuthn P-256 platform authenticator (default for legal-effect PDAs), WebAuthn P-256 synced passkey (consumer ergonomics, forbidden on legal-effect PDAs by the §F PDA+ guardrail), and EIP-712 wallet secp256k1 (subject-self-sovereign Mode B). A fourth surface — QTSP-issued QES — is supported when the PDA elects `qes_subject_required = true`. The PDA+ "σ_subject authenticator class guardrail" (WP §F line 511) maps `legal_effect_expected` to the allowed `subject_authenticator_class` enum value, frozen at commit in `pda_root` (§3.3.4).

PII content of σ_subject construction at the spec layer: NONE in the keccak-preimage-bound `sigma_subject_digest` field. σ_subject's pubkey IS PII (passkey pubkeys + EOA addresses are identity-bearing pseudo-identifiers under EU GDPR Art. 4(1)) — that is why σ_subject's storage is vault-only off-chain rather than on-chain anchored.

### 5.1 σ_subject construction overview

The subject signs σ_subject over a fixed-width digest binding the commit's authorization context plus the PDA's terms:

```
σ_subject_input = keccak256(
  TAG_SIGMA_SUBJECT_V3                 // 32 bytes per §2.3.5 (V3 domain separator)
  ‖ h_commit_preimage                  // 404-byte keccak preimage from §3.4.1 (NOT h_commit's 32-byte digest)
  ‖ PDA_terms_digest                   // 32 bytes — keccak of the canonicalized PDA terms surfaced by the §4.7 verifier
)
```

**Total preimage length:** 32 (TAG) + 404 (h_commit_preimage) + 32 (PDA_terms_digest) = **468 bytes**. Output: 32 bytes (keccak-256), used as the input message to the chosen authenticator's signing primitive.

Three load-bearing properties of this construction:

1. **`h_commit_preimage` (NOT `h_commit`).** The subject signs over the keccak preimage bytes that produce `h_commit`, not over the 32-byte `h_commit` digest. This binds σ_subject to every input field of `h_commit` per §3.4.1 (15 inputs including `aad_digest`, `composite_identity_digest`, `endpoint_attestation_digest`, etc.) at the byte level. A maliciously-crafted `h_commit` collision (computationally infeasible under keccak-256 second-preimage resistance) would still fail σ_subject verification because the SIGNED bytes are the preimage, not the digest.
2. **`PDA_terms_digest`.** The keccak of the canonicalized PDA terms presented by the §4.7 subject-side verifier. This is the subject's explicit assent to the FULL PDA configuration the verifier displayed — condition module logic (reveal-side + shred-side), conditional_recipient set, PDA+ policy surface, schema, retention windows, jurisdiction. Any drift between the displayed PDA terms and the SCALE-serialized policy is detectable at G4's reveal-time interlock per §4.7.3.
3. **TAG_SIGMA_SUBJECT_V3 prefix per §2.3.5.** Domain-separates the σ_subject signing input from any other keccak-preimage construction in V3 per the §1.3.1 fixed-width-with-TAG-prefix discipline.

The signing primitive is then chosen from the three normative authenticator paths in §5.2-§5.4 based on the PDA's `subject_authenticator_class` field (frozen in `pda_root` per §3.3.4). The signature bytes — variable-length per primitive (P-256 raw 64 bytes, EIP-712 secp256k1 65 bytes, QES variable per QTSP) — constitute σ_subject. Its keccak digest `sigma_subject_digest = keccak256(σ_subject)` is the `commit_AAD.sigma_subject_digest` field per §4.1 Group 2; σ_subject itself stays off-chain in the vault.

### 5.2 Path A — WebAuthn P-256 platform authenticator

For `subject_authenticator_class = 0x01 platform_authenticator` (per §3.3.4 enum):

#### 5.2.1 What it is

A WebAuthn assertion produced by a **platform authenticator** — a device-bound credential (Apple Touch ID / Face ID, Windows Hello, Android keystore, hardware Yubikey direct attestation). The credential's private key never leaves the authenticator hardware; the authenticator returns a signed assertion over the WebAuthn challenge, which carries the σ_subject input digest from §5.1.

#### 5.2.2 Cryptographic primitive

- **Curve:** P-256 (NIST P-256 / secp256r1) — WebAuthn-native per W3C WebAuthn Level 2.
- **Signature format:** ECDSA over P-256, raw signature = 64 bytes (32-byte `r` ‖ 32-byte `s`). Wrapped inside the WebAuthn assertion structure (which adds `authenticatorData`, `clientDataJSON` framing per W3C spec).
- **σ_subject bytes:** the FULL WebAuthn assertion structure (not just the raw 64-byte ECDSA signature). The combiner re-validates the assertion structure at reveal — `clientDataJSON.challenge` MUST equal the σ_subject input digest from §5.1; `authenticatorData.rpIdHash` MUST match the configurator-side relying-party ID; the ECDSA signature MUST verify under the credential's pubkey extracted from the `attestationObject` registered at onboarding.

#### 5.2.3 Attestation statement requirement

For `legal_effect_expected = true` PDAs (per WP §F line 511 PDA+ guardrail), the WebAuthn assertion MUST be accompanied by a WebAuthn **attestation statement** (`attestationObject` per W3C spec) produced at credential registration time. The configurator validates this attestation statement at commit time; the combiner re-validates at reveal. The attestation distinguishes platform-bound credentials (which produce attestation statements signed by the authenticator vendor's attestation key chain) from synced credentials (which typically do not produce verifiable attestation statements). This is the operational mechanism that enforces the "platform-bound, not synced" requirement.

#### 5.2.4 Use case mapping

Per WP §F line 511 PDA+ guardrail decision matrix:

- **Default for legal-effect PDAs** (KYC-lending, M&A, evidence, medical) when not electing QTSP-issued QES.
- **Permitted for non-legal-effect PDAs** (consumer, journalism, archival, testament) — though synced passkey is also allowed there per §5.3.

#### 5.2.5 §286 ZPO admissibility

σ_subject under Path A is an Advanced Electronic Signature (AES) per eIDAS Art. 26, NOT a Qualified Electronic Signature (QES) per eIDAS Art. 25. German court admissibility scopes to **§286 ZPO free-evaluation** (evidence weighed alongside other evidence with full judicial discretion). For the stronger §371a Anscheinsbeweis presumption, the PDA must elect QTSP-issued QES per §5.5. This distinction is normative for downstream public copy per Rule 30 + WP §K item 13.

### 5.3 Path B — WebAuthn P-256 synced passkey

For `subject_authenticator_class = 0x03 synced_passkey` (per §3.3.4 enum):

#### 5.3.1 What it is

A WebAuthn assertion produced by a **synced passkey** — a credential that exists on multiple devices via vendor sync (iCloud Keychain, Google Password Manager, 1Password, Bitwarden, etc.).

#### 5.3.2 Cryptographic primitive

Same as §5.2.2 — P-256 ECDSA inside WebAuthn assertion structure. The cryptographic substance is identical to Path A; the operational difference is that the credential is multi-device-resident rather than device-bound.

#### 5.3.3 Forbidden on legal-effect PDAs

Per WP §F line 511 PDA+ guardrail, synced passkey σ_subject is REJECTED at the configurator for any PDA with `legal_effect_expected = true`. The eIDAS Art. 26 AES requirements ("uniquely linked" and "under the sole control" of the signatory) are not met by multi-device synced credentials — the credential is, by design, replicated across the vendor's sync service plus N user devices, so neither the unique-link nor the sole-control criterion holds in the strict sense the eIDAS framework intends.

#### 5.3.4 Use case mapping

Permitted for non-legal-effect PDAs (consumer, journalism, archival, testament) where consumer ergonomics dominate the lower evidentiary bar. Configurator surfaces the choice at PDA configuration time; archetype defaults follow the per-archetype table at brief-05 §5.

#### 5.3.5 Admissibility

Same as §5.2.5 — §286 ZPO free-evaluation. Does NOT scope to §371a regardless of WebAuthn flavor.

### 5.4 Path C — EIP-712 wallet (secp256k1)

For PDAs operating in P14 Mode B (subject-self-sovereign) where the subject signs via a Web3 wallet (MetaMask, WalletConnect, Rabby, etc.):

#### 5.4.1 What it is

An EIP-712 typed-data signature produced by the subject's wallet, signing over the σ_subject input digest from §5.1 wrapped inside an EIP-712 typed-data structure.

#### 5.4.2 Cryptographic primitive

- **Curve:** secp256k1 (Ethereum-native).
- **Signature format:** ECDSA over secp256k1, exactly **65 bytes** (1-byte `v` recovery ID ‖ 32-byte `r` ‖ 32-byte `s`).
- **σ_subject bytes:** the 65-byte secp256k1 signature.

#### 5.4.3 EIP-712 typed-data structure (Simon Decision D5 LOCKED)

Per Simon Decision D5 (per outline rev.2 line 19, LOCKED 2026-04-25):

```
EIP712Domain {
  name:              "CealisSubjectAssent",
  version:           "1",
  chainId:           per `pda_root.chain_id` (Base mainnet 8453 or Base Sepolia 84532; future chain IDs per registry per WP §N),
  verifyingContract: 0x0000000000000000000000000000000000000000,
  salt:              omitted (not part of V3 σ_subject domain)
}

CealisSubjectAssent {
  authorizationId:    bytes32,
  h_commit_preimage:  bytes,                // the 404-byte preimage from §3.4.1
  pda_terms_digest:   bytes32
}
```

The 3-field typed-data shape is normative. The σ_subject input digest from §5.1 is NOT a separate field — verifiers MUST re-derive it per the §5.1 formula `keccak256(TAG_SIGMA_SUBJECT_V3 ‖ h_commit_preimage ‖ PDA_terms_digest)` and validate ECDSA recovery against THAT digest (universal-tripwire pattern per §3.4.6 ciphertext_digest recompute + §5.7.2 σ_subject digest recompute). Including σ_subject_input as a fourth EIP-712 field would create two attack surfaces: (a) implementations that trust the signed value rather than re-deriving (drift undetected at signing time), and (b) EIP-712 typeHash lock to a 4-field shape that future schema revisions would break by collision.

The wallet computes the EIP-712 typed-data digest per the EIP-712 specification (`keccak256("\x19\x01" ‖ DomainSeparator ‖ keccak256(encodeData(CealisSubjectAssent)))`) over the 3-field struct and signs that digest with the subject's secp256k1 private key. The combiner verifies σ_subject by: (1) recomputing the EIP-712 domain separator + the 3-field typed-data digest from the loaded `(authorizationId, h_commit_preimage, pda_terms_digest)`; (2) independently re-deriving the §5.1 σ_subject_input digest and verifying it matches `keccak256(TAG_SIGMA_SUBJECT_V3 ‖ h_commit_preimage ‖ PDA_terms_digest)` (universal-tripwire); (3) ECDSA-recovering the signer pubkey from the EIP-712-formatted digest (NOT the §5.1 σ_subject_input directly), enforcing low-s normalization per EIP-2 (high-s signatures rejected with `ERR_AUTHENTICATOR_LOW_S_VIOLATION` per §16); (4) comparing the recovered address against the subject's registered EOA at onboarding (P14 Mode B). Mismatch at any step aborts with the corresponding `ERR_*` per §16 fail-closed model.

#### 5.4.4 Why `verifyingContract = address(0)`

σ_subject is an off-chain signing surface — there is no on-chain Solidity contract that verifies σ_subject. The EIP-712 `verifyingContract` field is conventionally bound to a specific contract address that scopes the typed-data domain to that contract's verification surface; when no on-chain contract exists, the convention is `address(0)` (32-byte zero address). This explicitly marks the domain as off-chain-bounded and prevents accidental signature replay against a hypothetical on-chain `CealisSubjectAssent` contract that does not and will not exist in V3 custody.

#### 5.4.5 NOT V1 inheritance

V1 used the EIP-712 domain `"CealisRevealManager"` v `"1"` for guardian-vote signatures. V3 has NO guardian network — guardian votes do not exist in V3 custody. Inheritance of the V1 domain string would be analogue-reach. The V3 domain `"CealisSubjectAssent"` v `"1"` is a fresh, V3-specific lock per Simon Decision D5.

#### 5.4.6 No additional TAG needed (per Simon Decision D14)

EIP-712's own domain separator (`EIP712Domain` typed-data hash, computed from `name`, `version`, `chainId`, `verifyingContract`) is structurally distinct from V3's keccak `TAG_*_V3` discipline — the EIP-712 domain provides its own domain-separation guarantee. Per Simon Decision D14 (outline line 28), no additional `TAG_*_V3` entry in the §2 registry is needed for EIP-712 surfaces. The σ_subject input digest still consumes `TAG_SIGMA_SUBJECT_V3` per §5.1 (that TAG is for the signing-input digest construction, NOT for the EIP-712 domain).

#### 5.4.7 Admissibility

Same as §5.2.5 + §5.3.5 — §286 ZPO free-evaluation by default. The PDA may elect QTSP-issued QES per §5.5 to scope to §371a.

### 5.5 Path D — QTSP-issued QES (eIDAS Qualified Electronic Signature)

For `subject_authenticator_class = 0x02 qtsp_qes` (per §3.3.4 enum), elected via `qes_subject_required = true` + `qtsp_provider_ref` from `QTSPRegistry`:

#### 5.5.1 What it is

A Qualified Electronic Signature (QES) issued under a registered EU QTSP's signing chain. The QTSP — a registered EU Qualified Trust Service Provider per eIDAS Art. 24 — produces σ_subject through its qualified signing infrastructure (smart card / remote QSCD / cloud-resident HSM). σ_subject's bytes are the QES bundle from the QTSP.

#### 5.5.2 Cryptographic primitive

- **Curve:** Per QTSP — typically RSA-based (≥2048-bit per eIDAS Annex II minimum) or ECDSA-based (P-256 / P-384), per the QTSP's published signing chain. S2-1 specifies the byte-exact verification surface; the QTSP key-length enumeration is operational surface bound to the registered QTSP entry. The combiner verifies against `QTSPRegistry.qtsp_root_pubkey` for the entry referenced by `pda_root.qtsp_provider_ref` (§3.3.4 D1 addition).
- **Signature length:** Per QTSP — typically several hundred bytes for RSA-based QES bundles, smaller for ECDSA-based bundles.
- **σ_subject bytes:** the FULL QES bundle as produced by the QTSP's signing infrastructure (signature + certificate chain + QTSP-specific framing per the QTSP's API).

#### 5.5.3 QTSPRegistry verification at commit's block

The combiner re-validates σ_subject's QTSP signature chain against `QTSPRegistry` state **at the commit's block, not current state** — same backward-compat pattern as `g4_authority_ref` per §4.6.2. A QTSP rotating its signing root, being deprecated under the asymmetric registry governance per WP §F line 523, or being struck from the EU Trusted List leaves prior QES-anchored σ_subject signatures verifiable indefinitely against the original registry entry.

Per WP §N line 1092 ("QTSP backward-compat"): **§371a ZPO admissibility for QES-bound commits is anchored to the σ_subject's QES status at commit time, NOT at reveal time** — German court practice on §371a treats the Anscheinsbeweis as conditioned on the signature being qualified at the time of signing. Rotation of QTSP roots after the commit does not retroactively degrade admissibility.

#### 5.5.4 §371a ZPO Anscheinsbeweis

σ_subject under Path D scopes to **§371a ZPO Anscheinsbeweis** (presumed-authenticity admissibility) per WP §K line 921. The combiner emits a `RevealArtifactBundle.qes_subject = true` marker so per-recipient verifier tooling can rely on the §371a posture without re-deriving from `pda_root.subject_authenticator_class`.

#### 5.5.5 Backward-compat operational obligation

Per P25 + WP §N line 1092, combiners MUST maintain backward-compat verification paths for prior QTSP entries indefinitely. This is a live operational obligation — partner-facing combiner upgrades cannot drop verification support for any QTSP entry that has ever been registered, as long as commits anchored to that QTSP entry exist.

### 5.6 PDA+ "σ_subject authenticator class guardrail"

WP §F line 511 normative rule: for PDAs with `legal_effect_expected = true`, σ_subject MUST be either Path A (platform_authenticator) OR Path D (qtsp_qes). Path B (synced_passkey) is REJECTED by the configurator at commit time. Path C (EIP-712 wallet) is permitted under Mode B but does not satisfy §371a alone — the PDA must additionally elect Path D via `qes_subject_required = true`.

#### 5.6.1 Decision matrix

| `legal_effect_expected` | Allowed `subject_authenticator_class` values | Forbidden |
|---|---|---|
| `true` (KYC-lending / M&A / evidence / medical) | `0x01 platform_authenticator` OR `0x02 qtsp_qes` | `0x03 synced_passkey` |
| `false` (consumer / journalism / archival / testament) | `0x01 platform_authenticator` OR `0x02 qtsp_qes` OR `0x03 synced_passkey` | (none) |

#### 5.6.2 Configurator enforcement

The configurator validates `subject_authenticator_class` against `legal_effect_expected` at PDA configuration time and rejects synced-passkey selection on legal-effect PDAs. Both fields are frozen at commit in `pda_root` (§3.3.4); switching either post-commit is impossible.

#### 5.6.3 Combiner enforcement at reveal

The combiner re-validates σ_subject's authenticator class against `pda_root.subject_authenticator_class` at reveal:

- For `0x01 platform_authenticator`: parse WebAuthn assertion + attestation; reject if attestation absent or attestation is not a platform-attestation type.
- For `0x02 qtsp_qes`: validate QTSP signature chain against `QTSPRegistry` at commit's block.
- For `0x03 synced_passkey`: parse WebAuthn assertion; no attestation requirement (synced passkeys typically do not produce verifiable attestation statements). MUST verify `pda_root.legal_effect_expected = false` — if a `subject_authenticator_class = 0x03` somehow appears on a legal-effect PDA (which the configurator should have prevented), the combiner aborts at §14.1 pre-verify.

### 5.7 Storage discipline — vault-only off-chain

σ_subject is stored exclusively in the off-chain vault. Three separate locations carry σ_subject-related data:

| Location | Content | Purpose |
|---|---|---|
| **Vault** | Full σ_subject bytes (variable-length per authenticator path) | Storage. Recipient retrieves at reveal via the `RevealArtifactBundle` per §D. |
| **Vault** | σ_subject signing pubkey + credential metadata (variable per authenticator path) | Verification anchor at reveal. Recipient combiner extracts pubkey from σ_subject bytes (WebAuthn assertion's `attestationObject` for Path A/B; recovers from σ_subject signature via ECDSA recovery for Path C; QTSP signature chain for Path D). |
| **commit_AAD field `sigma_subject_digest` (§4.1 Group 2)** | `keccak256(σ_subject)` — 32 bytes | AEAD bind. AEAD verification at reveal fails if σ_subject in vault drifts from its `sigma_subject_digest` at commit. |
| **On-chain** | NOTHING. σ_subject is NEVER on-chain. σ_subject's pubkey is NEVER on-chain. | Cross-partner unlinkability. |

#### 5.7.1 Why σ_subject's pubkey stays off-chain

WebAuthn passkey pubkeys and EIP-712 wallet EOAs are identity-bearing pseudo-identifiers under EU GDPR Art. 4(1) for natural persons. On-chain anchoring of either would create cross-partner linkability on the subject layer — an observer correlating on-chain state across two partners using the same subject's pubkey could identify the same subject across partnerships, defeating the per-partner unlinkability that `subject_commitment_v3` provides at §3.1.5.

The discipline: only `subject_commitment_v3` (per-partner-namespaced, unlinkable by construction) anchors on-chain via `commit_AAD`. The signing pubkey that produced σ_subject stays off-chain in the vault alongside σ_subject itself.

#### 5.7.2 Drift detection via AEAD bind

If a vault operator substitutes a tampered σ_subject for the original, the substitution is detected at reveal:

1. `commit_AAD.sigma_subject_digest` is bound at commit and embedded in `h_commit` via `aad_digest` per §4.3.
2. At reveal, the AEAD verification consumes the FULL `commit_AAD` (including the original `sigma_subject_digest`) per §6.4.3.
3. The recipient combiner, after AEAD-validating the payload, MUST recompute `keccak256(loaded_σ_subject_from_vault)` and compare against `commit_AAD.sigma_subject_digest`. If the two values differ, the combiner aborts with `ERR_SIGMA_SUBJECT_DIGEST_MISMATCH` per §16.

This is symmetric to the `ciphertext_digest` recompute rule at §3.4.6 — chain-anchored digest is the ground truth; vault is untrusted at the byte-stream layer.

### 5.8 Subject-side verifier interlock (cross-reference §4.7)

σ_subject signing is gated by the §4.7 subject-side pre-σ verifier. The plugin MUST refuse to invoke any of the four authenticator paths in §5.2-§5.5 without ALL of the following confirmations:

- Per-recipient confirmation for every conditional_recipient stanza per §4.7.2.
- Overall confirmation on the condition spec digest per §4.7.2.
- For Art. 9-scoped PDAs: additional Art. 9-grade explicit-consent flow per WP §F line 512 (separate plain-language explanation of the special-category data class, separate consent confirmation, explicit acknowledgment that consent is freely given, specific, informed, and unambiguous).

The verifier displays the `PDA_terms_digest` derivation alongside the `h_commit_preimage` derivation so the subject sees the EXACT bytes that will go into the σ_subject input digest at §5.1. The forward-direction (subject signs over the digest displayed by the verifier) and reverse-direction (G4 re-derives the digest at reveal per §4.7.3) form a cryptographic closed loop that survives configurator-server compromise.

### 5.9 Cross-reference index

This section consumes the following primitives and registries from earlier sections:

- **§1.1.1** keccak-256 — every digest in this section is keccak-256.
- **§1.3.1** byte concatenation with TAG_*_V3 prefix — used at §5.1 σ_subject input digest construction.
- **§2.3.5** `TAG_SIGMA_SUBJECT_V3` — consumed at §5.1 per the V3 TAG-prefix discipline.
- **§3.3.4** `subject_authenticator_class` enum values (`0x01 platform_authenticator` / `0x02 qtsp_qes` / `0x03 synced_passkey`) + `qtsp_provider_ref` — consumed at §5.2-§5.6 per the PDA+ guardrail.
- **§3.4.1** `h_commit_preimage` (404 bytes) — consumed at §5.1 as the input to σ_subject's signing digest. NOTE: the SIGNED bytes are the preimage, NOT the 32-byte `h_commit` digest.
- **§4.1** `sigma_subject_digest` field in `commit_AAD` (Group 2) — consumes `keccak256(σ_subject)` per §5.7's storage discipline.
- **§4.7** subject-side verifier — gates σ_subject signing per §5.8 interlock.

Forward-references (consumed by later sections):

- **§6.4.3** ChaCha20-Poly1305 AEAD takes `aad = SCALE_encode(commit_AAD)` which embeds `sigma_subject_digest` per §4.1; AEAD failure on σ_subject drift per §5.7.2.
- **§9** G4 verification component re-derives `commit_AAD.conditional_recipients_policy_digest` at reveal per §4.7.3 — same closed-loop pattern as σ_subject's PDA_terms_digest interlock.
- **§10** σ_conditional Mode 2 (WALLET_EOA) uses a parallel EIP-712 domain `"CealisConditionalRecipient"` v `"1"` per Simon Decision D5; same `verifyingContract = address(0)` discipline as §5.4.4. NOT inherited from σ_subject's `"CealisSubjectAssent"` domain — separate signing surface, separate domain.
- **§14.1** combiner pre-verify checklist runs §5.7.2 σ_subject digest recompute + §5.6.3 authenticator-class re-validation BEFORE the AEAD verification fires.
- **§16** error model: `ERR_SIGMA_SUBJECT_DIGEST_MISMATCH` (vault tamper detection) + `ERR_AUTHENTICATOR_CLASS_MISMATCH` (PDA-vs-vault drift on authenticator class) + `ERR_QTSP_REGISTRY_MISMATCH` (QES verification failure under registry state at commit's block) + `ERR_AUTHENTICATOR_LOW_S_VIOLATION` (Path C ECDSA high-s rejection per EIP-2 low-s normalization, §5.4.3).

### 5.10 Legal positioning — §286 default, §371a only with QTSP

Per WP §K line 921 (Rule 30 banned-phrasing constraint): public-facing copy MUST default to **§286 ZPO free-evaluation** admissibility framing for σ_subject. **§371a ZPO Anscheinsbeweis** framing is permitted ONLY when the PDA has elected QTSP integration via `qes_subject_required = true` and σ_subject is sourced from a registered QTSP per §5.5.

The distinction is normative for this spec because S2-1 is the byte-exact reference that downstream public copy (Stage-3 partner-facing materials, landing page, grants, outreach) inherits framing from. Treating the stronger §371a posture as the baseline — when the actual baseline is §286 plus §371a only on QTSP opt-in — would propagate a Rule 30 violation through the spec stack.

The decision matrix:

| σ_subject path | eIDAS classification | German ZPO admissibility |
|---|---|---|
| Path A — WebAuthn platform authenticator | AES (Art. 26) | §286 free-evaluation |
| Path B — WebAuthn synced passkey | AES (Art. 26), but rejected on legal-effect PDAs | §286 free-evaluation (non-legal-effect only) |
| Path C — EIP-712 wallet | AES (Art. 26) | §286 free-evaluation |
| Path D — QTSP-issued QES | QES (Art. 25) | §371a Anscheinsbeweis |

Both §286 and §371a are valid evidentiary postures; the difference is the burden allocation in court. §286 weighs evidence alongside other evidence with full judicial discretion; §371a presumes authenticity absent successful rebuttal. Partner choice between the baseline and the QTSP-elected stronger posture follows from `qes_subject_required` at PDA configuration time.

### 5.11 PII content statement

The spec-layer constructs in this section are PII-NONE in the keccak-bound `sigma_subject_digest` field. The signing primitives' inputs and outputs carry the following PII surface:

- **`sigma_subject_digest = keccak256(σ_subject)`** — 32-byte digest. NOT PII directly; reveals nothing about σ_subject's pubkey or content under keccak preimage-resistance.
- **σ_subject bytes (vault-stored)** — variable-length per authenticator path. Cryptographically binds the subject to the commit, but the bytes themselves do not directly expose plaintext PII. However: σ_subject's signing pubkey IS recoverable from the bytes (e.g., ECDSA recovery for EIP-712, public-key extraction from WebAuthn assertion structure). σ_subject's pubkey IS PII (passkey pubkey or EOA, identity-bearing under GDPR Art. 4(1)).
- **σ_subject's signing pubkey** — IS PII. Stays off-chain in the vault. Cross-partner unlinkability per §5.7.1 holds because no on-chain anchor exists for the pubkey.

Path-specific PII surfaces:

- **Path A + Path B (WebAuthn passkey):** The credential's pubkey (P-256 32-byte coord pair) plus the relying-party-bound credential ID. Both stay off-chain in the vault.
- **Path C (EIP-712 wallet):** The subject's EOA address (20 bytes). Recoverable from σ_subject via ECDSA recovery; the EOA is structurally on-chain (it exists as an account on Ethereum / Base regardless of Cealis), but Cealis does NOT anchor it to the commit per §5.7.1. The pseudo-identifier protection here is that the EOA's link to the specific commit stays in the vault.
- **Path D (QTSP-issued QES):** The QTSP-issued certificate, which carries the subject's name + identifying data per the QTSP's signing chain. Stays off-chain in the vault. The QTSP signing chain's pubkey is anchored via `qtsp_provider_ref` in `pda_root` (§3.3.4 D1 addition), but the QTSP's pubkey is partner-side metadata about the QTSP service, not subject-side metadata about the natural person — the pseudo-identifier surface (subject's name + qualified identity) stays in σ_subject's bytes which stay off-chain.

**PII-NONE claim at the spec layer:** holds for `sigma_subject_digest`, the only construct in this section that anchors on-chain via `commit_AAD` → `aad_digest` → `h_commit`. Pseudo-identifier protection for σ_subject's pubkey and σ_subject's bytes is via the off-chain storage discipline at §5.7, not via cryptographic primitives at this section.

The discipline pattern matches §3.6 ¶3 + §4.9: keccak-bound fields in V3 keccak preimages are PII-NONE; pseudo-identifiers exist in upstream constructions whose preimages stay either in vault metadata (here) or in derived inputs to upstream digests (per §3.6's `wallet_address` / `provider_id` defense).

---

## §6 — age-plugin-cealis-v3 — envelope spec

> **See S2-8 (controlled-use spec) §5 for the per-slice envelope chain that extends `commit_AAD` with three fixed-width fields (`slice_id`, `slice_preceding_envelope_ref`, `slice_position`) under `commit_version = 0x0303`.**

The `age-plugin-cealis-v3` envelope is `header || payload`. The header carries SCALE-encoded stanzas (§6.1) plus per-stanza hybrid post-quantum wrapping (§6.2) of Shamir shares. The payload is a single ChaCha20-Poly1305 AEAD ciphertext under a commit-time random DEK with a deterministic nonce (§6.4). At reveal, verified σ values authorize per-stanza decap; the combiner recovers shares and reconstructs `file_key = DEK` by Shamir threshold combination (§6.3). The mandatory subject-side pre-σ verifier (§6.5) runs on the subject's device before σ_subject signing fires.

### §6.1 — Stanza format

This subsection specifies the byte-exact format of the `age-plugin-cealis-v3` envelope header — three mandatory gate stanzas, the polymorphic `CONDITIONAL_RECIPIENT_*` stanza family, the per-stanza MAC binding, the additional conditional-recipient MAC binding, the MAC-before-parse rule, and the normative stanza-ordering invariant.

#### 6.1.1 Envelope shape

The `age-plugin-cealis-v3` envelope is the standard `age` two-part shape — a header containing recipient stanzas plus a single AEAD payload — instantiated against the V3 custody primitives.

```
age_envelope := header || payload

header  := [ stanza[0], stanza[1], stanza[2], stanza[3], …, stanza[2 + n] ]
payload := ChaCha20-Poly1305 ciphertext over plaintext   ; spec'd in §6.4
```

The header carries two stanza families, in this order:

| Stanza index | Recipient family | Mandatory? | Source of truth |
|---|---|---|---|
| `0` | `LIT_ACC` (G2 Lit V3 access-control condition) | yes | WP §C, brief-04 §2 |
| `1` | `G3_ID` (G3 dcipher identity OR G3 drand round) | yes | WP §C, brief-04 §2 |
| `2` | `G4_ATTESTATION_AUTHORITY` (G4 authority root reference) | yes | WP §C, brief-04 §2 |
| `3 .. 2 + n` | `CONDITIONAL_RECIPIENT_*` (variants `0x01`, `0x02`, `0x03`-RESERVED) | optional, `n ≥ 0` | designs/conditional-recipient.md, WP §C |

`n` is the recipient count from the PDA's `conditional_recipients_policy` (§F PDA surface; `n = 0` collapses to the three-gate envelope). The k-of-n threshold `k ≤ n` is a reveal-time semantics carried by the policy; at envelope-construction time every recipient slot in `0 .. n - 1` is materialised as a stanza, regardless of whether that recipient ultimately signs at reveal.

**Access-structure profile is derived, not a new wire field in `commit_version = 0x0302`.** The combiner derives the profile from `conditional_recipients_policy` bound through `conditional_recipients_policy_digest`:

| Profile | Condition | Top-level structure | Recipient branch |
|---|---|---|---|
| `FIXED_ONLY` | `n = 0`, `k = 0` | `3-of-3` over Lit, G3, G4 | absent |
| `RECIPIENT_1_OF_1` | `n = 1`, `k = 1` | `4-of-4` over Lit, G3, G4, recipient branch | branch is the single configured recipient share |
| `RECIPIENT_K_OF_N` | `n > 1`, `1 ≤ k ≤ n` | `4-of-4` over Lit, G3, G4, recipient aggregate share | nested `k-of-n` over configured recipients |

Every wrapped share is typed by `(share_domain, share_role, logical_index, x)`. `share_domain = 0x01 TOP_LEVEL` for Lit/G3/G4 and the recipient aggregate branch, and `share_domain = 0x02 RECIPIENT_BRANCH` for nested conditional-recipient shares. `share_role = 0x01 LIT`, `0x02 G3`, `0x03 G4`, `0x04 RECIPIENT_AGGREGATE`, `0x05 CONDITIONAL_RECIPIENT`. This metadata is bound in the §6.2 wrap AAD and is consumed by §6.3; it prevents surplus conditional-recipient shares from substituting for any fixed gate.

**Stanza payloads carry recipient pubkeys and wrapped Shamir shares, NOT signatures.** Each stanza reserves the cryptographic identity under which a gate (or conditional recipient) will later authorize share release at reveal. The σ values (`σ_Lit`, `σ_G3`, `σ_G4`, `σ_conditional`) are authorization signatures gathered at reveal time and never embedded into the commit-time envelope. §6.3 specifies how the recovered shares compose into the file_key; §14.2 specifies σ verification and share confidentiality.

This same envelope structure applies under both Mode A (TEE-ingest) and Mode B (device-encrypt) ingestion — the envelope is constructed inside the Cealis TEE under Mode A and on the subject's device under Mode B, but the byte-level stanza set, ordering, and MAC discipline are identical (see §G of the WP for ceremony differences).

#### 6.1.2 Stanza ordering — normative MUST

Stanza ordering is normative. The combiner verifies stanzas at fixed indices: gate stanzas at `0`, `1`, `2`; conditional-recipient stanzas at `3` through `2 + n` in PDA-author-supplied insertion order, frozen via `commit_AAD.conditional_recipients_policy.recipient_stanza_merkle_root` (§F `conditional_recipients_policy`).

Re-ordering any stanza invalidates that stanza's MAC, because `stanza_index` is one of the MAC's bound fields (§6.1.4). Re-ordering is therefore not a presentation artefact — it is a cryptographically detectable tamper. The plugin MUST construct stanzas in the ordering specified above and MUST abort decryption if any stanza appears outside its declared index.

Conditional-recipient stanza ordering specifically: insertion order at PDA-config time, as committed into `recipient_stanza_merkle_root` per author-supplied order (Decision D8, P1 lock). Ordering is partner-controlled and bound into `commit_AAD` via the policy digest (§4); a swap of two conditional-recipient slots changes both `recipient_stanza_merkle_root` and the per-stanza MACs of the affected slots, and is detected at the combiner's policy-digest check (§14.1) plus at MAC verification.

#### 6.1.3 Mandatory gate stanzas

##### `stanza[0]` — `LIT_ACC` (G2 Lit V3 access-control condition)

Reserves the Lit top-level Shamir share under the Lit V3 access-control condition (ACC) that the assigned serving TEE will satisfy at reveal time. The ACC is the chain-state predicate Lit's TEE evaluates against Base L1 before signing `σ_Lit`.

Stanza payload fields:

| Field | Type | Semantics |
|---|---|---|
| `id` | `bytes32` | `authorizationId` (§3) — pins the ACC evaluation to this commit's authorization |
| `chain_condition` | `Bytes` (SCALE-length-prefixed UTF-8) | Lit V3 ACC source. Evaluated by Lit's serving TEE at reveal against chain state. Exact ACC syntax is Lit-defined; bound here as opaque bytes, validated against Lit's parser at PDA-config time (§S2-3 / S2-6). |
| `block_hash_bound` | `bool` | MUST be `true`. Asserts that the per-op DCAP quote returned by the serving TEE binds `(authorizationId ‖ h_commit ‖ block_hash)` in its `user_data` field — the A14 anti-replay binding (§11.2). Verifier rejects the stanza if `false`. |

Per-stanza MAC binding tag (§6.1.4): `TAG_LIT_ACC_BINDING_V3` (§2).

The `σ_Lit` signature this stanza reserves is a BLS12-381 signature over `authorizationId ‖ h_commit ‖ block_hash`, produced by a single Lit V3 serving TEE assigned per-request from Lit's permissionless operator pool. §7 specifies `σ_Lit` semantics; §11.1–§11.2 specify the assignment-record + per-op DCAP verification path the combiner runs at reveal.

##### `stanza[1]` — `G3_ID` (G3 dcipher identity OR G3 drand round)

Reserves the G3 top-level Shamir share under the G3 path declared at PDA-config time. dcipher and drand are at the same normative depth (Stage-0 Q-0-1); the stanza is variant-tagged on the `type` field per `g3_choice`.

Stanza payload fields:

| Field | Type | Semantics |
|---|---|---|
| `type` | `uint8` | `g3_choice` from `commit_AAD` (§4). `0` = dcipher (Randamu Threshold Association), `1` = drand (League of Entropy). Frozen at commit; cannot rotate. |
| `id` | tagged-union (SCALE) keyed by `type` | When `type = 0` (dcipher): `bytes32 = authorizationId`. When `type = 1` (drand): `uint64 (big-endian) = drand_round` — the target round number selected at commit time, bound into the stanza so the recipient verifies `σ_G3` against the league's round signature for that exact round. The `type` field above is the union discriminator; `id` is encoded immediately following `type`, with the field's width determined by `type`. Combiner MUST read `type` before parsing `id`. The stanza's serialized length depends on `type` (32 bytes when `type = 0`, 8 bytes when `type = 1`). |

Per-stanza MAC binding tag (§6.1.4):

- `type = 0` (dcipher): `TAG_DCIPHER_IBE_BINDING_V3`
- `type = 1` (drand): `TAG_DRAND_ROUND_BINDING_V3`

`TAG_G3_BINDING_V3` is the abstract parent referenced when the spec discusses G3 generically; it is not a per-stanza MAC binding tag — only the path-specific tag binds per-stanza MACs.

§8.2 specifies the dcipher path; §8.3 specifies the drand path. Both sections define the σ_G3 byte format under their respective primitive families.

##### `stanza[2]` — `G4_ATTESTATION_AUTHORITY` (G4 authority root reference)

Reserves the G4 top-level Shamir share under the G4 authority root, NOT the per-instance G4 signing key. This indirection is the A04 anti-rotation-race fix: G4 authority keys rotate on a 7-day TimelockController + per-entry `DeprecationFlag` schedule (§N + §12.2), and binding the stanza to the authority root rather than the live signing key allows historical commits to verify against the authority entry valid at their commit block, even after rotation.

Stanza payload fields:

| Field | Type | Semantics |
|---|---|---|
| `authority_pubkey_ref` | tagged enum (SCALE) | Variant tag is `uint8`. Two variants:<br>• `0` = `RootConstant`: payload is `bytes65` (P-256 uncompressed) for Phase 2 DCAP OR `bytes32` (Ed25519 root) for Phase 1 — width determined by `commit_AAD.phase` (§4). The payload carries the actual root pubkey bytes; combiner verifies σ_G4 directly against this key.<br>• `1` = `RegistryReference`: payload is `{ contract: bytes20, authority_hash: bytes32 }` where `authority_hash` is the registry's keccak-256 entry key per `G4AuthorityRegistry`'s `(hash, effective_block, tombstone_block)` tuple semantics (§12.2 + S2-2). Combiner resolves the entry at the commit's block, recovers the authority pubkey, then verifies σ_G4 against it.<br><br>**Encoding author-locked at S2-1; S2-2 `G4AuthorityRegistry` contract interface MUST honor this byte layout.** |

Per-stanza MAC binding tag (§6.1.4): `TAG_G4_ATTESTATION_AUTHORITY_V3` (§2).

The `σ_G4` signature this stanza reserves is — at Phase 2 (the partner-anchor configuration per Stage-0 Q-0-2) — a DCAP quote whose `user_data` binds `authorizationId ‖ h_commit ‖ block_hash`. §9.3 specifies Phase 2 σ_G4 normatively. §9.2 specifies Phase 1 (sealed-code Ed25519) as dev-scaffold-only, with explicit non-partner-use notice.

`TAG_G4_ATTESTATION_AUTHORITY_V3` is the authority-binding tag for stanza[2]; `TAG_G4_ATTESTATION_V3` (§2) is the separate domain separator for σ_G4's own signing input, used inside §9. The two tags are distinct on purpose: stanza[2] binds the recipient identity (the authority root); §9's tag binds what the signer actually signs over.

#### 6.1.4 Per-stanza MAC — gate stanzas

Every gate stanza (`stanza[0]`, `stanza[1]`, `stanza[2]`) carries a MAC under `TAG_STANZA_MAC_V3` over the tuple `(stanza_index, binding_tag, plugin_version_digest)`.

Construction (byte-concat with TAG-prefix per §1 SF-3; multi-byte integers are big-endian):

```
mac_input := stanza_index (uint32, big-endian)
           ‖ binding_tag (bytes32)             // TAG_LIT_ACC_BINDING_V3 /
                                               // TAG_DCIPHER_IBE_BINDING_V3 /
                                               // TAG_DRAND_ROUND_BINDING_V3 /
                                               // TAG_G4_ATTESTATION_AUTHORITY_V3
           ‖ plugin_version_digest (bytes32)   // commit_AAD.plugin_version_digest (§4)

stanza_mac := keccak256(TAG_STANZA_MAC_V3 ‖ mac_input)
```

The MAC is keyless because all three bound fields are public and on-chain-anchored (`stanza_index` is determined by the envelope structure; `binding_tag` is one of the four enumerated values; `plugin_version_digest` is in commit_AAD which the AEAD binds at decryption). The MAC's role is integrity, not authenticity — it crypto-enforces the combiner's stanza-discipline contract at the plugin layer rather than at the source-review layer (the A02 fix).

Encoding rationale: byte-concat with TAG-prefix is the canonical form per §1 SF-3 for fixed-width keccak preimages. All three fields here are fixed-width (uint32 + bytes32 + bytes32 = 68 bytes total mac_input). The same byte-concat with explicit big-endian convention applies to the conditional-recipient MAC (§6.1.6) so a single codec covers both MAC families. SCALE encoding is reserved for variable-length structures (commit_AAD §4, conditional_recipients_policy §F, endpoint-attestation sum types).

The MAC is stored as the final `bytes32` of the stanza's serialized form. The plugin computes it at envelope-construction and verifies it before parsing the stanza's payload at decryption (§6.1.6).

#### 6.1.5 Conditional-recipient stanzas — polymorphic

The `CONDITIONAL_RECIPIENT_*` family generalises the per-PDA non-partner-recipient surface: heir, beneficiary, acquirer-counsel, medical-proxy, subject-alternate, journalism-recipient, subject-self. Polymorphic by `delivery_mode`, with three variants spec'd at V2 (one shipping pair plus one reserved variant per Decision Reconfirm B). Per-mode σ_conditional verification protocols are spec'd in §10.

Variant tag occupies the first byte of every conditional-recipient stanza payload, so the MAC (§6.1.7) covers it; this closes byte-reinterpretation attacks where a payload of one variant's shape is reparsed as another variant.

##### Variant `0x01` — `PASSKEY_ACCOUNT` (ships V2)

For natural-person recipients identified by their Cealis-account passkey. Identity-bound at PDA-config time via QR-mediated account linkage; rotation handled by the on-chain `PasskeyRotationLog` ABI (§13).

Stanza payload fields:

| Field | Type | Semantics |
|---|---|---|
| `variant_tag` | `uint8 = 0x01` | Variant discriminator |
| `account_id` | `bytes32` | Cealis-issued opaque identifier for the recipient's account. Cross-partner stable (the same recipient appears under the same `account_id` across all PDAs they are conditional-recipient on). |
| `initial_passkey_pubkey` | `bytes65` | P-256 uncompressed public key registered to the account at commit time. Anchors the rotation-log walk (§13). |
| `initial_delivery_x25519_pubkey` | `bytes32` | Explicit X25519 delivery/wrap public key registered to the account at commit time. Used by §6.2 hybrid wrapping and post-reveal delivery. This key is NOT derived from the P-256 passkey; the P-256 key authenticates WebAuthn assertions only. Rotation tracked atomically with the passkey via PasskeyRotationLog (§13). |
| `initial_mlkem_pubkey` | `bytes1184` | ML-KEM-768 public key registered to the account at commit time, used by the per-stanza hybrid PQ wrap (§6.2). Length per FIPS 203 ML-KEM-768 public-key encoding. Rotation tracked atomically with the passkey via PasskeyRotationLog (§13). |
| `rotation_log_anchor` | `bytes32` | `keccak256(TAG_ROTATION_LOG_ANCHOR_V3 ‖ contract_address ‖ account_id ‖ entry_index_at_commit ‖ entry_pubkey_at_commit ‖ entry_delivery_x25519_pubkey_at_commit ‖ entry_mlkem_pubkey_at_commit)` — snapshot of the `PasskeyRotationLog` head at commit time, covering the P-256 passkey, explicit X25519 delivery key, and ML-KEM-768 pubkey of the head entry (§13). TAG-prefix per generalized D6 V3 TAG-prefix discipline (BP-4 default applied 2026-04-25 by dw-lead; designs/conditional-recipient.md §2 line 51 receives Rule 33 propagation patch). |
| `role_tag` | enum (`uint8`) | Semantic metadata: `0x01 HEIR`, `0x02 BENEFICIARY`, `0x03 ACQUIRER_COUNSEL`, `0x04 MEDICAL_PROXY`, `0x05 SUBJECT_ALTERNATE`, `0x06 JOURNALISM_RECIPIENT`, `0x07 SUBJECT_SELF`. Behaviour-neutral; surfaces in the subject-side verifier display (§6.5) and the combiner's reveal-challenge digest (§10.1). |
| `delivery_hint` | `Option<uint8>` | Optional: `0x01 IN_APP_NOTIFICATION`, `0x02 PASSIVE`, `0x03 EMAIL_NOTIFICATION_NO_CONTENT`. Drives recipient-side notification UX, not delivery-cryptography. |

Curve: P-256 for WebAuthn authentication; X25519 and ML-KEM-768 for delivery/share wrapping. There is no P-256-to-X25519 conversion path in V2.

##### Variant `0x02` — `WALLET_EOA` (ships V2)

For self-sovereign recipients identified by an Ethereum externally-owned-account (EOA) address. Identity-bound at PDA-config time without Cealis-account onboarding; the recipient's wallet is the integrity anchor.

Stanza payload fields:

| Field | Type | Semantics |
|---|---|---|
| `variant_tag` | `uint8 = 0x02` | Variant discriminator |
| `wallet_address` | `bytes20` | Recipient's EOA address. The EIP-712 signature recovered from `σ_conditional` at reveal MUST equal this value (§10.2). |
| `delivery_x25519_pubkey` | `bytes32` | Recipient-provided X25519 public key. Used both as the per-stanza hybrid PQ wrap pubkey (§6.2) and as the post-DEK delivery wrap pubkey at reveal. Recipient-provided (not derived from the EOA's secp256k1 key) because BIP-32 X25519 derivation is not standardised; explicit is cleaner and auditable at PDA-config (designs/conditional-recipient.md §3). |
| `delivery_mlkem_pubkey` | `bytes1184` | Recipient-provided ML-KEM-768 public key used by the per-stanza hybrid PQ wrap (§6.2). Length per FIPS 203 ML-KEM-768 public-key encoding. Recipient-managed; published at PDA-config time alongside `delivery_x25519_pubkey`. |
| `delivery_url` | `String` (SCALE-length-prefixed UTF-8, ≤ 512 bytes) | Recipient's preferred delivery endpoint (HTTPS or IPFS gateway URL). Configurator rejects strings longer than 512 bytes; this bound is enforced at PDA-config-time and does not appear inside the stanza encoding as a separate length field beyond SCALE's standard length prefix. |
| `role_tag` | enum (`uint8`) | Same enum as variant `0x01`. |

Curve: secp256k1 for the σ_conditional signature (EIP-712); X25519 for the delivery-wrap (a separate non-input material use).

The `delivery_url` and `delivery_x25519_pubkey` fields are public-by-construction — they appear in plaintext within the stanza, so the recipient's network-level delivery is observable to passive observers (per WP §K item 12, this property is honestly named). Subjects with strong network-privacy requirements should configure recipient-pull via IPFS (the recipient pulls their wrapped payload from an IPFS CID rather than receiving an HTTP POST) or use variant `0x01` PASSKEY_ACCOUNT (in-app Cealis dashboard delivery, no recipient-controlled URL).

##### Variant `0x03` — `WALLET_EIP1271` (RESERVED — configurator rejects at V2)

Architected at the byte level so the spec is forward-compatible per Rule 31 (full-engine, not pilot-subset), but the V2 configurator MUST reject `delivery_mode = WALLET_EIP1271` at PDA-config time. The stanza ships post-V2 as a PDA+ capability, with a §K carve-out clarifying that EIP-1271 is contract-trust consent rather than cryptographic consent (designs/conditional-recipient.md §5; WP §K item 11).

Stanza payload fields:

| Field | Type | Semantics |
|---|---|---|
| `variant_tag` | `uint8 = 0x03` | Variant discriminator |
| `contract_address` | `bytes20` | Recipient smart-contract address |
| `contract_bytecode_hash_at_commit` | `bytes32` | `keccak256(extcodehash(contract_address) at commit_anchor_block_hash)` — the contract's runtime bytecode hash at commit. Combiner re-checks at reveal (§10.3). |
| `reject_on_bytecode_change` | `bool` | When `true`: combiner rejects σ_conditional if the current `extcodehash(contract_address)` differs from `contract_bytecode_hash_at_commit`. When `false`: combiner emits a `STALE_BYTECODE` warning and continues. |
| `delivery_x25519_pubkey` | `bytes32` | Same as variant `0x02` |
| `delivery_mlkem_pubkey` | `bytes1184` | Same as variant `0x02` |
| `delivery_url` | `String` (≤ 512 bytes) | Same as variant `0x02` |
| `role_tag` | enum (`uint8`) | Same enum as variant `0x01` |

Combiner behaviour: when this variant is encountered in an envelope under V2, the combiner aborts decryption with `ERR_MODE_3_NOT_SHIPPED_AT_V2`. The variant exists in the envelope SCALE schema solely so that post-V2 PDA+ enablement requires no envelope-format change. The subject-side verifier (§6.5) additionally rejects variant `0x03` stanzas at σ_subject signing time, defending against a compromised configurator that somehow emits a Mode 3 stanza despite configurator rejection.

**Minimum σ_conditional length normative requirement.** When this variant is enabled post-V2, the combiner MUST reject any σ_conditional whose byte length is zero — empty signatures are explicitly rejected to prevent the always-return-magic-on-empty bypass some permissive `isValidSignature` implementations exhibit. Per WP §D + designs/conditional-recipient.md §5: minimum σ length is 1 byte. The combiner enforces this at MAC-verify time (§6.1.7 step 4 augmented by §10.3), before issuing the `eth_call` to `isValidSignature`.

**`role_tag` byte values author-locked at S2-1.** S2-1's per-mode σ_conditional verification protocols (§10.1, §10.2) MUST use the same `uint8` byte representation when computing the reveal-challenge digest (`role_tag` enters the keccak preimage `keccak256(TAG_REVEAL_CHALLENGE_V3 ‖ … ‖ role_tag ‖ …)` per WP §D). S2-4 (configurator-pda-spec) MUST honor these byte values when defining the configurator's role_tag validation surface; new role_tag values require coordinated update across §6.1.5, §10, S2-4. Same lock-here discipline applies to `delivery_hint`'s byte values, though `delivery_hint` does not enter any cryptographic preimage and thus has weaker downstream binding.

#### 6.1.6 Conditional-recipient stanza MAC — additional layer

In addition to the gate-stanza MAC (§6.1.4) — which conditional-recipient stanzas also carry under `TAG_STANZA_MAC_V3` over `(stanza_index, binding_tag, plugin_version_digest)` where `binding_tag = TAG_CONDITIONAL_RECIPIENT_BINDING_V3` — every conditional-recipient stanza carries a second MAC under `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` whose input covers the variant tag and the full SCALE-length-prefixed payload.

Construction:

```
cr_mac_input := variant_tag (uint8)
              ‖ stanza_index (uint32, big-endian per §1)
              ‖ plugin_version_digest (bytes32)
              ‖ SCALE_length_prefix(payload_bytes)
              ‖ payload_bytes

cr_stanza_mac := keccak256(TAG_CONDITIONAL_RECIPIENT_BINDING_V3 ‖ cr_mac_input)
```

Two MACs cover each conditional-recipient stanza: the standard `TAG_STANZA_MAC_V3` MAC (combiner-bypass enforcement, identical mechanism to gate stanzas) and the additional `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` MAC (cross-variant substitution defense, covering the variant tag plus the full payload bytes).

The two-MAC construction is not redundant. The standard MAC binds the stanza's role in the envelope (its index and its binding-tag identity); the additional MAC binds the stanza's payload-bytes contents under its declared variant. A re-ordering attack is caught by the standard MAC's `stanza_index` field; a payload-reinterpretation attack (variant `0x02` payload reparsed as variant `0x01`) is caught by the additional MAC's `variant_tag` + payload coverage. Both MAC families are crypto-enforced: a non-conforming plugin that skips MAC verification fails the discipline cryptographically, not via source-review. This is the same enforcement pattern §13 applies to PasskeyRotationLog walks (Cealis-as-infrastructure-not-authority) — the system's integrity does not rest on combiner honesty.

The combiner verifies both MACs before parsing the stanza payload (§6.1.7).

#### 6.1.7 MAC-before-parse rule — normative

The plugin MUST verify all stanza MACs before parsing any stanza payload field for any purpose other than computing the MAC input itself.

Specifically, for each stanza in `0 .. 2 + n` order:

1. Read the stanza's serialized bytes.
2. Recover `stanza_index` (its position in the header), `binding_tag` (from the stanza's declared family), and `plugin_version_digest` (from `commit_AAD`). At MAC-verification time, `plugin_version_digest`'s integrity is anchored through the chain: `aad_digest = keccak256(TAG_AAD_V3 ‖ SCALE(commit_AAD))` (per D6, §4) is one of `h_commit`'s 15 inputs (§3.4), and `h_commit` is on-chain anchored at commit. The AEAD check at step 5 re-verifies commit_AAD against the payload binding; the integrity path used at MAC-time is the chain anchor, distinct from but consistent with the AEAD path.
3. Recompute `mac_input` per §6.1.4 and verify the stored stanza MAC matches `keccak256(TAG_STANZA_MAC_V3 ‖ mac_input)`. If mismatch → abort with `ERR_GATE_STANZA_MAC_FAIL` (§16) before any further field is parsed.
4. For conditional-recipient stanzas only: additionally read `variant_tag` (the first payload byte), recompute `cr_mac_input` per §6.1.6, and verify the stored conditional-recipient MAC matches `keccak256(TAG_CONDITIONAL_RECIPIENT_BINDING_V3 ‖ cr_mac_input)`. If mismatch → abort with `ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL` (§16) before any further field is parsed.
5. Only after both MACs have verified does the plugin parse the stanza payload's other fields (e.g., `account_id`, `wallet_address`, `chain_condition`).

The rule is normative because it forecloses a class of attack where a payload field is interpreted (and routed to a specific resolver — a wrong rotation-log address, a wrong signature-verification path, a wrong delivery_url) before the field's integrity has been confirmed. In the absence of this rule, a tampered stanza could trigger downstream effects (an HTTP request to an attacker-controlled `delivery_url`, a contract call to an attacker-controlled `contract_address`) before the verifier discovers the tamper at MAC verification.

The rule extends to deserialization safety more broadly: the plugin MUST use a SCALE decoder configured for fail-closed semantics on malformed input (length-prefix overflow, truncated fields, invalid variant tags). Decoder errors abort with `ERR_SCALE_DECODE_FAIL` (§16) at the point of error, never returning partial data to downstream code.

#### 6.1.8 Cross-references and forward-pointers

§6.2 specifies how each stanza's recipient public key is used to wrap a typed Shamir share under the ML-KEM-768 + X25519 hybrid construction (Decision D2 — per-stanza wrap, locked Phase 1). §6.3 specifies how verified σ values authorize stanza decap and how recovered shares reconstruct `file_key` via typed Shamir.combine. §6.4 specifies the ChaCha20-Poly1305 AEAD payload, with `nonce = HKDF(DEK, TAG_AEAD_V3 ‖ commit_context_digest_0)[:12]` and `aad = commit_AAD_0` (§4). §10 specifies per-mode σ_conditional verification, where the stanza-payload fields fixed here become the input to the reveal-challenge digest formulae. §13 specifies the `PasskeyRotationLog` ABI surface that variant `0x01`'s `rotation_log_anchor` references. §14.2.1 step 5 enforces the MAC-before-parse rule of §6.1.7 as part of the combiner pre-verify checklist.

The envelope structure described here is structurally invariant across re-key generations (§15): re-key adds new stanza generations under fresh wrapping primitives without re-encrypting the payload bytes. This invariance is why §6.1's stanza-format and MAC discipline are the right place to lock the byte-level structure — every re-key generation reuses the same `(LIT_ACC, G3_ID, G4_ATTESTATION_AUTHORITY, [CONDITIONAL_RECIPIENT_*])` template under whatever primitive is current. §15 covers the operational ceremony — including how the additive-stanza form interacts with the `ciphertext_digest` binding in h_commit (the SOFT-3 question per D3 lock; worker-3 owns the §15 resolution). At §6.1's altitude, the stanza-format invariance across re-key generations is what we lock; the ceremony semantics are §15.

### §6.2 — Hybrid PQ wrapping (per-stanza)

This subsection specifies the per-stanza hybrid post-quantum wrapping construction for the `age-plugin-cealis-v3` envelope. ML-KEM-768 (FIPS 203) + X25519 (RFC 7748) hybrid KEM, applied independently per stanza per Decision D2 (Simon Phase 1 lock 2026-04-25). Under the 2026-05-05 dek-lifecycle lock, each stanza wraps one Shamir share of the commit-time random DEK. Verified σ values authorize the matching stanza decap; `file_key` reconstruction happens only after `Shamir.combine` reaches the threshold in §6.3. The per-stanza hybrid PQ wrap applies on ALL stanzas — gate stanzas + conditional-recipient stanzas.

#### 6.2.1 Context — what this layer accomplishes

The age envelope's recipient stanzas serve a different purpose under V3 custody than under standard age usage. In standard age, a stanza wraps the `file_key` under a recipient's public key, and the recipient unwraps the stanza directly to recover the file_key bytes. Under V3 custody `commit_version = 0x0302`, the commit-time TEE generates a random DEK, encrypts the payload once, Shamir-splits the DEK, and each stanza wraps one 32-byte Shamir share. The stanza payloads at commit time therefore carry recipient public keys plus wrapped share material; σ values are collected only at reveal and authorize the decap path.

§6.2 specifies a per-stanza hybrid post-quantum wrap that runs alongside the recipient-identity reservation. The wrap binds a 32-byte Shamir share under the stanza's recipient public key using ML-KEM-768 + X25519 hybrid KEM. This binding is what makes ML-KEM-768 + X25519 hybrid load-bearing for the future-proofing claim of P21 — without threshold shares, file_key cannot be reconstructed even if σ values are observed.

Three load-bearing properties result:

1. **Hybrid post-quantum defense at the stanza layer.** Each stanza's seed is recoverable only by an attacker who breaks BOTH the X25519 ECDH and the ML-KEM-768 KEM for that stanza's recipient pubkey. Either primitive holding (classical or post-quantum) defends the seed.
2. **Per-stanza independence.** The per-stanza wrap is local to one stanza — re-keying one stanza (under fresh primitives) does not require re-wrapping the others (§15). This is the operational property D2's per-stanza topology was selected for.
3. **σ-as-authorization discipline preserved.** σ values authorize share release; they are not key material. Observing σ values alone is insufficient to reconstruct file_key because the combiner still needs ≥ threshold Shamir shares.

The construction below is normative for `age-plugin-cealis-v3` V2-launch builds.

#### 6.2.2 Per-stanza recipient public-key surface

Per-stanza wrap binds to the stanza's recipient public key as exposed by §6.1's per-variant payload tables:

| Stanza | Recipient pubkey class | Source of pubkey | Notes |
|---|---|---|---|
| `stanza[0]` LIT_ACC | Lit V3 per-commit gate-recipient KEM pubkey | Published per operation by the Lit V3 serving TEE assignment record and verified through §11.4 + §12 gate-recipient-pubkey publication discipline | The wrap pubkey is per-commit ephemeral. The serving TEE's σ_Lit verifies authorization; the ephemeral KEM pubkey authorizes share decap only for this commit. |
| `stanza[1]` G3_ID | G3 path-specific: dcipher committee KEM pubkey OR drand long-lived committee KEM pubkey | Resolved at commit from §11.3 G3 committee pubkey fetch | dcipher may expose an epoch/commit-scoped committee key through Randamu. drand has no per-commit ephemeral primitive; it uses a long-lived committee KEM key with share-only leak mitigation under Shamir threshold. |
| `stanza[2]` G4_ATTESTATION_AUTHORITY | G4 per-commit gate-recipient KEM pubkey | Published by the G4 authority entry / Phase 2 TEE attestation and verified through §11.4 + §12 gate-recipient-pubkey publication discipline | Phase 2 uses a per-commit ephemeral KEM key inside the G4 TEE. Phase 1 dev-scaffold publishes the same field through the sealed-code authority registry shape. |
| `stanza[3..]` CONDITIONAL_RECIPIENT_PASSKEY_ACCOUNT | Recipient's explicit X25519 delivery pubkey + ML-KEM pubkey (variant `0x01`, §6.1.5) | `initial_delivery_x25519_pubkey` + `initial_mlkem_pubkey` in the stanza, with rotation-log walk to current delivery/wrap keys at reveal | The P-256 passkey authenticates WebAuthn assertions only. The wrap layer uses the explicit X25519 delivery key; no P-256-to-X25519 conversion is defined or permitted. |
| `stanza[3..]` CONDITIONAL_RECIPIENT_WALLET_EOA | Recipient-provided X25519 pubkey (variant `0x02`, §6.1.5) | `delivery_x25519_pubkey` in the stanza | The X25519 pubkey is recipient-provided explicitly per the design rationale in §6.1.5 (BIP-32 X25519 derivation from secp256k1 wallets is not standardized). The wrap layer uses this pubkey directly. ML-KEM-768 keys are recipient-managed. |
| `stanza[3..]` CONDITIONAL_RECIPIENT_WALLET_EIP1271 (RESERVED at V2) | Contract-defined (variant `0x03`, §6.1.5) | Not applicable at V2 — stanza format is reserved; wrap is not constructed | Variant `0x03` is configurator-rejected at V2 launch; combiner aborts decryption with `ERR_MODE_3_NOT_SHIPPED_AT_V2` before any wrap unwrap is attempted. The wrap construction below applies only to shipping variants. |

Every stanza that needs an X25519 wrap key exposes one explicitly through its gate-recipient-pubkey publication path or recipient payload. P-256 passkeys and secp256k1 EOAs are authentication keys only; they are never converted to X25519. Ed25519 Phase-1 authority keys likewise do not double as wrap keys. S2-3 pins the publication/registry source for each explicit X25519 key and MUST reject any implementation path that attempts a cross-curve conversion not named in this table.

#### 6.2.3 Per-stanza wrap construction — KDF-combined hybrid KEM

Each stanza carries a wrap structure produced at commit time by the plugin's `wrap` operation, against the stanza's recipient public key. The construction is a KDF-combined hybrid KEM (the canonical hybrid pattern used by RFC 9180 HPKE and IETF post-quantum hybrid drafts), applied per stanza independently.

For each stanza `s` with recipient public key `(pk_x25519_s, pk_mlkem_s)`:

```
# Sender side (commit, inside the plugin's wrap operation)

1. Generate fresh per-stanza ephemeral X25519 keypair: (sk_eph_x25519, pk_eph_x25519)
2. Compute X25519 shared secret:           ss_x25519  = X25519(sk_eph_x25519, pk_x25519_s)
3. Encapsulate ML-KEM-768 shared secret:   (ct_mlkem, ss_mlkem) = ML-KEM-768.Encaps(pk_mlkem_s)
4. Combine shared secrets:                 stanza_wrap_key_s = HKDF-SHA256(
                                              salt = TAG_STANZA_WRAP_V3 ‖ stanza_index_be ‖ commit_context_digest_N,
                                              ikm  = ss_x25519 ‖ ss_mlkem ‖ pk_eph_x25519 ‖ ct_mlkem,
                                              info = binding_tag_s ‖ pk_x25519_s ‖ pk_mlkem_s,
                                              len  = 32
                                           )
                                              // where stanza_index_be is `stanza_index` encoded as
                                              // uint32 big-endian per §1.2 (4 bytes total in the salt).
5. Read the typed Shamir share for this stanza: share_s = Shamir.share_for(share_domain, share_role, logical_index)
                                              // Produced from the commit-time random DEK before any
                                              // plaintext/DEK zeroization; exactly 32 bytes.
6. Wrap share_s under stanza_wrap_key:
   wrapped_share_s = ChaCha20-Poly1305.encrypt(
                       key   = stanza_wrap_key_s,
                       nonce = HKDF(stanza_wrap_key_s, TAG_STANZA_WRAP_NONCE_V3 ‖ stanza_index_be)[:12],
                       aad   = SCALE_encode({
                                  stanza_index,
                                  binding_tag_s,
                                  plugin_version_digest,
                                  commit_context_digest_N,
                                  share_domain,
                                  share_role,
                                  logical_index,
                                  x
                               }),
                       pt    = share_s
                   )
                                              // stanza_index_be in nonce HKDF salt is uint32 big-endian
                                              // per §1.2 (same encoding as step 4 salt).
                                              // stanza_index in SCALE-encoded AAD is SCALE-native LE
                                              // per §1.4 (SCALE codec convention, distinct from the
                                              // direct keccak-preimage BE encoding used in salts).

# Sender then writes into the stanza payload:
#   - pk_eph_x25519           (32 bytes, this stanza's X25519 ephemeral pubkey)
#   - ct_mlkem                (1088 bytes, ML-KEM-768 ciphertext)
#   - wrapped_share_s         (32 + 16 bytes; ChaCha20-Poly1305 ciphertext + tag)
```

Two new TAG_*_V3 constants are introduced by §6.2 and registered in §2:

- `TAG_STANZA_WRAP_V3 = keccak256(bytes("CEALIS_V3_STANZA_WRAP_V3"))` — domain separator for the per-stanza wrap KDF combination.
- `TAG_STANZA_WRAP_NONCE_V3 = keccak256(bytes("CEALIS_V3_STANZA_WRAP_NONCE_V3"))` — domain separator for the per-stanza wrap AEAD nonce derivation.

`binding_tag_s` is the stanza-specific binding tag from §6.1 (`TAG_LIT_ACC_BINDING_V3` for stanza 0, `TAG_DCIPHER_IBE_BINDING_V3` or `TAG_DRAND_ROUND_BINDING_V3` for stanza 1, `TAG_G4_ATTESTATION_AUTHORITY_V3` for stanza 2, `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` for conditional-recipient stanzas).

The stanza payload's MAC (§6.1.4 / §6.1.6) covers `(stanza_index, binding_tag_s, plugin_version_digest)` — not the wrap fields directly. Wrap-field tampering is detected by a separate path: at unwrap, an attacker-substituted `pk_eph_x25519` or `ct_mlkem` produces a different `stanza_wrap_key`, the AEAD tag on `wrapped_share_s` fails, and the plugin aborts with `ERR_STANZA_WRAP_AEAD_FAIL` (§16) before `share_s` is recovered.

Generation-N stanza wraps consume `commit_context_digest_N`. They MUST NOT consume final `h_commit_N`, because final `h_commit_N` cannot exist until the generation-N envelope bytes have been serialized and hashed as `ciphertext_digest_N`. The wrap AAD also binds typed share metadata so a recovered conditional-recipient branch share cannot be re-labelled as Lit, G3, G4, or the recipient aggregate share.

**HKDF info parameter intent.** The 1248-byte info parameter (`binding_tag_s ‖ pk_x25519_s ‖ pk_mlkem_s` = 32 + 32 + 1184 bytes) provides full context-binding redundancy with the recipient pubkeys explicitly named in the KDF input. The pubkeys are also implicit in the input material (via `ss_x25519` and `ss_mlkem` derived from them); explicit naming in info is a defense against input material-collision attacks where two distinct (pubkey, pubkey) pairs produce the same shared-secret tuple. The 1248-byte size is acceptable per RFC 5869 (no upper bound on info) and is appropriate for the per-stanza context-binding semantics. Across an envelope with 8 stanzas (3 gates + 5 conditional-recipients at k=5 mixed-mode), info totals ~10 KB across the wrap layer — accepted as part of the BP-8 stanza-size budget documented at §6.2.6.

#### 6.2.4 Per-stanza unwrap — recipient or combiner side

At reveal, the recipient (or the recipient-delegated combiner per §14.3) unwraps each stanza using the recipient's private key material `(sk_x25519_s, sk_mlkem_s)`:

```
# Receiver side (reveal, inside the plugin's unwrap operation)

1. Read pk_eph_x25519, ct_mlkem, wrapped_share_s from stanza payload
2. Recompute X25519 shared secret:         ss_x25519  = X25519(sk_x25519_s, pk_eph_x25519)
3. Decapsulate ML-KEM-768:                 ss_mlkem   = ML-KEM-768.Decaps(sk_mlkem_s, ct_mlkem)
4. Recompute stanza_wrap_key:              stanza_wrap_key_s = HKDF-SHA256(
                                              salt = TAG_STANZA_WRAP_V3 ‖ stanza_index_be ‖ commit_context_digest_N,
                                              ikm  = ss_x25519 ‖ ss_mlkem ‖ pk_eph_x25519 ‖ ct_mlkem,
                                              info = binding_tag_s ‖ pk_x25519_s ‖ pk_mlkem_s,
                                              len  = 32
                                           )
                                              // stanza_index_be: uint32 big-endian per §1.2
                                              // (matches the commit-side encoding in §6.2.3 step 4).
5. Recover Shamir share:                  share_s = ChaCha20-Poly1305.decrypt(
                                              key   = stanza_wrap_key_s,
                                              nonce = HKDF(stanza_wrap_key_s, TAG_STANZA_WRAP_NONCE_V3 ‖ stanza_index_be)[:12],
                                              aad   = SCALE_encode({
                                                        stanza_index,
                                                        binding_tag_s,
                                                        plugin_version_digest,
                                                        commit_context_digest_N,
                                                        share_domain,
                                                        share_role,
                                                        logical_index,
                                                        x
                                                     }),
                                              ct    = wrapped_share_s
                                           )
   # AEAD failure → ERR_STANZA_WRAP_AEAD_FAIL; abort.
```

The recovered `share_s` values are Shamir shares over the commit-time random DEK. They are the only material §6.3 consumes for file_key reconstruction. σ values authorize this unwrap path; σ bytes themselves are not fed into a KDF.

**Disjoint-operator property under hybrid PQ failure.** If a single stanza's hybrid layer falls (both X25519 and ML-KEM-768 broken for that recipient's pubkey class), only that stanza's typed Shamir share becomes recoverable to the attacker. A single share is information-theoretically zero about the DEK below threshold; file_key still requires the complete §6.3 access structure. This is the per-stanza independence property that D2 was selected for.

#### 6.2.5 Hybrid combination justification — KDF over both KEMs

The construction in §6.2.3 combines `ss_x25519` and `ss_mlkem` by feeding both into a single HKDF-SHA256 invocation, with both ephemeral / ciphertext public values bound into the input material and the recipient public keys bound into the info parameter. This is the canonical hybrid KEM combiner pattern from RFC 9180 (HPKE) §9.1 and the IETF draft `draft-ietf-tls-hybrid-design-09`. It is selected over alternatives:

- **XOR combination of `ss_x25519` ⊕ `ss_mlkem`**: rejected. Vulnerable to malformed-public-key attacks where the attacker submits a degenerate ML-KEM ciphertext that produces a known `ss_mlkem`, forcing `stanza_wrap_key = ss_x25519 ⊕ known`. KDF combination defends against this because all KEM outputs and all KEM ciphertexts/public-keys feed the KDF together.
- **Concatenation only (no KDF)**: rejected. Loses domain-separation; vulnerable to context-ambiguity attacks across stanzas. The KDF construction binds `stanza_index`, `commit_context_digest_N`, and `binding_tag_s` so each stanza's wrap key is structurally distinct.
- **Sequential ECDH then KEM**: rejected. Sequential composition does not provide the "either holds → seed protected" property. KDF combination of both shared secrets does.

The S2-3 custody-integration spec pins specific library implementations of ML-KEM-768 (FIPS 203 reference) and X25519 (RFC 7748). The construction here is library-agnostic; libraries that satisfy FIPS 203 + RFC 7748 conformance produce identical wrap-key bytes.

**Security property.** The KDF-combined hybrid KEM construction satisfies IND-CCA2 security under the "either-component-secure" assumption — even if one of (X25519 ECDH, ML-KEM-768 KEM) is broken, the wrap-key remains indistinguishable from random to a CCA adversary provided the other component holds. This is the standard hybrid-KEM combiner-security result formalized in RFC 9180 §9.1 and the IETF post-quantum hybrid design draft. The seed thus remains protected under the weaker of the two primitive assumptions, matching P21's "attacker needs both to fall" claim.

#### 6.2.6 Recipient ML-KEM-768 key-pair management

The per-stanza wrap requires every recipient (gate operators and conditional recipients) to publish an ML-KEM-768 public key alongside their existing identity pubkey. For gate operators (Lit V3, dcipher, drand, Cealis G4), ML-KEM-768 keys are managed at the operator level and published via the same registries that publish the X25519/Ed25519/BLS public keys — §11.1–§11.4 specify the per-gate fetch path; S2-3 specifies how the registries surface ML-KEM-768 public keys alongside the identity public keys.

For conditional recipients, ML-KEM-768 keys are recipient-managed:

- **Mode 1 PASSKEY_ACCOUNT.** Cealis-account onboarding (§13) generates an explicit X25519 delivery/wrap key pair and an ML-KEM-768 key pair alongside the initial WebAuthn passkey. The X25519 and ML-KEM public keys are registered into the account's PasskeyRotationLog entry alongside the passkey pubkey; rotations include all three keys atomically. The `initial_delivery_x25519_pubkey: bytes32` and `initial_mlkem_pubkey: bytes1184` fields in §6.1.5 variant `0x01` are the source of the wrap keys. The P-256 passkey pubkey never enters the wrap KDF.
- **Mode 2 WALLET_EOA.** Recipients publish an ML-KEM-768 public key at PDA-config time alongside `delivery_x25519_pubkey`. The `delivery_mlkem_pubkey: bytes1184` field is added to the §6.1.5 variant `0x02` payload (already applied).
- **Mode 3 WALLET_EIP1271 (RESERVED).** Reserved alongside the rest of the variant; the architected stanza format includes `delivery_mlkem_pubkey` at the byte level so post-V2 enablement requires no envelope-format change.

**Stanza-size cost (BP-8 documented).** Per A1+Shamir's full per-stanza wrap on ALL stanzas: ~2400 bytes per conditional-recipient stanza (1184-byte ML-KEM-768 pubkey + 1088-byte ML-KEM-768 ciphertext + ~100 bytes other fields). Per gate stanza: similar scale once the gate operator's ML-KEM-768 pubkey + ciphertext land. For a k=5 mixed-mode conditional-recipient policy with 3 gate stanzas, total envelope header is approximately 19 KB. Accepted per Rule 31 (full engine, not pilot-subset); Simon's Δ12 pick was made with explicit stanza-size awareness. Downstream specs S2-4 (configurator-pda-spec) + S2-5 (ingestion-delivery-API-spec) inherit this size budget for PDA configuration validation + ingestion bandwidth planning.

#### 6.2.7 Re-key forward-pointer — additive share-wrap layer

§15 specifies the re-key ceremony's full discipline; §6.2.7 captures the §6.2-layer slice. Per WP §M post-BP-6 patched prose:

- **`Shamir share` values are FROZEN at commit-time and persist across re-key generations.** Each stanza's `Shamir share_s` is a 32-byte share of the commit-time random DEK. The same share value is subsequently re-wrapped under fresh primitives during re-key. The share VALUES do not change; only the WRAP material around them changes.
- **Wrap material grows additively at the stanza layer.** Re-key ceremony (§15) generates a new generation of stanzas — same `Shamir share_s` values per stanza-index, re-wrapped under fresh wrapping primitives where re-wrapping is required. Original stanzas remain in the envelope; the new generation appends. Share values are recovered inside the re-key ceremony's hardened context, re-wrapped under new primitives, and immediately zeroized.
- **`file_key` reconstruction is threshold-stable at the share layer.** `file_key` remains valid for AEAD decryption of unchanged payload because `Shamir.combine` reconstructs the same commit-time random DEK from the same indexed share values. σ values authorize share decap; they are not HKDF input and not the source of DEK bytes.
- **Old wrap primitives + their stanzas continue to be valid recovery paths** until governance-deprecated. Recipients holding original-generation stanzas recover the same Shamir share bytes via the original primitives; recipients onboarding post-re-key recover the same share bytes via the new primitives. file_key reconstruction paths at §6.3 depend on threshold share values, not on which wrap-generation produced the recovered shares.

This is the architectural-truth framing per A1+Shamir's share-threshold semantics — distinct from a "swap stanzas, regenerate shares, re-encrypt payload" model that would imply different recovered file_keys per stanza generation and would VIOLATE BP-6's "payload bytes never touched" invariant. Under A1+Shamir, the commit-time random DEK is the single file_key truth; the stanza wrap layer carries Shamir shares of that DEK.

§15's re-key ceremony specifies the operational mechanics — how Cealis governance decides to fire a re-key, who participates, how new stanzas are produced from stable share values, how the rotation is communicated to recipients, and how old generations are eventually deprecated. §6.2 specifies only that under A1+Shamir, re-key changes wrapping paths, not payload bytes or DEK bytes.

#### 6.2.8 Cross-source resolution and architectural lock

The per-stanza wrap construction in this section was an S2-1 NEW SPECIFICATION item per delta-audit Δ12 — neither WP §M nor flows-spec-final.md §0.5 enumerated the per-stanza wrap mechanics. Δ12 escalation Q-W3-13 routed to Simon for architecture arbitration; Simon's 2026-04-26 lock selected A1+Shamir. The construction above is now formally locked per:

- Decision D2 (Simon Phase 1 lock 2026-04-25) — per-stanza topology, not per-envelope.
- Δ12 A1+Shamir lock (Simon 2026-04-26, revised by dek-lifecycle 2026-05-05) — σ authorizes share release; per-stanza wrap carries Shamir shares; threshold shares reconstruct file_key.
- BP-6 (WP §M re-key prose patched 2026-04-26) — payload bytes untouched; re-key operates at the wrapping/share-delivery layer.
- BP-7 (outline rev.2 D3 inline lock 2026-04-26) — A1+Shamir semantics propagated.
- The KDF-combined hybrid KEM pattern from RFC 9180 (HPKE) and the IETF post-quantum hybrid design draft.
- The age-plugin idiom of stanza-local wrapped material being independently unwrappable per recipient.

The §6.2 architecture is now the binding source of truth for per-stanza wrap mechanics across the §6 cascade; downstream §6.3 (file_key reconstruction) + §13 (PasskeyRotationLog ABI with mlkem field extensions per A1+Shamir) + §15 (re-key ceremony with additive share-wrap semantics) all inherit the §6.2 architecture without further escalation.

### §6.3 — Shamir reconstruction (typed access-structure file_key reconstruction)

This subsection specifies the byte-exact file_key reconstruction that the `age-plugin-cealis-v3` combiner runs at reveal time under `commit_version = 0x0302`. The file_key is the commit-time random DEK reconstructed from typed Shamir shares. σ values are authorization signatures / attestation outputs AND authorization evidence: the combiner verifies them against gate authority state at the commit block, then uses that authorization to decap and admit the corresponding stanza share. σ bytes are NOT DEK material, not Shamir share values, and not HKDF input.

#### 6.3.1 Access-structure profiles (IB-2 normative)

The commit-time sealing context generates one random 32-byte DEK and splits it according to the profile derived in §6.1.1:

```
DEK_commit = random_bytes(32)

if profile == FIXED_ONLY:
  top_shares = Shamir.split(secret = DEK_commit, k = 3, n = 3)
  assign top_shares to {Lit, G3, G4}

if profile == RECIPIENT_1_OF_1:
  top_shares = Shamir.split(secret = DEK_commit, k = 4, n = 4)
  assign top_shares to {Lit, G3, G4, recipient_branch}
  assign recipient_branch directly to the single configured conditional recipient

if profile == RECIPIENT_K_OF_N:
  top_shares = Shamir.split(secret = DEK_commit, k = 4, n = 4)
  assign top_shares to {Lit, G3, G4, recipient_branch_aggregate}
  recipient_branch_shares = Shamir.split(
    secret = recipient_branch_aggregate,
    k = k_conditional,
    n = n_conditional
  )
```

Reveal reconstruction mirrors that structure:

```
require admitted TOP_LEVEL shares for Lit, G3, and G4

if profile == FIXED_ONLY:
  file_key = Shamir.combine({Lit, G3, G4})

if profile == RECIPIENT_1_OF_1:
  require admitted recipient share
  file_key = Shamir.combine({Lit, G3, G4, recipient})

if profile == RECIPIENT_K_OF_N:
  require at least k_conditional admitted RECIPIENT_BRANCH shares
  recipient_branch_aggregate = Shamir.combine(first policy-ordered k_conditional recipient shares)
  file_key = Shamir.combine({Lit, G3, G4, recipient_branch_aggregate})
```

Flat `3 + k_conditional` reconstruction is forbidden. Conditional-recipient material satisfies only the recipient branch; it can never substitute for Lit, G3, or G4. Missing any configured mandatory top-level branch makes `file_key` reconstruction impossible.

#### 6.3.2 Finite field and share serialization

S2-1 normatively pins byte-sliced Shamir over `GF(2^8)` using the AES irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (`0x11b`). A 32-byte secret is split as 32 independent byte lanes. Each lane uses a random polynomial of degree `k - 1` over `GF(2^8)` with the secret byte as coefficient `a_0`. The share value is the 32-byte vector of polynomial evaluations at the share's non-zero x-coordinate.

The x-coordinate mapping is:

- Top-level branch: `x = top_level_index + 1`, where `top_level_index` is `0 Lit`, `1 G3`, `2 G4`, `3 recipient_branch`.
- Nested recipient branch: `x = recipient_index + 1`, where `recipient_index` is the zero-based order in `conditional_recipients_policy.recipients[]`.
- `x = 0` is reserved and invalid in every domain.

The combiner consumes typed share records:

```scale
struct ShareRecord {
  share_domain:  u8,     // 0x01 TOP_LEVEL, 0x02 RECIPIENT_BRANCH
  share_role:    u8,     // 0x01 LIT, 0x02 G3, 0x03 G4, 0x04 RECIPIENT_AGGREGATE, 0x05 CONDITIONAL_RECIPIENT
  logical_index: u32,    // top-level index or recipient_index, SCALE-native LE in this struct
  x:             u8,     // non-zero GF(2^8) coordinate
  value:         [u8;32] // byte-sliced Shamir value
}
```

The wrapped plaintext in §6.2 remains the 32-byte `value`; the metadata is bound in wrap AAD and reconstructed from stanza position + committed policy. Duplicate `(share_domain, x)` pairs, `x = 0`, out-of-policy indices, or role/domain mismatches abort before interpolation with `ERR_SHAMIR_SHARE_INDEX_INVALID`.

#### 6.3.3 Combine algorithm pseudocode

For each byte lane independently:

```
gf_add(a,b) = a XOR b
gf_mul(a,b) = carryless multiply reduced modulo 0x11b
gf_inv(a)   = a^254 in GF(2^8), with a != 0

lagrange_at_zero(shares):
  secret_byte = 0
  for each share i:
    lambda_i = 1
    for each share j where j != i:
      require x_i != x_j and x_i != 0 and x_j != 0
      lambda_i = gf_mul(lambda_i, gf_mul(x_j, gf_inv(gf_add(x_i, x_j))))
    secret_byte = gf_add(secret_byte, gf_mul(y_i, lambda_i))
  return secret_byte

Shamir.combine(shares):
  require len(shares) == threshold for the profile branch being combined
  return concat(lagrange_at_zero(shares[*].value[byte_index]) for byte_index in 0..31)
```

For `RECIPIENT_K_OF_N`, the recipient branch combine runs first over `k_conditional` `RECIPIENT_BRANCH` shares and returns a 32-byte aggregate. That aggregate is then re-labelled as the `TOP_LEVEL / RECIPIENT_AGGREGATE / logical_index=3 / x=4` share for the top-level `4-of-4` combine.

#### 6.3.4 Test vectors (normative)

Positive top-level vector (`k=3`, `n=3`, GF polynomial fixed for vector determinism):

| Item | Hex |
|---|---|
| secret / DEK | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| x=1 share | `b0b1b2b3b4b5b6b7b8b9babbbcbdbebf808182838485868788898a8b8c8d8e8f` |
| x=2 share | `9691989f8a8d8483aea9a0a7b2b5bcbba6a1a8afbabdb4b39e99909782858c8b` |
| x=3 share | `2621282f3a3d34331e19101702050c0b3631383f2a2d24230e09000712151c1b` |
| combine x=1,2,3 | returns secret / DEK above |

Positive nested-recipient vector (`k=2`, `n=3`):

| Item | Hex |
|---|---|
| recipient aggregate | `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f` |
| x=1 nested share | `8080808080808080808080808080808080808080808080808080808080808080` |
| x=2 nested share | `dbd8ddded7d4d1d2c3c0c5c6cfccc9caebe8edeee7e4e1e2f3f0f5f6fffcf9fa` |
| x=3 nested share | `1b191f1d131117150b090f0d030107053b393f3d333137352b292f2d23212725` |
| combine x=1,2 | returns recipient aggregate above |

Negative vectors:

- Duplicate x: combining two records with the same `(share_domain, x)` MUST fail with `ERR_SHAMIR_SHARE_INDEX_INVALID`.
- x=0: any share record with `x = 0` MUST fail with `ERR_SHAMIR_SHARE_INDEX_INVALID`.
- Below threshold: top-level two-of-three for `FIXED_ONLY` or recipient-branch `k-1` for `RECIPIENT_K_OF_N` MUST fail with `ERR_SHAMIR_THRESHOLD_NOT_MET`.
- Cross-domain substitution: a `RECIPIENT_BRANCH` share presented as `TOP_LEVEL / G4` MUST fail metadata validation before interpolation.
- Tampered share: flipping any bit of an otherwise valid share set SHOULD produce a different combined key and MUST fail §6.4 AEAD verification with `ERR_AEAD_TAG_VERIFY_FAIL`.

IB-2 mandatory-gate negative vectors (per `designs/4-gate-and-shamir-access-structure.md` §9 checklist):

- **Lit + G3 + surplus conditionals, missing G4 (`RECIPIENT_K_OF_N` with `n > k`):** attacker holds `s_Lit`, `s_G3`, and all `n_conditional` nested conditional shares. The attacker can reconstruct `s_recipient_aggregate` from the nested shares. However, the top-level `4-of-4` reconstruction requires `{s_Lit, s_G3, s_G4, s_recipient_aggregate}` — without `s_G4`, `Shamir.combine` MUST fail with `ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT`. Raw flat interpolation over any 4-subset (including `s_Lit + s_G3 + nested_0 + nested_1`) MUST be rejected by the typed combiner before interpolation.
- **Symmetric: missing Lit or missing G3 (`FIXED_ONLY`):** attacker holds `s_G3 + s_G4` (missing `s_Lit`) or `s_Lit + s_G4` (missing `s_G3`). In both cases top-level `3-of-3` cannot complete. Reconstruction MUST fail with `ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT`.
- **drand public σ_G3, G4 absent:** drand's σ_G3 is public/time-available by design, so `s_G3` can in principle be recovered by any observer after the target round. But without `s_G4`, the top-level branch set is still incomplete. DEK reconstruction MUST fail with `ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT` regardless of σ_G3 public availability.
- **Mixed re-key generation:** same typed share values used under generation-N stanza wraps and generation-0 stanza wraps within a single combine call. Shares recovered from incompatible generations (where stanza MACs differ) MUST fail MAC verification per §6.1.7 before share admission. Mixing generations at the typed combine layer MUST fail with `ERR_STANZA_MAC_VERIFY_FAIL` or `ERR_SHARE_DOMAIN_MISMATCH`.

#### 6.3.5 σ verification as authorization

A share is eligible for `Shamir.combine` only after the matching σ verifies against the gate's registry state at the commit's block and against `(authorizationId, h_commit_N, block_hash)` for the reveal authorization. Verification surfaces are:

- `σ_Lit` — §7, verified against the Lit assignment record and DCAP evidence.
- `σ_G3` — §8, verified under dcipher or drand according to `commit_AAD.g3_choice`.
- `σ_G4` — §9, verified against G4 authority state and refusal-state checks.
- `σ_conditional` — §10, verified against the conditional-recipient mode and policy.

A valid σ authorizes decap and typed share admission. It is not itself secret key material; publishing σ after reveal does not allow an observer to reconstruct the DEK without the released shares / decap material needed for the access structure above.

#### 6.3.6 Security properties

**Mandatory-gate halt.** Missing Lit, G3, or G4 prevents top-level reconstruction in every profile. If G4 refuses, no G4 share is admitted; `Shamir.combine` cannot form the top-level branch set and no DEK exists for the combiner.

**Recipient branch isolation.** Conditional-recipient surplus only satisfies the nested recipient branch. It cannot increase fixed-gate availability or bypass the universal tripwire. This is the IB-2 enforcement layer.

**Single-share confidentiality.** A recovered single share is information-theoretically zero about the DEK below threshold. This is the mitigation for the drand long-lived committee KEM path: a compromise that exposes only the drand stanza share does not expose the DEK.

**AEAD replay defense.** Replay and substitution defense lives in σ verification (§7-§10, §14.1), the §6.2 wrap AAD binding over `commit_context_digest_N`, and the §6.4 AEAD AAD binding over `commit_AAD_0`. A share from another commit has different wrap AAD, stanza MAC context, and final `h_commit_N` authorization binding; it fails before or at AEAD verification.

#### 6.3.7 Combiner protocol boundary

§6.3 fires inside the `age-plugin-cealis-v3` combiner at reveal time, after §14.1 has passed all pre-verification checks and after §6.2 unwrap has recovered at least the candidate shares. The combiner then:

1. discards shares whose matching σ did not verify;
2. validates typed share metadata and x-coordinate mapping;
3. enforces the profile-specific access predicate;
4. runs `Shamir.combine` on the recipient branch if configured;
5. runs `Shamir.combine` on the top-level branch;
6. treats the result as the 32-byte `file_key`;
7. immediately passes `file_key` to §6.4 ChaCha20-Poly1305 decryption;
8. zeroizes shares, polynomial/interpolation intermediates, and `file_key` after plaintext-or-abort.

No partial plaintext is produced on below-threshold, share-decode, duplicate-index, metadata, or AEAD failure.

#### 6.3.8 Failure modes

| Condition | §16 error code | Semantics |
|---|---|---|
| Required Lit/G3/G4 top-level share absent | `ERR_SHAMIR_THRESHOLD_NOT_MET` | No DEK reconstruction; abort before AEAD. |
| Recipient branch absent when profile requires it | `ERR_SHAMIR_THRESHOLD_NOT_MET` | Recipient branch unavailable; abort before AEAD. |
| Conditional-recipient shares below `k_conditional` | `ERR_SHAMIR_THRESHOLD_NOT_MET` | Nested threshold unmet; abort before AEAD. |
| Share recovered from stanza whose σ fails verification | gate-specific `ERR_SIGMA_*` plus `ERR_SHARE_UNAUTHORIZED` | Share is discarded; if access predicate unmet, abort. |
| Duplicate, zero, cross-domain, or out-of-policy share index | `ERR_SHAMIR_SHARE_INDEX_INVALID` | Abort before combine. |
| Shamir combine library failure | `ERR_SHAMIR_COMBINE_FAIL` | Abort; no fallback derivation path. |
| Combined file_key fails §6.4 AEAD tag verification | `ERR_AEAD_TAG_VERIFY_FAIL` | Wrong share set or tampered envelope; abort with no plaintext. |

#### 6.3.9 Re-key boundary

Re-key does not re-encrypt the payload. For Lit, G4, and conditional-recipient paths with per-commit or per-recipient ephemeral KEM keys, re-key can publish new stanza wraps over the same typed Shamir share values without touching the payload. The share VALUES do not change; only wrap material and generation-specific `commit_context_digest_N` change. The reconstructed file_key remains the original commit-time DEK.

### §6.4 — ChaCha20-Poly1305 AEAD payload

This subsection specifies the byte-exact construction of the `age-plugin-cealis-v3` envelope payload — the ChaCha20-Poly1305 AEAD encryption of plaintext under the file_key (DEK), with deterministic nonce derivation from the DEK and the generation-0 `commit_context_digest_0`, and `commit_AAD_0` as the additional-authenticated-data input. In `commit_version = 0x0302`, the DEK is generated randomly at commit time, encrypted once under §6.4, and reconstructed at reveal by §6.3 Shamir combination. §6.4 is invariant to the share-wrap mechanics: it consumes one 32-byte file_key and either returns authenticated plaintext or aborts.

#### 6.4.1 Payload position in the envelope

Per §6.1.1, the `age-plugin-cealis-v3` envelope is `header || payload`. The payload is a single byte string produced by ChaCha20-Poly1305 encryption of the plaintext, with the file_key (DEK) as the symmetric key, a deterministically-derived 96-bit nonce, and `commit_AAD_0` (§4 — the original generation-0 AAD, unchanged across all re-key generations) as the additional-authenticated-data binding. The payload occupies the entire suffix of the envelope after the SCALE-encoded header; recovery of payload bytes at reveal does not require parsing structure inside the payload (the AEAD ciphertext-and-tag is a single contiguous byte sequence).

Payload byte length: `len(plaintext) + 16` (Poly1305 authentication tag is 16 bytes per RFC 8439). The plaintext length is not encoded in the payload; recipients infer it from the envelope length minus the header length minus 16. Both lengths are bounded by the partner's PDA schema and ingestion-API limits (§S2-5). No padding is applied; ChaCha20-Poly1305 is a stream cipher AEAD whose ciphertext length equals plaintext length plus a fixed authentication-tag suffix.

#### 6.4.2 Cipher pin — ChaCha20-Poly1305 (RFC 8439)

The payload AEAD is **ChaCha20-Poly1305** as specified in RFC 8439. No alternative cipher is permitted at envelope-construction time; any future cipher rotation requires a new `commit_version` and a coordinated patch across §C, §6.4, and §16.

Pin parameters:

| Parameter | Value | Source |
|---|---|---|
| Symmetric cipher | ChaCha20 (RFC 8439 §2) | RFC 8439 |
| MAC | Poly1305 (RFC 8439 §2.5) | RFC 8439 |
| Combined construction | ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) | RFC 8439 |
| Key length | 32 bytes (256-bit) | RFC 8439 §2.3 |
| Nonce length | 12 bytes (96-bit) | RFC 8439 §2.3 |
| Authentication tag length | 16 bytes (128-bit Poly1305 output) | RFC 8439 §2.5 |
| Maximum AAD length | 2^64 − 1 bytes (no practical bound at V2 scale) | RFC 8439 §2.8 |
| Maximum plaintext length | 2^32 − 1 blocks of 64 bytes ≈ 256 GiB | RFC 8439 §2.8 ChaCha20 32-bit counter limit |

Library family pin (`@noble/ciphers ^1.0` per `flows-spec-final.md:250`) lives in S2-3 (custody-integration-spec) per the spec-discipline rule that S2-1 fixes algorithm-level parameters and wire formats while S2-3 fixes specific library implementations and version pins.

Selection rationale: ChaCha20-Poly1305 is the canonical age-plugin payload cipher (filippo.io/age uses it across all stanzas), is constant-time on commodity hardware without requiring AES-NI, and is multi-decade-secure under both classical and Grover-speedup quantum models per §M crypto-aging horizon (the key length collapse from 256-bit to effective 128-bit under Grover is acceptable margin for any V2-realistic retention window). Cure53 audit covers `@noble/ciphers` per the library pin in S2-3.

#### 6.4.3 Encryption — commit-time construction

At commit time, after the TEE (Mode A) or subject device (Mode B) has generated the random DEK, Shamir-split it, computed `commit_AAD_0`, `aad_digest_0`, and `commit_context_digest_0`, but before final `h_commit_0` exists, the payload is constructed as follows:

```
nonce      := HKDF-SHA256(
                ikm  = DEK,
                salt = TAG_AEAD_V3 ‖ commit_context_digest_0,
                info = ""               // empty info string
              )[0..12]                  // first 12 bytes of HKDF output

payload    := ChaCha20-Poly1305-Encrypt(
                key   = DEK,            // 32-byte file_key from §6.3
                nonce = nonce,          // 12 bytes per RFC 8439
                aad   = SCALE(commit_AAD_0),  // original generation only; unchanged payload bytes do not switch to commit_AAD_N during re-key
                pt    = plaintext       // partner-supplied bytes
              )
              // returns ciphertext_bytes ‖ poly1305_tag (16 bytes)
```

The notation `HKDF-SHA256(ikm, salt, info)[0..12]` denotes "the first 12 bytes of the HKDF output," where HKDF is used in the standard `Extract-then-Expand` form (RFC 5869): `Extract(salt, ikm)` produces a 32-byte pseudo-random key, then `Expand(prk, info, len)` produces the requested output length. With `info = ""` and `len = 12`, only the first HKDF-Expand block is needed.

The `salt` parameter `TAG_AEAD_V3 ‖ commit_context_digest_0` is a 64-byte byte-concat: `TAG_AEAD_V3` (32 bytes, the keccak256 of the byte-string `"CEALIS_V3_AEAD_V3"` per §2) followed by `commit_context_digest_0` (32 bytes). Per §1 SF-3, this byte-concat is the canonical form for fixed-width keccak / KDF inputs.

The `aad` parameter is the SCALE-encoded original `commit_AAD_0` structure (§4) in its full canonical byte form. The AEAD's authentication tag covers the AAD bytes — any drift in any generation-0 commit_AAD field at decryption time fails the tag check (see §6.4.5).

After encryption, the plaintext bytes, DEK bytes, Shamir polynomial coefficients, and any unwrapped share material are securely zeroized in memory (Mode A: inside the Cealis TEE boundary before TEE attestation closes; Mode B: on the subject's device after upload completes). No party stores the DEK. Reveal reconstructs it only through §6.3 threshold combination.

#### 6.4.4 Nonce uniqueness — by construction

The nonce derivation is deterministic in `(DEK, commit_context_digest_0)`. Both inputs are unique per commit by construction:

- `DEK` is freshly generated per commit by CSPRNG. It is then Shamir-split and zeroized, so no two distinct commits share a DEK except with negligible 2^-256 random collision probability.
- `commit_context_digest_0` is the pre-payload acyclic context per §3.4.1. It binds the same fixed-width field layout as final `h_commit_0` except the not-yet-known `ciphertext_digest_0` field is exactly `ZERO32`. Final `h_commit_0` later binds the actual `ciphertext_digest_0`.

The composition `HKDF(DEK, TAG_AEAD_V3 ‖ commit_context_digest_0)[0..12]` is therefore deterministic per commit and unique across commits with overwhelming probability (collision probability bounded by HKDF-SHA256 collision-resistance under distinct inputs, ≈ 2^−128 per SHA-256 collision-resistance; the 96-bit nonce output length itself is NOT the security bound — under deterministic nonce derivation, the bound inherits from the HKDF input space, not the nonce output space).

Re-encryption attacks are foreclosed: an attacker who attempts to re-encrypt a different plaintext under the same DEK + `commit_context_digest_0` would require either (a) a colliding plaintext-to-ciphertext byte sequence under a different `commit_AAD_0` (impossible — the AEAD authentication tag would mismatch at decryption), or (b) a fresh DEK or commit context (which by construction produces a different envelope, not a re-encryption). The deterministic nonce derivation is what closes this attack class without requiring per-commit nonce randomness or storage.

The derivation also makes encryption deterministic for the same `(DEK, commit_context_digest_0, commit_AAD_0)` tuple: encrypting the same plaintext under the same commit context twice produces identical bytes. This property is leveraged by re-key ceremony (§15) — re-key adds new stanza wraps over the same Shamir shares without re-encrypting payload bytes. Payload AEAD is generation-0-bound: generation-N contexts are for generation-N stanza wraps and lineage verification unless a future `commit_version` explicitly introduces payload re-encryption.

#### 6.4.5 Decryption — reveal-time verification

At reveal time, after the combiner has run the pre-verify checklist (§14.1), verified σ authorizations, recovered threshold shares through §6.2, and reconstructed the file_key through §6.3, the payload is decrypted as follows:

```
1. Read payload bytes from the envelope
   (entire suffix after the SCALE-encoded header).
2. Verify payload length ≥ 16 (Poly1305 tag is 16 bytes; payload shorter
   than 16 bytes is malformed; abort with ERR_AEAD_TRUNCATED_PAYLOAD).
3. Recompute nonce:
   nonce := HKDF-SHA256(
              ikm  = DEK,
              salt = TAG_AEAD_V3 ‖ commit_context_digest_0,
              info = ""
            )[0..12]
4. Reconstruct the SCALE-encoded generation-0 commit_AAD bytes from the loaded envelope's
   commit_AAD_0 structure (§4); MUST be the same canonical byte form the
   encryption side produced. Any drift here fails the tag check at step 5.
5. plaintext := ChaCha20-Poly1305-Decrypt(
                  key   = DEK,
                  nonce = nonce,
                  aad   = SCALE(commit_AAD_0),
                  ct    = payload
                )
   - Returns plaintext bytes if the Poly1305 tag verifies.
   - Returns AEAD failure if the tag does not verify; abort with
     ERR_AEAD_TAG_VERIFY_FAIL (§16) and return NO PARTIAL plaintext.
```

The procedure above describes the §6.4 decryption path that runs AFTER the combiner has reconstructed file_key by §6.3 Shamir combination. If file_key cannot be reconstructed (e.g., G4 refusal, below-threshold conditional shares, stanza unwrap failure, or share-index failure), §6.4 is unreached — the failure surfaces at §6.3 / §14.1 with the appropriate error code, not at §6.4. §6.4's responsibility begins after file_key is in hand and ends at plaintext-or-abort.

The AEAD-failure semantic is critical: the plugin MUST NOT return partial plaintext on tag-verification failure. Standard ChaCha20-Poly1305 implementations satisfy this property (per RFC 8439 §2.8 and the `@noble/ciphers` API contract pinned in S2-3); the spec normatively requires it.

#### 6.4.6 commit_AAD as universal-tripwire enforcement at the AEAD layer

The AEAD's AAD binding to the SCALE-encoded generation-0 `commit_AAD_0` is the §6.4-layer enforcement of the original payload context. `commit_AAD_0` carries 22 mandatory fields per §4 (post-BP-SD-1 2026-05-05) — including `authorizationId`, `pda_root`, `subject_commitment_v3`, `plugin_version_digest`, `g4_authority_ref`, `endpoint_attestation_digest`, `recipients_root`, `conditional_recipients_policy_digest`, `sdMerkleRoot`, `g3_choice`, `phase`, `superseded_commit_ref = ZERO32`, `commit_generation = 0`, and others. Any drift in any of these fields at reveal time produces a different SCALE byte form, which produces a different Poly1305 tag computation, which fails verification.

Concretely:

- Recipient combiner attempts to decrypt under an envelope that has been served from the vault with a single bit flipped in the `pda_root` field of commit_AAD → AEAD tag fails → plaintext never produced.
- Combiner attempts to use a different `g3_choice` than the one frozen at commit (i.e., processing a drand commit as if it were dcipher) → AEAD tag fails → plaintext never produced.
- Combiner attempts to use the wrong plugin binary (whose `plugin_version_digest` does not match `commit_AAD.plugin_version_digest`) → caught earlier at §14.1 step 2 (plugin_version_digest match against PluginHashRegistry-at-commit-block); even if step 2 were bypassed, the AEAD tag verification at step 5 would fail because the recovered DEK would derive from wrong stanza interpretations.

The AEAD layer is the last line of defense — every other check in §14.1 catches its target attack class earlier and emits a more specific error code (§16). The AEAD check catches anything that slipped through, and converts it to "no plaintext" rather than "wrong plaintext." This is what makes the universal tripwire structural rather than procedural at this layer.

#### 6.4.7 Same-DEK invariant under A1+Shamir

The §6.4 spec receives exactly one 32-byte file_key. Under A1+Shamir, every valid threshold share set reconstructs the same commit-time DEK; below-threshold sets reconstruct nothing. An implementation that produces different file_key bytes from different valid threshold subsets is non-conforming and MUST fail interoperability tests. The payload bytes are therefore stable across recipients, conditional-recipient subsets, and re-key generations.

#### 6.4.8 Cross-references and forward-pointers

§3.4 specifies `commit_context_digest_0` as the second salt component of payload nonce derivation and final `h_commit_N` as the chain-anchored commit identity. §4 specifies `commit_AAD_0` as the payload AEAD AAD for unchanged payload bytes. §6.1 specifies envelope structure (the position of the payload within the envelope). §6.2 / §6.3 specify Shamir-share wrapping and reconstruction (the input DEK to §6.4). §13 specifies PasskeyRotationLog (referenced indirectly via commit_AAD's `conditional_recipients_policy_digest` binding). §14.1 specifies the combiner pre-verify checklist (which runs in full before §6.4.5 decryption fires). §15 specifies the re-key ceremony (which depends on §6.4's deterministic-nonce property to reuse payload bytes across stanza generations). §16 specifies the error model (`ERR_AEAD_TRUNCATED_PAYLOAD`, `ERR_AEAD_TAG_VERIFY_FAIL`). The §6.4 spec is otherwise a clean leaf in the dependency graph — it produces no forward bindings and consumes a single primitive (file_key from §6.3).

### §6.5 — Subject-side pre-σ verifier

Backprop note 2026-05-05: §6.5 remains owned by the subject-side verifier implementation spec; it inherits the §6.2 Shamir-share wrap discipline and the §4 `sdMerkleRoot` binding without adding new byte layouts in S2-1.

### §6.6 PII content statement

PII content of every byte-layout in §6 (envelope structure §6.1, hybrid PQ wrap §6.2, typed Shamir reconstruction §6.3, AEAD payload §6.4): **NONE in any commit-time keccak preimage or AEAD AAD**. Cleartext plaintext recovered post-decryption inside the §6.4 + §14 in-process boundary IS subject-PII for use cases that escrow personal data (KYC/identity, testament, medical), but that plaintext lives below the cryptographic-layer scope and is governed by §14.1.1 constraint 4 (the combiner does not retain or process plaintext after handing it to the §D RevealArtifactBundle assembly + per-recipient schema-selector filtering layer). Per-field defense for the four cross-partner-stable or recipient-bound surfaces that warrant explicit treatment:

- **`account_id` (Mode 1 PASSKEY_ACCOUNT, bytes32 — §6.1.5 stanza variant `0x01`):** Cealis-issued opaque cross-partner-stable identifier. The cross-partner-stable property means the same recipient appears under the same `account_id` across all PDAs they participate in as conditional-recipient (this is a routing convenience for recipients participating in multiple PDAs, not a public re-identification surface). Per §13.10.1's Breyer C-582/14 GDPR Recital 26 strict-interpretation precedent: for a third-party observer with no access to Cealis's internal account-creation database, `account_id` is not personal data (no reasonably-likely linkage path exists); for Cealis itself, `account_id` IS personal data within Cealis's controller-scope (Cealis can link `account_id` → subject identity via its internal database), governed by Cealis's existing data-processing legal basis per WP §K item 5 + §M closed-source vault discipline. **On-chain visibility: NONE** — `account_id` appears in stanza payloads inside `age_envelope_N` ciphertext under §6.4 AEAD, never in any keccak preimage bound to chain. **Off-chain visibility:** vault (encrypted at rest under DEK) + recipient artifact post-reveal (per WP §D §417 RevealArtifactBundle) + combiner in-process during §14 verification.

- **`wallet_address` (Mode 2 WALLET_EOA, bytes20 — §6.1.6 stanza variant `0x02`):** Recipient's Ethereum externally-owned-account address. Per §10.10's wallet-address PII disposition + §13.10.1's Breyer precedent: `wallet_address` IS personal data under strict GDPR Art. 4(1) for any controller with the means reasonably likely to be used to link the EOA address to a natural person (chain-analysis vendors, exchanges with KYC linkage, etc.). The recipient self-doxxes by registering their EOA at PDA-config time; no Cealis-side controllership concession is created beyond what the recipient already exposes via on-chain activity. **On-chain visibility: NONE at the commit layer** — `wallet_address` appears in stanza payloads inside `age_envelope_N` ciphertext under §6.4 AEAD, not in any keccak preimage bound to chain (the chain only sees `h_commit`, recipients_root Merkle leaf hashes, and the §10 reveal-challenge digest bound to wallet_address via σ_conditional EOA recovery — none of which expose the bytes20 EOA on-chain unless the recipient otherwise transacts under it). **Off-chain visibility:** vault + recipient artifact post-reveal + combiner in-process.

- **`delivery_url` (Mode 2 WALLET_EOA, SCALE-length-prefixed UTF-8 ≤ 512 bytes — §6.1.6 stanza variant `0x02`):** Recipient's preferred delivery endpoint (HTTPS or IPFS gateway URL). Per WP §K item 12 (honestly-named property): `delivery_url` is **public-by-construction within the stanza** — it appears in plaintext within the stanza payload (encrypted under §6.4 AEAD on-chain, but observable to anyone holding the post-reveal envelope or `RevealArtifactBundle`), so the recipient's network-level delivery is observable to passive observers of the post-reveal artifact and the recipient's own ISP / DNS resolver. The plaintext `delivery_url` is NOT subject-PII (it is recipient-self-published metadata) but MAY be recipient-PII for natural-person recipients who use a personally-identifying URL (e.g., a vanity domain or hosted-mail subdomain that names them). Subjects with strong network-privacy requirements should configure recipient-pull via IPFS (the recipient pulls their wrapped payload from an IPFS CID) or use variant `0x01` PASSKEY_ACCOUNT (in-app Cealis dashboard delivery, no recipient-controlled URL). **On-chain visibility: NONE** in commit-time preimages. **Off-chain visibility:** vault + recipient artifact post-reveal + delivery-layer transport (per S2-5 delivery-API runtime).

- **Stanza pubkey fields (`initial_passkey_pubkey`, `initial_delivery_x25519_pubkey`, `initial_mlkem_pubkey` Mode 1; `delivery_x25519_pubkey`, `delivery_mlkem_pubkey` Mode 2):** Cryptographic public keys per FIDO2 / RFC 7748 / FIPS 203 ML-KEM-768 encodings. Per §13.10 + §4.9 framing: pubkeys are identity-bearing pseudo-identifiers under EU GDPR Art. 4(1) for any controller holding the linkage to a natural person, but structurally non-PII to a third-party observer who lacks the reasonably-likely linkage path. Same scope analysis as `account_id` (Mode 1) and `wallet_address` (Mode 2). **On-chain visibility: NONE inside the stanza** — pubkeys are inside `age_envelope_N` ciphertext, not in keccak preimages bound to chain (chain only sees `h_commit` + the §13 `PasskeyRotationLog` `entry_pubkey_at_commit` + `entry_delivery_x25519_pubkey_at_commit` + `entry_mlkem_pubkey_at_commit` via the on-chain `PasskeyRotationLog` entries themselves, governed by §13.10's PII-NONE-with-Breyer-precedent disposition). **Off-chain visibility:** vault + recipient artifact post-reveal + combiner in-process.

PII content of `Shamir share_s` values (output of §6.2 hybrid PQ wrap decapsulation, input to §6.3 `Shamir.combine`): **NONE**. Shamir shares are 32-byte cryptographic secrets that are inputs to the polynomial-interpolation reconstruction; share secrecy is the §14.3 share secrecy discipline anchor; share values do NOT carry subject-PII content (they are derived from the random commit-time DEK by polynomial-evaluation per §6.3, not from subject-identifying data). Recovered shares are zeroized per §14.4.2 after `file_key` reconstruction.

PII content of `file_key` / DEK: **NONE in the key bytes themselves** (the DEK is a 32-byte cryptographic secret randomly generated at commit time per A1+Shamir; it is not derived from subject-identifying data). The DEK is the AEAD key for §6.4 payload decryption; recovered DEK is zeroized per §14.4.2 after AEAD decryption fires. The plaintext that the DEK decrypts may be subject-PII (use-case-dependent), but plaintext disposition lives at §14.1.1 constraint 4 + §D RevealArtifactBundle assembly, not in §6.

---

## §7 — Gate signature σ_Lit

This section defines the byte-exact construction of `σ_Lit`, the gate signature produced by the G2 Lit V3 per-op TEE at reveal time. σ_Lit binds the chain-state-evaluated access-control condition (ACC) to a specific commit's authorization context via a BLS12-381 signature over `(authorizationId, h_commit, block_hash)`. The signature is authorization evidence verified before §6.3 file_key reconstruction under A1+Shamir, and it is companion-paired with a per-op DCAP quote whose `user_data` field binds the same `(authorizationId, h_commit, block_hash)` tuple (the A14 anti-replay fix that prevents quote-reuse across commits).

### 7.1 σ-as-authorization normative discipline (per WP §B P22 revisited)

σ_Lit is an authorization signature / attestation output AND authorization evidence, not DEK material or HKDF input. The combiner verifies σ_Lit over `(authorizationId, h_commit_N, block_hash)` against the Lit V3 assignment record and attested serving TEE state. A valid σ_Lit authorizes decap/admission of the Lit top-level Shamir share; it is not itself sufficient to reconstruct file_key and MAY appear in the reveal artifact after verification.

Transport remains authenticated and integrity-protected because a forged or replayed σ would authorize the wrong share path. Confidentiality requirements attach to the released Shamir share, stanza decap material, reconstructed DEK, and plaintext. Logging σ_Lit is not a DEK leak by itself, but implementations SHOULD still avoid raw σ logs unless the recipient artifact explicitly requires them.

### 7.2 Lit V3 per-op TEE assignment record

σ_Lit is signed by a single Lit V3 serving TEE assigned per-request from Lit's permissionless operator pool (~30 operators, mixed PKI: Intel SGX, AMD SEV-SNP, AWS Nitro). The assignment is published on-chain via the `LitV3Assignment` record at the commit's RevealAuthorized block per §11.2 endpoint attestation:

```
LitV3Assignment(authorizationId) → assigned_tee_id + block_number + assigned_tee_pubkey
```

The combiner verifies the assigned TEE's identity and pubkey at reveal per §11.2. This binding is the A06 anti-adversary-chosen-TEE fix: an attacker cannot select a compromised TEE to serve their commit because the assignment is governance-published per Lit V3 protocol and cryptographically anchored on-chain at commit's block.

The assigned TEE produces σ_Lit + the per-op DCAP quote (§7.5) inside its enclave; both are returned to the recipient combiner via the confidential transport per §7.1.

### 7.3 Signing input

σ_Lit signs over a fixed-width byte concatenation per §1.3.1 byte-concat discipline:

```
σ_Lit_input = authorizationId ‖ h_commit ‖ block_hash
```

| Field | Width | Source |
|---|---|---|
| `authorizationId` | 32 bytes | Per §3.2 — the per-commit identifier; uniformly distributed under keccak-256 |
| `h_commit` | 32 bytes | Per §3.4 — the on-chain anchor hash for this commit's envelope |
| `block_hash` | 32 bytes | Per §11.2 — the Base L1 block hash of the `RevealAuthorized` event; A14 anti-replay binding |

**Total signing-input length:** 32 + 32 + 32 = **96 bytes**.

**No TAG-prefix.** σ_Lit's signing input is a byte concatenation without TAG-prefix because the BLS12-381 signature scheme provides its own domain separation via the elliptic-curve point representation + the message-to-curve hash function (typically `hash_to_curve` per RFC 9380 BLS12-381 ciphersuite). Commit binding is provided by the signed `(authorizationId, h_commit, block_hash)` tuple and by the stanza MAC / AEAD AAD layers; per-σ TAG-prefix at the signing-input layer would be redundant and is not part of the BLS12-381 signing convention.

The `block_hash` binding (NOT just `block_number`) is the A14 anti-replay fix per `flows-spec-final.md:196` + WP §D wp.md:333. Without `block_hash`, a Lit V3 quote produced for an authorization on a reorg-defeated block could in principle be replayed onto the new canonical chain's authorization for the same `authorizationId`. The `block_hash` binding defeats this by tying σ_Lit to the exact block that emitted the `RevealAuthorized` event.

### 7.4 BLS12-381 signature byte format

σ_Lit is a BLS12-381 signature in G2-compressed form (Lit V3's documented Chipotle convention).

| Property | Value |
|---|---|
| Curve | BLS12-381 |
| Group | G2 (signature) / G1 (pubkey) — per Lit V3 Chipotle convention |
| Signature length | exactly **96 bytes** (G2 compressed per RFC 9380 + ZCash BLS12-381 encoding) |
| Pubkey length | 48 bytes (G1 compressed) |
| Hash-to-curve | per RFC 9380 BLS12-381 ciphersuite (typically `BLS12381G2_XMD:SHA-256_SSWU_RO_` or Lit V3's documented variant) |

Library family: `@noble/curves` BLS12-381 module per `flows-spec-final.md:241` (S2-3 pins specific library version + ciphersuite). The signing-input bytes (§7.3) are mapped to a G2 point via `hash_to_curve`, then signed with the assigned TEE's BLS private key inside the enclave; the resulting G2 point is serialized to the 96-byte compressed form as σ_Lit.

S2-1 specifies the wire format; S2-3 (custody-integration-spec) pins the specific Lit V3 SDK version and the exact hash-to-curve ciphersuite identifier. Implementations that satisfy the BLS12-381 G2-compressed conformance + Lit V3 SDK ciphersuite produce byte-identical σ_Lit values.

### 7.5 Per-op DCAP quote — companion artifact

Every σ_Lit is companion-paired with a per-op DCAP attestation quote produced by the same Lit V3 serving TEE that signed σ_Lit. The quote attests that:

1. The serving TEE's enclave measurement matches the Lit V3 enclave hash registered on-chain.
2. The σ_Lit signing happened inside that enclave (not in a non-attested execution context).
3. The signing context bound the same `(authorizationId, h_commit, block_hash)` tuple that σ_Lit signs over.

**The DCAP quote's `user_data` field MUST include the 32-byte Lit-specific digest:**

```
lit_user_data_digest = keccak256(authorizationId ‖ h_commit ‖ block_hash)[:32]
DCAP user_data (Lit V3 per-op) = lit_user_data_digest ‖ 32 zero bytes
```

This is the A14 anti-replay fix per `flows-spec-final.md:196`: without the `user_data` binding, a DCAP quote produced for one commit could be replayed as evidence for a different commit using a tampered σ_Lit. With the binding, the combiner re-computes the 96-byte raw preimage `(authorizationId, h_commit, block_hash)`, keccak-compresses it to 32 bytes, and rejects if the first 32 bytes of DCAP `user_data` do not match or the remaining 32 bytes are not zero.

The DCAP quote bytes are typically 4-8 KB (varies per vendor: Intel SGX vs AMD SEV-SNP vs AWS Nitro). The quote travels alongside σ_Lit in the `RevealArtifactBundle` per §D for chain-of-custody auditability; recipients verify both σ_Lit AND the DCAP quote at reveal per §7.6.

Per Simon Decision D11 byte-budget consideration, S2-1 canonicalizes the keccak-compressed 32-byte layout for Lit V3. Lit does not use `TAG_G4_ATTESTATION_V3`; the raw preimage remains `authorizationId ‖ h_commit ‖ block_hash`, compressed only to fit DCAP `user_data`. The §3.4.3 endpoint_attestation_digest construction (SCALE sum-type per Simon D10) handles the on-chain commitment to the commit-time attestation; the full per-op DCAP quote bytes travel off-chain in the RevealArtifactBundle.

### 7.6 Verification protocol

The recipient combiner verifies σ_Lit at reveal per the following 4-step protocol (these steps occur inside the §14.1 combiner pre-verify checklist, before §6.3 file_key reconstruction fires):

1. **Verify σ_Lit BLS signature.** Verify σ_Lit is a valid BLS12-381 G2 signature under the assigned TEE's pubkey (recovered from `LitV3Assignment(authorizationId).assigned_tee_pubkey` per §7.2 / §11.2) over the signing input `authorizationId ‖ h_commit ‖ block_hash`. If the BLS verification fails, abort with `ERR_SIGMA_LIT_SIGNATURE_INVALID` per §16.

2. **Verify DCAP quote.** Verify the per-op DCAP quote against the appropriate hardware vendor's attestation root (Intel SGX root / AMD SEV-SNP root / AWS Nitro root depending on the assigned TEE's vendor per §7.2). Use the on-chain `zkDCAPVerifier` (Automata) per §11.2 + S2-3 library pin. If the DCAP verification fails, abort with `ERR_LIT_DCAP_INVALID` per §16.

3. **Verify DCAP `user_data` binding.** Recompute `keccak256(authorizationId ‖ h_commit ‖ block_hash)[:32]` from the loaded envelope + on-chain anchor; compare against the first 32 bytes of the DCAP quote's `user_data` field and require the remaining 32 bytes to be zero. If mismatch, abort with `ERR_LIT_DCAP_USER_DATA_MISMATCH` per §16. This is the A14 anti-replay enforcement.

4. **Verify TEE assignment.** Verify the serving TEE's id (recovered from the DCAP quote's enclave measurement) matches the on-chain `LitV3Assignment(authorizationId).assigned_tee_id` at the commit's `RevealAuthorized` block. If mismatch, abort with `ERR_LIT_TEE_ASSIGNMENT_MISMATCH` per §16. This is the A06 anti-adversary-chosen-TEE enforcement.

All four steps MUST pass before σ_Lit can authorize decapsulation of the Lit stanza's Shamir share. Any step's failure aborts the reveal at the §14.1 pre-verify layer per fail-closed §1.7 error model.

### 7.7 Cross-vendor mandate (per A11 fix)

If the Lit V3 serving TEE's vendor for a given op is Intel SGX, then the G4 Phase 2 attestation's TEE vendor MUST be either AMD SEV-SNP or AWS Nitro per §9.3 cross-vendor requirement. The mandate prevents single-vendor PKI compromise from breaking both gates simultaneously — if an attacker compromises (e.g.) Intel SGX's attestation root, the cross-vendor G4 TEE remains uncompromised and authorized recovery still requires G4's independent attestation chain and top-level Shamir share.

Vendor diversity is evaluated by normalized vendor family, not marketing product name. Intel SGX and Intel TDX are the same family. AWS Nitro is its own family even on Intel or AMD host CPUs when the attestation root and isolation claim are Nitro's. AMD SEV-SNP is the AMD family. Ambiguous vendor classification fails closed until S2-3 §2.4 records an explicit classification.

The cross-vendor enforcement happens at PDA configuration time per §F PDA+ guardrail (configurator rejects PDAs whose Lit V3 + G4 vendor pair is single-vendor) and is re-validated at reveal by the combiner per §11 endpoint attestation cross-check. §9.3 carries the corresponding G4-side spec for the cross-vendor mandate.

### 7.8 Storage discipline

σ_Lit follows the σ-as-authorization transport discipline per §7.1:

| Location | Content | Purpose |
|---|---|---|
| **Vault (RevealArtifactBundle staging)** | Full σ_Lit bytes (96 bytes BLS12-381 G2 compressed) + per-op DCAP quote bytes | Off-chain delivery to recipient combiner per §D RevealArtifactBundle. Confidential transport per §7.1. |
| **commit_AAD field** | NOTHING. σ_Lit is NOT bound at commit time; it is produced at reveal time per the §11.2 Lit V3 per-op flow. | σ_Lit is a reveal-time artifact, not a commit-time anchor. |
| **On-chain** | NOTHING by default. σ_Lit bytes do not need on-chain anchoring; post-reveal artifact publication is off-chain unless a future PDA elects a public audit hash. | σ_Lit is authorization evidence, not key material. |
| **`endpoint_attestation_digest` (§3.4.3 in `commit_AAD` per §4.1)** | Phase 2: SCALE-encoded `EndpointAttestation::Phase2 { dcap_quote_bytes }` digest (per §3.4.3 SCALE sum-type) bound at commit time | Anchors the COMMIT-time DCAP quote (Lit V3 enclave measurement at commit) to h_commit. The PER-OP DCAP at reveal (§7.5) is a separate quote anchored to (authorizationId, h_commit, block_hash). |
| **Combiner memory (reveal-time)** | σ_Lit transient — verified before §6.3 Shamir, then zeroized per §14.2 one-shot-exposure discipline | σ_Lit lives in combiner memory only for the duration of file_key reconstruction; never persisted. |

The discipline matches the σ-as-authorization pattern at §5.7 (σ_subject) + §6.4 (DEK as transient one-shot). σ_Lit is a per-reveal artifact; commit-time only carries the on-chain anchor (`endpoint_attestation_digest` for the COMMIT-time Lit V3 enclave measurement) plus the on-chain Lit assignment record (§11.2). Reveal-time produces the actual σ_Lit + per-op DCAP, both confidential, both consumed-then-zeroized.

### 7.9 Cross-reference index

This section consumes the following primitives and registries from earlier sections:

- **§1.1.3** asymmetric primitives — BLS12-381 enumerated as a V3 normative curve.
- **§1.3.1** byte-concat discipline — applied at §7.3 σ_Lit signing input (no TAG-prefix per §7.3 rationale; BLS scheme provides domain separation via hash-to-curve).
- **§3.2** authorizationId — first 32 bytes of σ_Lit signing input.
- **§3.4** h_commit — second 32 bytes of σ_Lit signing input.
- **§4.1** commit_AAD `endpoint_attestation_digest` field (Group 2) — anchors the commit-time Lit V3 enclave measurement; per-op σ_Lit attestation is reveal-time per §7.5.
- **§6.3** Shamir file_key reconstruction — admits the Lit Shamir share only after σ_Lit verifies.

Forward-references (consumed by later sections):

- **§9.3** σ_G4 Phase 2 — same DCAP quote pattern as §7.5; cross-vendor mandate per §7.7.
- **§11.1** Lit V3 enclave measurement — commit-time attestation that anchors `endpoint_attestation_digest`.
- **§11.2** Lit V3 per-op attestation flow — assignment record fetch + per-op DCAP verification (§7.5 + §7.6).
- **§14.1** combiner pre-verify checklist — runs §7.6's 4-step verification BEFORE §6.3 file_key reconstruction fires.
- **§14.2** share secrecy operational discipline — full hardened-context discipline for σ_Lit handling.
- **§16** error model: `ERR_SIGMA_LIT_SIGNATURE_INVALID` + `ERR_LIT_DCAP_INVALID` + `ERR_LIT_DCAP_USER_DATA_MISMATCH` + `ERR_LIT_TEE_ASSIGNMENT_MISMATCH`.

Library SDK version pins are S2-3 territory.

### 7.10 PII content statement

σ_Lit is PII-NONE at the cryptographic-construct layer. The signing input bytes (`authorizationId ‖ h_commit ‖ block_hash`) are all keccak-256 / chain-state digests of upstream constructions whose preimages were already PII-free per §3.6 + §4.9. The σ_Lit signature bytes themselves (96 bytes BLS12-381 G2) are computationally indistinguishable from random under BLS12-381's signature-randomization properties — they reveal nothing about the underlying signing input or the signing key beyond what BLS verification surfaces.

The per-op DCAP quote (§7.5) carries enclave measurement bytes and `user_data` bytes; both are non-PII per the DCAP attestation framing (enclave measurement is an immutable hash of the Lit V3 enclave's compiled image; `user_data` is the commit-binding tuple). The DCAP quote's signature bytes are produced by the hardware vendor's attestation key (Intel / AMD / AWS), not by any subject-identity-bearing key.

The Lit V3 serving TEE's pubkey (recovered from `LitV3Assignment` per §7.2) is operator-side metadata, not subject-side metadata. There is no PII surface in σ_Lit's construction or verification path.

σ transport discipline per §7.1 protects reveal-operation integrity before the combiner admits the corresponding Shamir share; it is NOT a PII protection mechanism (σ values themselves carry no PII). The two protection layers are orthogonal: PII is protected by AEAD payload encryption per §6.4, and share secrecy is protected by stanza wrapping plus in-memory combiner discipline.

---

## §8 — Gate signature σ_G3

This section defines the byte-exact construction of `σ_G3`, the gate signature produced by the G3 path declared at PDA-config commit time. G3 supports two paths at SAME normative depth per Stage-0 Q-0-1 LOCKED: **dcipher** (Randamu Threshold Association threshold-IBE; KYC / M&A / regulated-EU / evidence use cases) and **drand** (League of Entropy threshold-BLS12-381 beacon; time-locked / testament / archival / dead-man's-switch / long-retention use cases). Per-PDA choice is frozen at commit via `g3_choice` field in `commit_AAD` (§4.1 Group 3) + `commit_AAD` SCALE encoding + `pda_root` enumeration. Both produce variable-length BLS-derived signatures carried as reveal artifacts and verified before the G3 stanza share may be admitted to §6.3 Shamir reconstruction.

### 8.1 σ-as-authorization normative discipline (per WP §B P22 revisited)

σ_G3 is an authorization signature / attestation output AND authorization evidence, not DEK material or HKDF input. The combiner verifies σ_G3 under dcipher or drand according to `commit_AAD.g3_choice`; once valid, σ_G3 authorizes decap/admission of the G3 top-level Shamir share.

The drand path remains public-by-design: drand round signatures are observable on the public beacon. That is compatible with A1+Shamir because public σ_G3 is authorization evidence, not a Shamir share or file_key input. Observing σ_G3 bytes alone is insufficient; the protected material is the G3 Shamir share recovered from the stanza wrap, and a single G3 share is information-theoretically zero about the DEK below the §6.3 access predicate.

### 8.2 dcipher path — `g3_choice = 0`

For PDAs configured with `g3_choice = 0` per §3.3.4 + §4.1 Group 3:

#### 8.2.1 What it is

A threshold-IBE (identity-based encryption) signature produced by the **Randamu Threshold Association** dcipher committee — a Swiss non-profit operating a threshold network with committee membership and rotation. The committee aggregates a single threshold-BLS-derived signature over a per-commit binding; the on-chain dcipher protocol publishes the committee's pubkey for the current epoch.

#### 8.2.2 Cryptographic primitive

- **Curve:** BLS12-381 (threshold-IBE family per Boneh-Boyen + threshold extension per Kate-Goyal-Boldyreva).
- **Signature length:** variable per dcipher SDK variant choice. Per BP-5 LOCKED + canonical §1.1.4 line 38, dcipher's minimum-pubkey-size vs minimum-signature-size variant assignment is deferred to S2-3 SDK confirmation pending Randamu dcipher SDK availability per `flows-spec-final.md:242`. For S2-1 wire-format, treat σ_G3 (dcipher) as variable-length `Bytes` SCALE element per §6.3.2; the verifier MUST verify σ_G3 under the variant the Randamu dcipher SDK's published protocol uses.
- **Library family:** `@noble/curves` BLS12-381 module + Randamu dcipher SDK (when available). S2-3 pins specific library versions and the variant assignment.

#### 8.2.3 Signing input

```
σ_G3_input (dcipher) = authorizationId ‖ h_commit ‖ block_hash
```

| Field | Width | Source |
|---|---|---|
| `authorizationId` | 32 bytes | Per §3.2 — per-commit identifier |
| `h_commit` | 32 bytes | Per §3.4 — on-chain anchor hash |
| `block_hash` | 32 bytes | Per §11 — Base L1 block hash of `RevealAuthorized` event; A14 anti-replay binding |

**Total signing-input length:** 32 + 32 + 32 = **96 bytes** (same as σ_Lit per §7.3).

**No TAG-prefix on σ_G3 (dcipher) signing input** — same rationale as §7.3: BLS12-381 hash-to-curve via RFC 9380 ciphersuite identifier provides cryptographic domain separation at the curve layer; per-σ keccak TAG-prefix at signing-input layer would be redundant and is not part of BLS12-381 signing convention. Commit binding is enforced by the signed reveal tuple plus §6.1 stanza MAC and §6.4 AEAD AAD.

#### 8.2.4 dcipher committee pubkey verification

The combiner verifies σ_G3 (dcipher) against the dcipher committee pubkey from the **Randamu Threshold Association registry** at the commit's block — NOT current state. Per §11.3 G3 committee pubkey fetch:

1. Read `g3_choice = 0` from `commit_AAD` (§4.1 Group 3) confirming dcipher path.
2. Resolve dcipher committee pubkey at the commit's `RevealAuthorized` block from on-chain Randamu Threshold Association registry (epoch-stable; rotations emit on-chain events).
3. Verify σ_G3 (BLS12-381 threshold signature aggregation) under the resolved committee pubkey over `σ_G3_input`.
4. If verification fails, abort with `ERR_SIGMA_G3_DCIPHER_INVALID` per §16.

The "registry state at commit's block, not current state" pattern matches §4.6.2 g4_authority_ref backward-compat semantics + §11 endpoint attestation registry-snapshot discipline. dcipher committee key rotation is an orthogonal ceremony (per §15.6.3 framing); rotations after the commit do not retroactively invalidate prior σ_G3 verifications because recipients verify against the committee pubkey at the commit's block.

#### 8.2.5 Use case mapping

Per Stage-0 Q-0-1 LOCKED 2026-04-25 (internal stage-0 decisions log, not in this export):

> *"dcipher for KYC / M&A / regulated-EU / evidence use cases."*

dcipher is the default G3 choice for PDAs whose use case requires a regulated-EU threshold-network operator with committee membership transparency + Swiss legal-entity governance. Partner may override via PDA configuration; configurator surfaces both dcipher + drand at PDA-config time and applies the use-case default when partner doesn't pick.

### 8.3 drand path — `g3_choice = 1`

For PDAs configured with `g3_choice = 1` per §3.3.4 + §4.1 Group 3:

#### 8.3.1 What it is

A BLS12-381 threshold beacon signature produced by the **League of Entropy** drand network — a coalition of 22 multi-national public-good operators (Cloudflare, EPFL, Protocol Labs, Kudelski Security, etc.) operating the drand beacon since 2019. Each beacon round publishes a threshold-aggregated BLS signature over the round number; the drand chain is publicly verifiable.

#### 8.3.2 Cryptographic primitive

- **Curve:** BLS12-381 (G1 pubkey, G2 signature per drand-protocol minimum-pubkey-size variant per §1.1.4 + BP-5 LOCKED). The minimum-pubkey-size variant assigns the **public key to G1 (48 bytes compressed)** and the **signature to G2 (96 bytes compressed)**.
- **Signature length:** exactly **96 bytes** (BLS12-381 G2-compressed per drand-protocol specification + `drand/kyber` library family per `flows-spec-final.md:243`). The drand committee public key is 48 bytes (G1-compressed) per the same variant assignment.
- **Library family:** `drand/kyber` Go library + `@noble/curves` BLS12-381 module for verification. S2-3 pins specific library versions.

#### 8.3.3 Signing input — round signature

```
σ_G3_input (drand) = drand_round_signature(target_round_at_commit)
```

The σ_G3 value for drand is the **drand beacon's round signature** for the target round number specified at PDA-config commit time (per `flows-spec-final.md:24, 350, 545`). The "binding" to `(authorizationId, h_commit, block_hash)` is implicit via:

1. The commit's `g3_choice = 1` field selecting the drand path (frozen in `commit_AAD` + `pda_root`).
2. The commit's `stanza[1]` payload specifying `target_drand_round` per §6.1.3 stanza variant (G3 stanza payload with `type = 1` carrying `drand_round: uint64 (BE)`).
3. The drand beacon signing the round number itself (the BLS signature is over the round number, not over a per-commit binding).

The σ_G3 artifact for drand is the round signature bytes themselves (96 bytes BLS12-381 G2-compressed per minimum-pubkey-size variant — see §8.3.2) — same bytes that the drand beacon publishes publicly on its chain when it advances to the target round.

#### 8.3.4 drand beacon pubkey verification

The combiner verifies σ_G3 (drand) against the **drand beacon pubkey** for the League of Entropy chain (per the drand protocol specification + drand HTTP API):

1. Read `g3_choice = 1` from `commit_AAD` (§4.1 Group 3) confirming drand path.
2. Read `target_drand_round: uint64` from `stanza[1]` payload per §6.1.3.
3. Fetch the drand round signature for `target_drand_round` from any drand operator (Cloudflare endpoint, Protocol Labs endpoint, etc. — the drand chain is replicated across all 22 League of Entropy operators).
4. Verify σ_G3 (BLS12-381 G2 threshold signature, 96 bytes compressed per minimum-pubkey-size variant) under the drand beacon pubkey (G1, 48 bytes compressed; League of Entropy public chain) over `target_drand_round`.
5. Verify the round signature is for the EXACT target round specified at commit (no off-by-one, no different round).
6. If verification fails, abort with `ERR_SIGMA_G3_DRAND_INVALID` per §16.

The drand chain is publicly verifiable — anyone with access to a drand HTTP endpoint can verify σ_G3 (drand) without needing trust in a specific operator. This is the public-by-design property that makes drand suitable for time-locked / archival / long-retention use cases where decades of operational continuity matter more than committee transparency.

#### 8.3.5 Use case mapping

Per Stage-0 Q-0-1 LOCKED:

> *"drand for time-locked / testament / archival / dead-man's-switch / long-retention use cases."*

drand is the default G3 choice for PDAs whose use case requires:
- **Time-locked release.** The target round is published at commit; the beacon will advance to that round in the future, at which point the round signature becomes available; before the target round, σ_G3 (drand) is cryptographically unavailable, providing time-lock semantics.
- **Long-retention operational continuity.** drand has been operational since 2019 (~7 years operational track at V2 launch) with 22-operator multi-national distribution; designed for multi-decade availability.
- **Public verifiability.** The drand chain is publicly replicated; recipients can verify σ_G3 without trust assumptions on Cealis or any single operator.

Partner may override via PDA configuration; configurator surfaces both choices.

### 8.4 Per-path normative depth (Stage-0 Q-0-1 LOCKED)

Both dcipher and drand are at **SAME normative depth** per Stage-0 Q-0-1 LOCKED 2026-04-25. Neither is "future work," neither is preferred at the spec layer. The choice is per-PDA at PDA-config time.

Configurator surfaces both at PDA-config time:
- Default: per the use-case mapping at §8.2.5 (dcipher) + §8.3.5 (drand).
- Partner override: PDA author can select either explicitly.
- Frozen at commit: `g3_choice` is bound into `pda_root` (§3.3.4 — `g3_choice: uint8` in commit_AAD; transitively bound via `pda_root` into `h_commit`) and into `commit_AAD` (§4.1 Group 3); switching post-commit is impossible.

Combiner consumes `g3_choice` from `commit_AAD` to determine which protocol applies at reveal. The reveal artifact carries either path's signature bytes; dcipher (variable per Randamu SDK variant — S2-3 confirms) and drand (96 bytes G2 per minimum-pubkey-size variant) are distinguished by the verification branch selected from `g3_choice`, not by §6.3.

### 8.5 σ_G3 verification protocol — unified surface

The combiner's §14.1 pre-verify checklist runs σ_G3 verification per the following branching protocol:

1. **Read `g3_choice` from `commit_AAD`** per §4.1 Group 3.
2. **Branch on `g3_choice`:**
   - `g3_choice = 0` → dcipher path (§8.2.4 verification: committee pubkey resolution + threshold-BLS verification + registry-state-at-commit's-block).
   - `g3_choice = 1` → drand path (§8.3.4 verification: round signature fetch + beacon pubkey + target-round match).
3. **If verification fails on either path, abort** with the path-specific ERR per §16:
   - `ERR_SIGMA_G3_DCIPHER_INVALID` (dcipher path)
   - `ERR_SIGMA_G3_DRAND_INVALID` (drand path)
   - `ERR_SIGMA_G3_PATH_MISMATCH` (g3_choice value not 0 or 1; this is a `commit_AAD` corruption or schema-violation case caught earlier at §14.1 pre-verify)
4. **If verification succeeds, σ_G3 authorizes G3 share admission**: the corresponding G3 stanza may be decapsulated and its Shamir share admitted to §6.3 reconstruction.

The verification fails fail-closed per §1.7 error model. No partial admission of σ_G3 — either it verifies fully under the path-specific protocol, or it aborts.

### 8.6 Storage discipline

σ_G3 follows the same σ-as-authorization transport discipline per §8.1 + §7.8 pattern (extended for the drand-public-by-design caveat at §8.1.2):

| Location | dcipher path | drand path |
|---|---|---|
| **Vault (RevealArtifactBundle staging)** | Full σ_G3 bytes (variable length per Randamu dcipher SDK variant — S2-3 confirms; treat as `Bytes` SCALE element per §6.3.2) | Full σ_G3 bytes (96 bytes BLS12-381 G2-compressed per minimum-pubkey-size variant) |
| **commit_AAD field** | NOTHING — σ_G3 is a reveal-time artifact (committee resolves identity at reveal) | NOTHING — σ_G3 is the drand round signature published at the target round, not at commit |
| **On-chain (Base L1 / G1 ConditionEngine)** | NOTHING — σ bytes are not published on Base by S2-2 | NOTHING on Base L1 — but the drand chain (separate public beacon infrastructure operated by League of Entropy) publishes the round signature; treat as publicly observable per §8.1 special-case framing |
| **`stanza[1]` G3_ID payload (per §6.1.3)** | `type = 0` (dcipher) + `id = bytes32 = authorizationId` per §6.1.3 G3_ID stanza format | `type = 1` (drand) + `id = uint64 (BE) = drand_round` per §6.1.3 G3_ID stanza format |
| **Combiner memory (reveal-time)** | σ_G3 transient — verified before §6.3 Shamir, then zeroized per §14.2 | σ_G3 transient — same discipline; the public availability on drand chain does NOT change the combiner-side handling discipline |

The drand path's public availability is a unique property of the drand operator design (publicly-replicated beacon for time-locked / public-good use cases). It does NOT compromise the σ-as-authorization property for the V3 custody architecture as a whole because file_key reconstruction requires admitted Shamir shares under the §6.3 access predicate. An attacker observing σ_G3 (drand) on the drand chain still lacks the G3 wrapped-share decap material, Lit and G4 admitted top-level shares, and any required recipient-branch shares.

### 8.7 Cross-vendor mandate (per A11 fix) — does NOT apply to G3

The A11 cross-vendor mandate from §7.7 (Lit V3 + G4 Phase 2 must use different TEE vendors) does NOT extend to G3:

- **dcipher** is a threshold-network operator (Randamu Threshold Association committee), NOT a TEE-attested signer. There is no DCAP attestation involved in σ_G3 (dcipher); the trust model is committee threshold + on-chain registry transparency.
- **drand** is a public-good beacon operator (League of Entropy), NOT a TEE-attested signer. There is no DCAP attestation involved in σ_G3 (drand); the trust model is multi-operator public replication + drand protocol's threshold-BLS aggregation.

The cross-vendor mandate is specifically about TEE attestation chain diversity (Lit V3 + G4 Phase 2 both produce DCAP quotes; A11 requires they use different hardware vendors so single-vendor PKI compromise doesn't break both). G3's trust model is orthogonal — committee transparency for dcipher, public replication for drand, neither dependent on hardware-vendor PKI.

### 8.8 Cross-reference index

This section consumes the following primitives and registries from earlier sections:

- **§1.1.3** asymmetric primitives — BLS12-381 enumerated as a V3 normative curve (used by both dcipher + drand paths).
- **§1.1.4** post-quantum primitives — drand uses minimum-pubkey-size BLS12-381 variant per BP-5 lock.
- **§3.2** authorizationId — first 32 bytes of σ_G3 (dcipher) signing input.
- **§3.3.4** `g3_choice` field per pda_root D1 expansion — frozen at commit; determines which path applies.
- **§3.4** h_commit — second 32 bytes of σ_G3 (dcipher) signing input.
- **§4.1** commit_AAD `g3_choice` field (Group 3) — bound at commit; consumed by combiner at reveal.
- **§6.1.3** stanza[1] G3_ID variant — carries `type` discriminator + `id` per dcipher (bytes32 authorizationId) or drand (uint64 round) format.
- **§6.3.2** share encoding and ordering — σ_G3 authorization admits the G3-indexed Shamir share to reconstruction.

Forward-references (consumed by later sections):

- **§11.3** G3 committee pubkey fetch protocol — registry-state-at-commit's-block resolution for both dcipher (Randamu Threshold Association) + drand (League of Entropy public chain).
- **§14.1** combiner pre-verify checklist — runs §8.5's branching verification protocol BEFORE §6.3 file_key reconstruction fires.
- **§14.2** share secrecy operational discipline — full hardened-context discipline for σ_G3 handling (with drand-path public-availability caveat per §8.6).
- **§15.6.3** gate authority key rotation — orthogonal ceremony framing; G3 committee key rotation does NOT break share-value invariance across re-key generations because σ values are generation-specific authorization evidence and recipients verify against committee/beacon state for the selected generation.
- **§16** error model: `ERR_SIGMA_G3_DCIPHER_INVALID` + `ERR_SIGMA_G3_DRAND_INVALID` + `ERR_SIGMA_G3_PATH_MISMATCH`.

Library SDK version pins are S2-3 territory.

### 8.9 PII content statement

σ_G3 is PII-NONE at the cryptographic-construct layer. The signing input bytes (dcipher path: `authorizationId ‖ h_commit ‖ block_hash`; drand path: `target_drand_round` uint64) are all keccak-256 / chain-state digests / round numbers — none contain plaintext subject data, plaintext partner data, or plaintext PDA configuration data.

The σ_G3 signature bytes themselves:

- **dcipher path:** Threshold-BLS aggregation signature; computationally indistinguishable from random under BLS12-381 signature randomization. Reveals nothing about the underlying signing input or any committee member's individual signing share.
- **drand path:** BLS12-381 G2 round signature (96 bytes compressed per minimum-pubkey-size variant) published publicly on the drand chain. Computationally indistinguishable from random under BLS12-381 signature randomization. The public availability is a feature of drand's operator design, NOT a PII surface (the round signature carries no subject-identifying data; it is a beacon for the round number itself).

No subject-identifying data appears at any layer of σ_G3's construction or verification path. The G3 operators (Randamu Threshold Association committee members for dcipher; League of Entropy operators for drand) are operator-side identities, NOT subject-side identities.

The σ transport discipline per §8.1 is NOT a PII protection mechanism. The drand path's public availability of σ_G3 is a unique caveat: file_key remains protected because σ_G3 alone releases at most the G3 share and Shamir reconstruction still requires the threshold shares authorized by Lit, G4, and any conditional recipients.

---

## §9 — Gate signature σ_G4

This section defines the byte-exact construction of `σ_G4`, the gate signature produced by the G4 Cealis verification component (Phase 1 sealed-code server / Phase 2 partner-ready DCAP TEE). σ_G4 binds Cealis's independent chain-state read + structured refusal-capable attestation to a specific commit's authorization context. The signature is authorization evidence verified before §6.3 file_key reconstruction under A1+Shamir. **Phase choice is per-PDA, frozen at commit via the `phase: uint8` field in `commit_AAD` (§4.1) + transitively via `pda_root` into `h_commit`; partner-facing legal-effect PDAs MUST use Phase 2 per WP §F PDA+ guardrail (configurator-rejected at commit time for Phase 1 + legal-effect type combinations).**

### 9.1 σ-as-authorization normative discipline (per WP §B P22 revisited)

σ_G4 is an authorization signature / attestation output AND authorization evidence, not DEK material or HKDF input. The combiner verifies σ_G4 against G4 authority state, endpoint attestation, refusal state, and `(authorizationId, h_commit_N, block_hash)`. A valid σ_G4 authorizes decap/admission of the G4 top-level Shamir share.

G4 refusal remains enforced by the access predicate: when G4 refuses codes `0x01`-`0x09`, no σ_G4-valid share is admitted. The combiner cannot satisfy the §6.3 top-level access predicate without the fixed G4 share, so no DEK is reconstructed. Phase 1 remains dev-scaffold-only; Phase 2 is partner-ready. The phase distinction changes attestation shape, not the σ-as-authorization doctrine.

### 9.2 Phase 1 — sealed-code server (`phase = 1`, DEV-SCAFFOLD ONLY)

For PDAs configured with `phase = 1` per §3.4.3 EndpointAttestation::Phase1 + §4.1 commit_AAD `phase: uint8 = 1`:

#### 9.2.1 What it is

A 64-byte Ed25519 signature produced by the **Cealis-operated G4 sealed-code server** (a reproducible-build Linux daemon running on commodity infrastructure: AWS, Hetzner, or equivalent VPS). The server's binary is registered on-chain via `G4AuthorityRegistry` with `(binary_hash, effective_block, tombstone_block)` tuples per WP §M (per Brief 07 §1).

**This Phase 1 server is a development scaffold only.** Per Stage-0 Q-0-2 LOCKED 2026-04-23 (internal stage-0 decisions log, not in this export):

> *"Partner-signing (funding-committed partner) runs on Phase 2 G4: rented TEE with DCAP attestation, σ_G4 binds to the attestation quote. Phase 1 (sealed-code server + on-chain binary-hash registry) is pre-funding dev scaffold only — not a partner-ready product tier."*

**PDA+ guardrail.** Per WP §F (`wp.md:495`):

> *"G4 phase guardrail. Legal-effect PDA types — KYC-lending, M&A, evidence, medical — cannot be committed under Phase 1 G4. The configurator rejects any such PDA whose `g4_phase` is set to Phase 1."*

The configurator MUST reject any commit attempting to combine `phase = 1` + `legal_effect_expected = true` (per §3.3.4 D1 + WP §F PDA+ guardrail). This is defense-in-depth against (a) dev-environment leakage of legal-effect commits and (b) emergency-fallback misuse of the Phase 1 scaffold for partner-facing operations.

#### 9.2.2 Cryptographic primitive

- **Curve / scheme:** Ed25519 (RFC 8032 EdDSA over Curve25519) per canonical §1.1.3 line 40.
- **Signature length:** exactly **64 bytes**.
- **Signing key:** Cealis-G4-Phase1 long-term Ed25519 private key, held server-side in the sealed-code daemon's protected memory; rotation tracked via `G4AuthorityRegistry` `(binary_hash, effective_block, tombstone_block)` tuples.
- **Library family:** `@noble/curves` Ed25519 module + Cealis G4 sealed-code daemon (S2-3 pins specific library version + daemon binary hash).

#### 9.2.3 Signing input

σ_G4 (Phase 1) signs over a TAG-prefixed byte concatenation per §1.3.1 byte-concat discipline + §2.10 TAG_G4_ATTESTATION_V3 prefix discipline:

```
σ_G4_input (Phase 1) = TAG_G4_ATTESTATION_V3
                     ‖ binary_hash
                     ‖ block_hash
                     ‖ authorizationId
                     ‖ h_commit
                     ‖ timestamp
```

| Field | Width | Source |
|---|---|---|
| `TAG_G4_ATTESTATION_V3` | 32 bytes | Per §2 — `keccak256("CEALIS_V3_G4_ATTESTATION_V3")` |
| `binary_hash` | 32 bytes | keccak-256 of the Cealis G4 sealed-code daemon binary; registered in `G4AuthorityRegistry` |
| `block_hash` | 32 bytes | Per §11 — Base L1 block hash of `RevealAuthorized` event; A17 anti-reorg-replay binding |
| `authorizationId` | 32 bytes | Per §3.2 — per-commit identifier |
| `h_commit` | 32 bytes | Per §3.4 — on-chain anchor hash for this commit's envelope |
| `timestamp` | 8 bytes (uint64 BE) | G4 attestation timestamp (UTC seconds since Unix epoch); operational freshness signal |

**Total signing-input length:** 32 + 32 + 32 + 32 + 32 + 8 = **168 bytes**.

**TAG-prefix per generalized D6 V3 TAG-prefix discipline.** Unlike σ_Lit (§7.3) and σ_G3 (§8.2.3) where BLS hash-to-curve provides RFC 9380 domain separation at the curve layer, Ed25519's signing path does NOT inherently carry a V3 domain separator — the signing is a deterministic computation over the input bytes per RFC 8032 with no per-protocol domain tag. The `TAG_G4_ATTESTATION_V3` keccak prefix at the signing-input layer provides V3 domain separation explicitly, matching the canonical §2 line 239 entry's normative spec for `TAG_G4_ATTESTATION_V3` use-site.

The `block_hash` binding (NOT just `block_number`) is the A17 anti-reorg-replay fix per `flows-spec-final.md:25, 199` + WP §D `wp.md:337`. Without `block_hash`, an Ed25519 signature produced for an authorization on a reorg-defeated block could in principle be replayed onto the new canonical chain's authorization for the same `authorizationId`. The `block_hash` binding defeats this by tying σ_G4 (Phase 1) to the exact block that emitted the `RevealAuthorized` event.

The `binary_hash` binding ties the signature to the specific Cealis G4 daemon binary that produced it; combined with `G4AuthorityRegistry` `(binary_hash, effective_block, tombstone_block)` tuples, this allows recipients to verify σ_G4 (Phase 1) against the registered binary at the commit's block — even after binary rotation, historical commits remain verifiable per the at-commit-block reading discipline (§9.5 + §11.4 + Brief 07 §2).

#### 9.2.4 G4 sealed-code daemon attestation

The sealed-code daemon's `binary_hash` is registered on-chain via `G4AuthorityRegistry` per WP §M (Brief 07 §1):

```
G4AuthorityRegistry: binary_hash → (effective_block, tombstone_block, deprecation_state)
```

At reveal, the combiner verifies:
1. The σ_G4 (Phase 1) signature is valid Ed25519 under the public key associated with `binary_hash` from `G4AuthorityRegistry`.
2. `binary_hash` is in `G4AuthorityRegistry` with `effective_block ≤ commit_block ≤ tombstone_block` (or `tombstone_block = 0` indicating non-tombstoned).
3. `binary_hash` is NOT flagged in the deprecation state at the commit's `RevealAuthorized` block per §9.4 deprecation discipline + §12 registry verification.

The "registry state at commit's block, not current state" pattern matches §4.6.2 g4_authority_ref backward-compat semantics + §11 endpoint attestation registry-snapshot discipline + §15.6.3 orthogonal-ceremony framing for gate authority key rotation. G4 Phase 1 binary rotation does NOT retroactively invalidate prior commits because recipients verify against the binary registered at the commit's block (per the tombstone tuple semantics).

#### 9.2.5 Use case mapping (Phase 1)

Phase 1 is the default G4 path for **dev-environment + pre-funding pilot commits ONLY**:
- **Dev-environment commits.** Pre-funding development testing; no partner involvement.
- **Pre-funding pilot commits.** Internal Cealis testing of full envelope flow before partner-signing engagement.

Phase 1 is FORBIDDEN for:
- **Legal-effect PDA types** per WP §F PDA+ guardrail: KYC-lending, M&A, evidence, medical, testament, financial-records-audit. Configurator-enforced rejection at commit time.
- **Partner-facing PDA commits** of any kind once a partner-signing relationship is established (funding-committed partner = Phase 2 only per Stage-0 Q-0-2 LOCKED).

### 9.3 Phase 2 — partner-ready DCAP TEE (`phase = 2`, NORMATIVE for partner-signing)

For PDAs configured with `phase = 2` per §3.4.3 EndpointAttestation::Phase2 + §4.1 commit_AAD `phase: uint8 = 2`:

#### 9.3.1 What it is

A DCAP attestation quote produced by a **rented TEE** (commodity TEE infrastructure: AWS Nitro Enclave / Intel TDX on rented bare-metal / future Phala TEE pool). The Cealis G4 Phase 2 verification component runs inside the rented TEE; Cealis operates the G4 role but does NOT own the silicon — the trust model is "commodity TEE rental + on-chain attestation registry," not "Cealis-staked custody hardware."

Phase 2 is the **NORMATIVE path for partner-signing** per Stage-0 Q-0-2 LOCKED. It carries the §286 ZPO free-evaluation admissibility default + the §371a Anscheinsbeweis admissibility path conditioned on QTSP integration per Brief 05 + WP §J legal posture.

#### 9.3.2 Cryptographic primitive

- **Format:** DCAP attestation quote per Intel Data Center Attestation Primitives spec (canonical §1.1.5 line 52); on-chain verification via Automata zkDCAP verifier circuit (or equivalent — S2-3 pins).
- **Length:** Variable per vendor (typically 4-8 KB; varies between Intel SGX vs AMD SEV-SNP vs AWS Nitro).
- **Signing key:** TEE attestation key (vendor-rooted: Intel SGX Quoting Enclave / AMD SEV-SNP Versioned Chip Endorsement Key / AWS Nitro Attestation Document signing key).
- **Library family:** Automata zkDCAP on-chain verifier + per-vendor TEE SDK (Intel SGX SDK / AMD SEV-SNP SDK / AWS Nitro NSM SDK). S2-3 pins specific verifier + SDK versions.

#### 9.3.3 DCAP `user_data` binding

The DCAP quote's `user_data` field MUST bind the per-commit context as a **keccak-compressed 32-byte digest** per canonical §1.1.5 line 143 (DCAP `user_data` field is exactly 64 bytes per Intel SGX limit, vendor-neutral DCAP spec constraint observed by all three vendors: Intel SGX, AMD SEV-SNP, AWS Nitro):

```
user_data_digest (Phase 2) = keccak256(
  TAG_G4_ATTESTATION_V3
  ‖ authorizationId
  ‖ h_commit
  ‖ block_hash
)[:32]
```

| Field (preimage) | Width | Source |
|---|---|---|
| `TAG_G4_ATTESTATION_V3` | 32 bytes | Per §2 line 239 — `keccak256("CEALIS_V3_G4_ATTESTATION_V3")` |
| `authorizationId` | 32 bytes | Per §3.2 — per-commit identifier |
| `h_commit` | 32 bytes | Per §3.4 — on-chain anchor hash |
| `block_hash` | 32 bytes | Per §11 — Base L1 block hash of `RevealAuthorized` event; A14 anti-replay binding |

**Preimage length (input to keccak-256):** 32 + 32 + 32 + 32 = **128 bytes**.
**Output `user_data_digest` length (placed in DCAP `user_data` field):** **32 bytes** (with the remaining 32 bytes of the 64-byte `user_data` field zero-padded per DCAP spec field-width).

**Why keccak-compression to 32 bytes is the default:** per canonical §1.1.5 line 143, the DCAP `user_data` field is exactly 64 bytes wide (Intel SGX limit, observed vendor-neutrally by AMD SEV-SNP + AWS Nitro per DCAP spec). Raw 128-byte concatenation does not fit the 64-byte field. The keccak-256 compression preserves (a) TAG_G4_ATTESTATION_V3 V3 domain separation per generalized D6 V3 TAG-prefix discipline, (b) A14 anti-replay binding via `block_hash` collision-resistance through keccak preimage, and (c) full preimage tuple recovery at verification time for combiner-side recompute. Compression is a pure structural fit to the DCAP wire-format constraint per Simon Decision D11; cryptographic security of the binding is preserved by keccak's preimage-resistance + collision-resistance properties.

The `endpoint_attestation_digest` field at §3.4.3 + §4.1 commit_AAD anchors the COMMIT-time DCAP attestation (TEE enclave measurement at commit) via SCALE-encoded `EndpointAttestation::Phase2 { dcap_quote_bytes }`; the PER-OP DCAP at reveal (this §9.3.3) is a separate quote anchored to `(authorizationId, h_commit, block_hash)` via the keccak-compressed `user_data_digest`. This dual-DCAP discipline mirrors §7.5 σ_Lit's commit-time + reveal-time pattern.

#### 9.3.4 A11 cross-vendor mandate (with G2 Lit V3)

If the Lit V3 serving TEE's vendor for a given op is Intel SGX, then the G4 Phase 2 attestation's TEE vendor MUST be either AMD SEV-SNP or AWS Nitro per the cross-vendor requirement spec'd at §7.7. This is the A11 fix for single-vendor PKI compromise: an attacker compromising (e.g.) Intel SGX's attestation root cannot break both gates simultaneously because the cross-vendor G4 TEE remains uncompromised.

The cross-vendor enforcement happens at:
1. **PDA configuration time** per WP §F PDA+ guardrail (configurator rejects PDAs whose Lit V3 + G4 Phase 2 vendor pair is single-vendor).
2. **Reveal time** by the combiner per §11 endpoint attestation cross-check (combiner re-validates the cross-vendor invariant at the op's actual TEE assignment vs the commit-time pinned vendor).

The Phase 1 path has NO cross-vendor mandate because Phase 1 is the Cealis-operated sealed-code server with NO TEE attestation — there is no second vendor to cross with.

#### 9.3.5 Use case mapping (Phase 2)

Phase 2 is the NORMATIVE path for **all partner-facing commits** per Stage-0 Q-0-2 LOCKED:
- **All legal-effect PDA types** per WP §F PDA+ guardrail: KYC-lending, M&A, evidence, medical, testament, financial-records-audit (Phase 2 MANDATORY for these).
- **All partner-facing PDA commits** once a funding-committed partner-signing relationship is established.

Phase 2 carries:
- **§286 ZPO free-evaluation admissibility default** for evidentiary commits per WP §J Layer L1 framing.
- **§371a Anscheinsbeweis path** conditioned on QTSP integration per Brief 05 §4 + the `qtsp_provider_ref` field in σ_subject (§5.3 platform-authenticator path under QTSP context).
- **eIDAS-AES-aligned attestation grade** per WP §N operational posture.

### 9.4 G4RefusalRegistry — 10-code reason enum

The G4 verification component is **refusal-capable**: at any point before σ_G4 emission, G4 can refuse to sign and instead emit a structured refusal signal to the on-chain `G4RefusalRegistry`. Refusal codes 0x01-0x09 are normative refusal reasons (each blocks σ_G4 emission, halting file_key reconstruction cryptographically per §9.1 strict-AND); code 0x0A is an **opt-out informational signal** (G4 PROCEEDS with signing despite an ostensibly-applicable deprecation event, but logs the opt-out fact for auditability).

Per canonical §2.10 line 154 + Brief 07 §5 normative spec:

#### 9.4.1 Per-commit refusal codes (semantic scope: this commit only)

| Code | Meaning | Origin |
|---|---|---|
| `0x01` | Legal compel | Court order; Cealis ops sign refusal |
| `0x02` | GDPR Art. 17 | Subject erasure mid-flight; shred propagation |
| `0x03` | GDPR Art. 18 | Subject restriction / processing-freeze |
| `0x04` | Integrity fail | Per-commit integrity failure in G4's own state |
| `0x05` | Chain mismatch | ConditionEngine state doesn't match G4's independent read |

#### 9.4.2 Class-wide deprecation-driven refusal codes (semantic scope: all commits referencing the deprecated entry)

| Code | Triggered by |
|---|---|
| `0x06` | Plugin deprecated — commit's plugin hash is flagged in `PluginHashRegistry` |
| `0x07` | Authority deprecated — commit's G4 authority key is flagged in `G4AuthorityRegistry` |
| `0x08` | DSL deprecated — commit's DSL version is flagged in `DSLVersionRegistry` |
| `0x09` | Oracle deprecated — an oracle pinned in the commit's condition is flagged in `OracleRegistry` |

Each class-wide refusal event carries `(entry_id, deprecation_block, disclosure_cid)` in the `proof` field per Brief 07 §5. Recipients distinguish class-wide deprecation from per-commit integrity failure (`0x04` reverts to per-commit semantics only).

#### 9.4.3 Opt-out informational signal (semantic scope: PDA's `cealis_class_wide_halt_opt_out = true`)

| Code | Triggered by |
|---|---|
| `0x0A` | Opt-out active — PDA has `cealis_class_wide_halt_opt_out = true`; G4 PROCEEDS with signing despite an ostensibly-applicable class-wide deprecation event (codes 0x06-0x09); the opt-out fact is logged on-chain via `G4RefusalRegistry` for auditability, but σ_G4 is still emitted and reveal proceeds |

Per WP §F PDA+ guardrail, `cealis_class_wide_halt_opt_out = true` is FORBIDDEN on legal-effect PDAs (configurator-rejected at commit time). 0x0A is therefore only emittable on non-legal-effect PDAs that have explicitly opted out of class-wide halt protection at PDA-config time.

#### 9.4.4 Encrypted-reason mode (codes 0x02, 0x03)

Per WP §F refusal-reason encryption guardrail (`wp.md:498`) + Brief 07 §5 spec discipline #5 + Brief 08 cross-reference: refusal codes **0x02 (GDPR Art. 17)** and **0x03 (GDPR Art. 18)** MUST emit refusal events in **encrypted-reason mode** by default — the on-chain `G4RefusalRegistry` stores `encrypted_reason_blob` rather than plaintext reason data; the on-chain event emits only `RefusalSignal(authorizationId, "refused")` without revealing whether the cause was Art. 17 (erasure-driven) vs Art. 18 (restriction-driven), since either could leak subject-side information that itself constitutes processing of personal data.

`encrypted_reason_blob` byte format:

```
encrypted_reason_blob = ECIES_envelope(
  recipient_pubkey = subject_recipient_x25519_pubkey_at_commit,
  plaintext = SCALE_encode(RefusalReason {
    code: uint8,                           // 0x02 or 0x03
    article_ref: U8_ARRAY,                 // "Art_17" or "Art_18"
    timestamp: uint64,                     // when refusal fired
    [optional metadata SCALE-encoded]
  })
)
```

**Recipient pubkey resolution.** The `subject_recipient_x25519_pubkey_at_commit` is the X25519 pubkey of the subject's CONDITIONAL_RECIPIENT_PASSKEY_ACCOUNT stanza (Mode 1 per §10.1 + §6.1 stanza variant 0x01) at the commit's `RevealAuthorized` block, resolved via the §13.5 PasskeyRotationLog walk-from-anchor protocol — exactly the same walk discipline used to resolve the recipient's current decryption pubkey for stanza unwrap. For PDAs whose conditional-recipient set does not include a Mode 1 PASSKEY_ACCOUNT subject-self entry (e.g., Mode 2 WALLET_EOA-only PDAs per §10.2), encrypted-reason mode is structurally infeasible at the cryptographic layer; for those PDAs, refusal codes 0x02/0x03 fall back to the plaintext-reason mode default with the explicit understanding that the PDA's conditional-recipient configuration accepts the subject-side information leakage trade-off (configurator surfaces this trade-off at commit time per WP §F PDA+ guardrail).

**At-commit-block resolution discipline.** The encrypted_reason_blob targets the X25519 pubkey resolved at the commit's `RevealAuthorized` block via PasskeyRotationLog walk-from-anchor — NOT the current rotation-log head. This matches the at-commit-block reading discipline per §11.4 + §13.5 + §15.6.3 orthogonal-ceremony framing. Subjects with active key rotation (PasskeyRotationLog walk per §13) MAY have rotated their passkey + X25519 pubkey post-commit; the encrypted_reason_blob still targets the key-resolved-at-commit's-block to preserve historical-commit verifiability across rotations.

The ECIES envelope wrap discipline matches age envelope X25519 recipient semantics per §6.1 + §6.2 hybrid PQ wrap pattern; the X25519 wrap layer is the inner wrap targeting the subject-resolved pubkey. The G4 verification component reads the PasskeyRotationLog state at the commit's `RevealAuthorized` block via on-chain query when constructing the encrypted_reason_blob.

Codes 0x01 (legal compel) + 0x04-0x09 (integrity / class-wide deprecation) are emitted in **plaintext-reason mode** by default — these codes do NOT carry subject-side personal data; they identify operational/jurisdictional/registry causes that benefit from public visibility for auditability + downstream verifier trust-basis assessment. PDAs MAY override via `refusal_reason_mode` configuration field if they require encryption for codes 0x01 / 0x04-0x09 (per WP §F flexible PDA+ guardrail), but the default is plaintext for those codes.

### 9.5 σ_G4 verification protocol — branching by phase

The combiner's §14.1 pre-verify checklist runs σ_G4 verification per the following branching protocol:

1. **Read `phase` from `commit_AAD`** per §4.1 (1-byte uint8: `1 = Phase 1`, `2 = Phase 2`).
2. **Branch on `phase`:**
   - `phase = 1` → Phase 1 verification (§9.5.1).
   - `phase = 2` → Phase 2 verification (§9.5.2).
3. **If verification fails on either path, abort** with the path-specific ERR per §16:
   - `ERR_SIGMA_G4_PHASE1_INVALID` (Phase 1 path)
   - `ERR_SIGMA_G4_PHASE2_DCAP_INVALID` (Phase 2 path — DCAP quote)
   - `ERR_SIGMA_G4_PHASE2_USER_DATA_MISMATCH` (Phase 2 path — `user_data` binding)
   - `ERR_SIGMA_G4_AUTHORITY_REGISTRY_MISMATCH` (binary_hash / TEE measurement not in G4AuthorityRegistry at commit's block)
   - `ERR_SIGMA_G4_PHASE_MISMATCH` (`phase` value not 1 or 2; commit_AAD corruption)
   - `ERR_SIGMA_G4_REFUSED` (G4 emitted refusal code 0x01-0x09 instead of σ_G4; combiner reads the code from `G4RefusalRegistry`)
4. **If verification succeeds, σ_G4 authorizes G4 share admission**: the corresponding G4 stanza may be decapsulated and its Shamir share admitted to §6.3 reconstruction. The Phase 1 signature or Phase 2 DCAP quote bytes remain authorization evidence, not Shamir input.

Verification fails fail-closed per §1.7 error model. No partial admission of σ_G4 — either it verifies fully under the phase-specific protocol, or it aborts.

#### 9.5.1 Phase 1 verification protocol

Per §9.2 + Brief 07 §1 endpoint attestation 4-check:

1. **Read `binary_hash` from `endpoint_attestation_digest`** per §3.4.3 EndpointAttestation::Phase1 SCALE decoding.
2. **Resolve G4 authority pubkey from `G4AuthorityRegistry`** at the commit's `RevealAuthorized` block (per the at-commit-block reading discipline, §11.4). Verify `binary_hash` is in the registry with `effective_block ≤ commit_block ≤ tombstone_block`.
3. **Recompute σ_G4 signing input** per §9.2.3 (`TAG_G4_ATTESTATION_V3 ‖ binary_hash ‖ block_hash ‖ authorizationId ‖ h_commit ‖ timestamp`).
4. **Verify Ed25519 signature** σ_G4 (Phase 1) under the resolved G4 authority pubkey over the recomputed signing input. If verification fails, abort with `ERR_SIGMA_G4_PHASE1_INVALID`.
5. **Check deprecation state at commit's block** per §9.4 + §12 registry verification. If `binary_hash` is flagged with deprecation code 0x07 + the PDA does NOT carry `cealis_class_wide_halt_opt_out = true`, the commit MUST have been refused per §9.4.2 — combiner reads `G4RefusalRegistry` and aborts with `ERR_SIGMA_G4_REFUSED`.

#### 9.5.2 Phase 2 verification protocol

Per §9.3 + Brief 07 §1 endpoint attestation 4-check + canonical §1.1.5 DCAP attestation discipline:

1. **Verify DCAP quote** against the appropriate hardware vendor's attestation root (Intel SGX root / AMD SEV-SNP root / AWS Nitro root depending on the assigned TEE's vendor per §11.2 endpoint attestation). Use the on-chain `zkDCAPVerifier` (Automata) per §11 + S2-3 library pin. If the DCAP verification fails, abort with `ERR_SIGMA_G4_PHASE2_DCAP_INVALID`.
2. **Verify DCAP `user_data` binding.** Recompute the keccak-compressed `user_data_digest = keccak256(TAG_G4_ATTESTATION_V3 ‖ authorizationId ‖ h_commit ‖ block_hash)[:32]` per §9.3.3; compare against the first 32 bytes of the DCAP quote's `user_data` field (the remaining 32 bytes of the 64-byte `user_data` field MUST be zero-padded per §9.3.3 + canonical §1.1.5 line 143). If mismatch, abort with `ERR_SIGMA_G4_PHASE2_USER_DATA_MISMATCH`. This is the A14 anti-replay enforcement.
3. **Verify TEE enclave measurement is in `G4AuthorityRegistry`** at the commit's `RevealAuthorized` block. If absent or tombstoned for the commit's block, abort with `ERR_SIGMA_G4_AUTHORITY_REGISTRY_MISMATCH`.
4. **Verify cross-vendor mandate (A11)** per §9.3.4: if Lit V3's serving TEE for this op is Intel SGX, the G4 Phase 2 TEE MUST be AMD SEV-SNP or AWS Nitro. If the cross-vendor invariant is violated at this op (vs the commit-time pinned vendor), abort with `ERR_SIGMA_G4_PHASE2_CROSS_VENDOR_VIOLATION` per §16 (G4-side code; complements §7's `ERR_LIT_TEE_ASSIGNMENT_MISMATCH` Lit-side code per the same A11 cross-vendor mandate at §11.2 + §7.7).
5. **Check deprecation state at commit's block** per §9.4 + §12. Same opt-out semantics as Phase 1 step 5.

### 9.6 Phase swap discipline (Phase 1 → Phase 2 cutover)

Per WP §N `wp.md:1090` + Brief 06 §3.3:

- **API-compatible drop-in.** The σ_G4 reveal-artifact field accepts both Phase 1 (64-byte Ed25519) and Phase 2 (variable DCAP quote) without changing the §6.3 Shamir input shape, because σ bytes authorize share release rather than becoming share material.
- **What changes at cutover:**
  - Attestation primitive (Ed25519 → DCAP).
  - Host environment (sealed-code daemon → rented TEE).
  - Legal-admissibility grade (operational only → eIDAS-AES-aligned per §9.3.5).
- **What does NOT change:**
  - 4-gate composition (§6.3 A1+Shamir).
  - Re-key ceremonies (§15).
  - Age envelope format (§6).
  - ConditionEngine API (§3.3.4 + outline).
  - Vault format (§3.5).
  - Chain contracts (§11 + §12).
  - Lit V3 + G3 rental integration (§7 + §8).
- **Phase 1 dev-scaffold commits stay valid post-cutover.** Per §9.5.1 + §15.6.3 orthogonal-ceremony framing for gate authority key rotation: `G4AuthorityRegistry` tombstone tuples preserve the verification path indefinitely. A Phase 1 commit made before the cutover remains verifiable under Phase 1 attestation after the cutover, because recipients verify against `G4AuthorityRegistry` state at the commit's block.

### 9.7 Storage discipline

σ_G4 follows the same σ-as-authorization transport discipline per §9.1 + §7.8 + §8.6 pattern:

| Location | Phase 1 path | Phase 2 path |
|---|---|---|
| **Vault (RevealArtifactBundle staging)** | Full σ_G4 bytes (64 bytes Ed25519 signature) + supporting metadata (binary_hash, timestamp) | Full DCAP quote bytes (variable per vendor, ~4-8 KB) + per-op TEE assignment record |
| **commit_AAD field** | NOTHING — σ_G4 is a reveal-time artifact (G4 attestation produced at reveal); commit-time only carries `endpoint_attestation_digest` per §3.4.3 EndpointAttestation::Phase1 (binary_hash digest) | NOTHING — same; commit-time `endpoint_attestation_digest` per EndpointAttestation::Phase2 (DCAP quote digest) |
| **On-chain (Base L1 / G1 ConditionEngine + G4RefusalRegistry)** | NOTHING for σ_G4 itself; `binary_hash` registered in `G4AuthorityRegistry`; `RefusalSignal` emitted to `G4RefusalRegistry` if G4 refuses (§9.4) | NOTHING for σ_G4 itself; TEE enclave measurement in `G4AuthorityRegistry`; `RefusalSignal` to `G4RefusalRegistry` if G4 refuses |
| **`endpoint_attestation_digest` (§3.4.3 in `commit_AAD` per §4.1)** | SCALE-encoded `EndpointAttestation::Phase1 { binary_hash_at_commit, effective_block }` digest | SCALE-encoded `EndpointAttestation::Phase2 { dcap_quote_bytes_at_commit }` digest |
| **Combiner memory (reveal-time)** | σ_G4 transient — verified before §6.3 Shamir, then zeroized per §14.2 one-shot-exposure discipline | Same discipline — DCAP quote consumed-then-zeroized |

The discipline matches the σ-as-authorization pattern at §7.8 (σ_Lit) + §8.6 (σ_G3) + §5.7 (σ_subject). σ_G4 is a per-reveal artifact; commit-time only carries the on-chain anchor (`endpoint_attestation_digest` for the COMMIT-time Phase 1 binary or Phase 2 DCAP quote) plus the on-chain `G4AuthorityRegistry` entry. Reveal-time produces the actual σ_G4, consumed-then-zeroized.

### 9.8 Cross-reference index

This section consumes the following primitives and registries from earlier sections:

- **§1.1.3** asymmetric primitives — Ed25519 enumerated as a V3 normative scheme; cross-ref to §9.1.
- **§1.1.5** DCAP attestation primitive — cross-ref to §9.3; `user_data` is 32-byte keccak-compressed digest per canonical §1.1.5 line 143 (64-byte DCAP field width with 32 bytes of zero-padding per Simon D11).
- **§1.3.1** byte-concat discipline — applied at §9.2.3 σ_G4 (Phase 1) signing input (TAG-prefix per §2.10 line 239 + generalized D6 V3 TAG-prefix discipline; differs from §7.3 + §8.2.3 BLS no-TAG-prefix because Ed25519 lacks RFC 9380 hash-to-curve domain separation).
- **§2 line 239** TAG_G4_ATTESTATION_V3 — domain separator applied at both Phase 1 signing input + Phase 2 DCAP user_data per §9.2.3 + §9.3.3.
- **§3.2** authorizationId — fourth 32 bytes of σ_G4 (Phase 1) signing input + second 32 bytes of Phase 2 user_data.
- **§3.3.4** `phase`, `cealis_class_wide_halt_opt_out`, `legal_effect_expected` fields per pda_root D1 expansion — frozen at commit; determine which path applies + opt-out semantics + PDA+ guardrail enforcement.
- **§3.4** h_commit — fifth 32 bytes of σ_G4 (Phase 1) signing input + third 32 bytes of Phase 2 user_data.
- **§3.4.3** endpoint_attestation_digest SCALE sum-type EndpointAttestation::Phase1 + Phase2 — anchors commit-time G4 attestation (binary_hash for Phase 1; DCAP quote for Phase 2).
- **§4.1** commit_AAD `phase: uint8` field — bound at commit; consumed by combiner to determine §9.5 verification branch.
- **§6.3** Shamir file_key reconstruction — consumes the G4-indexed Shamir share after σ_G4 verifies; signature/quote bytes are retained as authorization evidence.

Forward-references (consumed by later sections):

- **§7.7** σ_Lit cross-vendor mandate — A11 fix mirror; §9.3.4 carries the corresponding G4 Phase 2 side.
- **§11.2** Lit V3 per-op assignment record — paired with §9.3.4 cross-vendor enforcement.
- **§11.4** at-commit-block registry reading discipline — applies to G4 authority resolution at §9.5.1 + §9.5.2.
- **§12.2** G4AuthorityRegistry full verification protocol — §9.5 calls into this.
- **§12** G4RefusalRegistry — full registry spec; §9.4 enumerates the reason-code semantics.
- **§13.5** PasskeyRotationLog walk-from-anchor protocol — applied at §9.4.4 to resolve `subject_recipient_x25519_pubkey_at_commit` for encrypted-reason mode.
- **§14.1** combiner pre-verify checklist — runs §9.5's branching verification protocol BEFORE §6.3 file_key reconstruction fires.
- **§14.2** share secrecy operational discipline — full hardened-context discipline for σ_G4 handling.
- **§15.6.3** gate authority key rotation — orthogonal ceremony framing; G4 Phase 1 binary rotation + Phase 2 TEE measurement rotation do NOT break share-value invariance across re-key generations because σ values are generation-specific authorization evidence and recipients verify against G4AuthorityRegistry state for the selected generation.
- **§16** error model: `ERR_SIGMA_G4_PHASE1_INVALID` + `ERR_SIGMA_G4_PHASE2_DCAP_INVALID` + `ERR_SIGMA_G4_PHASE2_USER_DATA_MISMATCH` + `ERR_SIGMA_G4_AUTHORITY_REGISTRY_MISMATCH` + `ERR_SIGMA_G4_PHASE_MISMATCH` + `ERR_SIGMA_G4_REFUSED` + `ERR_SIGMA_G4_PHASE2_CROSS_VENDOR_VIOLATION`.

Library SDK version pins are S2-3 territory.

### 9.9 PII content statement

σ_G4 is PII-NONE at the cryptographic-construct layer. The signing input bytes (Phase 1: `TAG_G4_ATTESTATION_V3 ‖ binary_hash ‖ block_hash ‖ authorizationId ‖ h_commit ‖ timestamp`; Phase 2: `TAG_G4_ATTESTATION_V3 ‖ authorizationId ‖ h_commit ‖ block_hash`) are all keccak-256 / chain-state digests / operational metadata — none contain plaintext subject data, plaintext partner data, or plaintext PDA configuration data.

The σ_G4 signature/quote bytes themselves:

- **Phase 1 (Ed25519, 64 bytes):** Ed25519 signature; computationally indistinguishable from random under Ed25519 signature randomization (RFC 8032 deterministic signing produces signatures that are uniformly distributed under the signing key's randomization). Reveals nothing about the underlying signing input or the signing key beyond what Ed25519 verification surfaces.
- **Phase 2 (DCAP quote, ~4-8 KB):** DCAP quote bytes contain (a) the TEE enclave measurement (immutable hash of the Cealis G4 TEE enclave's compiled image; non-PII per DCAP attestation framing), (b) the `user_data` field carrying the 32-byte keccak-compressed `user_data_digest` per §9.3.3 + zero-padding to fill the 64-byte field per canonical §1.1.5 line 143 (non-PII per the commit-binding preimage being already-PII-free + keccak preimage-resistance), (c) the TEE attestation key signature over the quote (vendor-rooted: Intel / AMD / AWS attestation key, not subject-identity-bearing). No PII surface in the quote bytes.

The G4 authority pubkey (Phase 1: Ed25519 long-term key registered in `G4AuthorityRegistry`; Phase 2: TEE enclave measurement registered in same) is operator-side metadata (Cealis G4 verification component identity), NOT subject-side metadata.

The G4RefusalRegistry encrypted-reason mode for codes 0x02 + 0x03 (§9.4.4) is specifically designed to prevent subject-side PII leakage via refusal events — the on-chain `RefusalSignal` event emits only `(authorizationId, "refused")` without revealing whether the cause was Art. 17 or Art. 18, since either could leak subject-side processing-state information. The plaintext refusal reason is encrypted under `subject_recipient_x25519_pubkey_at_commit` (resolved via the §13.5 PasskeyRotationLog walk-from-anchor protocol at the commit's `RevealAuthorized` block per §9.4.4) via ECIES + age-X25519 wrap discipline; only the subject (or an authorized recipient with that key) can decrypt. PDAs without a Mode 1 PASSKEY_ACCOUNT subject-self entry fall back to plaintext-reason mode per §9.4.4 with the configurator surfacing the trade-off at commit time.

---

## §10 — σ_conditional per delivery mode

> **See S2-8 (controlled-use spec) §4 for the cross-vendor cosign-gate that the controlled-use profile adds for Stream 2 audit-event signing (PDA-selected from `{G2_lit, G3_dcipher, G3_drand}`).**

This section defines the byte-exact construction of `σ_conditional` per the three delivery modes spec'd architected for V3 custody. σ_conditional is the gate signature produced by a recipient (subject-self, heir, beneficiary, medical-proxy, or other role-tagged conditional-recipient) authenticating their own decryption authority at reveal. Unlike σ_Lit / σ_G3 / σ_G4 (gate operator signatures), σ_conditional binds **recipient-side authentication** to the per-commit reveal context — a recipient who cannot produce a valid σ_conditional is structurally excluded from file_key reconstruction per §6.3 A1+Shamir.

The σ_conditional vector is variable-length: it carries exactly `k` valid σ_conditional values (per `conditional_recipients_policy.k` k-of-n threshold). Each valid value authorizes decapsulation of its corresponding conditional-recipient stanza share. Each σ_conditional element is one of three modes per §6.1.5 conditional_recipient stanza variant: **Mode 1 PASSKEY_ACCOUNT** (variant `0x01`, P-256 WebAuthn assertion), **Mode 2 WALLET_EOA** (variant `0x02`, secp256k1 EIP-712 signature), or **Mode 3 WALLET_EIP1271** (variant `0x03`, RESERVED at V2 launch — configurator-rejected, spec'd architected for post-V2 enable).

### 10.1 σ-as-authorization normative discipline (per WP §B P22 revisited)

σ_conditional values are conditional-recipient authorization signatures / attestation outputs AND authorization evidence, not DEK material or HKDF input. A valid σ_conditional proves that the recipient mode's reveal challenge was satisfied and authorizes decap/admission of that recipient's nested recipient-branch Shamir share. Fixed gate shares are mandatory at the top level; conditional-recipient signatures satisfy only the recipient branch defined by §6.3.

σ_conditional bytes MAY be included in the recipient artifact after verification. Confidentiality requirements attach to the conditional-recipient Shamir share, decap material, DEK, and plaintext.

### 10.2 Mode 1 — PASSKEY_ACCOUNT (variant `0x01`)

For conditional-recipient stanzas with `variant = 0x01` per §6.1.5:

#### 10.2.1 What it is

A WebAuthn assertion produced by the recipient signing into their Cealis account via the current registered passkey (P-256 hardware authenticator: TPM, Secure Enclave, FIDO2 token, or equivalent platform authenticator). The recipient's account is identified by an opaque Cealis-issued `account_id` (cross-partner stable per §6.1.5 line 1400); the current passkey is resolved at reveal via the §13.5 PasskeyRotationLog walk-from-anchor protocol from the commit-time `rotation_log_anchor` per §6.1.5 line 1403.

#### 10.2.2 Cryptographic primitive

- **Curve / scheme:** P-256 (FIPS 186-5 / NIST P-256 / WebAuthn-native) per canonical §1.1.3 line 39.
- **Signature length:** minimum **64 bytes** (raw P-256 r ‖ s); typically delivered in CBOR-encoded WebAuthn assertion format 100-300 bytes per browser implementation. The on-chain spec verifies the signature value extracted from the assertion structure per WebAuthn Level 2 + CTAP2 specifications.
- **Signing key:** Recipient's current registered passkey, resolved via §13.5 PasskeyRotationLog walk-from-anchor at commit's `RevealAuthorized` block — NOT current rotation-log head. Anti-rotation-race framing per §11.4 + §13.5 + §15.6.3 orthogonal-ceremony discipline.
- **Library family:** `@simplewebauthn/server` for verification + browser-native WebAuthn API for signing (per `flows-spec-final.md:WebAuthn ceremony spec`). S2-3 pins specific library versions.

#### 10.2.3 Signing input — reveal_challenge_digest (Mode 1)

σ_conditional (Mode 1) signs the WebAuthn-wrapped reveal_challenge_digest per canonical §2 line 251 TAG_REVEAL_CHALLENGE_V3 use-site spec:

```
reveal_challenge_digest (Mode 1) = keccak256(
  TAG_REVEAL_CHALLENGE_V3
  ‖ authorizationId
  ‖ h_commit
  ‖ account_id           // mode-specific binding for variant 0x01
  ‖ role_tag
  ‖ stanza_index
  ‖ reveal_block_hash
)
```

| Field | Width | Source |
|---|---|---|
| `TAG_REVEAL_CHALLENGE_V3` | 32 bytes | Per §2 line 251 — `keccak256("CEALIS_V3_REVEAL_CHALLENGE_V3")` |
| `authorizationId` | 32 bytes | Per §3.2 — per-commit identifier |
| `h_commit` | 32 bytes | Per §3.4 — on-chain anchor hash |
| `account_id` | 32 bytes | Per §6.1.5 line 1400 — Cealis-issued opaque recipient identifier (cross-partner stable) |
| `role_tag` | 1 byte | Per §6.1.5 line 1404 — `enum (uint8)` per-stanza role (e.g., `0x07 SUBJECT_SELF` / `0x01 HEIR` / `0x02 BENEFICIARY` / `0x04 MEDICAL_PROXY`) |
| `stanza_index` | 4 bytes (uint32 BE) | Per §6.1.6 line 1459 — recipient's position in the conditional_recipients_policy ordered set; big-endian per §1.2 BE-keccak-preimage convention |
| `reveal_block_hash` | 32 bytes | Per §11 — Base L1 block hash of `RevealAuthorized` event; A14 anti-replay binding |

**Total preimage length:** 32 + 32 + 32 + 32 + 1 + 4 + 32 = **165 bytes**.
**Output `reveal_challenge_digest` length:** **32 bytes** (keccak-256 output).

The 32-byte digest is then signed via the WebAuthn ceremony — the browser/authenticator wraps the digest as the `clientDataJSON.challenge` field per WebAuthn Level 2, the authenticator produces a P-256 signature over the WebAuthn-internal signing payload (`authenticatorData ‖ SHA-256(clientDataJSON)`), and the resulting assertion is the σ_conditional bytes.

#### 10.2.4 Verification protocol

The combiner verifies σ_conditional (Mode 1) per the following protocol at §14.1 pre-verify:

1. **Read variant `0x01` from stanza** per §6.1.5 stanza format.
2. **Verify BOTH stanza MACs BEFORE parsing the stanza payload** per §6.1.6 line 1467 + §6.1.7 MAC-before-parse rule: (a) standard `TAG_STANZA_MAC_V3` MAC (combiner-bypass enforcement, identical mechanism to gate stanzas) — failure → `ERR_STANZA_MAC_VERIFY_FAIL` per §16; (b) cross-variant `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` MAC (cross-variant substitution defense, covering variant tag + full payload bytes per §6.1.6) — failure → `ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL` per §16 + §6.1.7 line 1482.
3. **Parse stanza payload** to extract `account_id` + `rotation_log_anchor` per §6.1.5 variant 0x01 fields.
4. **Resolve current_passkey_pubkey via §13.5 PasskeyRotationLog walk-from-anchor:** start from `rotation_log_anchor` at commit's `RevealAuthorized` block, walk forward to find the current head pubkey. Failure → `ERR_PASSKEY_ROTATION_WALK_FAIL` per §16. **Forensic-layering note:** `ERR_PASSKEY_ROTATION_WALK_FAIL` at this §10 layer is the wrap-around-error code matching the §14.5 wrap-around-vs-forensic pattern; for diagnostic granularity, the underlying §13.5 7-step walk protocol surfaces 5 distinct forensic codes (`ERR_ROTATION_ANCHOR_MISMATCH` + `ERR_ROTATION_WEBAUTHN_INVALID` + `ERR_ROTATION_ENTRY_INDEX_NONMONOTONIC` + `ERR_ROTATION_PASSKEY_CHAIN_BROKEN` + `ERR_ROTATION_MLKEM_CHAIN_BROKEN` per §13.7) which §10 verification surfaces via the wrap-around code while preserving the §13.7 forensic codes for auditor diagnostics.
5. **Recompute reveal_challenge_digest** per §10.2.3 using the parsed `account_id` + `role_tag` + `stanza_index` from stanza + `authorizationId` + `h_commit` + `reveal_block_hash` from on-chain.
6. **Verify WebAuthn assertion** under `current_passkey_pubkey` over the WebAuthn-wrapped digest per WebAuthn Level 2 verification protocol. The combiner library MUST verify (a) the assertion structure parses correctly per WebAuthn spec, (b) the `clientDataJSON.challenge` matches the reveal_challenge_digest, (c) the P-256 signature verifies under `current_passkey_pubkey`. Failure → `ERR_SIGMA_CONDITIONAL_PASSKEY_INVALID` per §16.
7. **If verification succeeds, σ_conditional (Mode 1) authorizes share admission** for the matching conditional-recipient stanza per `conditional_recipients_policy.k` count.

#### 10.2.5 Plaintext delivery

In-app Cealis dashboard. The recipient's plugin client (running inside the Cealis dashboard or equivalent in-process consumer) receives the AEAD-decrypted plaintext in-process per §14.1.3 in-process boundary discipline. NO wire-export of plaintext; per-recipient schema-selector filtering applies per §14.6 + §14.9.1 plaintext-PII boundary.

### 10.3 Mode 2 — WALLET_EOA (variant `0x02`)

For conditional-recipient stanzas with `variant = 0x02` per §6.1.5:

#### 10.3.1 What it is

An EIP-712 typed-data signature produced by the recipient signing with their Externally-Owned Account (EOA) wallet's secp256k1 private key. The recipient is identified by their 20-byte Ethereum wallet address (`wallet_address` per §6.1.5 line 1418); the EIP-712 signature recovered at verification MUST equal this commit-time-pinned address.

#### 10.3.2 Cryptographic primitive

- **Curve / scheme:** secp256k1 (Standards for Efficient Cryptography 2 SEC 2) per canonical §1.1.3 line 41.
- **EIP-712 domain:** `"CealisConditionalRecipient"` v `"1"` per Simon Decision D5 LOCKED (per canonical §1.1.5 line 50). `chainId = 8453` (Base Mainnet) or `84532` (Base Sepolia testnet); `verifyingContract = address(0)` per the §5.4.4 σ_subject EIP-712 domain pattern (off-chain signature with no on-chain verifier contract).
- **Signature length:** exactly **65 bytes** (`r ‖ s ‖ v`, where `r` and `s` are 32 bytes each and `v` is 1 byte recovery id).
- **EIP-2 low-s normalization:** combiners SHOULD canonicalize `s` to the low half of the secp256k1 group order before recovery per EIP-2 + canonical §1.1.3 line 41 spec.
- **Signing key:** Recipient's wallet private key (held in MetaMask, Ledger, Trezor, WalletConnect-compatible wallet, or equivalent secp256k1 EOA wallet).
- **Library family:** `viem` / `ethers.js` / `@noble/curves` for verification (S2-3 pins). Recipient-side wallet signing per the wallet provider's EIP-712 implementation.

#### 10.3.3 Signing input — reveal_challenge_digest (Mode 2)

σ_conditional (Mode 2) signs the EIP-712-wrapped reveal_challenge_digest per canonical §2 line 251 TAG_REVEAL_CHALLENGE_V3 use-site spec:

```
reveal_challenge_digest (Mode 2) = keccak256(
  TAG_REVEAL_CHALLENGE_V3
  ‖ authorizationId
  ‖ h_commit
  ‖ wallet_address       // mode-specific binding for variant 0x02 (20 bytes, NOT 32)
  ‖ role_tag
  ‖ stanza_index
  ‖ reveal_block_hash
)
```

| Field | Width | Source |
|---|---|---|
| `TAG_REVEAL_CHALLENGE_V3` | 32 bytes | Per §2 line 251 — `keccak256("CEALIS_V3_REVEAL_CHALLENGE_V3")` |
| `authorizationId` | 32 bytes | Per §3.2 — per-commit identifier |
| `h_commit` | 32 bytes | Per §3.4 — on-chain anchor hash |
| `wallet_address` | 20 bytes | Per §6.1.5 line 1418 — recipient's EOA address |
| `role_tag` | 1 byte | Per §6.1.5 line 1404 — `enum (uint8)` per-stanza role |
| `stanza_index` | 4 bytes (uint32 BE) | Per §6.1.6 line 1459 — recipient's position in the conditional_recipients_policy ordered set; big-endian per §1.2 BE-keccak-preimage convention |
| `reveal_block_hash` | 32 bytes | Per §11 — Base L1 block hash of `RevealAuthorized` event; A14 anti-replay binding |

**Total preimage length:** 32 + 32 + 32 + 20 + 1 + 4 + 32 = **153 bytes**.
**Output `reveal_challenge_digest` length:** **32 bytes** (keccak-256 output).

The 32-byte digest is then EIP-712-wrapped per the `"CealisConditionalRecipient"` v `"1"` domain (per §10.3.2). The recipient's wallet signs the EIP-712-wrapped digest, producing the 65-byte σ_conditional signature.

**Per-mode recipient-binding-field width difference (Mode 1 vs Mode 2):** Mode 1 uses 32-byte `account_id` (Cealis-issued opaque identifier); Mode 2 uses 20-byte `wallet_address` (Ethereum EOA). The 12-byte width difference between modes is per-stanza-known via the `variant` discriminator at §6.1.5 — combiners MUST use the correct width per the parsed stanza variant. A mode-selection error at the combiner produces a different reveal_challenge_digest preimage and the verification fails fail-closed. Note: `role_tag` (1 byte uint8) and `stanza_index` (4 bytes uint32 BE) are mode-INVARIANT — both modes consume identical widths for these two fields per canonical §6.1.5 line 1404 + §6.1.6 line 1459.

#### 10.3.4 Verification protocol

The combiner verifies σ_conditional (Mode 2) per the following protocol at §14.1 pre-verify:

1. **Read variant `0x02` from stanza** per §6.1.5 stanza format.
2. **Verify BOTH stanza MACs BEFORE parsing the stanza payload** per §6.1.6 line 1467 + §6.1.7 MAC-before-parse rule: (a) standard `TAG_STANZA_MAC_V3` MAC (combiner-bypass enforcement, identical mechanism to gate stanzas) — failure → `ERR_STANZA_MAC_VERIFY_FAIL` per §16; (b) cross-variant `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` MAC (cross-variant substitution defense, covering variant tag + full payload bytes per §6.1.6) — failure → `ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL` per §16 + §6.1.7 line 1482.
3. **Parse stanza payload** to extract `wallet_address` + `delivery_x25519_pubkey` + `delivery_url` per §6.1.5 variant 0x02 fields.
4. **Recompute reveal_challenge_digest** per §10.3.3 using the parsed `wallet_address` + `role_tag` + `stanza_index` from stanza + `authorizationId` + `h_commit` + `reveal_block_hash` from on-chain.
5. **EIP-712-wrap the digest** per the `"CealisConditionalRecipient"` v `"1"` domain (per §10.3.2).
6. **Recover EOA address** from `(EIP-712-wrapped digest, σ_conditional)` via `ECDSA.recover` (with low-s canonicalization per EIP-2). The recovered address MUST equal `wallet_address` from the stanza. Failure → `ERR_SIGMA_CONDITIONAL_WALLET_RECOVER_MISMATCH` per §16.
7. **If verification succeeds, σ_conditional (Mode 2) authorizes share admission** for the matching conditional-recipient stanza.

#### 10.3.5 Plaintext delivery

Per-recipient payload encrypted to `delivery_x25519_pubkey` (per §6.1.5 variant 0x02 stanza payload) via age X25519 recipient stanza, POSTed to `delivery_url` or pulled via IPFS per recipient's URL convention. The X25519 wrap layer matches the §6.1 + §6.2 hybrid PQ wrap pattern; recipient decrypts the X25519-wrapped payload locally with their X25519 private key.

### 10.4 Mode 3 — WALLET_EIP1271 (variant `0x03`, RESERVED at V2 launch)

For conditional-recipient stanzas with `variant = 0x03` per §6.1.5: **RESERVED. Configurator REJECTS Mode 3 selection at PDA-config time at V2 launch per Stage-0 Reconfirm B.**

#### 10.4.1 RESERVED status at V2 launch

Per canonical §2 line 251 TAG_REVEAL_CHALLENGE_V3 entry:
> *"Variant 0x03 (WALLET_EIP1271) consumes the same digest as input to `isValidSignature` per §10.3 — but variant 0x03 is RESERVED at V2 launch per Reconfirm B; the configurator rejects Mode 3 selection at PDA-config time. The TAG_REVEAL_CHALLENGE_V3 preimage form is spec'd architected for post-V2 enable; no V2 commits will produce a Mode 3 σ_conditional reveal-challenge digest."*

The Mode 3 byte format + verification protocol below are **architected for post-V2 enable** — they spec how Mode 3 will work when the configurator carve-out is removed, but they are NOT live spec at V2 launch. The configurator MUST reject any commit attempting to set `variant = 0x03` in any conditional_recipient stanza.

#### 10.4.2 Architecture for post-V2 enable

When enabled post-V2 (timeline + activation ceremony per S2-6):

##### 10.4.2.1 What it is

A signature produced by an on-chain smart contract implementing EIP-1271 (`isValidSignature`). The recipient is identified by the contract's address (`contract_address` per §6.1.5 variant 0x03); the contract may implement arbitrary signing logic (multisig, social recovery, time-lock, etc.) and returns a magic value to indicate signature validity.

##### 10.4.2.2 Cryptographic primitive

- **Scheme:** EIP-1271 contract signature wrapping an EIP-712 typed-data digest.
- **Signature length:** opaque bytes (contract-defined). **Minimum length: 1 byte** (empty σ explicitly rejected per Brief 06 §4.3 spec discipline — empty-sig permissive contracts that always return magic value would defeat the cryptographic enforcement).
- **EIP-1271 magic value:** `0x1626ba7e` (per EIP-1271 specification).

##### 10.4.2.3 Signing input — reveal_challenge_digest (Mode 3)

Same digest formula as Mode 2 (§10.3.3) with `wallet_address` replaced by `contract_address` (20 bytes EOA-style):

```
reveal_challenge_digest (Mode 3) = keccak256(
  TAG_REVEAL_CHALLENGE_V3
  ‖ authorizationId
  ‖ h_commit
  ‖ contract_address     // mode-specific binding for variant 0x03 (20 bytes)
  ‖ role_tag             // 1 byte uint8 per §6.1.5 line 1404
  ‖ stanza_index         // 4 bytes uint32 BE per §6.1.6 line 1459
  ‖ reveal_block_hash
)
```

**Total preimage length:** 32 + 32 + 32 + 20 + 1 + 4 + 32 = **153 bytes** (same as Mode 2 since `contract_address` and `wallet_address` are both 20-byte Ethereum addresses; mode-INVARIANT widths for `role_tag` + `stanza_index` per §6.1.5 + §6.1.6).

##### 10.4.2.4 Verification protocol (post-V2)

When Mode 3 is enabled post-V2, the combiner verifies σ_conditional (Mode 3) per:

1. **Read variant `0x03` from stanza** per §6.1.5 stanza format.
2. **Verify BOTH stanza MACs** per §6.1.6 line 1467 + §6.1.7 (same dual-MAC discipline as Mode 1/Mode 2): (a) `TAG_STANZA_MAC_V3` → `ERR_STANZA_MAC_VERIFY_FAIL`; (b) `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` → `ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL`.
3. **Parse stanza payload** to extract `contract_address` + `contract_bytecode_hash_at_commit` + `reject_on_bytecode_change: bool` + `delivery_x25519_pubkey` + `delivery_url` per §6.1.5 variant 0x03 fields.
4. **Bytecode integrity check.** Compute current `extcodehash(contract_address)`; compare to stanza's `contract_bytecode_hash_at_commit`:
   - If `reject_on_bytecode_change = true` AND hashes differ → reject σ_conditional with `ERR_SIGMA_CONDITIONAL_EIP1271_BYTECODE_CHANGED` per §16.
   - If `reject_on_bytecode_change = false` AND hashes differ → emit `STALE_BYTECODE` warning, continue.
5. **Recompute reveal_challenge_digest** per Mode 3 formula above.
6. **EIP-712-wrap the digest** per the `"CealisConditionalRecipient"` v `"1"` domain.
7. **Issue `eth_call`** to `contract_address.isValidSignature(EIP-712-wrapped digest, σ_conditional)` per EIP-1271; expect magic value `0x1626ba7e`. Failure → `ERR_SIGMA_CONDITIONAL_EIP1271_INVALID` per §16.
8. **If verification succeeds, σ_conditional (Mode 3) authorizes share admission** for the matching conditional-recipient stanza.

#### 10.4.3 Configurator rejection at V2 launch — defense-in-depth chain

The Cealis configurator MUST reject any PDA configuration containing a conditional_recipient stanza with `variant = 0x03` at V2 launch. The rejection error is `ERR_PDA_CONFIG_MODE_3_RESERVED` per §16 (configurator-side; not a combiner-side error).

**Defense-in-depth chain.** Three independent enforcement layers ensure no V2 reveal can consume a Mode 3 σ_conditional:

1. **PDA-config time (configurator-side):** configurator rejects `variant = 0x03` selection at PDA creation per §10.4.3 with `ERR_PDA_CONFIG_MODE_3_RESERVED`.
2. **Envelope-load time (subject-side verifier):** per canonical §6.1.5 line 1445, the subject-side verifier (§6.5) additionally rejects variant `0x03` stanzas at σ_subject signing time, defending against a compromised configurator that somehow emits a Mode 3 stanza despite configurator rejection.
3. **Reveal time (combiner-side):** per §10.5 step 3 + canonical §6.1.5 line 1445, the combiner aborts decryption with `ERR_MODE_3_NOT_SHIPPED_AT_V2` when a variant `0x03` stanza is encountered in an envelope under V2.

This carve-out is per Stage-0 Reconfirm B — Mode 3 spec is architected for forward-compat, but no V2 commits will produce Mode 3 σ_conditional values. Recipients deploying EIP-1271 wallet contracts (Safe multisig, etc.) MUST use Mode 2 with their own EOA at V2 launch; Mode 3 enables once the configurator carve-out is removed in a future protocol version.

### 10.5 σ_conditional verification protocol — unified surface

The combiner's §14.1 pre-verify checklist runs σ_conditional verification per the following branching protocol for each element of the σ_conditional Vec:

1. **Read variant from stanza** per §6.1.5 (1-byte enum: `0x01 = PASSKEY_ACCOUNT`, `0x02 = WALLET_EOA`, `0x03 = WALLET_EIP1271 RESERVED`).
2. **Verify BOTH stanza MACs BEFORE branching** per §6.1.6 line 1467 + §6.1.7 MAC-before-parse rule (mode-agnostic, applies to all variants): (a) standard `TAG_STANZA_MAC_V3` MAC → `ERR_STANZA_MAC_VERIFY_FAIL` per §16; (b) cross-variant `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` MAC → `ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL` per §16. Per-mode steps below (§10.2.4/§10.3.4/§10.4.2 step 2) inherit dual-MAC discipline from this unified surface.
3. **Branch on variant:**
   - `0x01` → Mode 1 verification per §10.2.4
   - `0x02` → Mode 2 verification per §10.3.4
   - `0x03` → Mode 3 verification per §10.4.2 (post-V2 only); at V2 launch, this branch is unreachable per configurator rejection at §10.4.3 — combiner aborts with `ERR_MODE_3_NOT_SHIPPED_AT_V2` per §16 if encountered (defense-in-depth: combiner enforces the configurator's rejection at reveal in case of configurator bypass)
4. **k-of-n threshold check.** Per `conditional_recipients_policy.k` count from `commit_AAD` (§4) — exactly `k` valid σ_conditional values MUST be present in the σ_conditional Vec. If fewer than `k` valid → `ERR_SIGMA_CONDITIONAL_THRESHOLD_INSUFFICIENT` per §16. If more than `k` → combiner uses the first `k` valid in the conditional_recipients_policy ordered set per §6.1 stanza ordering discipline.
5. **If all k σ_conditional values verify, the matching conditional-recipient shares are admitted** to §6.3 reconstruction in policy order.

Verification fails fail-closed per §1.7 error model. No partial admission of σ_conditional — either all k values verify under their respective per-mode protocols, or it aborts.

### 10.6 Per-mode k-of-n threshold semantics

Per §4.1 `commit_AAD.conditional_recipients_policy_digest` + §6.1 conditional_recipients_policy stanza ordering discipline:

The σ_conditional Vec MUST contain exactly `k` valid signatures per `conditional_recipients_policy.k`. The `k` is committed at PDA-config time + frozen via `commit_AAD.conditional_recipients_policy_digest` per §4 + transitively via `h_commit` per §3.4. Recipients in the n-set may be:

- **All same mode:** all Mode 1 (PASSKEY_ACCOUNT subject + heirs all on Cealis accounts) or all Mode 2 (WALLET_EOA subject + heirs all on EOA wallets).
- **Mixed modes:** some Mode 1 + some Mode 2 in the same n-set per partner-defined PDA configuration. Each recipient's σ_conditional verifies under their respective per-mode protocol; the combiner's branching at §10.5 step 3 handles per-stanza variant correctly.
- **Mode 3 RESERVED:** at V2 launch, n-set MUST NOT include any Mode 3 stanzas per §10.4.3 configurator rejection.

The k-of-n threshold is **distinct from** the gate-signature tuple (σ_Lit + σ_G3 + σ_G4) at §6.3 A1+Shamir — gate signatures are mandatory-AND (all required, no flexion). There are two distinct architectural classes:

- **`FIXED_ONLY` profile (§6.3):** the PDA has no conditional-recipient branch. The access predicate is top-level `3-of-3` over Lit, G3, and G4 only. There are no conditional-recipient stanzas, no σ_conditional collection, and no `k ≥ 1` requirement because there is no recipient branch at all. §10's σ_conditional machinery does not fire for `FIXED_ONLY` commits.
- **`RECIPIENT_1_OF_1` and `RECIPIENT_K_OF_N` profiles (§6.3):** the PDA has a conditional-recipient branch. σ_conditional is k-of-n threshold (k mandatory, partner-configured per PDA per `k` value, with `1 ≤ k ≤ n` enforced by the configurator at PDA-config time). Both gate σ values AND the recipient-branch threshold are required for file_key reconstruction.

A PDA with no conditional_recipients is a `FIXED_ONLY` PDA — a structurally distinct architectural class, not a degenerate recipient-branch PDA. It is not routed through §10's conditional-recipient verification at all.

### 10.7 Storage discipline

σ_conditional follows the same σ-as-authorization transport discipline per §10.1 + §7.8 + §8.6 + §9.7 pattern:

| Location | Mode 1 PASSKEY_ACCOUNT | Mode 2 WALLET_EOA | Mode 3 WALLET_EIP1271 (post-V2) |
|---|---|---|---|
| **Vault (RevealArtifactBundle staging)** | Full WebAuthn assertion bytes (typically 100-300 bytes CBOR-encoded) | Full EIP-712 signature (65 bytes) | Full EIP-1271 contract signature (variable, ≥1 byte) |
| **commit_AAD field** | NOTHING — σ_conditional is a reveal-time artifact (recipient signs at reveal) | NOTHING — same | NOTHING — same |
| **On-chain (Base L1 / G1 ConditionEngine)** | NOTHING — σ_conditional bytes are not published on-chain | NOTHING — same | NOTHING — same (Mode 3 EIP-1271 contract is on-chain, but the σ_conditional bytes from `eth_call` are NOT published — they are returned to the combiner via JSON-RPC) |
| **conditional_recipient stanza payload (§6.1.5)** | `account_id` (32 bytes) + `rotation_log_anchor` (32 bytes) + delivery hints — recipient identity bound here | `wallet_address` (20 bytes) + `delivery_x25519_pubkey` (32 bytes) + `delivery_url` — recipient identity bound here | `contract_address` (20 bytes) + `contract_bytecode_hash_at_commit` (32 bytes) + `reject_on_bytecode_change` (1 byte bool) + delivery hints |
| **Combiner memory (reveal-time)** | σ_conditional (Mode 1) transient — verified before §6.3 Shamir, then zeroized per §14.2 | Same discipline — σ_conditional (Mode 2) consumed-then-zeroized | Same discipline (post-V2) |

The discipline matches the σ-as-authorization pattern at §7.8 + §8.6 + §9.7. σ_conditional values are per-reveal artifacts; commit-time only carries the on-chain anchor (`commit_AAD.conditional_recipients_policy_digest` for the FULL conditional_recipients_policy at commit time per §4) plus the per-stanza payload (recipient identity bindings, delivery hints). Reveal-time produces the actual σ_conditional values via per-mode signing ceremonies, consumed-then-zeroized at the combiner.

### 10.8 Cross-vendor mandate (per A11 fix) — does NOT apply to σ_conditional

The A11 cross-vendor mandate from §7.7 (Lit V3 + G4 Phase 2 must use different TEE vendors) does NOT extend to σ_conditional:

- **Mode 1 PASSKEY_ACCOUNT** uses recipient-side hardware authenticators (TPM, Secure Enclave, FIDO2 token). The recipient's hardware authenticator is NOT a Cealis-vendor-selectable TEE; it's the recipient's own hardware. Cross-vendor mandate is not applicable because Cealis does not select the recipient's authenticator vendor.
- **Mode 2 WALLET_EOA** uses recipient-side wallet software (MetaMask, Ledger, Trezor, etc.). Same reasoning — recipient picks wallet, not Cealis.
- **Mode 3 WALLET_EIP1271** (post-V2) uses recipient-deployed contracts. Same reasoning — recipient deploys contract, not Cealis.

The cross-vendor mandate is specifically about Cealis-controllable TEE attestation chain diversity (Lit V3 + G4 Phase 2 both produce DCAP quotes; A11 requires different hardware vendors). σ_conditional's trust model is recipient-controlled (recipient picks their own authenticator/wallet/contract); cross-vendor diversity is therefore implicit in the multi-recipient k-of-n composition — different recipients use different authenticators/wallets, providing organic vendor diversity.

### 10.9 Cross-reference index

This section consumes the following primitives and registries from earlier sections:

- **§1.1.3** asymmetric primitives — P-256 (WebAuthn passkey σ_conditional Mode 1 §10.2) + secp256k1 (EIP-712 wallet σ_conditional Mode 2 §10.3).
- **§1.1.5** EIP-712 + EIP-1271 + WebAuthn — cross-ref to §10.2 / §10.3 / §10.4; EIP-712 domain `"CealisConditionalRecipient"` v `"1"` per Simon Decision D5 LOCKED.
- **§1.3.1** byte-concat discipline — applied at §10.2.3 + §10.3.3 + §10.4.2 reveal_challenge_digest preimages (TAG-prefix per §2 line 251 + generalized D6 V3 TAG-prefix discipline).
- **§2 line 251** TAG_REVEAL_CHALLENGE_V3 — domain separator applied at all three modes' reveal_challenge_digest per §10.2.3 / §10.3.3 / §10.4.2.
- **§2 line 256** TAG_ROTATION_LOG_ANCHOR_V3 — domain separator applied at §6.1.5 variant 0x01 `rotation_log_anchor` derivation; consumed at §10.2.4 verification step 4 walk-from-anchor.
- **§3.2** authorizationId — second 32 bytes of all three reveal_challenge_digest preimages.
- **§3.4** h_commit — third 32 bytes of all three reveal_challenge_digest preimages.
- **§4.1** commit_AAD `conditional_recipients_policy_digest` field — anchors the FULL policy (n, k, ordered recipient stanza set, delivery modes, bindings, delivery hints) at commit time.
- **§5.4.4** σ_subject EIP-712 domain `"CealisSubjectAssent"` — distinct from `"CealisConditionalRecipient"` per §10.3.2; separate signing surface, separate domain, both per Simon D5.
- **§6.1.5** stanza variants `0x01` PASSKEY_ACCOUNT / `0x02` WALLET_EOA / `0x03` WALLET_EIP1271 RESERVED — recipient identity binding fields per variant.
- **§6.1.7** MAC-before-parse rule — applied at §10.2.4 step 2 + §10.3.4 step 2 + §10.4.2 step 2 BEFORE per-mode signing-input parsing.
- **§6.3** Shamir file_key reconstruction — consumes the conditional-recipient Shamir shares after their matching σ_conditional values verify.

Forward-references (consumed by later sections):

- **§11** endpoint attestation — §10.x verification protocols invoke §11 endpoint_attestation_digest checks indirectly via the per-stanza recipient endpoint attestation discipline.
- **§13.5** PasskeyRotationLog walk-from-anchor protocol — applied at §10.2.4 step 4 to resolve `current_passkey_pubkey` from commit-time `rotation_log_anchor`. Mode-1-only.
- **§14.1** combiner pre-verify checklist — runs §10.5 unified σ_conditional verification protocol BEFORE §6.3 file_key reconstruction fires.
- **§14.2** share secrecy operational discipline — full hardened-context discipline for σ_conditional handling.
- **§15.6.3** gate authority key rotation — orthogonal ceremony framing; recipient passkey rotation per §13.5 walk-from-anchor does NOT break share-value invariance across re-key generations because §13.5 resolves the current head pubkey for authorization evidence and re-key preserves the indexed Shamir shares.
- **§16** error model: `ERR_SIGMA_CONDITIONAL_PASSKEY_INVALID` + `ERR_SIGMA_CONDITIONAL_WALLET_RECOVER_MISMATCH` + `ERR_SIGMA_CONDITIONAL_EIP1271_INVALID` + `ERR_SIGMA_CONDITIONAL_EIP1271_BYTECODE_CHANGED` + `ERR_MODE_3_NOT_SHIPPED_AT_V2` + `ERR_SIGMA_CONDITIONAL_THRESHOLD_INSUFFICIENT` + `ERR_PASSKEY_ROTATION_WALK_FAIL` (wrap-around code at §10 layer; surfaces §13.7's 5 forensic codes for diagnostics per §10.2.4 step 4 forensic-layering note) + `ERR_PDA_CONFIG_MODE_3_RESERVED` (configurator-side, not combiner-side) + `ERR_STANZA_MAC_VERIFY_FAIL` + `ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL` (shared with §6.1.7). **§16 ERR consolidation index:** internal S2-1 error-codes index (worker-3 maintained; consumed at §16 drafting time for full ERR enumeration consistency check + 43-code baseline cross-check).

  **Architectural-truth-template multi-layer-defense INSTANCE callout (per §14.7.4 carry-forward):** §10's Mode 3 RESERVED enforcement chain at §10.4.3 + §10.5 step 3 demonstrates the §14.7.4 architectural-truth-template multi-layer-defense pattern at the σ_conditional Mode 3 substrate variant: three independent enforcement layers (configurator + envelope-load-time subject-side verifier + reveal-time combiner) all enforce the same architectural truth ("no V2 reveal consumes Mode 3 σ_conditional") under different substrate variants (PDA-config substrate + envelope-stanza substrate + combiner-pre-verify substrate). §16 SHOULD callout this as architectural-truth-template multi-layer-defense INSTANCE alongside §14.7.4 + §13.6 Cealis-as-infrastructure-not-authority pattern.

Library SDK version pins are S2-3 territory.

### 10.10 PII content statement

σ_conditional is PII-NONE at the cryptographic-construct layer. The signing input bytes (per-mode reveal_challenge_digest preimages at §10.2.3 + §10.3.3 + §10.4.2) are all keccak-256 / chain-state digests / stanza-bound recipient identifiers. None contain plaintext subject data, plaintext partner data, or plaintext PDA configuration data.

The σ_conditional signature bytes themselves:

- **Mode 1 PASSKEY_ACCOUNT (P-256 WebAuthn assertion):** ECDSA P-256 signature wrapped in WebAuthn assertion structure. The signature bytes are computationally indistinguishable from random under ECDSA P-256 randomization. The WebAuthn assertion structure includes (a) `authenticatorData` (counter + flags + RP ID hash — non-PII per WebAuthn framing), (b) `clientDataJSON` (challenge + origin + type — challenge is the reveal_challenge_digest, origin is Cealis app domain, type is "webauthn.get" — all non-PII), (c) `signature` (raw P-256 r ‖ s — non-PII). The recipient's `account_id` bound at stanza-config time (§6.1.5 line 1400) is a Cealis-issued opaque identifier — it identifies the recipient ACROSS Cealis (cross-partner stable) but does NOT contain external personal data; per §3.6 ¶3 + §4.9 ¶2 reusable PII-NONE template, `account_id` is keccak-protected per the Cealis-issuance discipline.

- **Mode 2 WALLET_EOA (secp256k1 EIP-712 signature):** ECDSA secp256k1 signature exactly 65 bytes. Computationally indistinguishable from random under ECDSA secp256k1 randomization. The `wallet_address` bound at stanza-config time (§6.1.5 line 1418) is a 20-byte Ethereum EOA address — per §3.6 ¶3 + §4.9 ¶2 framework, `wallet_address` is a pseudo-identifier under EU GDPR Art. 4(1) for natural persons in some configurations (e.g., subject's own EOA under Mode B subject-self-sovereign onboarding per §3.1.2). However, the `wallet_address` appears in the keccak-protected reveal_challenge_digest preimage (§10.3.3) and the on-chain conditional_recipient stanza (§6.1.5) — NOT directly in any §6.4 AEAD-decrypted plaintext. The keccak abstraction (preimage-resistance assumption) means the digest reveals nothing about `wallet_address` without brute-force search; the per-onboarding nonces (per §3.1) defeat brute-force per the V1 PRO-222 mitigation. The §10.10 PII-NONE claim therefore holds at the cryptographic-construct layer; pseudo-identifier protection inherits transitively from §3.6.

  **Strict GDPR interpretation (Breyer C-582/14 + Recital 26 carry-forward from §13.10.1):** Mode 2 wallet_address may be cross-partner-stable (the same recipient appears under the same wallet_address across multiple PDAs they are conditional-recipient on), creating a third-party-observer-vs-Cealis-controller-scope distinction analogous to the §13.10.1 Mode 1 account_id framework. Per CJEU Breyer C-582/14 (joined cases) + GDPR Recital 26 strict interpretation: a third-party observer with access to public Ethereum ledger state could in principle correlate `wallet_address` across PDAs to construct a recipient-activity profile without invoking Cealis-controller cooperation. However, this is an EXTERNAL-observer reachability surface (Ethereum ledger is public infrastructure, not Cealis-controlled) — the Cealis-controller scope at §10.10 is bounded to (a) the keccak-protected `reveal_challenge_digest` preimage layer + (b) the on-chain stanza payload's wallet_address binding. Within Cealis-controller scope, `wallet_address` is keccak-protected per §3.6 ¶3 + §4.9 ¶2 + the configurator surfaces the cross-partner-linkability trade-off at PDA-config time per WP §F PDA+ guardrail (recipient awareness of EOA-pseudonymity-vs-pseudo-identifier trade-off is a recipient-side onboarding decision, not a Cealis-controller-imposed PII surface). The Mode 1 account_id substrate (Cealis-issued opaque identifier per §6.1.5 line 1400) provides a privacy-stronger alternative for recipients who prefer non-Ethereum-correlatable identifiers — Mode 2 is the EOA-wallet-ergonomic option with this explicit trade-off per the configurator-surfaced framing.

- **Mode 3 WALLET_EIP1271 (opaque contract signature, post-V2):** opaque bytes per contract-defined signing logic. The bytes themselves carry no inherent PII (computationally indistinguishable from random per the underlying cryptographic primitive used by the contract); the `contract_address` is an Ethereum address with the same pseudo-identifier semantics as `wallet_address` per §3.6 ¶3 + §4.9 ¶2.

The recipient's authenticator pubkey (Mode 1: P-256 WebAuthn pubkey; Mode 2: secp256k1 EOA pubkey recovered from signature; Mode 3: contract address) is recipient-side metadata, NOT subject-of-the-PDA-side metadata. (The subject of the PDA may also be a conditional-recipient under SUBJECT_SELF role_tag, in which case the recipient identity = subject identity — but this is a configuration choice at PDA-config time, not a structural PII property of σ_conditional.)

σ_conditional transport discipline per §10.1 protects the conditional-recipient share handoff; it is NOT a PII protection mechanism. The two protection layers are orthogonal: PII is protected by AEAD payload encryption per §6.4, and share secrecy is protected by stanza wrapping plus in-memory combiner discipline. Plus the reveal_challenge_digest preimage's pseudo-identifier inputs (Mode 2 + Mode 3 `wallet_address` / `contract_address`) are keccak-protected at the digest layer per §3.6 ¶3 + §4.9 ¶2 framework.

### §10.11 Mode T (Token) — controlled-use access tokens (commit_version = 0x0303)

Mode T is the σ_conditional delivery mode for the controlled-use configuration profile per S2-8 §2 token model + §4 write-validation gate + §1.9 cosign-gate enum. Mode T composes with PresentedTokenCondition (the 10th ConditionEngine module per S2-8 §6 + S2-2 §4.11.5) and the holder-binding form selected at credential issuance (passkey-bound default; hardware-bound, app-session-issued, or EOA-bound also architecturally first-class per S2-8 §2.3).

The §10.4-occupied slot for Mode 3 WALLET_EIP1271 (RESERVED) is preserved; Mode T takes §10.11 to avoid renumbering existing canonical anchors §10.4-§10.10. Mode T is RESERVED at this spec's first authoring; the byte-exact construction is locked at S2-8 §4 and §6 architecturally but the byte-exact form belongs in a coordinated S2-1 §10.11 + S2-2 §4.11.5 amendment after first pilot validation (App. C BP-CU-1). This sub-section names the construction slot, the input fields, and the cosign-gate co-signing discipline; the canonical byte ordering is pending.

**Construction slot (sketch, not normative byte form):**

```
σ_conditional (Mode T) preimage:
  TAG_CU_AUDIT_STREAM2_V3 ‖
  authorizationId ‖
  h_envelope ‖              # the per-slice envelope ref this presentation reads/writes
  credential_digest ‖       # holder credential digest (32 bytes; see §2.3.5 TAG_CU_CREDENTIAL_V3)
  sub_token_digest ‖        # sub-token derivation digest (32 bytes; see §2.3.5 TAG_CU_SUB_TOKEN_V3)
  op_kind (u8) ‖            # READ / WRITE / COMPOSED_READ / COMPOSED_WRITE
  slice_id ‖                # the slice being accessed
  reveal_block_hash         # binds presentation to a specific chain state
```

**Cosign-gate discipline (S2-8 §1.9):** Mode T σ_conditional is signed by the holder's bound key (P-256 passkey via WebAuthn for passkey-bound; secp256k1 EIP-712 for EOA-bound; etc.) AND co-signed by the PDA-selected cosign-gate from `{G2_LIT, G3_DCIPHER, G3_DRAND}` per `audit_policy.stream2_cosign_gate` (S2-8 §3 PDA field). The cosign covers the same preimage; absence of cosign at presentation time triggers `CU_ERR_STREAM2_COSIGN_MISSING` per S2-8 §15 error model.

**Vendor-family consistency rule:** the PDA's `stream2_cosign_gate` choice MUST match the PDA's `g3_choice` field family when `G3_*` is selected (a PDA selecting `g3_choice = G3_dcipher` for the read path cannot select `stream2_cosign_gate = G3_DRAND` for audit cosign). Cross-vendor disjoint analysis composes coherently across read-path σ_G3 and audit-cosign σ at presentation time.

Mode T does NOT introduce a new keccak-preimage TAG beyond the existing `TAG_REVEAL_CHALLENGE_V3` and the new `TAG_CU_AUDIT_STREAM2_V3`; the construction reuses the existing reveal-challenge domain separation pattern with the controlled-use-specific binding fields.

---

## §11 — Endpoint attestation verification protocol

This section defines the endpoint attestation 4-check verification protocol that runs at BOTH commit time (subject-side, before plaintext transits to the G4 ingestion endpoint) AND at reveal time (combiner-side, before σ_G4 + σ_Lit can authorize share decapsulation). The 4-check sequence is the load-bearing defense against (a) adversary-chosen-TEE substitution attacks (A06), (b) per-op DCAP quote replay across commits (A14), (c) G3 committee staleness during rotation, and (d) G4 authority registry race conditions (A04) + reorg-replay attacks (A17).

The 4-check sequence is **identical** at commit and reveal — the same field bindings + the same registry-state-at-commit's-block reading discipline. This identity is what makes tamper between commit and reveal cryptographically detectable: any drift in any of the 4 checks at reveal time produces verification failure that aborts before file_key reconstruction per §1.7 fail-closed error model + §14.2.1 combiner pre-verify checklist step 6.

### §11.1 The 4-check sequence

Per WP §C `wp.md:147-156` + canonical §3.4.3 EndpointAttestation SCALE sum-type definition + brief-07 §1:

| # | Check | Defends against | Canonical source-of-truth |
|---|---|---|---|
| 1 | **Lit V3 assignment record** for this `authorizationId` — query on-chain `LitV3Assignment` contract per §11.2; verify the assigned TEE identity matches the σ_Lit signing TEE per §7.2 | A06 — adversary-chosen-TEE substitution | §7.2 + canonical §7.2 lines 1963-1966 + §11.2 below |
| 2 | **Per-op DCAP quote** from the assigned TEE — verify the quote's `user_data` field binds the 32-byte keccak-compressed `(authorizationId, h_commit, block_hash)` digest per §9.3.3 (G4 Phase 2) + §7.5 (Lit V3); reject if mismatch (replay from different op) | A14 — quote replay across commits | §7.5 + §9.3.3 + canonical §1.1.5 line 143 (DCAP user_data 64-byte field) |
| 3 | **G3 committee pubkey** for the chosen G3 path — resolve from `G3AuthorityRegistry` (dcipher Swiss Threshold Association registry OR drand League of Entropy beacon chain) at the commit's `RevealAuthorized` block per §11.4 + §12 + §8.2.4 + §8.3.4 | G3 staleness / committee rotation racing | §8.2.4 + §8.3.4 + §12 G3 registry verification |
| 4 | **G4 authority attestation** — phase-specific verification per §9.5: Phase 1 verifies Ed25519 signature over `(TAG_G4_ATTESTATION_V3 ‖ binary_hash ‖ block_hash ‖ authorizationId ‖ h_commit ‖ timestamp)` 168-byte preimage against `G4AuthorityRegistry` Phase 1 binary entry at the commit's block; Phase 2 verifies DCAP quote's `user_data` field carries the 32-byte keccak-compressed digest per §9.3.3 + verifies TEE enclave measurement against `G4AuthorityRegistry` Phase 2 entry at the commit's block | A04 (registry race), A17 (reorg replay) | §9.5.1 + §9.5.2 + canonical §1.1.3 line 40 (Ed25519 64 bytes) + §3.4.3 EndpointAttestation::Phase1/Phase2 SCALE sum-type |

All 4 checks MUST PASS before σ_Lit + σ_G4 can authorize decapsulation of their matching stanza shares. Any check failure aborts the reveal at the §14.2.1 combiner pre-verify checklist step 6 (endpoint_attestation parse check) per §1.7 fail-closed error model with the corresponding ERR code per §16.

**At-commit-block reading discipline.** Per WP §C `wp.md:156` + canonical §11.4 below: identical checks run at reveal against the commit's block, not current state. This is the key to historical commit verifiability across registry key rotations + Lit V3 assignment rotations + G3 committee rotations + G4 authority rotations — the 4-check sequence resolves to the registry/assignment state that was valid at the commit's block, NOT current state.

### §11.2 LitV3Assignment record (Check 1 substrate)

The `LitV3Assignment` on-chain contract publishes per-commit Lit V3 serving-TEE assignments. Per canonical §7.2 lines 1963-1966:

```
LitV3Assignment(authorizationId) → {
  assigned_tee_id: bytes32,         // TEE identifier (vendor-specific format; matched against DCAP enclave measurement)
  block_number: uint64,             // commit's RevealAuthorized block number
  assigned_tee_pubkey: bytes,       // assigned TEE's per-op signing pubkey (BLS12-381 G1-compressed 48 bytes per §7.4 + canonical §1.1.4 line 38 minimum-pubkey-size variant)
}
```

| Field | Width | Source |
|---|---|---|
| `assigned_tee_id` | 32 bytes | TEE-vendor-specific identifier; matched against DCAP quote's enclave measurement per Check 2 |
| `block_number` | 8 bytes (uint64 BE) | Commit's `RevealAuthorized` block — anchors at-commit-block reading discipline |
| `assigned_tee_pubkey` | variable per Lit V3 SDK variant | BLS12-381 pubkey per Lit V3 Chipotle convention. Per BP-5 LOCKED + canonical §1.1.4 line 38, Lit V3 + dcipher variant assignments are deferred to S2-3 SDK confirmation (drand variant LOCKED to minimum-pubkey-size = G1 pubkey 48 bytes); Lit V3 minimum-pubkey-size vs minimum-signature-size variant assignment pending S2-3. For S2-1 wire-format, treat `assigned_tee_pubkey` as `Bytes` per the dcipher pattern at §8.2.2; the verifier MUST verify σ_Lit under the variant the Lit V3 Chipotle SDK's published protocol uses. |

**Verification protocol (Check 1):**

1. Query on-chain `LitV3Assignment(authorizationId)` at the commit's `RevealAuthorized` block per §11.4 at-commit-block reading discipline.
2. If no assignment record exists for this `authorizationId` at the commit's block → abort with `ERR_LIT_V3_ASSIGNMENT_MISSING` per §16. This catches commits that bypass Lit governance assignment (A06 enforcement).
3. Recover `assigned_tee_id` + `assigned_tee_pubkey` from the record. The pubkey is consumed at §7.6 step 1 σ_Lit BLS verification; the TEE id is consumed at §7.6 step 4 + Check 2 below for cross-reference with DCAP quote.

**A06 cross-vendor enforcement.** Per §7.7 + §9.3.4, the assigned TEE's vendor (Intel SGX vs AMD SEV-SNP vs AWS Nitro) is recovered from the DCAP quote at Check 2 + cross-checked against the G4 Phase 2 TEE vendor for cross-vendor mandate (A11 fix). If both are Intel SGX, the cross-vendor mandate is violated → abort with `ERR_LIT_TEE_ASSIGNMENT_MISMATCH` per §7.6 + `ERR_SIGMA_G4_PHASE2_CROSS_VENDOR_VIOLATION` per §9.5.2.

### §11.3 Dual-DCAP discipline (Check 2 substrate)

Per §7.5 + §9.3.3 + canonical §3.4.3 EndpointAttestation SCALE sum-type + canonical §1.1.5 line 143 (DCAP user_data 64-byte field width):

The endpoint attestation 4-check involves TWO independent DCAP quotes per gate:

#### §11.3.1 Commit-time anchor (per-phase distinct: NOT-DCAP for Phase 1, DCAP for Phase 2)

Per §3.4.3 EndpointAttestation SCALE sum-type — the COMMIT-time anchor is phase-specific. **Phase 1 carries `binary_hash + effective_block` (NOT a DCAP quote)**; **Phase 2 carries `dcap_quote_bytes` (the actual DCAP quote)**. The "dual-DCAP" discipline applies only at the Phase 2 commit-time level + at the reveal-time per-op level (§11.3.2). Phase 1 commits are dev-scaffold only per Stage-0 Q-0-2 LOCKED + canonical §9.2 spec.

```
endpoint_attestation_digest = keccak256(
  SCALE_encode(EndpointAttestation)     // SCALE sum-type variant per §1.3.3 mixed pattern
)

enum EndpointAttestation {
  Phase1 {                              // variant tag 0x01
    binary_hash: bytes32,               // 32 bytes — Cealis G4 sealed-code daemon binary hash
    effective_block: uint64,            // 8 bytes BE — G4AuthorityRegistry effective_block field
  }
  Phase2 {                              // variant tag 0x02
    dcap_quote_bytes: Bytes,            // variable per vendor (~4-8 KB)
  }
}
```

The commit-time `endpoint_attestation_digest` is bound into `commit_AAD` (§4.1) → transitively into `h_commit` (§3.4) — frozen at commit, anchored on-chain via `RevealAuthorized` event. This is the COMMIT-TIME DCAP attestation (TEE enclave measurement at commit) — distinct from the reveal-time per-op DCAP at §11.3.2.

#### §11.3.2 Reveal-time per-op DCAP (anchored via `user_data`) — per-gate split

Per §7.5 (σ_Lit) + §9.3.3 (σ_G4 Phase 2): the reveal-time per-op DCAP `user_data` formula is **per-gate distinct** — Lit V3 uses RAW byte concatenation per canonical §7.5 line 2020 (BLS hash-to-curve provides RFC 9380 domain separation at the curve layer per canonical §9.2.3 line 2383); G4 Phase 2 uses TAG-prefix per canonical §2 line 239 + generalized D6 V3 TAG-prefix discipline (Ed25519 + DCAP both lack RFC 9380 BLS hash-to-curve domain separation per canonical §9.2.3 line 2383).

**Lit V3 (BLS hash-to-curve domain separation; NO TAG-prefix) per canonical §7.5 line 2020:**

```
user_data_digest (Lit V3) = keccak256(
  authorizationId    // 32 bytes per §3.2
  ‖ h_commit         // 32 bytes per §3.4
  ‖ block_hash       // 32 bytes per §11 — A14 anti-replay binding
)[:32]
```

| Field (preimage) | Width | Source |
|---|---|---|
| `authorizationId` | 32 bytes | Per §3.2 |
| `h_commit` | 32 bytes | Per §3.4 |
| `block_hash` | 32 bytes | Per §11 — Base L1 block hash of `RevealAuthorized` event |

**Lit V3 preimage length:** 32 + 32 + 32 = **96 bytes**.

**G4 Phase 2 (Ed25519 / DCAP shared TAG; TAG-prefix per generalized D6) per canonical §9.3.3 + §2 line 239:**

```
user_data_digest (G4 Phase 2) = keccak256(
  TAG_G4_ATTESTATION_V3   // 32 bytes per §2 line 239
  ‖ authorizationId       // 32 bytes per §3.2
  ‖ h_commit              // 32 bytes per §3.4
  ‖ block_hash            // 32 bytes per §11 — A14 anti-replay binding
)[:32]
```

| Field (preimage) | Width | Source |
|---|---|---|
| `TAG_G4_ATTESTATION_V3` | 32 bytes | Per §2 line 239 |
| `authorizationId` | 32 bytes | Per §3.2 |
| `h_commit` | 32 bytes | Per §3.4 |
| `block_hash` | 32 bytes | Per §11 — Base L1 block hash of `RevealAuthorized` event |

**G4 Phase 2 preimage length:** 32 + 32 + 32 + 32 = **128 bytes**.

**Output `user_data_digest` length (both gates):** **32 bytes** (placed in DCAP `user_data` field with 32 bytes zero-padding to fill the 64-byte DCAP field width per canonical §1.1.5 line 143 + Simon Decision D11).

**Per-gate asymmetric discipline rationale.** Per canonical §9.2.3 line 2383: BLS signatures (Lit V3 σ_Lit per §7) get RFC 9380 hash-to-curve domain separation at the curve layer — no per-protocol TAG-prefix needed. Ed25519 + DCAP attestation (G4 σ_G4 per §9) lack equivalent curve-layer domain separation — TAG-prefix per generalized D6 V3 discipline is needed to prevent cross-protocol signature reuse. The asymmetry is canonical, not arbitrary: Lit V3 inherits §7.5 raw-bytes formula; G4 Phase 2 inherits §9.3.3 TAG-prefixed formula.

#### §11.3.3 Dual-DCAP verification (Check 2)

The combiner verifies BOTH the commit-time DCAP AND the reveal-time per-op DCAP:

1. **Commit-time DCAP verification:** SCALE-decode `EndpointAttestation` from `endpoint_attestation_digest`'s preimage (recovered from `commit_AAD`); recompute `keccak256(SCALE_encode(EndpointAttestation))` and verify against `endpoint_attestation_digest` field bound in `h_commit`. Mismatch → `ERR_ENDPOINT_ATTESTATION_DIGEST_MISMATCH` per §16.
2. **Reveal-time per-op DCAP verification:** for each gate with DCAP attestation (Lit V3 always + G4 Phase 2 conditional), recompute the **per-gate-specific** `user_data_digest` per §11.3.2 (Lit V3: 96-byte raw preimage per canonical §7.5 line 2020; G4 Phase 2: 128-byte TAG-prefixed preimage per canonical §9.3.3) + compare against the first 32 bytes of the per-op DCAP quote's `user_data` field. Mismatch → `ERR_LIT_DCAP_USER_DATA_MISMATCH` per §7.6 step 3 (Lit V3) OR `ERR_SIGMA_G4_PHASE2_USER_DATA_MISMATCH` per §9.5.2 step 2 (G4 Phase 2).
3. **DCAP quote signature verification:** verify both DCAP quotes against the appropriate hardware vendor's attestation root (Intel SGX root / AMD SEV-SNP root / AWS Nitro root). Use on-chain `zkDCAPVerifier` (Automata) per S2-3. Failures: `ERR_LIT_DCAP_INVALID` per §7.6 step 2 OR `ERR_SIGMA_G4_PHASE2_DCAP_INVALID` per §9.5.2 step 1.

**Cross-vendor enforcement (A11) re-validated at reveal time.** Per §7.7 + §9.3.4: if the Lit V3 serving TEE for this op is Intel SGX, the G4 Phase 2 TEE MUST be AMD SEV-SNP or AWS Nitro. The combiner re-validates this invariant at the per-op DCAP layer (recovering vendors from each DCAP quote's signature root) — single-vendor pair → abort with `ERR_LIT_TEE_ASSIGNMENT_MISMATCH` (Lit-side) + `ERR_SIGMA_G4_PHASE2_CROSS_VENDOR_VIOLATION` (G4-side).

### §11.4 At-commit-block reading discipline (NORMATIVE)

**Scope-disambiguation note (6 historical-lookup surfaces vs 5 V3 registries):** §11.4 enumerates SIX historical-lookup surfaces below — `LitV3Assignment` (Check 1 substrate, on-chain Lit V3 governance contract) + the 5 V3 registries (`PluginHashRegistry` + `G4AuthorityRegistry` + `DSLVersionRegistry` + `OracleRegistry` + `QTSPRegistry`). The team-wide framing "5 V3 registries" refers to the 5 Cealis-governed V3 registries (without LitV3Assignment, which is Lit V3 governance, not Cealis); §12 normative scope per outline + dw-lead routing covers those 5. The 6th surface (LitV3Assignment) is canonical to §11 endpoint attestation Check 1 substrate per §11.2 — same at-commit-block reading discipline applies, but governance + registry-shape spec is in Lit V3 documentation, not §12.

Per WP §C `wp.md:156` + WP §D `wp.md:387` + canonical §3.4.3 + brief-07 §2:

> *"Identical checks run at reveal (§D) against the commit's block, so tamper anywhere between commit and reveal is detectable. G4AuthorityRegistry governance and the zkDCAP verification chain are detailed in §N and §M; the client-side check runs against registry state at the transaction's block, not current state, which is how the system survives key rotations without breaking historical commits."*

This discipline is the load-bearing mechanism for historical commit verifiability across registry rotations + assignment record rotations + committee rotations + authority rotations:

1. **LitV3Assignment** is queried at the commit's `RevealAuthorized` block per §11.2 — assignments rotated for new commits do NOT invalidate historical commits.
2. **G3AuthorityRegistry** (dcipher Randamu Threshold Association OR drand League of Entropy) is queried at the commit's `RevealAuthorized` block per §11.1 Check 3 + §8.2.4 + §8.3.4 — G3 committee rotations do NOT invalidate historical commits.
3. **G4AuthorityRegistry** is queried at the commit's `RevealAuthorized` block per §11.1 Check 4 + §9.5.1 + §9.5.2 + §12.2 — G4 authority key rotations do NOT invalidate historical commits per the `(binary_hash, effective_block, tombstone_block)` tuple semantics.
4. **PluginHashRegistry** is queried at the commit's `RevealAuthorized` block per §14.2.1 step 1 + §12 — plugin binary rotations do NOT invalidate historical commits.
5. **DSLVersionRegistry + OracleRegistry** are queried at the commit's `RevealAuthorized` block per §12 — DSL or oracle rotations do NOT invalidate historical commits.
6. **QTSPRegistry** is queried at the commit's `RevealAuthorized` block per §12 + cross-references at §3.3.4 D1 line 521 (`qtsp_provider_ref` field) + §5 σ_subject QTSP path — QTSP entry rotations do NOT invalidate historical commits.

The **distinction from in-flight protection** (§12 + brief-07 §2 + WP §D `wp.md:387`): deprecation flags set AFTER `RevealAuthorized` do NOT halt the in-flight reveal ceremony per gate-signing-window architectural-halt-impossibility per WP §D `wp.md:402` + §14.2.1 step 8 registry deprecation snapshot check. The at-commit-block reading discipline is for HISTORICAL verifiability; in-flight protection is for active ceremony continuity.

**Architectural-truth-template multi-substrate-variant INSTANCE callout (per §14.7.4 carry-forward):** §11.4's 6-substrate at-commit-block reading discipline IS a §14.7.4 architectural-truth-template multi-substrate-variant pattern at the registry-historical-lookup substrate layer: six independent registry/assignment substrates (LitV3Assignment + 5 V3 registries) all enforce the same architectural truth ("historical commits remain verifiable across registry rotations") under different substrate variants (Lit V3 governance contract + Cealis-governed registries with `(hash, effective_block, tombstone_block)` tuples + threshold-network registries with epoch-pubkey rotations + QTSPRegistry with provider-metadata entries). §16 SHOULD callout this as architectural-truth-template multi-substrate-variant INSTANCE alongside §14.7.4 (combiner) + §13.6 Cealis-as-infrastructure-not-authority + §10.9 Mode 3 RESERVED enforcement chain (configurator + envelope-load + reveal-time).

### §11.5 Cross-section integration with §7 + §9 verification protocols

The 4-check sequence is INVOKED from §7.6 (σ_Lit verification) + §9.5 (σ_G4 verification) + §14.2.1 step 6 (combiner pre-verify checklist) — §11 spec'd the unified protocol; §7 + §9 invoke it per their gate-specific verification flow. Cross-section integration:

- **§7.6 step 1** (σ_Lit BLS verification) consumes Check 1 (`LitV3Assignment.assigned_tee_pubkey` from §11.2)
- **§7.6 steps 2-3** (σ_Lit DCAP verification + user_data binding) consume Check 2 Lit V3 path (per-op DCAP per §11.3.2 Lit V3 formula — 96-byte raw preimage recompute per canonical §7.5 line 2020 + §7.6 step 3)
- **§7.6 step 4** (σ_Lit TEE assignment verification) consumes Check 1 (`assigned_tee_id` from §11.2 cross-reference with DCAP enclave measurement)
- **§9.5.1 steps 1-5** (σ_G4 Phase 1 verification) consume Check 4 Phase 1 path (`G4AuthorityRegistry` lookup at commit's block + Ed25519 signature verification per §9.2.3)
- **§9.5.2 steps 1-4** (σ_G4 Phase 2 verification) consume Check 4 Phase 2 path (DCAP verification + user_data binding per §11.3.2 G4 Phase 2 formula — 128-byte TAG-prefixed preimage per canonical §9.3.3 + TEE measurement registry check + cross-vendor mandate per §9.3.4 + §11.3.3)
- **§8.2.4 step 3** (σ_G3 dcipher verification) consumes Check 3 dcipher path (Randamu Threshold Association registry pubkey at commit's block)
- **§8.3.4 step 4** (σ_G3 drand verification) consumes Check 3 drand path (League of Entropy beacon pubkey, public chain — registry-equivalent at commit's block)

**§14.2.1 step 6 endpoint attestation parse check** runs the unified §11 4-check sequence; failures abort the combiner pre-verify with `ERR_ENDPOINT_ATTESTATION_INVALID` per §16 (umbrella ERR; surfaces the gate-specific underlying ERR per §7 / §8 / §9 forensic-layering pattern matching §14.5 wrap-around-vs-forensic discipline).

### §11.6 Storage discipline

The endpoint attestation 4-check substrates follow the σ-as-authorization transport discipline pattern per §7.8 + §8.6 + §9.7 + §10.7 (gate signatures authorize share admission; their attestation substrates are non-PII auditor-readable):

| Substrate | Location | Storage | Discipline |
|---|---|---|---|
| `LitV3Assignment` record | On-chain (Lit V3 governance contract) | Per-commit assignment published at commit's `RevealAuthorized` block | At-commit-block reading per §11.4 |
| Commit-time DCAP (Phase 2) | `endpoint_attestation_digest` (32 bytes in `commit_AAD` per §4.1) — full DCAP quote bytes off-chain in RevealArtifactBundle vault staging | Anchored on-chain via 32-byte digest; full quote off-chain | Dual-DCAP discipline per §11.3 |
| Reveal-time per-op DCAP | Off-chain (delivered alongside σ_Lit / σ_G4 in RevealArtifactBundle staging) | NEVER on-chain — per-op DCAP is reveal-time artifact | DCAP carries σ authorization context, not a Shamir share or DEK |
| `G3AuthorityRegistry` state | On-chain (Randamu Threshold Association registry OR drand League of Entropy beacon chain) | Per-epoch committee pubkey published; rotations emit on-chain events | At-commit-block reading per §11.4 |
| `G4AuthorityRegistry` state | On-chain (Cealis governance contract) | Per-rotation `(binary_hash / TEE measurement, effective_block, tombstone_block)` tuples | At-commit-block reading per §11.4 + §12.2 |
| Cross-vendor invariant (A11) | Derived at reveal from DCAP quote signature roots | Re-validated at reveal per §7.7 + §9.3.4 + §11.3.3 | Combiner re-validation discipline |

The discipline matches the σ-as-authorization pattern at §7.8 + §8.6 + §9.7 + §10.7. Endpoint attestation substrates are commit-time + reveal-time artifacts; commit-time only carries the on-chain anchor (`endpoint_attestation_digest` for the COMMIT-time DCAP measurement) plus the on-chain assignment / registry state. Reveal-time produces the actual per-op DCAP quotes (delivered via RevealArtifactBundle), consumed-then-zeroized at the combiner per §14.4.2 zeroize-after-share-admission discipline.

### §11.7 Cross-reference index

This section consumes the following primitives and registries from earlier sections:

- **§1.1.3** asymmetric primitives — Ed25519 (G4 Phase 1 σ_G4 attestation) + BLS12-381 G1 (LitV3Assignment.assigned_tee_pubkey).
- **§1.1.5** DCAP attestation primitive — used at Check 2 (per-op DCAP) + Check 4 Phase 2 (G4 DCAP); 64-byte user_data field hard limit per canonical §1.1.5 line 143.
- **§1.2** endianness convention — `block_number` (uint64 BE) + `effective_block` (uint64 BE) + `tombstone_block` (uint64 BE) per §1.2 BE-keccak-preimage convention.
- **§1.3.2** SCALE encoding rules + **§1.3.3** mixed pattern — `EndpointAttestation` SCALE sum-type per Simon Decision D10 + canonical §3.4.3 (TAG-prefix wrapping a SCALE-encoded sum-type pattern per §1.3.3).
- **§2 line 239** `TAG_G4_ATTESTATION_V3` — used at Check 4 G4 Phase 2 user_data preimage + Check 4 G4 Phase 1 signing input. **Lit V3 user_data preimage uses NO TAG-prefix** per canonical §7.5 line 2020 (BLS hash-to-curve provides RFC 9380 domain separation at the curve layer per canonical §9.2.3 line 2383) — per-gate asymmetric discipline.
- **§3.2** authorizationId — per-commit identifier, query key for `LitV3Assignment` + per-op DCAP user_data binding.
- **§3.4** h_commit — anchors `endpoint_attestation_digest` field; consumed at Check 2 + Check 4 user_data binding.
- **§3.4.3** endpoint_attestation_digest SCALE sum-type — Phase1 + Phase2 variant payload spec.
- **§4.1** commit_AAD `endpoint_attestation_digest` field — bound at commit; consumed at Check 2 commit-time DCAP verification.
- **§7.2** LitV3Assignment record format — Check 1 substrate.
- **§7.5** σ_Lit dual-DCAP precedent — Check 2 commit-time + reveal-time pattern.
- **§7.6** σ_Lit verification protocol steps 1-4 — invokes §11 Checks 1 + 2.
- **§7.7** A11 cross-vendor mandate (Lit V3 + G4 Phase 2) — re-validated at §11.3.3.
- **§8.2.4** σ_G3 dcipher verification — invokes §11 Check 3 dcipher path.
- **§8.3.4** σ_G3 drand verification — invokes §11 Check 3 drand path.
- **§9.3.3** σ_G4 Phase 2 user_data binding — Check 4 Phase 2 substrate.
- **§9.3.4** A11 cross-vendor mandate (G4 Phase 2 side) — re-validated at §11.3.3.
- **§9.5** σ_G4 verification protocol — invokes §11 Check 4.

Forward-references (consumed by later sections):

- **§12** Registry verification — full spec for the 5 V3 registries (PluginHashRegistry / G4AuthorityRegistry / DSLVersionRegistry / OracleRegistry / QTSPRegistry) + at-commit-block reading discipline + DeprecationFlag governance.
- **§14.1** combiner pre-verify checklist — runs §14.2.1 step 6 endpoint attestation parse check invoking §11 4-check sequence BEFORE §6.3 file_key reconstruction fires.
- **§14.2.1 step 6** combiner pre-verify endpoint_attestation parse check — explicit cross-reference to §11 4-check sequence.
- **§16** error model: `ERR_ENDPOINT_ATTESTATION_INVALID` (umbrella) + `ERR_LIT_V3_ASSIGNMENT_MISSING` + `ERR_ENDPOINT_ATTESTATION_DIGEST_MISMATCH` + cross-references to §7 + §8 + §9 gate-specific ERR codes (`ERR_LIT_DCAP_INVALID`, `ERR_LIT_DCAP_USER_DATA_MISMATCH`, `ERR_LIT_TEE_ASSIGNMENT_MISMATCH`, `ERR_SIGMA_G3_DCIPHER_INVALID`, `ERR_SIGMA_G3_DRAND_INVALID`, `ERR_SIGMA_G4_PHASE1_INVALID`, `ERR_SIGMA_G4_PHASE2_DCAP_INVALID`, `ERR_SIGMA_G4_PHASE2_USER_DATA_MISMATCH`, `ERR_SIGMA_G4_AUTHORITY_REGISTRY_MISMATCH`, `ERR_SIGMA_G4_PHASE2_CROSS_VENDOR_VIOLATION`).

Library SDK version pins are S2-3 territory.

### §11.8 PII content statement

Endpoint attestation 4-check substrates are PII-NONE at the cryptographic-construct layer. The 4-check substrates contain:

- **LitV3Assignment record** — TEE identifier (vendor-specific, non-PII per DCAP attestation framing) + commit's `RevealAuthorized` block number (chain-state metadata, non-PII) + assigned TEE's BLS pubkey (operator-side cryptographic identity, non-PII).
- **Commit-time DCAP (Phase 2)** — TEE enclave measurement (immutable hash of the Cealis G4 / Lit V3 enclave's compiled image, non-PII per DCAP attestation framing) + DCAP quote signature (vendor-rooted: Intel / AMD / AWS attestation key, non-PII).
- **Reveal-time per-op DCAP** — same DCAP quote shape; user_data field carries 32-byte keccak-compressed digest of `(authorizationId, h_commit, block_hash)` per §11.3.2 (non-PII per commit-binding's already-PII-free preimage + keccak preimage-resistance).
- **G3AuthorityRegistry state** — committee pubkey (operator-side cryptographic identity, non-PII) + epoch metadata (operator-side, non-PII).
- **G4AuthorityRegistry state** — `(binary_hash / TEE measurement, effective_block, tombstone_block)` tuples (operator-side cryptographic identity + chain-state metadata, non-PII).

No subject-identifying data appears at any layer of the endpoint attestation 4-check verification path. The 4 checks are operator-side cryptographic substrates (Lit V3 governance, G3 threshold network operators, Cealis G4 verification component) — NOT subject-side identifiers.

The σ transport discipline per §7.1 + §9.1 protects share-admission integrity; the endpoint attestation 4-check substrates are operator-side authentication metadata that supports the σ-as-authorization model (combiner verifies σ values came from the correct operators) WITHOUT introducing subject-side PII surface. The two protection layers are orthogonal: PII is protected by AEAD payload encryption per §6.4; endpoint attestation integrity is protected by the 4-check verification protocol per §11.1 (the checks ensure σ values are authentic per the registered operators at the commit's block).

**Strict GDPR interpretation (Breyer C-582/14 + Recital 26): EXPLICITLY NOT APPLICABLE to §11 substrates.** Unlike §10.10 Mode 2 `wallet_address` (cross-partner-stable natural-person pseudo-identifier per §3.6 ¶3 + §4.9 ¶2 framework + §10.10 Breyer carry-forward), §11 endpoint attestation 4-check substrates (LitV3Assignment + 5 V3 registries entries) carry only operator-side cryptographic identities (Lit V3 governance assignment records + Cealis-governed registry entries + threshold-network committee pubkeys + QTSP provider metadata) — NONE of these are natural-person identifiers, cross-partner-stable or otherwise. The Breyer C-582/14 third-party-observer-vs-controller-scope distinction at §10.10 + §13.10.1 framework does NOT apply to §11 substrates because there is no natural-person identifier in §11's substrate set to which the third-party-observer reachability surface could attach. §11's PII-NONE claim is structurally complete at the cryptographic-construct layer + operator-side substrate layer with no auditor-side strict-interpretation residue.

---

## §12 — Registry verification (5 V3 registries)

This section defines the canonical preimage forms + at-commit-block reading discipline + DeprecationFlag governance for the **5 Cealis-governed V3 registries** that anchor the V2 system's forward-compatibility surface: `PluginHashRegistry`, `G4AuthorityRegistry`, `DSLVersionRegistry`, `OracleRegistry`, `QTSPRegistry`. All 5 registries follow a common at-commit-block reading discipline + asymmetric governance pattern (slow on additions, fast on deprecations) that crypto-enforces P25 open-architecture forward-compat per WP §B `wp.md:133`.

**Scope-disambiguation note (per §11.4 6-vs-5 framing):** §12 covers the **5 Cealis-governed V3 registries**. The 6th historical-lookup surface enumerated at §11.4 — `LitV3Assignment` — is Lit V3 governance (not Cealis); spec'd at §11.2 + §7.2 (substrate) + Lit V3 documentation (governance). `PasskeyRotationLog` (per-Cealis-account passkey rotation) is ABI standard, not a singleton registry — spec'd at §13. `ShredRegistry` (per-commit shred state) is briefs-04+08 / §F territory; not a versioning registry. `G4RefusalRegistry` (on-chain refusal signals 0x01-0x0A) is per-commit semantics; spec'd at §9.5 + §16.

### §12.0 Registry-key derivation discipline (NORMATIVE)

**Source-of-truth:** `designs/v3-registry-class-discipline.md` (committed via /design pipeline 2026-05-04, closes BP-13/14/15).

**Two registry classes, decided by the preimage-role-at-any-construction-site test.**

#### §12.0.1 Class definitions

- **Class CRYPTO** — TAG-prefix the lookup key. **Membership rule:** the lookup key is a deterministic function of a primitive cryptographic identity (binary hash digest, signing pubkey, attestation digest) **OR** participates as a keccak preimage at any construction site (Merkle leaf, HKDF input, MAC input, etc.) anywhere in the V3 protocol — current or planned.

- **Class CATALOG** — raw 32-byte ref at lookup-key layer; domain separation derives from upstream `TAG_AAD_V3` wrap or equivalent. **Membership rule:** governance-assigned opaque key with **no preimage role** anywhere in the V3 protocol. Collision resistance derives from registry write-discipline (§12.1) + at-commit-block reading discipline (§12.6).

The two classes are mutually exclusive and exhaustive over Cealis-governed V3 registries. The preimage-role test is decisive: if a registry's lookup key participates as a keccak preimage at any construction site (current or planned), it MUST be class-CRYPTO.

#### §12.0.2 V3 class table

| Registry | Class | Per-key TAG | Preimage role | Reference |
|---|---|---|---|---|
| `PluginHashRegistry` | CRYPTO | `TAG_PLUGIN_VERSION_V3` (BP-3) | binary hash digest in §4.6.1 commit_AAD field bind | §12.2 |
| `G4AuthorityRegistry` | CRYPTO | `TAG_G4_ATTESTATION_AUTHORITY_V3` (BP-4) | attestation pubkey digest in §6.1 stanza[2] binding | §12.3 |
| `OracleRegistry` | CRYPTO | `TAG_ORACLE_REGISTRY_V3` (BP-14, NEW 2026-05-04) | per-leaf preimage in `oracle_references_root` Merkle tree | §12.5.1 |
| `DSLVersionRegistry` | CATALOG | none | none — `dsl_version_ref` is a single field inside `commit_AAD`, domain-separated by `TAG_AAD_V3` upstream wrap | §12.4 |
| `QTSPRegistry` | CATALOG | none | none — `qtsp_provider_ref` is a single field inside `pda_root` (transitively inside `commit_AAD`), domain-separated by `TAG_AAD_V3` upstream wrap | §12.7 |

#### §12.0.3 Per-CATALOG residual-threat closure (NORMATIVE)

For each CATALOG-class registry, the per-key threat-model defense is enumerated below — auditors verify each closure independently from the class assignment.

| Registry | Domain separation source | Collision resistance source |
|---|---|---|
| `DSLVersionRegistry` | `TAG_AAD_V3` upstream wrap of `commit_AAD` per §4.3 | Governance write-discipline per §12.1 (TimelockController 7-day; Cealis-governed assignment) |
| `QTSPRegistry` | `TAG_AAD_V3` upstream wrap via `pda_root` per §4.3 | Governance write-discipline per §12.1 + EU Trusted List anchoring per §5.5.3 (eIDAS qualified-status binding) |

Class-CATALOG members do NOT need per-key TAG-prefix because the upstream `TAG_AAD_V3` wrap provides the domain-separation guarantee at the commit_AAD-binding layer, and governance write-discipline provides collision-resistance against an attacker attempting to register a colliding key. Adding per-key TAG-prefix to a CATALOG-class registry would buy zero threat-mitigation but cost one TAG entry + commit_version coordination per addition (under §2.8 outside the §2.8.5 carve-out window).

#### §12.0.4 Boundary-case classification (NORMATIVE worked examples)

For future 6th-registry classification, the preimage-role test resolves boundary cases mechanically. Two worked examples:

- **Hypothetical `ConditionModuleRegistry`** (catalog of condition module address + bytecode hash + ABI signatures). Bytecode hash IS a primitive cryptographic identity (content-addressed); module address is location-addressed. The bytecode hash participates as a preimage when condition modules are committed to via `pda_root.condition_module_set_root` (hypothetical future field). **Class: CRYPTO.** Add a `TAG_CONDITION_MODULE_V3` per the §12.0.1 rule.

- **Hypothetical `PartnerKeyRegistry`** (governance-assigned partner UUID maps to entry-payload pubkey + entry metadata). The partner UUID has no preimage role — partner identity is verified at the entry-payload pubkey layer, not the registry-key layer. **Class: CATALOG.** No new TAG; rely on upstream `TAG_AAD_V3` wrap for domain separation.

A registry sitting at a genuinely novel boundary (e.g., governance-assigned key derived FROM a cryptographic identity but not directly content-addressed) opens a new BP-N candidate per §2.8 — the class-rule is decisive over the surface case but does not preclude future architectural escalation if a third class surfaces.

#### §12.0.5 Class-assignment rule + §2.1 universal-discipline integration

The §2.1 universal TAG-prefix discipline ("every keccak / HMAC / HKDF construction in §3 through §15 of this specification consumes a TAG from this registry") applies UNCHANGED to all per-construction-site preimages. The §12.0 carve-out is narrow: it applies only at registry **lookup-key derivation** for class-CATALOG members, where the governance-assigned opaque key is consumed downstream INSIDE a `TAG_AAD_V3`-wrapped construction (and therefore inherits domain separation from the upstream wrap). Class-CRYPTO members continue to follow per-key TAG-prefix discipline at lookup-key derivation.

This is an architectural distinction at the §12 registry-substrate layer, not a relaxation of §2.1 at any cryptographic construction site.

#### §12.0.6 BP-13 / BP-14 / BP-15 disposition

- **BP-13 (DSLVersionRegistry → `TAG_DSL_VERSION_V3`):** REJECT. Class-CATALOG. `dsl_version_ref` is a governance-opaque single-field entry inside `commit_AAD`; domain separation from `TAG_AAD_V3` upstream wrap. No preimage role. Per-key TAG-prefix would buy zero threat-mitigation.

- **BP-14 (OracleRegistry → `TAG_ORACLE_REGISTRY_V3` per-leaf):** ACCEPT. Class-CRYPTO. `oracle_id_i` participates as a Merkle-leaf preimage in `oracle_references_root` (§12.5.1). Without per-leaf TAG-prefix, future Merkle trees in V3 would carry an inverted invariant; per-leaf TAG-prefix forecloses cross-tree leaf substitution at the source. Added to §2.3.4 active table 2026-05-04 under §2.8.5 initial-Stage-2 drafting carve-out.

- **BP-15 (QTSPRegistry → `TAG_QTSP_PROVIDER_V3`):** REJECT. Class-CATALOG. `qtsp_provider_ref` is a governance-opaque single-field entry inside `pda_root` → `commit_AAD`; eIDAS legal force lives in entry-payload signed Trust List (Article 22), not in lookup-key derivation. Domain separation from `TAG_AAD_V3` upstream wrap.

Disposition closes §17.7 BP-13/14/15. See `designs/v3-registry-class-discipline.md` for full alternatives + stress-test analysis + ground-check verdict.

### §12.1 Common governance shape (NORMATIVE)

Per WP §M `wp.md:1014-1018` + brief-07 §2 + emergency-response design:

All 5 V3 registries share the same governance shape — additive extension within governance, not by fork or migration (P25 anti-bloat enforcement per WP §B `wp.md:133`):

| Action | Authority | Timelock |
|---|---|---|
| Add entry to any registry | TimelockController | 7-day (recipient observation window) |
| Deprecate non-canonical entry | CealisSecurityMultisig (2-of-3) | 0 (instant) |
| Deprecate canonical-in-use entry | CealisSecurityMultisig (2-of-3) + TimelockController expedited delay | 24h (partner/recipient observation window) |
| Clear deprecation flag | TimelockController | 7-day |
| Re-deprecate same entry after auto-clear | TimelockController | 7-day (30-day cooldown applies) |

**Asymmetric rationale (per emergency-response design `:14-17` + brief-07 §3):** slow on additions enforces a public observation window where partners + recipients can audit new entries before they become reachable. Fast on deprecations enforces fast incident-response (active exploit, disclosed vulnerability, compromised operator) without forcing a 7-day delay that would extend exposure. The asymmetry is the architectural commitment that makes registries safe to extend additively without race-condition exposure.

Full S2-2 contract surface for `CealisSecurityMultisig` + `EmergencyGovernance` + `publishDisclosure` is **S2-2 territory** — §12 cites for combiner-side verification, S2-2 spec'd contract surface.

### §12.2 PluginHashRegistry

The `PluginHashRegistry` registers canonical `age-plugin-cealis-v3` binary hashes. Per canonical §2 line 255 + canonical §4.6.1 + brief-07 §2:

#### §12.2.1 Canonical preimage form

```
plugin_version_digest = keccak256(
  TAG_PLUGIN_VERSION_V3        // 32 bytes per §2 line 255
  ‖ canonical_binary_hash      // 32 bytes — keccak-256 of canonical binary bytes
)
```

| Field (preimage) | Width | Source |
|---|---|---|
| `TAG_PLUGIN_VERSION_V3` | 32 bytes | Per §2 line 255 (`"CEALIS_V3_PLUGIN_VERSION_V3"` keccak-prefixed) |
| `canonical_binary_hash` | 32 bytes | `keccak256(<canonical age-plugin-cealis-v3 binary bytes>)` |

**Preimage length:** 32 + 32 = **64 bytes**. Output: 32 bytes (keccak-256).

**Q-W2-30 LOCKED 2026-04-25** by dw-lead per generalized D6 V3 TAG-prefix discipline. Tracked at BP-3 in the internal S2-1 back-propagation log for back-propagation to `flows-spec-final.md:172` raw-bytes formula (V1-cargo-cult). Construction is canonically defined at §4.6.1 line 891 (`commit_AAD.plugin_version_digest` construction site); §12.2.1 reproduces the formula here as the registry-verification anchor.

#### §12.2.2 Per-entry data shape

```
PluginHashRegistry.entry[plugin_version_digest] → (
  effective_block:      uint64,            // RevealAuthorized block number from which entry is canonical
  tombstone_block:      uint64,            // 0 if non-tombstoned; otherwise block number of tombstone
  deprecation_flag:     DeprecationFlag,   // §12.8
  is_canonical:         bool,              // true if most recently added non-tombstoned non-deprecated entry
)
```

#### §12.2.3 Verification protocol (combiner-side, at commit's block)

1. Recover `plugin_version_digest` from `commit_AAD.plugin_version_digest` per §4.6.1.
2. Query `PluginHashRegistry.entry[plugin_version_digest]` at the commit's `RevealAuthorized` block per §12.6 at-commit-block reading discipline.
3. If entry does not exist at commit's block → abort with `ERR_PLUGIN_REGISTRY_MISMATCH` per §16.
4. If `effective_block > commit_block` → entry not yet active at commit's block → abort with `ERR_PLUGIN_NOT_YET_EFFECTIVE` per §16.
5. If `tombstone_block != 0 AND tombstone_block ≤ commit_block` → entry tombstoned before commit → abort with `ERR_PLUGIN_TOMBSTONED` per §16.
6. Check `deprecation_flag` state per §12.8 — see §12.8.4 in-flight protection vs class-wide refusal carve-out.

#### §12.2.4 Bound into commit

- **Field:** `commit_AAD.plugin_version_digest` (canonical §4.6.1 line 891)
- **Threat closed:** A12 — combiner uses wrong plugin binary (caught earlier at §14.2.1 step 1 plugin_version_digest match against PluginHashRegistry-at-commit-block; even if step 1 were bypassed, AEAD tag verification at step 5 would fail per canonical line 1911)

#### §12.2.5 G4 refusal signal

If deprecated BEFORE commit's block: G4 refuses σ_G4 with reason code `0x06 plugin_deprecated` per §9 G4 reason-code enum + §15 deprecation-snapshot mechanics + canonical line 894 + §11.5 cross-reference.

### §12.3 G4AuthorityRegistry

The `G4AuthorityRegistry` registers G4 authority key rotation tuples per Phase 1 (binary_hash) + Phase 2 (TEE measurement). Per canonical §2 line 240 + canonical §4.6.2 + brief-07 §2 + §9.2.4 + §9.5.1 / §9.5.2:

#### §12.3.1 Canonical preimage form

```
g4_authority_ref = keccak256(
  TAG_G4_ATTESTATION_AUTHORITY_V3   // 32 bytes per §2 line 240
  ‖ authority_key_pubkey            // 32 bytes (Phase 1 Ed25519) OR 65 bytes (Phase 2 P-256 uncompressed)
)
```

| Field (preimage) | Width | Source |
|---|---|---|
| `TAG_G4_ATTESTATION_AUTHORITY_V3` | 32 bytes | Per §2 line 240 (`"CEALIS_V3_G4_ATTESTATION_AUTHORITY_V3"` keccak-prefixed) |
| `authority_key_pubkey` | Phase 1: 32 bytes Ed25519 per canonical §1.1.3 line 40 / Phase 2: 65 bytes P-256 uncompressed per canonical §6.1.3 `authority_pubkey_ref::RootConstant` variant | The specific G4 attestation authority pubkey whose registration is valid at the commit's block |

**Preimage length:** Phase 1: 32 + 32 = **64 bytes**. Phase 2: 32 + 65 = **97 bytes**. Output: 32 bytes (keccak-256).

**Encoding author-locked at S2-1; the S2-2 G4AuthorityRegistry contract interface MUST honor this byte layout** per canonical §4.6.2 line 899 — same cross-spec pattern as §6.1.3 stanza[2] `authority_pubkey_ref` lock.

#### §12.3.2 Per-entry data shape

Per WP §M `wp.md:1006` + canonical line 901 + canonical lines 2391-2399 (§9 σ_G4 Phase 1):

```
G4AuthorityRegistry.entry[g4_authority_ref] → (
  binary_hash:          bytes32,           // Phase 1: keccak-256 of Cealis G4 sealed-code daemon binary
                                           // Phase 2: TEE enclave measurement
  effective_block:      uint64,            // RevealAuthorized block number from which entry is canonical
  tombstone_block:      uint64,            // 0 if non-tombstoned; otherwise block number of tombstone
  deprecation_flag:     DeprecationFlag,   // §12.8
  phase:                uint8,             // 1 (server scaffold) OR 2 (TEE)
  is_canonical:         bool,              // true if most recently added non-tombstoned non-deprecated entry
)
```

#### §12.3.3 Verification protocol (combiner-side, at commit's block)

1. Recover `g4_authority_ref` from `commit_AAD.g4_authority_ref` per §4.6.2.
2. Query `G4AuthorityRegistry.entry[g4_authority_ref]` at the commit's `RevealAuthorized` block per §12.6 at-commit-block reading discipline.
3. If entry does not exist at commit's block → abort with `ERR_G4_AUTHORITY_REGISTRY_MISMATCH` per §16 + canonical §9.5.1.
4. If `effective_block > commit_block` → entry not yet active → abort with `ERR_G4_AUTHORITY_NOT_YET_EFFECTIVE` per §16.
5. If `tombstone_block != 0 AND tombstone_block ≤ commit_block` → entry tombstoned before commit → abort with `ERR_G4_AUTHORITY_TOMBSTONED` per §16.
6. Phase-specific verification: Phase 1 verifies σ_G4 Ed25519 signature against entry's authority pubkey + binary_hash per §9.5.1; Phase 2 verifies DCAP quote's TEE enclave measurement against entry's binary_hash + cross-vendor mandate per §9.5.2 + §11.3.3. **Registry historical lookup at the commit's block IS load-bearing per canonical §15.6.1 byte-identity equation + §15.6.2 file_key invariant** — recipients verifying historical-generation σ_G4 use the original-generation authority key registered at the commit's block, NOT current authority key state; this is a load-bearing registry-historical-lookup property, NOT a σ-byte-invariance constraint (authority-key rotation is operational ceremony per S2-6, not a §15 invariant).

#### §12.3.4 Bound into commit

- **Field:** `commit_AAD.g4_authority_ref` (canonical §4.6.2 line 899)
- **Threat closed:** A04 — registry-race attack. Supports key rotation in `G4AuthorityRegistry` `(hash, effective_block, tombstone_block)` tuples per `flows-spec-final.md:199` without breaking historical commits — old commits verify under the registry entry that was valid at THEIR commit block per canonical line 901.

#### §12.3.5 G4 refusal signal

If deprecated BEFORE commit's block: G4 refuses σ_G4 with reason code `0x07 authority_deprecated` per §9 G4 reason-code enum + canonical line 902.

### §12.4 DSLVersionRegistry

The `DSLVersionRegistry` registers Claim DSL interpreter contract versions. Per canonical §3 line 506 + canonical §4 line 720 + WP §F `wp.md:521` + brief-07 §2:

#### §12.4.1 Canonical preimage form (architected-pending)

The canonical preimage form for `dsl_version_ref` is **NOT yet TAG-prefixed in canonical §2 / §4** as of S2-1. Per canonical §3 line 506 + §4 line 720, the field shape is:

```
dsl_version_ref = <32-byte registry entry key>   // raw 32-byte ref per canonical §4 line 720
```

| Field | Width | Source |
|---|---|---|
| `dsl_version_ref` | 32 bytes | `commit_AAD.dsl_version_ref` per canonical §4 line 720 — references DSLVersionRegistry entry key |

**BP-13 disposition (RESOLVED 2026-05-04):** `dsl_version_ref` is a raw 32-byte governance-assigned ref per §12.0 NORMATIVE class rule (class-CATALOG). DSLVersionRegistry's lookup key has no preimage role anywhere in V3 — it is a single field inside `commit_AAD`, domain-separated by `TAG_AAD_V3` upstream wrap (§4.3). Per-key TAG-prefix (`TAG_DSL_VERSION_V3`) is REJECTED — see `designs/v3-registry-class-discipline.md`.

**Precedent-set framing (post-2026-05-04):** the V3 registry-key TAG-prefix precedents are BP-3 (PluginHashRegistry) + BP-11 (SupersededCommitRegistry) + BP-14 (OracleRegistry per-leaf, 2026-05-04 ACCEPT). BP-4 (`rotation_log_anchor`) + BP-10 (`conditional_recipients_policy_digest`) + BP-12 (`rotation_authorization_digest`) are TAG-prefix discipline at OTHER preimage sites (stanza-payload anchor / commit_AAD field digest / PasskeyRotationLog ABI digest) under the universal §2.1 rule — they are NOT registry-key precedents. The earlier framing of "BP-3 + BP-4 + BP-10 + BP-11 + BP-12 generalized D6 discipline" as a 5-of-5 registry-key invariant was a category conflation; the actual registry-key precedent set is BP-3 + BP-11 + BP-14, and BP-13/BP-15 are class-CATALOG by §12.0.

#### §12.4.2 Per-entry data shape

```
DSLVersionRegistry.entry[dsl_version_ref] → (
  dsl_interpreter_contract_addr: bytes20,            // EVM contract address of the Claim DSL interpreter
  effective_block:               uint64,
  tombstone_block:               uint64,
  deprecation_flag:              DeprecationFlag,    // §12.8
  is_canonical:                  bool,
)
```

#### §12.4.3 Verification protocol (combiner-side, at commit's block)

1. Recover `dsl_version_ref` from `commit_AAD.dsl_version_ref` per §4.
2. Query `DSLVersionRegistry.entry[dsl_version_ref]` at the commit's `RevealAuthorized` block per §12.6.
3. If entry does not exist → abort with `ERR_DSL_VERSION_REGISTRY_MISMATCH` per §16.
4. If `effective_block > commit_block` → abort with `ERR_DSL_NOT_YET_EFFECTIVE` per §16.
5. If `tombstone_block != 0 AND tombstone_block ≤ commit_block` → abort with `ERR_DSL_TOMBSTONED` per §16.
6. Check `deprecation_flag` state per §12.8 + §12.8.4 in-flight protection.

#### §12.4.4 Bound into commit

- **Field:** `commit_AAD.dsl_version_ref` (canonical §4 line 720) + transitively via `pda_root.dsl_version` (canonical §3 line 506)
- **Threat closed:** Plugin attempts to use the wrong DSL interpreter for evaluating the commit's condition specs → caught at §14.2.1 step 8 registry deprecation snapshot check + §12.4.3 verification protocol.

#### §12.4.5 G4 refusal signal

If deprecated BEFORE commit's block: G4 refuses σ_G4 with reason code `0x08 dsl_deprecated` per §9 G4 reason-code enum + brief-07 §5.

### §12.5 OracleRegistry

The `OracleRegistry` registers oracle source pubkeys for ConditionEngine module evaluation. Per canonical §3 line 505 + canonical §4 line 721 + WP §F + brief-07 §2:

#### §12.5.1 Canonical preimage form (BP-14 LOCKED 2026-05-04)

The canonical preimage form for the oracle root is the Merkle root over the union of oracle IDs referenced by BOTH reveal and shred specs, each bound to its OracleRegistry entry at commit-time per canonical §3 line 505. **Per-leaf preimages are TAG-prefixed under `TAG_ORACLE_REGISTRY_V3` per BP-14 LOCKED 2026-05-04 (`designs/v3-registry-class-discipline.md`); OracleRegistry is class-CRYPTO per §12.0 NORMATIVE rule.**

```
oracle_id_i = keccak256(
  TAG_ORACLE_REGISTRY_V3        // 32 bytes per §2.3.4
  ‖ oracle_pubkey_or_addr        // variable per oracle_type per §12.5.2
)

oracle_references_root = MerkleRoot(
  SortedUnion({
    oracle_id_i  // for each oracle pinned by reveal-spec OR shred-spec
  })
)
```

| Field (per-leaf preimage) | Width | Source |
|---|---|---|
| `TAG_ORACLE_REGISTRY_V3` | 32 bytes | Per §2.3.4 (`"CEALIS_V3_ORACLE_REGISTRY_V3"` keccak-prefixed) |
| `oracle_pubkey_or_addr` | variable per `oracle_type` | Per `OracleRegistry.entry[oracle_id].oracle_pubkey_or_addr` per §12.5.2 (signed-feed: P-256 or P-384 pubkey; chain-event-emitter: 20-byte EVM address; etc.) |

| Field (Merkle root) | Width | Source |
|---|---|---|
| `oracle_references_root` | 32 bytes | `commit_AAD.oracle_references_root` per canonical §4 line 721 — Merkle root anchoring per-oracle entries |
| `oracle_id_i` (per leaf, after TAG-prefix) | 32 bytes per leaf | Per the preimage formula above |

**Rationale (BP-14 ACCEPT):** `oracle_id_i` participates as a Merkle-leaf preimage at `MerkleRoot(SortedUnion({oracle_id_i}))` construction. Per §12.0 class-rule: any registry whose lookup key participates as a keccak preimage at any construction site MUST be class-CRYPTO. Without per-leaf TAG-prefix, future Merkle trees in V3 would carry an inverted invariant ("must not collide with raw oracle_id"); per-leaf TAG-prefix forecloses cross-tree leaf substitution at the source. The TAG addition lands under §2.8.5 initial-Stage-2 drafting carve-out (no `commit_version` bump).

**Merkle ordering discipline:** sorted-union over per-leaf TAG-prefixed hash to ensure determinism + canonical-tree audit reproducibility (matches recipients_root sorted-rule per §10 Item #7 Option A split-rule decision; `TAG_RECIPIENT_LEAF_V3` and `TAG_ORACLE_REGISTRY_V3` are disjoint by construction so cross-tree leaf substitution is foreclosed under §2.2 collision-resistance).

#### §12.5.2 Per-entry data shape

```
OracleRegistry.entry[oracle_id] → (
  oracle_pubkey_or_addr: bytes,                      // variable per oracle type (P-256 / P-384 pubkey OR EVM contract address)
  oracle_type:           uint8,                      // 0x01 = signed-feed; 0x02 = chain-event-emitter; etc.
  effective_block:       uint64,
  tombstone_block:       uint64,
  deprecation_flag:      DeprecationFlag,            // §12.8
  is_canonical:          bool,
)
```

#### §12.5.3 Verification protocol (combiner-side, at commit's block)

1. Recover `oracle_references_root` from `commit_AAD.oracle_references_root` per §4.
2. For each oracle pinned by the commit's reveal-spec OR shred-spec, recover `oracle_id_i`.
3. Recompute `MerkleRoot(SortedUnion({oracle_id_i}))` and verify against `oracle_references_root`. Mismatch → `ERR_ORACLE_ROOT_MISMATCH` per §16.
4. Per oracle: query `OracleRegistry.entry[oracle_id_i]` at the commit's `RevealAuthorized` block per §12.6.
5. If entry does not exist → abort with `ERR_ORACLE_REGISTRY_MISMATCH` per §16.
6. If `effective_block > commit_block` → abort with `ERR_ORACLE_NOT_YET_EFFECTIVE` per §16.
7. If `tombstone_block != 0 AND tombstone_block ≤ commit_block` → abort with `ERR_ORACLE_TOMBSTONED` per §16.
8. Check `deprecation_flag` state per §12.8 + §12.8.4 in-flight protection.

#### §12.5.4 Bound into commit

- **Field:** `commit_AAD.oracle_references_root` (canonical §4 line 721) + transitively via `pda_root.oracle_references_root` (canonical §3 line 505)
- **Threat closed:** Oracle pubkey rotation post-commit → registry rotation does not retroactively change condition evaluation per canonical §3 line 505 + canonical §4.6 commit-time binding semantics.

#### §12.5.5 G4 refusal signal

If ANY oracle pinned in the commit's condition is deprecated BEFORE commit's block: G4 refuses σ_G4 with reason code `0x09 oracle_deprecated` per §9 G4 reason-code enum + brief-07 §5. The `0x09 oracle_deprecated` reason code is umbrella-class; per-oracle forensic granularity (which specific oracle within the commit's condition is deprecated) is carried via `G4RefusalRegistry.encrypted_reason_blob` per §9.4.4 encrypted-reason mode discipline + matches the per-curve split discipline pattern from §10/§11 wrap-around-vs-forensic ERR layering.

### §12.6 At-commit-block reading discipline (NORMATIVE)

Per WP §D `wp.md:387` + brief-07 §2 + canonical §11.4:

> *"Registry deprecation state at the authorization block, not current. The four V3 registries (PluginHashRegistry, G4AuthorityRegistry, DSLVersionRegistry, OracleRegistry) carry DeprecationFlags on individual entries (§F, §N). At reveal, the combiner reads deprecation state AT THE `RevealAuthorized` block — the block when G1 emitted the authorization for this ceremony — not at current state, for any entry pinned in the commit's AAD or referenced by the commit's condition evaluation."*

This discipline is the load-bearing mechanism for historical commit verifiability across registry rotations:

1. **PluginHashRegistry** read at commit's `RevealAuthorized` block per §12.2.3 — plugin binary rotations do NOT invalidate historical commits.
2. **G4AuthorityRegistry** read at commit's `RevealAuthorized` block per §12.3.3 — G4 authority key rotations do NOT invalidate historical commits per `(binary_hash, effective_block, tombstone_block)` tuple semantics.
3. **DSLVersionRegistry** read at commit's `RevealAuthorized` block per §12.4.3 — DSL interpreter rotations do NOT invalidate historical commits.
4. **OracleRegistry** read at commit's `RevealAuthorized` block per §12.5.3 — oracle pubkey rotations do NOT invalidate historical commits per canonical §3 line 505.
5. **QTSPRegistry** read at commit's `RevealAuthorized` block per §12.7.3 — QTSP root rotations / EU Trusted List removals do NOT invalidate historical QES-anchored σ_subject signatures per canonical §5.5.3 line 1135-1137.

The **distinction from in-flight protection** (§12.8.4 + WP §D `wp.md:387` + canonical §11.4 line 149): deprecation flags set AFTER `RevealAuthorized` do NOT halt the in-flight reveal ceremony per gate-signing-window architectural-halt-impossibility per WP §D `wp.md:402` + §14.2.1 step 8 registry deprecation snapshot check. The at-commit-block reading discipline is for HISTORICAL verifiability; in-flight protection is for active ceremony continuity. QTSPRegistry verification at the commit's block follows the same discipline (§12.7 verification protocol).

**Architectural-truth-template multi-substrate-variant INSTANCE callout (per §14.7.4 + §11.4 carry-forward):** §12's 5-registry at-commit-block reading discipline IS a §14.7.4 architectural-truth-template multi-substrate-variant pattern at the registry-historical-lookup substrate layer: five independent Cealis-governed registry substrates (Plugin / G4Authority / DSL / Oracle / QTSP) all enforce the same architectural truth ("historical commits remain verifiable across registry rotations") under different substrate variants (binary-hash registries with tuple semantics + DSL contract address registries + oracle pubkey registries with Merkle-root commitments + QTSP root registries with eIDAS metadata). Combined with §11.4's 6-substrate enumeration (LitV3Assignment + 5 V3 registries), the V2 system carries 6 historical-lookup substrates total under one architectural truth. §16 SHOULD callout this as architectural-truth-template multi-substrate-variant INSTANCE alongside §14.7.4 (combiner) + §13.6 Cealis-as-infrastructure-not-authority + §10.9 Mode 3 RESERVED enforcement chain + §11.4 endpoint attestation 6-substrate enumeration.

### §12.7 QTSPRegistry

The `QTSPRegistry` registers approved EU QTSPs whose QES is accepted as σ_subject when `qes_subject_required = true`. Per canonical §3 line 523 + canonical §5.5.3 + WP §F + brief-05 §4:

#### §12.7.1 Canonical preimage form (architected-pending)

The canonical preimage form for `qtsp_provider_ref` is the registry entry key per canonical §3 line 523 + §5.5.3:

```
qtsp_provider_ref = <32-byte registry entry key>   // per canonical §3 line 523 — references QTSPRegistry entry
```

| Field | Width | Source |
|---|---|---|
| `qtsp_provider_ref` | 32 bytes | `pda_root.qtsp_provider_ref` per canonical §3 line 523 — zeroed when `qes_subject_required = false` |

**BP-15 disposition (RESOLVED 2026-05-04):** `qtsp_provider_ref` is a raw 32-byte governance-assigned ref per §12.0 NORMATIVE class rule (class-CATALOG). QTSPRegistry's lookup key has no preimage role anywhere in V3 — it is a single field inside `pda_root` (transitively inside `commit_AAD`), domain-separated by `TAG_AAD_V3` upstream wrap (§4.3). eIDAS legal force lives at the entry-payload signed Trust List layer per §5.5.3 (Article 22), not at lookup-key derivation. Per-key TAG-prefix (`TAG_QTSP_PROVIDER_V3`) is REJECTED — see `designs/v3-registry-class-discipline.md`. Registry-key TAG-prefix precedent set (post-2026-05-04) is BP-3 + BP-11 + BP-14 (CRYPTO class); BP-4 / BP-10 / BP-12 are non-registry-key TAG-prefix sites under the universal §2.1 rule (per the §12.4.1 precedent-set framing).

**Zeroing semantics:** when `qes_subject_required = false`, the `qtsp_provider_ref` field is `0x00…00` (32 bytes of 0x00) per canonical §3 line 486 — per the D1 "zeroed when not applicable" rule.

#### §12.7.2 Per-entry data shape

Per WP §M `wp.md:1014-1018` + brief-05 §4 + brief-07 §2:

```
QTSPRegistry.entry[qtsp_provider_id] → (
  qtsp_root_pubkey:        bytes,                   // QTSP signature root (RSA ≥2048 / ECDSA P-256/P-384)
  qtsp_jurisdiction:       bytes2,                  // ISO 3166 alpha-2 country code (e.g., "DE", "FR")
  qtsp_eIDAS_status_url:   bytes,                   // EU Trusted List URL for current operational status
  qtsp_metadata:           bytes,                   // free-form metadata (display name, contact)
  effective_block:         uint64,
  tombstone_block:         uint64,
  deprecation_flag:        DeprecationFlag,         // §12.8
  is_canonical:            bool,
)
```

#### §12.7.3 Verification protocol (combiner-side, at commit's block)

Per canonical §5.5.3 line 1135-1137:

1. Recover `qtsp_provider_ref` from `pda_root.qtsp_provider_ref` per §3.3.4 (transitively bound into `commit_AAD` via `pda_root` field).
2. If `qtsp_provider_ref = 0x00…00` AND `qes_subject_required = false` → skip QTSP verification path; σ_subject verifies against WebAuthn passkey path per §5.4 OR EIP-712 wallet path per §5.6.
3. Otherwise: query `QTSPRegistry.entry[qtsp_provider_ref]` at the commit's `RevealAuthorized` block per §12.6.
4. If entry does not exist → abort with `ERR_QTSP_REGISTRY_MISMATCH` per §16.
5. If `effective_block > commit_block` → abort with `ERR_QTSP_NOT_YET_EFFECTIVE` per §16.
6. If `tombstone_block != 0 AND tombstone_block ≤ commit_block` → abort with `ERR_QTSP_TOMBSTONED` per §16.
7. Verify σ_subject's QTSP signature chain against `entry.qtsp_root_pubkey` per §5.5 (curve-specific verification per QTSP's published signing chain).
8. Check `deprecation_flag` state per §12.8 + §12.8.4 in-flight protection.

A QTSP rotating its signing root, being deprecated under the asymmetric registry governance per WP §F line 523, or being struck from the EU Trusted List leaves prior QES-anchored σ_subject signatures verifiable indefinitely against the original registry entry per canonical §5.5.3 line 1137.

#### §12.7.4 Bound into commit

- **Field:** `pda_root.qtsp_provider_ref` (canonical §3 line 523) — bound transitively via `pda_root` field in `commit_AAD`
- **Threat closed:** QTSP root rotation / EU Trusted List removal post-commit → registry rotation does not retroactively invalidate historical QES-anchored σ_subject signatures.

#### §12.7.5 G4 refusal signal

QTSPRegistry deprecation does NOT have a dedicated reason code in the `0x06`-`0x09` enum (which is plugin / authority / DSL / oracle). QTSP deprecation surfaces via per-commit `0x04 integrity_fail` per canonical §9 G4 reason-code enum + brief-07 §5. Recovery path: subject re-signs with a different (non-deprecated) QTSP per §5.5 + commits a new ceremony. (Future enum extension is governed by the WP §N TimelockController governance extensibility surface — additive registry entry under 7-day timelock per the same governance shape as §12.1.)

### §12.8 DeprecationFlag (NORMATIVE)

Per emergency-response design `:39-50` + brief-07 §3:

#### §12.8.1 Struct definition

```
DeprecationFlag {
  deprecated:                  bool,             // active deprecation flag
  deprecation_block_timestamp: uint64,           // block timestamp when flag was set
  deprecation_reason_code:     DeprecationReason, // 0x01 - 0x04 enum
  disclosure_cid:              bytes32,          // IPFS CID of full advisory
  disclosure_commit_hash:      bytes32,          // keccak256 of summary bytes for on-chain publication
  disclosure_verified_block:   uint64,           // set when publishDisclosure succeeds; 0 until then
  auto_clear_timestamp:        uint64,           // deprecation_block_timestamp + 72*3600
  is_canonical_at_set:         bool,             // true if entry was canonical at deprecation
}
```

#### §12.8.2 DeprecationReason enum (4 codes)

Per emergency-response design `:96-101`:

| Code | Meaning |
|---|---|
| `0x01` | Active exploit in the wild |
| `0x02` | Disclosed-but-unexploited vulnerability |
| `0x03` | Compromised operator/authority |
| `0x04` | Governance-initiated retirement |

#### §12.8.3 On-chain-verifiable disclosure flow

Per emergency-response design `:120-128` + brief-07 §3:

1. Multisig constructs advisory off-chain. Two parts: short summary (≤ 4 KiB, on-chain-publishable) + full advisory (on IPFS at `disclosure_cid`).
2. Multisig submits deprecation tx with `(entry_id, reason_code, disclosure_cid, disclosure_commit_hash = keccak256(summary_bytes))`. Flag active; `disclosure_verified_block = 0`.
3. Within 72h, any party calls `publishDisclosure(entry_id, bytes summary_content)`. Contract verifies `keccak256(summary_content) == disclosure_commit_hash`. If pass: emits `DisclosurePublished(entry_id, summary_content)`, sets `disclosure_verified_block = current_block`.
4. Size limit: `summary_content` ≤ 4096 bytes.

**If no `publishDisclosure` call lands within 72h:** flag auto-clears via `triggerAutoClear(entry_id)`.

**30-day re-deprecation cooldown:** after auto-clear, entry cannot be re-deprecated by CealisSecurityMultisig for 30 calendar days. Re-deprecation within cooldown requires TimelockController (7-day). Prevents ping-pong halts without accountability per emergency-response design `:140-142`.

#### §12.8.4 In-flight protection vs class-wide refusal carve-out

Per WP §D `wp.md:387` + emergency-response design `:144-168` + brief-07 §4:

The gate-signing window (σ_Lit collected → σ_G4 signed) is a **halt-impossibility window by architectural design** per WP §D `wp.md:402` + canonical §11.4 line 149 + canonical §14.2.1 step 8.

Halt-scope table:

| Commit state | Deprecation effect |
|---|---|
| **Pending** (no RevealAuthorized yet) | Halted — plugin refuses DEK derivation; G4 refuses σ_G4 under `0x06`-`0x09` |
| **Pre-RevealAuthorized** | Halted — G4 refuses authorization path |
| **In-flight** (RevealAuthorized + Lit assigned, pre-all-gates-signed) | Completes under deprecation state at authorization block — neither deprecation nor shred halts this window by architectural design |
| **Post-all-gates-signed** (pre-DEK-derive) | Completes — ceremony is cryptographically closed |
| **New ingestion** | Refused — 2-phase ingestion precheck refuses deprecated-entry references per emergency-response design `:202-208` + WP §F `wp.md:513` (S2-5 territory) |

**Opt-out code 0x0A** (per canonical line 2500 + brief-07 §5): on PDAs with `cealis_class_wide_halt_opt_out = true`, deprecation is ignored + reveal proceeds; G4 emits reason code `0x0A opt_out_active` in RevealArtifactBundle for downstream verifier transparency. Per legal-conform pass 2026-04-25, `cealis_class_wide_halt_opt_out` is forbidden on legal-effect PDAs.

**Encrypted-reason mode default for codes 0x02 + 0x03** per WP §N: G4RefusalRegistry stores `encrypted_reason_blob` rather than plaintext for these codes; on-chain event emits only `RefusalSignal(authorizationId, "refused")`. The encryption recipient is the partner-controlled refusal resolver key pinned for the PDA, not a subject-recipient key. If no partner resolver key is available, G4 fails closed and emits no plaintext fallback.

### §12.9 Cross-section integration with §11 + §14 + §9

The 5 V3 registries' verification protocols are INVOKED from §11.1 Check 3 + Check 4 (G3 + G4 attestation) + §14.2.1 step 1 (plugin) + step 8 (deprecation snapshot) + §9.5.1 / §9.5.2 (σ_G4 verification) + §5.5.3 (σ_subject QTSP path). §12 spec'd the unified protocol; §11 + §14 + §9 + §5 invoke it per their gate/attestation-specific verification flow. Cross-section integration:

- **§11.1 Check 3** (G3 committee pubkey lookup) consumes G3AuthorityRegistry equivalent (dcipher Randamu Threshold Association registry OR drand League of Entropy beacon chain — out of §12 Cealis-governed scope; spec'd at §8.2.4 + §8.3.4 + §11.4 entry 2)
- **§11.1 Check 4** (G4 authority attestation) consumes §12.3.3 G4AuthorityRegistry verification protocol (Phase 1: Ed25519 binary_hash; Phase 2: TEE measurement)
- **§14.2.1 step 1** (combiner pre-verify plugin hash check) consumes §12.2.3 PluginHashRegistry verification protocol — `commit_AAD.plugin_version_digest` matched against PluginHashRegistry-at-commit-block
- **§14.2.1 step 8** (combiner pre-verify registry deprecation snapshot check) consumes ALL 5 §12 registry verification protocols across the unified at-commit-block reading discipline
- **§9.5.1 / §9.5.2** (σ_G4 Phase 1 / Phase 2 verification) consume §12.3.3 G4AuthorityRegistry verification protocol per phase
- **§5.5.3** (σ_subject QTSP path verification) consumes §12.7.3 QTSPRegistry verification protocol when `qes_subject_required = true`

**§14.2.1 step 8 registry deprecation snapshot check** runs the unified §12 5-registry verification sequence; failures abort the combiner pre-verify with the registry-specific ERR codes per §16 (`ERR_PLUGIN_REGISTRY_MISMATCH` / `ERR_G4_AUTHORITY_REGISTRY_MISMATCH` / `ERR_DSL_VERSION_REGISTRY_MISMATCH` / `ERR_ORACLE_REGISTRY_MISMATCH` / `ERR_QTSP_REGISTRY_MISMATCH`) following the §11.5 wrap-around-vs-forensic discipline: registry-class-level umbrella `ERR_REGISTRY_VERIFICATION_FAILED` carries forensic per-registry sub-code per §16 forensic-layering pattern matching §14.5.

### §12.10 Storage discipline

The 5 V3 registry substrates follow the σ-as-authorization transport discipline pattern per §7.8 + §8.6 + §9.7 + §10.7 + §11.6 (gate signatures authorize share admission; their attestation substrates including registry state are non-PII auditor-readable):

| Substrate | Location | Storage | Discipline |
|---|---|---|---|
| `PluginHashRegistry` state | On-chain (Cealis governance contract on Base L1) | Per-rotation `(plugin_version_digest, effective_block, tombstone_block, deprecation_flag)` tuples | At-commit-block reading per §12.6 |
| `G4AuthorityRegistry` state | On-chain (Cealis governance contract on Base L1) | Per-rotation `(g4_authority_ref, binary_hash, effective_block, tombstone_block, deprecation_flag, phase)` tuples | At-commit-block reading per §12.6 + §11.4 + §11.6 |
| `DSLVersionRegistry` state | On-chain (Cealis governance contract on Base L1) | Per-rotation `(dsl_version_ref, dsl_interpreter_contract_addr, effective_block, tombstone_block, deprecation_flag)` tuples | At-commit-block reading per §12.6 |
| `OracleRegistry` state | On-chain (Cealis governance contract on Base L1) | Per-oracle `(oracle_id, oracle_pubkey_or_addr, oracle_type, effective_block, tombstone_block, deprecation_flag)` tuples | At-commit-block reading per §12.6 + per-oracle leaf binding via Merkle root per §12.5 |
| `QTSPRegistry` state | On-chain (Cealis governance contract on Base L1) | Per-QTSP `(qtsp_provider_id, qtsp_root_pubkey, qtsp_jurisdiction, qtsp_eIDAS_status_url, metadata, effective_block, tombstone_block, deprecation_flag)` tuples | At-commit-block reading per §12.6 |
| `DeprecationFlag` per-entry | On-chain alongside each registry entry | Per emergency-response design struct + 72h auto-clear + 30-day cooldown semantics | §12.8 + asymmetric governance per §12.1 |

The discipline matches the σ-as-authorization pattern at §7.8 + §8.6 + §9.7 + §10.7 + §11.6. Registry substrates are commit-time + reveal-time anchors; on-chain state is queried at commit's `RevealAuthorized` block to derive the authoritative entry semantics for that commit. Reveal-time consumes the same registry state without re-querying current state — at-commit-block discipline preserves historical commit verifiability across rotations.

### §12.11 Cross-reference index

This section consumes the following primitives and sections:

- **§1.2** endianness convention — `effective_block` (uint64 BE) + `tombstone_block` (uint64 BE) + `deprecation_block_timestamp` (uint64 BE) + `auto_clear_timestamp` (uint64 BE) + `disclosure_verified_block` (uint64 BE) per §1.2 BE-keccak-preimage convention.
- **§1.3.2** SCALE encoding rules + **§1.3.3** mixed pattern — registry entry on-chain serialization + DeprecationFlag struct serialization per §1.3.3.
- **§2 line 240** `TAG_G4_ATTESTATION_AUTHORITY_V3` — used at §12.3.1 G4AuthorityRegistry preimage form.
- **§2 line 255** `TAG_PLUGIN_VERSION_V3` — used at §12.2.1 PluginHashRegistry preimage form.
- **§3.3.4 D1** `qtsp_provider_ref` field — used at §12.7 QTSPRegistry binding.
- **§3 line 505** `oracle_references_root` — used at §12.5 OracleRegistry binding.
- **§3 line 506** `dsl_version` — used at §12.4 DSLVersionRegistry binding.
- **§4.6.1** `plugin_version_digest` construction — Q-W2-30 LOCKED 2026-04-25 per BP-3 + generalized D6 discipline.
- **§4.6.2** `g4_authority_ref` construction — V3 TAG-prefix discipline per BP-3 / BP-4 / BP-10 pattern.
- **§4 line 720** `dsl_version_ref` field — raw 32-byte ref; BP-13 resolved REJECT (class-CATALOG).
- **§4 line 721** `oracle_references_root` field — raw Merkle root with BP-14 resolved ACCEPT at the per-leaf OracleRegistry preimage.
- **§5.5.3** σ_subject QTSP path verification — invokes §12.7.3 QTSPRegistry verification protocol.
- **§9.5.1 / §9.5.2** σ_G4 Phase 1 / Phase 2 verification — invokes §12.3.3 G4AuthorityRegistry verification protocol per phase.
- **§11.1 Check 4** G4 authority attestation — invokes §12.3.3 G4AuthorityRegistry verification protocol.
- **§11.4** at-commit-block reading discipline — §12.6 carries the same discipline at the registry-historical-lookup substrate layer (5 of 6 substrates per §11.4 enumeration).
- **§14.2.1 step 1** combiner pre-verify plugin hash check — invokes §12.2.3 PluginHashRegistry verification protocol.
- **§14.2.1 step 8** combiner pre-verify registry deprecation snapshot check — invokes ALL 5 §12 registry verification protocols.

Forward-references (consumed by later sections):

- **§13** PasskeyRotationLog ABI standard — distinct substrate (per-account passkey rotation, not versioning registry); same at-commit-block reading discipline applies.
- **§15** Re-key ceremony — consumes G4AuthorityRegistry + PluginHashRegistry deprecation-snapshot mechanics at the new-stanza-addition step.
- **§16** error model: `ERR_REGISTRY_VERIFICATION_FAILED` (umbrella) + per-registry forensic sub-codes (`ERR_PLUGIN_REGISTRY_MISMATCH` / `ERR_PLUGIN_NOT_YET_EFFECTIVE` / `ERR_PLUGIN_TOMBSTONED` / `ERR_G4_AUTHORITY_REGISTRY_MISMATCH` / `ERR_G4_AUTHORITY_NOT_YET_EFFECTIVE` / `ERR_G4_AUTHORITY_TOMBSTONED` / `ERR_DSL_VERSION_REGISTRY_MISMATCH` / `ERR_DSL_NOT_YET_EFFECTIVE` / `ERR_DSL_TOMBSTONED` / `ERR_ORACLE_ROOT_MISMATCH` / `ERR_ORACLE_REGISTRY_MISMATCH` / `ERR_ORACLE_NOT_YET_EFFECTIVE` / `ERR_ORACLE_TOMBSTONED` / `ERR_QTSP_REGISTRY_MISMATCH` / `ERR_QTSP_NOT_YET_EFFECTIVE` / `ERR_QTSP_TOMBSTONED`) following §11.5 wrap-around-vs-forensic discipline.

S2-2 contract interface details (`CealisSecurityMultisig`, `EmergencyGovernance`, `publishDisclosure`, `triggerAutoClear`, per-registry contract surface) are S2-2 territory. Library SDK version pins are S2-3 territory. 2-phase ingestion API spec is S2-5 territory.

### §12.12 PII content statement

Registry verification substrates are PII-NONE at the cryptographic-construct layer. The 5 V3 registry substrates contain:

- **PluginHashRegistry entries** — canonical binary hash (immutable hash of `age-plugin-cealis-v3` build, non-PII per binary content addressing) + chain-state metadata (effective_block / tombstone_block, non-PII).
- **G4AuthorityRegistry entries** — Phase 1 binary_hash (Cealis G4 daemon binary hash, non-PII) OR Phase 2 TEE enclave measurement (immutable enclave hash, non-PII per DCAP attestation framing) + authority pubkey (operator-side cryptographic identity, non-PII) + chain-state metadata.
- **DSLVersionRegistry entries** — DSL interpreter contract address (operator-side cryptographic identity, non-PII) + chain-state metadata.
- **OracleRegistry entries** — oracle pubkey or address (operator-side cryptographic identity, non-PII) + oracle type (operator-side classification, non-PII) + chain-state metadata.
- **QTSPRegistry entries** — QTSP root pubkey (operator-side cryptographic identity, non-PII per eIDAS QTSP framing) + jurisdiction (ISO 3166 country code, operator-side metadata, non-PII) + EU Trusted List URL (operator-side metadata, non-PII).
- **DeprecationFlag struct** — reason codes + IPFS CIDs + disclosure summary hashes (operator-side governance metadata, non-PII).

No subject-identifying data appears at any layer of the registry verification path. The 5 registries are operator-side governance substrates (Cealis governance, EU QTSP authorities, oracle operators, DSL interpreter authors) — NOT subject-side identifiers.

The σ transport discipline per §7.1 + §9.1 protects share-admission integrity; the registry substrates are operator-side governance metadata that supports the σ-as-authorization model (combiner verifies σ values came from the correct operators per registered registry entries at the commit's block) WITHOUT introducing subject-side PII surface. The two protection layers are orthogonal: PII is protected by AEAD payload encryption per §6.4; registry verification integrity is protected by the 5-registry verification protocols per §12.2 / §12.3 / §12.4 / §12.5 / §12.7.

**Strict GDPR interpretation (Breyer C-582/14 + Recital 26): EXPLICITLY NOT APPLICABLE to §12 substrates** (matching §11.8 inverse-Breyer framing). Unlike §10.10 Mode 2 `wallet_address` (cross-partner-stable natural-person pseudo-identifier per §3.6 ¶3 + §4.9 ¶2 framework + §10.10 Breyer carry-forward), §12 registry substrates (PluginHashRegistry + G4AuthorityRegistry + DSLVersionRegistry + OracleRegistry + QTSPRegistry entries) carry only operator-side cryptographic identities (Cealis-governed binary hashes + authority pubkeys + DSL interpreter addresses + oracle pubkeys + QTSP roots + governance metadata) — NONE of these are natural-person identifiers, cross-partner-stable or otherwise. The Breyer C-582/14 third-party-observer-vs-controller-scope distinction at §10.10 + §13.10.1 framework does NOT apply to §12 substrates because there is no natural-person identifier in §12's substrate set to which the third-party-observer reachability surface could attach. §12's PII-NONE claim is structurally complete at the cryptographic-construct layer + operator-side substrate layer with no auditor-side strict-interpretation residue.

---

## §13 — PasskeyRotationLog ABI

This section specifies the ABI surface of `PasskeyRotationLog`, the on-chain ABI-standard contract carrying per-Cealis-account passkey rotation entries that supports Mode 1 (PASSKEY_ACCOUNT) conditional-recipient verification at reveal. Each entry is signed by the prior passkey's WebAuthn assertion; Cealis provides a canonical instance on Base L1 for V2 launch, but the contract is an **ABI standard, not a singleton** — recipients MAY use any ABI-compatible deployment.

The architectural framing is **Δ12 A1+Shamir LOCKED (Simon 2026-04-26)** + **BP-6 patched WP §M lines 1067-1069** + **A1+Shamir LOCKED (dw-lead disk-verified arbitration + worker-4 dual-cycle confirmation + dw-quality §6.3 cycle-2 APPROVED terminal verdict)** + **B5 HARD-5 PASSKEY_ACCOUNT repair (2026-05-06)**. Under A1+Shamir, each PasskeyRotationLog entry expands from the legacy Mode 1 design (see `designs/conditional-recipient.md` §61) to carry the explicit X25519 delivery/wrap pubkey and ML-KEM-768 hybrid PQ pubkey alongside the P-256 passkey pubkey at every entry. This subsection enumerates the expanded fields per entry, locks the entry preimage construction with TAG_ROTATION_LOG_ANCHOR_V3 prefix per BP-4, specifies the walk-from-anchor verification protocol used at reveal, and applies the §3.6 PII-NONE template to each entry pseudo-identifier.

### 13.1 Architectural lock — what PasskeyRotationLog is and is not

PasskeyRotationLog is an **on-chain ABI standard** that records WebAuthn-mediated passkey rotation events for Cealis accounts that participate as Mode 1 (PASSKEY_ACCOUNT) conditional-recipients on PDAs. The contract is append-only per account; rotation entries are signed by the **prior** passkey's WebAuthn assertion, ensuring rotation forgery requires compromising the prior passkey (which Cealis does not custody).

#### 13.1.1 What PasskeyRotationLog does

1. **Records** per-account append-only rotation entries on-chain. Each entry carries the passkey pubkey + explicit X25519 delivery/wrap pubkey + ML-KEM-768 hybrid-PQ pubkey + supporting metadata + the WebAuthn assertion that authorized this rotation under the prior passkey.
2. **Preserves** the chain-of-rotation walk-from-anchor protocol used at reveal: given a `rotation_log_anchor` snapshot from the original PDA-config commit, a verifier walks rotation entries forward to determine the current head pubkey set, validating each rotation's WebAuthn assertion under the prior pubkey.
3. **Anchors** Mode 1 stanza integrity: the `rotation_log_anchor` field in a PASSKEY_ACCOUNT stanza (§6.1.5 variant 0x01) commits the recipient's rotation-log head at PDA-config time. Subsequent rotations are visible to the verifier; any rotation that does not chain back to the anchor invalidates the recipient's σ_conditional.
4. **Provides** the canonical deployment on Base L1 (Cealis-operated UUPS proxy + 7-day TimelockController per S2-2 contracts spec); recipients MAY use any ABI-compatible alternative deployment per the censorship-mitigation property of WP §L item 14.

#### 13.1.2 What PasskeyRotationLog does NOT do

1. **Does not** allow Cealis (or any party) to forge a rotation. Each rotation entry's WebAuthn assertion must verify under the prior entry's `new_pubkey`; without the prior passkey's authenticator + user-presence ceremony, no valid assertion can be produced. Cealis cannot custody recipient passkeys (they live on recipient hardware authenticators).
2. **Does not** carry σ_conditional itself. σ_conditional is the WebAuthn assertion produced at **reveal** (over the §10.1 reveal_challenge digest), not the WebAuthn assertion stored in a rotation entry (which authorizes the rotation itself, not a reveal). The rotation log is the **infrastructure** that lets a verifier resolve `account_id → current_passkey_pubkey + current_delivery_pubkey_x25519 + current_mlkem_pubkey`; σ_conditional is verified separately under the resolved current_passkey_pubkey.
3. **Does not** mutate prior entries. Append-only per account — the on-chain enforcement guarantees no entry can be removed, edited, or reordered after publication. This is the core integrity property the §13.4 walk-from-anchor verification depends on.
4. **Does not** require Cealis-issued account_id to have semantic meaning. `account_id` is opaque, Cealis-issued, cross-partner stable — but it carries no PII content (per §13.10 PII-NONE defense). It is a routing identifier, not a recipient identity.
5. **Does not** require multi-chain deployment for V2. Base L1 only (per `designs/conditional-recipient.md` §81 + §325). Multi-chain `PasskeyRotationLog` deployment is a Stage-2+ consideration.

The conceptual model: PasskeyRotationLog is the **infrastructure** that makes Mode 1 PASSKEY_ACCOUNT conditional-recipient stanzas integrity-bound across the lifetime of the recipient's hardware authenticator(s). The system's enforcement does not rest on Cealis's honesty in operating the canonical deployment — recipients can self-publish via any ABI-compatible contract, and verifiers can walk any deployment that satisfies the ABI standard.

### 13.2 Per-entry data — explicit delivery key + hybrid PQ fields under A1+Shamir

Each `PasskeyRotationLog` entry is a SCALE-encoded struct. Per Δ12 A1+Shamir LOCKED + the per-stanza hybrid PQ wrap construction of §6.2 + the B5 HARD-5 repair, each entry expands from the legacy Mode 1 design (3 fields: `prev_pubkey` + `new_pubkey` + `webauthn_assertion`, plus `timestamp`) to **carry explicit X25519 delivery/wrap pubkeys and ML-KEM-768 pubkeys alongside the P-256 passkey pubkey at every entry**. P-256 authenticates WebAuthn assertions; X25519 + ML-KEM wrap/admit shares. No P-256-to-X25519 conversion exists.

#### 13.2.1 Entry struct definition

```
PasskeyRotationLogEntry {
    // ORIGINAL fields (per legacy Mode 1 design, conditional-recipient.md §67-§74)
    prev_pubkey:                    bytes65,    // P-256 passkey pubkey at entry i-1 (entry 0 special case: all-zero per §13.2.2)
    new_pubkey:                     bytes65,    // P-256 passkey pubkey at entry i
    timestamp:                      uint64,     // BE per §1.2 (block timestamp at entry publication)
    webauthn_assertion:             Bytes,      // SCALE Vec<u8>: WebAuthn signature by prev_pubkey over the rotation_authorization_digest (§13.3)
                                                // (entry 0 special case: empty Vec per §13.2.2)

    // NEW fields under A1+Shamir (Δ12 LOCKED 2026-04-26)
    prev_delivery_pubkey_x25519:       bytes32,    // X25519 delivery/wrap pubkey at entry i-1 (entry 0 special case: all-zero per §13.2.2)
    new_delivery_pubkey_x25519:        bytes32,    // X25519 delivery/wrap pubkey at entry i
    prev_mlkem_pubkey:              bytes1184,  // ML-KEM-768 pubkey at entry i-1 (entry 0 special case: all-zero per §13.2.2); per FIPS 203 ML-KEM-768 public-key encoding
    new_mlkem_pubkey:               bytes1184,  // ML-KEM-768 pubkey at entry i; per FIPS 203 ML-KEM-768 public-key encoding
    entry_index:                    uint32,     // BE per §1.2 (monotonic index per account; entry 0 is initial registration)
    contract_address:               bytes20,    // BE per §1.2 (the on-chain address of the PasskeyRotationLog contract instance — load-bearing for cross-deployment unambiguity in WebAuthn assertion preimages)
}
```

**Total per-entry SCALE byte budget:**
- `prev_pubkey`: 65 bytes (fixed-size)
- `new_pubkey`: 65 bytes (fixed-size)
- `timestamp`: 8 bytes (uint64, SCALE-LE)
- `webauthn_assertion`: variable (Compact<u32> length prefix + variable Bytes); typical WebAuthn assertion ≈ 70-200 bytes; entry 0 = 1 byte (empty Vec length prefix)
- `prev_delivery_pubkey_x25519`: 32 bytes (fixed-size, RFC 7748)
- `new_delivery_pubkey_x25519`: 32 bytes (fixed-size, RFC 7748)
- `prev_mlkem_pubkey`: 1184 bytes (fixed-size, ML-KEM-768 per FIPS 203)
- `new_mlkem_pubkey`: 1184 bytes (fixed-size, ML-KEM-768 per FIPS 203)
- `entry_index`: 4 bytes (uint32, SCALE-LE)
- `contract_address`: 20 bytes (fixed-size)

**Fixed-size sub-total:** 65 + 65 + 8 + 32 + 32 + 1184 + 1184 + 4 + 20 = **2594 bytes** per entry (excluding `webauthn_assertion`)
**Total per entry:** ~2594-2794 bytes depending on WebAuthn assertion length (≈ 2595 bytes for entry 0; ≈ 2660-2794 bytes for subsequent entries).

The ~2594-byte fixed-size baseline is dominated by the ML-KEM-768 pubkey pair (2368 bytes total, 91.3% of fixed-size baseline). This is the cost of the A1+Shamir hybrid PQ wrap construction at the rotation-log layer plus the explicit X25519 delivery/wrap key needed for Mode 1. Under a passkey-only design the wrap keys would not appear in the rotation-log, but that would reintroduce the invalid P-256-to-X25519 assumption; the per-entry storage cost is accepted per Rule 31 full-engine framing.

#### 13.2.2 Entry 0 special case

Entry 0 is the **initial passkey registration** at Cealis account creation. Per `conditional-recipient.md` §77: *"Entry 0 is the initial passkey registration; no signing required (subject inspection at PDA-config is the integrity anchor)."*

For entry 0:
- `prev_pubkey = 0x00...00` (65 bytes of zero)
- `prev_delivery_pubkey_x25519 = 0x00...00` (32 bytes of zero)
- `prev_mlkem_pubkey = 0x00...00` (1184 bytes of zero)
- `new_pubkey = subject's initial P-256 passkey pubkey`
- `new_delivery_pubkey_x25519 = subject's initial X25519 delivery/wrap pubkey`
- `new_mlkem_pubkey = subject's initial ML-KEM-768 pubkey`
- `webauthn_assertion = empty Vec<u8>` (1-byte SCALE Compact prefix `0x00`)
- `entry_index = 0`
- `timestamp = block timestamp at registration`
- `contract_address = the deployed PasskeyRotationLog contract address`

The integrity anchor for entry 0 is the **subject's pre-σ inspection of `initial_passkey_pubkey` + `initial_delivery_x25519_pubkey` + `initial_mlkem_pubkey`** via the mandatory `age-plugin-cealis-v3` subject-side verifier at PDA-config time (per WP §C lines 174-193 + §6.1.5 stanza variant 0x01). If the subject inspects the wrong pubkey (e.g., a substituted attacker pubkey in entry 0), the inspection fails the integrity anchor and the subject does not produce σ_subject. This is the anchoring mechanism that propagates downstream into the `rotation_log_anchor` snapshot at PDA-config commit time.

#### 13.2.3 Entry i ≥ 1 — rotation entries

For entry i ≥ 1 (any rotation event after initial registration):
- `prev_pubkey = entry[i-1].new_pubkey` (P-256)
- `prev_delivery_pubkey_x25519 = entry[i-1].new_delivery_pubkey_x25519` (X25519)
- `prev_mlkem_pubkey = entry[i-1].new_mlkem_pubkey` (ML-KEM-768)
- `new_pubkey = subject's new P-256 passkey pubkey for entry i`
- `new_delivery_pubkey_x25519 = subject's new X25519 delivery/wrap pubkey for entry i`
- `new_mlkem_pubkey = subject's new ML-KEM-768 pubkey for entry i` (rotated atomically with the passkey)
- `webauthn_assertion = WebAuthn assertion bytes signed by prev_pubkey` over the §13.3 rotation_authorization_digest
- `entry_index = i` (monotonic; verifier rejects out-of-order entries)
- `timestamp = block timestamp at entry publication`
- `contract_address = the deployed PasskeyRotationLog contract address`

The atomic rotation of the P-256 passkey + X25519 delivery key + ML-KEM-768 pubkey at every entry ensures that the rotation log's recipient identity (authentication key + hybrid wrap keys) remains internally consistent. A recipient cannot rotate one without rotating the others.

#### 13.2.4 Why X25519 + ML-KEM-768 pubkeys rotate with passkey under A1+Shamir

Per Δ12 A1+Shamir LOCKED, the per-stanza hybrid PQ wrap construction (§6.2) requires the recipient's X25519 and ML-KEM-768 pubkeys at PDA-config commit time (committed in stanza variant 0x01 as `initial_delivery_x25519_pubkey` + `initial_mlkem_pubkey` per §6.1.5). At reveal time, the σ_conditional for Mode 1 is verified under the **current** `new_pubkey` resolved by walking the rotation log from `rotation_log_anchor` forward (per §13.4); equivalently, the recipient's ability to **decrypt** their stanza's hybrid-PQ-wrapped `Shamir share` requires holding the **current** X25519 and ML-KEM-768 secret keys. Atomic rotation ensures these two surfaces (verification + decryption) refer to the same generation of recipient identity.

If the delivery/wrap pubkeys did NOT rotate atomically with the passkey, the per-stanza hybrid-PQ wrap would be tied to original-entry wrap keys (since `initial_delivery_x25519_pubkey` and `initial_mlkem_pubkey` are committed in the stanza); a recipient who rotated their passkey would still need old wrap secrets for decryption — defeating the operational hygiene of rotating the recipient identity together. Under A1+Shamir, the rotation log carries both wrap pubkeys at every entry so that verifiers can resolve the **current** wrap keys at reveal, enabling re-key ceremonies (§15) to add new-generation stanzas with the recipient's current X25519 + ML-KEM pubkeys rather than the original-entry pubkeys.

### 13.3 Rotation authorization digest — what the WebAuthn assertion signs

The WebAuthn assertion in `entry[i].webauthn_assertion` (for i ≥ 1) is signed by `entry[i-1].new_pubkey` over the **rotation_authorization_digest**:

```
rotation_authorization_digest = keccak256(
    TAG_ROTATION_AUTHORIZATION_V3
  ‖ contract_address                  [bytes20, BE]
  ‖ account_id                        [bytes32]
  ‖ entry_index                       [uint32, BE]
  ‖ new_pubkey                        [bytes65]
  ‖ new_delivery_pubkey_x25519        [bytes32]
  ‖ new_mlkem_pubkey                  [bytes1184]
  ‖ timestamp                         [uint64, BE]
)
```

Total preimage length: 32 (TAG) + 20 (contract_address) + 32 (account_id) + 4 (entry_index) + 65 (new_pubkey) + 32 (new_delivery_pubkey_x25519) + 1184 (new_mlkem_pubkey) + 8 (timestamp) = **1377 bytes**. Output: 32 bytes (keccak-256).

`TAG_ROTATION_AUTHORIZATION_V3` is registered in §2.3.5 per BP-12 LOCKED 2026-04-26 by dw-lead per generalized D6 V3 TAG-prefix discipline (same precedent as BP-3 / BP-4 / BP-5 / BP-9 / BP-10 / BP-11). Construction: `TAG_ROTATION_AUTHORIZATION_V3 = keccak256(bytes("CEALIS_V3_ROTATION_AUTHORIZATION_V3"))`. Use-site: WebAuthn assertion preimage in §13.3. designs/conditional-recipient.md §2 line 72 receives Rule 33 propagation patch on Simon ack at first-canonical-section checkpoint.

The `account_id` field in the digest is the recipient's Cealis-issued bytes32 opaque identifier, which is also referenced by Mode 1 stanza variant 0x01 (`account_id` field per §6.1.5 line 137). This binding ensures that a rotation authorized for one account cannot be replayed against another account's rotation log.

The `contract_address` field is included to disambiguate WebAuthn assertions across PasskeyRotationLog deployments — an assertion authorized for an account on the Cealis canonical deployment cannot be replayed against the same `account_id` on an alternative ABI-compatible deployment. This is the structural defense against cross-deployment replay that motivates including `contract_address` in the entry struct (§13.2.1) and in the rotation_authorization_digest preimage.

### 13.4 rotation_log_anchor — snapshot at PDA-config commit time

The Mode 1 stanza (variant 0x01 per §6.1.5) carries `rotation_log_anchor: bytes32` — a snapshot of the recipient's PasskeyRotationLog head at PDA-config commit time. The construction uses **TAG_ROTATION_LOG_ANCHOR_V3 prefix per BP-4 LOCKED 2026-04-25 by dw-lead generalized D6 V3 TAG-prefix discipline:**

```
rotation_log_anchor = keccak256(
    TAG_ROTATION_LOG_ANCHOR_V3
  ‖ contract_address                  [bytes20, BE]
  ‖ account_id                        [bytes32]
  ‖ entry_index_at_commit             [uint32, BE]
  ‖ entry_pubkey_at_commit            [bytes65]
  ‖ entry_delivery_pubkey_x25519_at_commit [bytes32]
  ‖ entry_mlkem_pubkey_at_commit      [bytes1184]
)
```

Total preimage length: 32 (TAG) + 20 (contract_address) + 32 (account_id) + 4 (entry_index_at_commit) + 65 (entry_pubkey_at_commit) + 32 (entry_delivery_pubkey_x25519_at_commit) + 1184 (entry_mlkem_pubkey_at_commit) = **1369 bytes**. Output: 32 bytes (keccak-256).

Field semantics:
- `entry_index_at_commit`: the rotation-log entry index pointed to by the anchor at PDA-config commit time. Most recipients onboard at entry 0 (`entry_index_at_commit = 0`); recipients who joined a PDA after rotating passkeys will have `entry_index_at_commit ≥ 1`.
- `entry_pubkey_at_commit`: the P-256 `new_pubkey` of the entry pointed to by the anchor (i.e., `entry[entry_index_at_commit].new_pubkey`).
- `entry_delivery_pubkey_x25519_at_commit`: the X25519 `new_delivery_pubkey_x25519` of the entry pointed to by the anchor.
- `entry_mlkem_pubkey_at_commit`: the ML-KEM-768 `new_mlkem_pubkey` of the entry pointed to by the anchor (i.e., `entry[entry_index_at_commit].new_mlkem_pubkey`).

The TAG-prefix `TAG_ROTATION_LOG_ANCHOR_V3` was added to the §2 registry under BP-4 LOCKED (per dw-lead routing 2026-04-25; preceded BP-9 / BP-10 / BP-11 in the generalized D6 stabilization sequence). The `designs/conditional-recipient.md` §2 line 51 receives a Rule 33 propagation patch noting the TAG-prefix discipline (post-canonical polish, no re-review).

The anchor commits the recipient's rotation-log state at PDA-config time — verifiers walk **from this anchor forward** (§13.5) to determine the current head at reveal time. The anchor itself does NOT change after PDA-config commit; rotation-log mutations after PDA-config commit are accumulated by the verifier walking the on-chain log.

### 13.5 Walk-from-anchor verification protocol

At reveal time, a verifier (recipient's plugin client, or an auditor) executes the following protocol to resolve `(account_id, rotation_log_anchor) → (current_passkey_pubkey, current_delivery_pubkey_x25519, current_mlkem_pubkey)`:

#### 13.5.1 Steps

1. **Read `rotation_log_anchor` from the Mode 1 stanza** (variant 0x01 per §6.1.5). Read `contract_address` from the same stanza (per §6.1.5 line 138; the stanza spec carries the `PasskeyRotationLog` contract address used by this recipient).
2. **Verify the anchor preimage.** Recompute `rotation_log_anchor` per §13.4 using `(contract_address, account_id, entry_index_at_commit, entry_pubkey_at_commit, entry_delivery_pubkey_x25519_at_commit, entry_mlkem_pubkey_at_commit)` and confirm equality with the stanza's `rotation_log_anchor` field. Mismatch → ERR_ROTATION_ANCHOR_MISMATCH (§13.7).
3. **Query the on-chain rotation log.** From `entry_index_at_commit`, read all subsequent entries on the `PasskeyRotationLog` contract at `contract_address`. Returns an ordered sequence `entry[entry_index_at_commit], entry[entry_index_at_commit + 1], …, entry[head]`.
4. **Verify each rotation's WebAuthn assertion.** For each `entry[i]` where `i > entry_index_at_commit`:
   - Recompute `rotation_authorization_digest` per §13.3 using `(contract_address, account_id, entry_index, entry[i].new_pubkey, entry[i].new_delivery_pubkey_x25519, entry[i].new_mlkem_pubkey, entry[i].timestamp)`.
   - Verify `entry[i].webauthn_assertion` under `entry[i-1].new_pubkey` (P-256 signature verification per WebAuthn spec) over the recomputed `rotation_authorization_digest`. Failure → ERR_ROTATION_WEBAUTHN_INVALID (§13.7).
   - Verify `entry[i].entry_index == entry[i-1].entry_index + 1` (monotonic). Failure → ERR_ROTATION_ENTRY_INDEX_NONMONOTONIC (§13.7).
   - Verify `entry[i].prev_pubkey == entry[i-1].new_pubkey` (passkey chain consistency). Failure → ERR_ROTATION_PASSKEY_CHAIN_BROKEN (§13.7).
   - Verify `entry[i].prev_delivery_pubkey_x25519 == entry[i-1].new_delivery_pubkey_x25519` (X25519 delivery-key chain consistency). Failure → ERR_ROTATION_DELIVERY_X25519_CHAIN_BROKEN (§13.7).
   - Verify `entry[i].prev_mlkem_pubkey == entry[i-1].new_mlkem_pubkey` (mlkem chain consistency). Failure → ERR_ROTATION_MLKEM_CHAIN_BROKEN (§13.7).
5. **Resolve current head.** `current_passkey_pubkey = entry[head].new_pubkey`; `current_delivery_pubkey_x25519 = entry[head].new_delivery_pubkey_x25519`; `current_mlkem_pubkey = entry[head].new_mlkem_pubkey`. If no rotations occurred since `entry_index_at_commit` (head == entry_index_at_commit), `current_passkey_pubkey = entry_pubkey_at_commit`, `current_delivery_pubkey_x25519 = entry_delivery_pubkey_x25519_at_commit`, and `current_mlkem_pubkey = entry_mlkem_pubkey_at_commit`.
6. **Verify σ_conditional under current_passkey_pubkey.** The recipient's σ_conditional for the reveal (per §10.1 Mode 1 reveal_challenge digest) is verified under `current_passkey_pubkey`. Failure → `ERR_SIGMA_CONDITIONAL_VERIFY_FAIL` (§16).
7. **Use current_delivery_pubkey_x25519 + current_mlkem_pubkey for conditional-recipient share recovery** (per §6.3 A1+Shamir). The recipient's hybrid-PQ stanza wrap (§6.2) uses the recipient's current X25519 and ML-KEM-768 secret keys for Shamir share recovery. The σ_conditional value for Mode 1 (the WebAuthn assertion) authorizes admission of that recovered share to §6.3.

#### 13.5.2 Walk integrity guarantees

The walk-from-anchor protocol has two cryptographic integrity guarantees:

1. **Chain integrity** — the chain of rotations from the anchor to the head is a sequence of WebAuthn assertions where each is signed by the prior entry's pubkey. An attacker cannot insert a rotation without producing a valid WebAuthn assertion under the prior pubkey. Compromising any single passkey along the chain only allows forward forgery from that point — earlier entries remain integrity-verified by the prior passkeys.
2. **Anchor integrity** — the `rotation_log_anchor` field in the Mode 1 stanza was committed at PDA-config commit time and is bound into `recipients_root` / `conditional_recipients_root` via the §3 Merkle tree, which is bound into `h_commit` (§3.4). The anchor cannot be substituted post-commit without changing `h_commit`, which would require a fresh PDA-config ceremony.

The composition of these two guarantees means: a verifier walking from a valid anchor to a current head is guaranteed to resolve the current pubkey set authorized by the recipient at every rotation along the walk. Any tampering at any layer (substituted anchor, forged rotation, reordered entries, missing entries) is caught by one of the verification steps.

#### 13.5.3 Walk performance + caching

For long-lived recipients with rotations (e.g., a recipient who has rotated passkeys 5-10 times over 5+ years on a long-retention PDA — typical operational profile for hardware authenticator replacement cycles), the walk cost is `O(N)` in the number of rotations since `entry_index_at_commit`. Caching strategies:

- **Recipient-side caching:** the recipient's plugin client may cache walk results per `(account_id, contract_address)` pair, invalidating on rotation event observed from on-chain monitoring.
- **Verifier-side trust assumption (NOT NORMATIVE):** verifiers MAY trust a recipient-provided `current_passkey_pubkey + current_delivery_pubkey_x25519 + current_mlkem_pubkey` claim if they independently verify the head entry's WebAuthn assertion under the claimed `prev_pubkey`, verify delivery-key + ML-KEM chain continuity, and verify the prev_pubkey chain continuity to the anchor — but this requires walking the chain anyway. There is no integrity-preserving way to skip the walk.

For typical V2 use cases (KYC-lending PDAs with retention windows of weeks to months), recipients rotate passkeys 0-3 times during any single PDA's lifetime, so walk cost is operationally bounded.

### 13.6 Cealis-as-infrastructure-not-authority property

Per WP §K item 9 + WP §L item 14, the trust framing for PasskeyRotationLog is explicit:

> **Cealis runs rotation-log INFRASTRUCTURE, not rotation AUTHORITY.**

What this means structurally:

1. **Cealis cannot forge rotations.** Each rotation requires the prior passkey's WebAuthn assertion. Cealis does not custody recipient passkeys (they live on recipient hardware authenticators — YubiKeys, Apple Secure Enclave, Windows Hello TPM, Android KeyMaster, etc.). Without the prior passkey, no valid WebAuthn assertion can be produced over the §13.3 rotation_authorization_digest.
2. **Cealis cannot substitute recipients.** Even if Cealis attempts to publish a fraudulent rotation entry, the verifier's walk-from-anchor protocol (§13.5) will reject it because the `webauthn_assertion` will not verify under the prior `new_pubkey`. The integrity anchor at entry 0 is the subject's pre-σ inspection of `initial_passkey_pubkey + initial_delivery_x25519_pubkey + initial_mlkem_pubkey` per §13.2.2; this anchors the entire rotation chain.
3. **Cealis CAN censor publication.** Cealis operates the canonical UX for registering new passkeys on the canonical Base L1 PasskeyRotationLog deployment; if Cealis refuses to publish a specific recipient's rotation, that rotation does not appear on the canonical deployment.
4. **Censorship mitigation: ABI-standard contract.** The PasskeyRotationLog is an ABI standard, not a singleton. Per WP §L item 14: *"recipients can self-publish their rotation via permissionless contract call on any ABI-compatible deployment."* The censored recipient may self-publish via direct contract call to the canonical Base L1 deployment (gas-paying themselves), or deploy/use any alternative ABI-compatible contract instance. The verifier's walk-from-anchor protocol works against any ABI-compatible deployment because `contract_address` is bound into `rotation_log_anchor` (§13.4) and into `rotation_authorization_digest` (§13.3).
5. **Worst-case substitution requires recipient passkey compromise.** For an adversary to substitute a recipient on a Mode 1 PASSKEY_ACCOUNT stanza, they must compromise the recipient's **current** passkey. This is outside Cealis's control (passkeys live on recipient hardware authenticators). No infrastructure compromise of Cealis can substitute recipients.

The PasskeyRotationLog is therefore a **convenience layer**, not an enforcement primitive. The cryptographic enforcement of recipient identity at reveal flows from WebAuthn under the recipient's hardware-authenticator-protected passkey, not from Cealis's operation of the canonical deployment.

### 13.7 Error model

| Error code | Trigger | Recovery |
|---|---|---|
| `ERR_ROTATION_ANCHOR_MISMATCH` | Recomputed `rotation_log_anchor` per §13.4 does not equal stanza's `rotation_log_anchor` field | Stanza is corrupt or attacker-substituted; verifier rejects the σ_conditional contribution; recipient unable to recover via this stanza; reveal aborts if recipient's stanza is required for σ_conditional |
| `ERR_ROTATION_WEBAUTHN_INVALID` | An `entry[i].webauthn_assertion` (for i > entry_index_at_commit) fails P-256 signature verification under `entry[i-1].new_pubkey` over the recomputed `rotation_authorization_digest` | Walk-from-anchor protocol rejects the entry; rotation chain is broken; verifier cannot resolve current head; σ_conditional rejected (cannot determine current_passkey_pubkey to verify against) |
| `ERR_ROTATION_ENTRY_INDEX_NONMONOTONIC` | An `entry[i].entry_index != entry[i-1].entry_index + 1` | Indicates an out-of-order entry on-chain — would only occur from a contract bug or storage corruption (real PasskeyRotationLog deployments enforce monotonic index at the contract layer per S2-2 spec); verifier aborts walk and rejects σ_conditional |
| `ERR_ROTATION_PASSKEY_CHAIN_BROKEN` | An `entry[i].prev_pubkey != entry[i-1].new_pubkey` (passkey chain inconsistency) | Passkey chain consistency violation — would only occur from contract bug, storage corruption, or a fraudulent entry that somehow passed WebAuthn verification (the latter requires prior-passkey compromise + producing a chain-inconsistent next entry, which is a contract-layer bug since legitimate WebAuthn rotation flows produce chain-consistent entries by construction); verifier aborts walk |
| `ERR_ROTATION_DELIVERY_X25519_CHAIN_BROKEN` | An `entry[i].prev_delivery_pubkey_x25519 != entry[i-1].new_delivery_pubkey_x25519` (X25519 chain inconsistency) | Delivery/wrap-key chain consistency violation; verifier aborts walk and rejects σ_conditional contribution. |
| `ERR_ROTATION_MLKEM_CHAIN_BROKEN` | An `entry[i].prev_mlkem_pubkey != entry[i-1].new_mlkem_pubkey` (mlkem chain inconsistency) | ML-KEM-768 chain consistency violation — same trigger family as passkey chain break (contract bug, storage corruption, or fraudulent entry); distinct error code allows per-curve diagnostics during forensic incident response; verifier aborts walk |
| `ERR_ROTATION_LOG_UNREACHABLE` | The `contract_address` does not respond to on-chain query (RPC failure, contract not deployed, contract paused) | Verifier surfaces operational error; recipient may need to retry; if persistent, recipient may need to walk an alternative ABI-compatible deployment per the censorship-mitigation property of §13.6 |
| `ERR_ROTATION_LOG_HEAD_UNAVAILABLE` | The `rotation_log_anchor` references an `entry_index_at_commit` that exceeds the contract's current head index (impossible under normal operation; sentinel for storage corruption or contract reset) | Contract reset / migration scenario — falls through to S2-6 operational ceremony for re-anchoring; recipient PDA may need re-config |

These are §13-specific extensions to the §16 unified error model. The §16 spec consumes this table and integrates with the broader error taxonomy.

### 13.8 Re-key ceremony interaction

Per §15.4.2 step 5 (Mode 1 PASSKEY_ACCOUNT interactive WebAuthn at re-key): *"The new-generation stanza is added to the envelope. The recipient's `entry_index` in the PasskeyRotationLog is updated to reflect the new generation (per §13 — append-only log)."*

Re-key ceremony interaction with PasskeyRotationLog:

#### 13.8.1 What happens in the rotation log at re-key

A re-key ceremony does **NOT** force a passkey rotation — recipients participating in a re-key ceremony continue to use their **current** passkey + X25519 delivery key + ML-KEM pubkey (whatever the head entry of their rotation log is at the time of re-key). The re-key ceremony's WebAuthn assertion (per §15.4.2 step 3) is signed by the recipient's current passkey over the §10.1 reveal_challenge digest evolved for the new commit_AAD_v2 binding (per §15.2 BP-2 supersession lineage); this is the same WebAuthn ceremony the recipient performs at any reveal. The X25519 + ML-KEM keys are used only for stanza share wrapping/recovery and are never derived from the P-256 passkey.

The recipient's **rotation log itself is not appended to** as part of a re-key ceremony — re-key adds new-generation stanzas to the envelope with a new `rotation_log_anchor` reflecting the recipient's current rotation-log head at re-key time, but does NOT mutate the rotation log's entry sequence (the rotation log only mutates when the recipient rotates a passkey, an event independent of re-key timing).

#### 13.8.2 What changes in the recipient's stanza at re-key

Per §15.4.2 + §13.2.4, the new-generation Mode 1 stanza added at re-key carries:
- A new `rotation_log_anchor` reflecting the recipient's current rotation-log head at re-key time (`entry_index_at_commit_v2 = current_head_at_rekey`).
- The recipient's current `entry_pubkey_at_commit_v2`, `entry_delivery_pubkey_x25519_at_commit_v2`, and `entry_mlkem_pubkey_at_commit_v2` (drawn from the head entry at re-key time).
- The recipient's per-stanza hybrid-PQ wrap (§6.2) of the same `Shamir share_s` value (per §6.2.7 A1+Shamir invariant: Shamir share VALUES are frozen at original commit + only WRAP primitives change at re-key) but wrapped under the recipient's CURRENT X25519 delivery key + ML-KEM-768 pubkey (which may differ from the original-commit `initial_delivery_x25519_pubkey` + `initial_mlkem_pubkey` if the recipient has rotated since the original commit).

This means recipients who have rotated their passkey + delivery/wrap keys since the original commit will, after re-key, have a new-generation stanza wrapped under their CURRENT X25519 + ML-KEM-768 pubkeys — making the wrap recoverable using the recipient's current X25519 + ML-KEM-768 secret keys. The original-generation stanza remains in the envelope wrapped under the original-commit `initial_delivery_x25519_pubkey` + `initial_mlkem_pubkey`; if the recipient still holds those original-generation secret keys (e.g., they have not rotated since commit, or they archived the secrets), they can recover via either generation.

#### 13.8.3 Recipient-side rotation handling between commit and re-key

If a recipient rotates their passkey + X25519 delivery key + ML-KEM pubkey **after** original commit but **before** re-key, they continue to be a valid Mode 1 PASSKEY_ACCOUNT recipient (the verifier walks from `rotation_log_anchor` forward to the current head per §13.5) but their stanza-recovery requires holding the **original-commit** X25519 + ML-KEM-768 secret keys (since `initial_delivery_x25519_pubkey` + `initial_mlkem_pubkey` in the original-generation stanza were set at original commit). If the recipient discarded the original-commit delivery/wrap secret keys during rotation (typical operational hygiene — secret keys are typically destroyed when rotated out), they cannot recover via the original-generation stanza.

The re-key ceremony resolves this gap: at re-key, the new-generation stanza wraps the same `Shamir share_s` VALUE under the recipient's CURRENT X25519 + ML-KEM-768 pubkeys, so the recipient can recover via the new-generation stanza using their CURRENT delivery/wrap secret keys.

This is the operational reason re-key requires interactive recipient participation (per §15.4.2): the new-generation stanza must wrap under the recipient's current delivery/wrap public keys, which only the recipient can present through the WebAuthn authorization + X25519/ML-KEM keygen ceremony.

### 13.9 Cross-section consistency notes

#### 13.9.1 §6.1.5 stanza variant 0x01 alignment

The `rotation_log_anchor` formula in §6.1.5 (cycle-2 final + BP-4 patched) and the §13.4 formula here are **identical** — the same TAG-prefix preimage construction. The §6.1.5 stanza spec is the consumer; the §13 spec is the producer (the on-chain contract enumeration that generates the entries the anchor snapshots). Cross-section consistency verified: same field names + same widths + same TAG.

#### 13.9.2 §10.1 Mode 1 reveal_challenge digest alignment

The `reveal_challenge` digest formula at WP §387:

```
reveal_challenge = keccak256(
    TAG_REVEAL_CHALLENGE_V3
  ‖ authorizationId
  ‖ h_commit
  ‖ account_id
  ‖ role_tag
  ‖ stanza_index
  ‖ reveal_block_hash
)
```

is the input to σ_conditional under the **current_passkey_pubkey** resolved by the §13.5 walk-from-anchor protocol. §10.1 (writer-B's future task) will spec this digest's exact byte budget + endianness; §13 establishes the walk that yields current_passkey_pubkey.

#### 13.9.3 §6.3 σ_conditional authorization evidence

σ_conditional from a Mode 1 PASSKEY_ACCOUNT recipient is the WebAuthn assertion bytes (P-256 signature, ≥ 64 bytes per WP §388) over the §13.9.2 reveal_challenge digest. σ_conditional is an authorization signature / attestation output AND authorization evidence, not DEK material or HKDF input. A valid σ_conditional authorizes admission of the matching conditional-recipient Shamir share recovered from the recipient stanza; it does not itself become a Shamir input. Anyone observing σ values alone still lacks the released shares / decap material required for §6.3 `Shamir.combine`.

#### 13.9.4 §15 re-key ceremony alignment

§15.4.2 step 5 cites §13's append-only log discipline. §13.8 above specifies the rotation-log behavior at re-key (no rotation-log mutation; new-generation stanza wraps under current-head delivery/wrap pubkeys). §15.6.1 share-value invariance across generations holds because re-key preserves the same indexed Shamir shares. Recipient rotations affect only the recipient's own stanza wrap layer (§6.2) and recovery path, not the DEK, Shamir polynomial, or share values.

### 13.10 PII content statement

PII content of every field in `PasskeyRotationLogEntry` and in `rotation_log_anchor`: **NONE**. All inputs are cryptographic pubkeys, opaque Cealis-issued identifiers, on-chain platform addresses, monotonic counters, or block timestamps. Pseudo-identifier protection inherits transitively from the §3.6 PII-NONE template applied per-field below.

#### 13.10.1 Per-field PII-NONE defense

Modeled on canonical §3.6 ¶3 pseudo-identifier protection paragraph; applies the same keccak preimage-resistance + per-onboarding nonce + cross-partner-stable-but-PDA-derived defense pattern to each entry pseudo-identifier:

- **`prev_pubkey` (P-256 passkey, bytes65):** WebAuthn / FIDO2 cryptographic pubkey, device-side. Generated by recipient's hardware authenticator (Apple Secure Enclave / Windows Hello TPM / YubiKey / Android KeyMaster). Carries no subject-PII content; the device-side pubkey is structurally a cryptographic public key, not an identifier of the natural person operating the device. Cross-partner unlinkability holds because the same recipient operating the same hardware authenticator produces a different pubkey per Cealis-account (per WebAuthn's account-scoped key-pair generation per FIDO2 spec); cross-deployment unlinkability holds because pubkeys per account differ across PasskeyRotationLog deployments.

- **`new_pubkey` (P-256 passkey, bytes65):** Same defense as `prev_pubkey`. Each rotation generates a fresh keypair via WebAuthn ceremony; the previous pubkey is retired and the new pubkey is registered. No subject-PII content.

- **`prev_delivery_pubkey_x25519` (X25519, bytes32):** RFC 7748 cryptographic public key generated by the recipient's plugin client at account creation or rotation event. It is not derived from the P-256 passkey, wallet address, KYC artifact, or any subject-identifying data. Carries no subject-PII content; structurally a delivery/wrap public key used for stanza share recovery only.

- **`new_delivery_pubkey_x25519` (X25519, bytes32):** Same defense as `prev_delivery_pubkey_x25519`. Each rotation generates a fresh X25519 keypair atomically with the passkey + ML-KEM key rotation. No subject-PII content.

- **`prev_mlkem_pubkey` (ML-KEM-768, bytes1184):** Per FIPS 203 ML-KEM-768 public-key encoding. Generated by recipient's plugin client at account creation or rotation event; not derived from any subject-identifying data. Carries no subject-PII content; structurally a post-quantum-secure cryptographic public key. Cross-partner unlinkability holds via per-account ML-KEM-768 keygen.

- **`new_mlkem_pubkey` (ML-KEM-768, bytes1184):** Same defense as `prev_mlkem_pubkey`. Each rotation generates a fresh ML-KEM-768 keypair atomically with the passkey rotation. No subject-PII content.

- **`timestamp` (uint64):** On-chain block timestamp at entry publication. Carries no subject-PII content; the timestamp is a public ledger property not tied to subject identity.

- **`webauthn_assertion` (Bytes):** WebAuthn signature over the §13.3 rotation_authorization_digest. Carries the assertion's clientDataJSON + authenticatorData + signature per WebAuthn spec. The clientDataJSON contains the type + challenge + origin (Cealis-specified, not subject-identifying) but NO subject-identifying fields under WebAuthn's design. authenticatorData contains the rpIdHash (Cealis domain hash, not subject-identifying) + flags + counter + attestation data (per WebAuthn spec the attestation data may be omitted at non-registration assertions, which rotation entries are). No subject-PII content.

- **`entry_index` (uint32):** Monotonic counter per account. Carries no subject-PII content; structurally a sequence number.

- **`contract_address` (bytes20):** On-chain platform identifier of the PasskeyRotationLog contract. Carries no subject-PII content; structurally a public ledger address.

- **`account_id` (bytes32, used in §13.3 + §13.4 preimages):** Cealis-issued opaque identifier. Cross-partner stable (the same recipient appears under the same `account_id` across all PDAs they participate in as conditional-recipient) — but PDA-derived-not-subject-identifying. The Cealis `account_id` is generated at Cealis-account creation as a random opaque identifier; it is NOT a hash of any subject-identifying data, NOT a deterministic function of any KYC artifact, NOT linkable to any subject-PII without access to Cealis's internal account-creation database (which is closed-source per WP §K item 5 + §M closed-source vault discipline). Cross-deployment linkability of `account_id` is a feature, not a bug — recipients carry their `account_id` across all Mode 1 PDA participations to avoid re-onboarding overhead. The cross-partner-stability does NOT leak subject-PII because the `account_id` itself does not encode any PII; it is an opaque routing identifier.

   **Strict GDPR interpretation note.** Under a strict reading of GDPR Art. 4(1) "personal data" definition (Recital 26 + Breyer C-582/14), an opaque cross-partner-stable identifier becomes "personal data" for any controller who has the **means reasonably likely to be used** to link the identifier to a natural person. For a third-party observer with no access to Cealis's internal account-creation database, the `account_id` is not personal data (no reasonably-likely linkage path exists). For Cealis itself, the `account_id` IS personal data within Cealis's controller-scope (Cealis can link `account_id` → subject identity via its internal database). The on-chain publication of `account_id` in PasskeyRotationLog entries therefore does not create a new public PII surface — the linkage capability stays with Cealis as controller, governed by Cealis's existing data-processing legal basis per WP §K item 5 + the §M closed-source vault discipline. The cross-partner-stable property is a routing convenience for recipients participating in multiple PDAs, not a public re-identification surface.

#### 13.10.2 PII NONE claim verified

None of the above inputs contains personally-identifiable information about the subject. The cryptographic pubkeys + opaque identifiers + platform addresses + monotonic counters + block timestamps are all structurally non-PII per the GDPR Art. 4(1) definition (a pseudo-identifier without a key to subject identity is not personal data within the meaning of Art. 4(1) for the holder of the pseudo-identifier, modulo recipient-side compromise of the recipient's hardware authenticator which is outside the scope of this spec layer).

The cross-partner-stable property of `account_id` is the closest approximation to a pseudo-identifier — but per §3.6 ¶3 framework, pseudo-identifiers are protected by (a) the cryptographic abstraction that prevents recovery of subject-PII from the pseudo-identifier alone, and (b) the closed-source operational layer at Cealis that holds the account-creation database. The `account_id` is therefore a cross-partner routing token that does not by itself disclose subject-PII to any party that does not already hold it via Cealis's internal database access (which Cealis controls and audits per the AuditLogger discipline of WP §C).

---

## §14 — Combiner protocol

This section specifies the recipient-side combiner protocol — the sealed binary that gathers σ values from the gates, runs the pre-verify checklist, verifies σ values as authorization evidence, decapsulates the per-stanza wraps to recover Shamir share values, reconstructs `file_key` via §6.3 `Shamir.combine`, and hands `file_key` to the §6.4 AEAD payload decryption. The combiner is the **last cryptographic step** in the V3 reveal flow; everything downstream is plaintext delivery (per §D RevealArtifactBundle assembly).

The architectural framing is **Δ12 A1+Shamir LOCKED (Simon 2026-04-26)** + **A1+Shamir LOCKED (dw-lead disk-verified arbitration + worker-4 dual-cycle confirmation + dw-quality §6.3 RECONSIDERED APPROVED)**, repaired by the B5 4-gate access-structure decision. Under A1+Shamir, the combiner reconstructs `file_key` once via §6.3 `Shamir.combine` over recovered typed shares admitted only after the matching σ values verify; per-stanza hybrid PQ wraps decapsulate independently to recover Shamir share values; AEAD decryption (§6.4) under `file_key` produces plaintext. The combiner runs in a **sealed binary**, **recipient-side**, **never network-exposed**, **never plaintext-PII-touching beyond DEK derivation** — these four properties are normative location constraints that flow from WP §J σ-as-authorization discipline + WP §K item 3 closed-source vault + WP §M storage discipline.

**Cross-references in this spec:** §1.1 (primitive abbreviations: σ_Lit / σ_G3 / σ_G4 / σ_conditional / DEK / file_key), §1.7 (error code conventions), §2 (TAG_*_V3 registry), §3.4 (h_commit re-derivation under the acyclic commit schedule), §4 (commit_AAD round-trip), §6.1 (stanza format), §6.2 (per-stanza hybrid PQ wrap), §6.3 (typed hierarchical Shamir access structure — file_key reconstruction formula), §6.4 (ChaCha20-Poly1305 AEAD payload), §11 (endpoint attestation 4-check), §12 (registry verification at RevealAuthorized block), §13 (PasskeyRotationLog walk-from-anchor for σ_conditional Mode 1), §15 (re-key ceremony — generation handling), §16 (unified error model — combiner error codes integrate here).

**Cross-references outside this spec:** WP §B P22 (σ-as-authorization discipline normative anchor), WP §D §400-§434 (combiner pre-verify checklist + RevealArtifactBundle assembly source), WP §J share secrecy framing + combiner location, WP §K item 3 (closed-source vault + combiner sealed-binary discipline), `designs/conditional-recipient.md` §90-§97 (walk-from-anchor protocol referenced from σ_conditional Mode 1), S2-2 smart-contracts-spec (on-chain registry contracts the combiner queries), S2-3 SDK version pins (combiner library version policy + σ-handling constraints), S2-5 ingestion-delivery-API (recipient-facing reveal initiation API; combiner runs inside the recipient's plugin client called from this API), S2-6 operational-ceremonies-spec (combiner sealed-binary release ceremony + reproducible-build verification).

### 14.1 Combiner location discipline

The combiner is a **sealed binary** running **recipient-side** (or at a non-custodial combiner-as-a-service that the recipient delegates to and that never retains σ values per WP §J §424). The location discipline is normative — violations collapse the V3 disjoint-operator composition at the last cryptographic step.

#### 14.1.1 The four normative location constraints

1. **Sealed binary.** The combiner is distributed as a binary whose integrity is verified against `plugin_version_digest` registered in `PluginHashRegistry` per §12. Recipients (or their plugin clients) verify the loaded binary's hash matches the on-chain registered hash before the binary executes any σ-handling code. This prevents combiner substitution attacks where a malicious binary would forward σ values out-of-band to an attacker.
2. **Recipient-side.** The combiner runs on hardware controlled by the recipient — recipient laptop, recipient server, recipient-trusted TEE, or a non-custodial combiner-as-a-service that the recipient explicitly delegates to and that does not retain recovered shares or DEK material. The combiner is **NOT** Cealis-operated; a Cealis-operated combiner would sit at the convergence point where verified σ values authorize share admission and recovered shares reconstruct `file_key`, collapsing the V3 4-gate disjoint-operator composition (per WP §J §424).
3. **In-flight σ redaction; post-reveal artifact carve-out.** During the combiner's σ-handling window — from σ arrival via §14.4 confidential delivery channels through §14.2 pre-verify + §6.3 share recovery — σ values MUST NOT be logged at the structured-log layer, MUST NOT be debug-traced or emitted to stderr/trace files, MUST NOT be exfiltrated via any wire protocol other than the §14.4 channel along which they arrived, and MUST NOT be cached in any persistent or shared-memory surface accessible to other processes. In-flight σ redaction prevents accidental leak via observability tooling and IPC surfaces during the verification window. **However**, σ values are authorization evidence per §0.3 + §14.3 + WP §B P22 + WP §D §417 — not key material — and verified σ values MAY appear in the post-reveal `RevealArtifactBundle` (per WP §D §417 + S2-5 §4 `sigma_block`) and in subject-facing or audit-facing exports of that artifact for §371a ZPO chain-of-custody and WP §B P22 verification by the recipient and downstream verifiers. The post-reveal artifact carve-out applies only AFTER successful §14.2 verification + §6.3 share recovery; an aborted reveal MUST zeroize σ buffers per §14.4.2 and MUST NOT publish σ values, since the artifact for an aborted reveal is undefined. The actual cryptographic-layer secrets — recovered Shamir shares, KEM decap material, Shamir interpolation intermediates, the reconstructed DEK, and AEAD-decrypted plaintext (until handed off to the §14.1.1 constraint 4 plaintext-delivery layer) — MUST NOT cross the combiner's process boundary in any direction. The only cryptographic-layer output crossing the boundary is `file_key` (32 bytes) consumed in-process by the §6.4 AEAD decryption step within the same in-process boundary; verified σ values are handed separately to the recipient artifact assembly layer per §14.4.3 + WP §D §417.
4. **Never plaintext-PII-touching beyond DEK derivation.** The combiner's role ends at `file_key` derivation + AEAD decryption (§6.4). The plaintext payload that emerges from AEAD decryption is delivered to the recipient via the recipient-trusted plaintext-handling layer (per WP §D §432-§434 RevealArtifactBundle assembly + per-recipient schema-selector filtering); the combiner itself does not retain or process plaintext after handing it to the delivery layer. This separates cryptographic key-handling (combiner) from plaintext-handling (recipient delivery), reducing the surface area of any single component that touches both.

#### 14.1.2 The combiner is NOT Cealis-operated

Per WP §J §424:

> *"The combiner runs on the recipient side or at a combiner service the recipient delegates to that does not retain the σ values. It is not a Cealis-operated component."*

Under A1+Shamir's 4-gate composition (Δ12 LOCKED + B5 repaired access structure), the same property holds with σ_conditional as authorization evidence for the recipient branch per §6.3 — a Cealis-operated combiner would control the convergence point where verified σ values admit shares and recovered shares reconstruct `file_key`. The combiner location discipline is therefore the **last load-bearing piece** of the V3 disjoint-operator security argument; without it, gate refusals (e.g., G4 refuses σ_G4 per WP §J §410) would be operationally meaningful only against a non-Cealis combiner.

S2-6 specifies the operational ceremonies for combiner sealed-binary release (reproducible-build verification, signed-binary distribution channels, recipient-side hash-verification UX). §14 specifies only the **cryptographic + structural** discipline; the **operational** runbook lives in S2-6.

#### 14.1.3 In-process boundary

The combiner runs as an **in-process** library inside the recipient's `age-plugin-cealis-v3` plugin client. The σ values arrive at the plugin client via the confidential delivery channels of §14.4 and are handed directly to the combiner library function call without crossing any wire boundary. The combiner library function returns `file_key` (32 bytes) to the calling plugin client, which then invokes the §6.4 AEAD decryption with `file_key` + `commit_AAD` + ciphertext. The combiner library zeroizes recovered shares, decap material, Shamir interpolation intermediates, and DEK material before returning; σ bytes are zeroized unless retained by an artifact schema as authorization evidence.

The in-process boundary is normative: an out-of-process combiner (e.g., a separate process invoked via IPC, or a remote combiner microservice) introduces a wire boundary across which σ values cross — violating §14.1.1 constraint 3. If a recipient delegates to a combiner-as-a-service per §14.1.2, the σ values are still delivered confidentially to the service (§14.4) and the service's combiner runs in-process within the service's plugin instance; the recipient's trust shifts from their own hardware to the service's hardware + binary-integrity attestation, not from in-process to out-of-process semantics.

### 14.2 Pre-verify checklist

Before deriving `file_key` via §6.3 Shamir, the combiner runs a **pre-verify checklist** of integrity checks. Failure of ANY check fails-closed — the combiner aborts with the matching error code per §16 and never invokes §6.3 Shamir derivation. This is the fail-closed discipline that prevents partial-state leakage on input corruption.

#### 14.2.1 Ordered checklist

The pre-verify checklist is **ordered**; each check depends on prior checks having passed. Combiner implementations MUST execute in this order (or an order proven equivalent in security analysis — typically the same):

1. **Binary integrity check.** The combiner's own binary hash is verified against `plugin_version_digest` from `commit_AAD` (§4) cross-checked against `PluginHashRegistry` state at the `RevealAuthorized` block (per §12). Failure → `ERR_COMBINER_BINARY_HASH_MISMATCH` (§16). This check is performed by the calling plugin client before invoking the combiner library function; the combiner library itself is the verified subject.

2. **Ciphertext digest check.** The loaded `age_envelope_N` byte string is keccak-hashed and compared to `ciphertext_digest_N` from the final `h_commit_N` input set (per §3.4.1 + WP §C §326). Mismatch → `ERR_CIPHERTEXT_DIGEST_MISMATCH` (§16). This catches envelope substitution + storage corruption.

3. **commit_AAD round-trip check.** The selected generation's `commit_AAD_N` SCALE struct is round-tripped (decode → re-encode → hash) per §1.4 SCALE encoding discipline; the recomputed `aad_digest_N = keccak256(TAG_AAD_V3 ‖ SCALE_encode(commit_AAD_N))` per §4 D6 is compared to the `aad_digest_N` field bound in `h_commit_N` (per §3.4 + §4). Mismatch → `ERR_AAD_DIGEST_MISMATCH` (§16). This catches commit_AAD field tampering or SCALE encoding non-canonicality.

4. **Acyclic context + h_commit re-derivation check.** The combiner re-derives `attestation_context_digest_N`, `endpoint_attestation_digest_N`, `aad_digest_N`, `commit_context_digest_N`, `ciphertext_digest_N`, and final `h_commit_N` per §3.4 in that order, then compares the final `h_commit_N` against the on-chain `h_commit_N` value (read from the `RevealAuthorized` event). `attestation_context_digest_N` mismatch → `ERR_ATTESTATION_CONTEXT_MISMATCH`; `commit_context_digest_N` mismatch → `ERR_COMMIT_CONTEXT_MISMATCH`; final anchor mismatch → `ERR_H_COMMIT_MISMATCH` (§16). This catches any input-field tampering not caught by the upstream `aad_digest` / `ciphertext_digest` checks.

5. **Stanza format parse check.** Each stanza in the loaded `age_envelope` is parsed per §6.1 stanza format; per-stanza MAC verification under `TAG_STANZA_MAC_V3` (gate stanzas) and `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` (conditional-recipient stanzas) MUST verify BEFORE the stanza payload is parsed (per §6.1.7 MAC-before-parse rule). Failure → `ERR_STANZA_MAC_VERIFY_FAIL` (§16). This catches cross-variant substitution attacks at the stanza layer.

6. **Endpoint attestation parse check.** The `endpoint_attestation_digest` from `commit_AAD` is verified against the parsed endpoint_attestation per §11 4-check sequence (Lit V3 DCAP quote + G3 dcipher/drand identity + G4 phase marker + per-stanza recipient endpoint attestation). Failure → `ERR_ENDPOINT_ATTESTATION_INVALID` (§16). This anchors the gate operators' identity to the commit's frozen attestation state.

7. **Gate signature shape verification.** Each σ value (σ_Lit, σ_G3, σ_G4, σ_conditional) is verified against the registry-published gate authority public key:
   - **σ_Lit**: verified against the Lit V3 serving TEE's per-op attested signing key, per the per-op DCAP quote bound to `(authorizationId, h_commit, block_hash)` (per WP §D §400 + §11). Failure → `ERR_SIGMA_LIT_VERIFY_FAIL` (§16).
   - **σ_G3**: verified against `G3AuthorityRegistry` state (dcipher Swiss Threshold Association pubkey OR drand League of Entropy threshold pubkey, per `g3_choice` PDA configuration field) at the `RevealAuthorized` block per §12. Failure → `ERR_SIGMA_G3_VERIFY_FAIL` (§16).
   - **σ_G4**: verified against `G4AuthorityRegistry` state at the `RevealAuthorized` block per §12 (NOT current state — historical lookup is normative for re-key generations + governance-rotated authority keys). Failure → `ERR_SIGMA_G4_VERIFY_FAIL` (§16).
   - **σ_conditional**: per-mode verification per §10 (Mode 1 PASSKEY_ACCOUNT walk-from-anchor protocol per §13.5; Mode 2 WALLET_EOA EIP-712 EOA recover; Mode 3 RESERVED rejected). Failure → `ERR_SIGMA_CONDITIONAL_VERIFY_FAIL` (§16).

   Note: gate signature **shape verification** confirms each σ verifies under its claimed authority key. This is necessary but not sufficient for V3 security; the verified σ values then authorize decapsulation and admission of their matching typed shares under the §6.3 access predicate.

8. **Registry deprecation snapshot check.** All 5 V3 registries (`PluginHashRegistry`, `G4AuthorityRegistry`, `DSLVersionRegistry`, `OracleRegistry`, `QTSPRegistry`) are queried at the `RevealAuthorized` block per §12. Any entry pinned in `commit_AAD` or referenced by the commit's condition evaluation that carries a DeprecationFlag set BEFORE `RevealAuthorized` → `ERR_REGISTRY_DEPRECATED_PRE_AUTHORIZATION` (§16). Deprecation set AFTER `RevealAuthorized` does NOT halt the in-flight reveal per WP §D §402 (gate-signing window is architectural halt-impossibility window).

9. **Shred state check.** Current `ShredRegistry` state for `h_commit` is queried per §12. If `shredded == true` → `ERR_COMMIT_SHREDDED` (§16). This catches the post-shred reveal-attempt scenario; per WP §E + §B P11, the gate-signing window is architecturally protected from shred via the mandatory `NOT post_challenge_reveal_in_progress` PDA+ guardrail, so a shredded `h_commit` arriving at the combiner is operationally a stale-state attempt.

10. **Re-key generation check.** If `commit_AAD_N.commit_generation > 0` (re-key generation per §15.2 BP-2), the combiner verifies the supersession lineage per §15.7.1 step 2 (walk `SupersededCommitRegistry` from `superseded_commit_ref` forward to chain head; verify each step is governance-authorized per S2-2). Failure → `ERR_SUPERSEDED_COMMIT_LINEAGE_BROKEN` (§16). The combiner uses final `h_commit_N` as the authorization target for generation-N σ verification, `commit_context_digest_N` for generation-N stanza unwrap, and original `commit_context_digest_0` / `commit_AAD_0` for unchanged payload AEAD unless a future `commit_version` explicitly re-encrypts the payload.

#### 14.2.2 Failure semantics

Pre-verify checks fail-closed. On ANY check failure:
- Combiner aborts immediately
- No σ values are passed to §6.3 Shamir
- No `file_key` is derived
- No AEAD decryption attempt is made
- All in-memory σ values + intermediate state are zeroized per §14.4.2
- Error code is propagated per §16 unified error model
- The reveal attempt is marked failed in the recipient's plugin client; recipient may retry with corrected inputs (e.g., re-fetched envelope, re-collected σ from a stale gate response) but the combiner does NOT permit partial-state continuation

The fail-closed discipline is normative: any combiner implementation that attempts to "fall back" to partial verification, or that reconstructs `file_key` from a share set whose matching σ evidence failed verification, violates the §14.2 protocol and the §14.3 share secrecy discipline.

#### 14.2.3 Pre-verify-vs-derive separation

The pre-verify checklist runs BEFORE §6.3 Shamir reconstruction. This separation is important: it ensures that `Shamir.combine` is invoked only when ALL inputs are integrity-verified, preventing the verified share set from containing tampered or unauthorized shares that would produce an attacker-controlled `file_key`. The pre-verify checklist's combined cost is `O(N)` in the number of stanzas + `O(1)` in the gate count (each gate sig is one elliptic-curve verification operation); the cost is bounded operationally and amortizes against the cost of the AEAD decryption that follows.

### 14.3 σ-as-authorization and share secrecy discipline

Per the 2026-05-05 dek-lifecycle design, σ values are authorization evidence. They verify gate consent / condition satisfaction over `(authorizationId, h_commit, block_hash)` and authorize per-stanza share release. They are not DEK material, are not HKDF input material, and may be public after reveal in the recipient artifact or audit trail.

The combiner's secrecy discipline therefore attaches to:

1. recovered Shamir shares;
2. hybrid KEM decap material;
3. Shamir interpolation coefficients / intermediates;
4. reconstructed file_key / DEK;
5. plaintext.

A conforming combiner MUST zeroize those materials after plaintext-or-abort and MUST NOT log them. σ bytes MAY be retained only as verification evidence where the artifact schema calls for them; raw shares and DEK never appear in artifacts.

#### 14.3.1 Anti-patterns

The following are non-compliant: logging Shamir shares, serializing recovered shares into caller-visible errors, caching DEK across reveals, deriving a fallback DEK from σ bytes, or admitting a share whose σ failed verification.

#### 14.3.2 Security level

Security of file_key reconstruction is threshold-based. A single recovered share is information-theoretically zero about the DEK below threshold; σ publication does not change that bound. The drand public-signature path relies on this property.

### 14.4 In-flight σ protection

σ values arrive at the combiner over their respective authenticated delivery channels (one per gate) before they authorize §6.3 Shamir-share admission. The in-flight protection discipline ensures σ values and recovered shares do not leak between gate signing, stanza decap, and Shamir reconstruction.

#### 14.4.1 Confidential delivery channels (per-gate)

Per WP §J §420:

> *"σ values are delivered confidentially from each gate to the recipient's combiner over authenticated encrypted channels. Never published on-chain. Never logged in transit. Never cached in intermediate systems."*

Each gate delivers its σ value to the recipient's combiner over an authenticated encrypted channel:

- **σ_Lit (G2 Lit V3)**: TLS 1.3 with mutual authentication; the Lit serving TEE attests its identity per the per-op DCAP quote (per §11), and the recipient's plugin client establishes a TLS session with the attested TEE endpoint. σ_Lit is transmitted as part of the Lit-attested response payload.
- **σ_G3 (dcipher OR drand)**: TLS 1.3 with mutual authentication to the dcipher Swiss Threshold Association nodes OR drand League of Entropy nodes. σ_G3 is the threshold-network signature output transmitted as part of the threshold-network response payload.
- **σ_G4 (Cealis verification component)**: TLS 1.3 with mutual authentication to the G4 Phase 1 server / Phase 2 TEE. σ_G4 is transmitted as part of the G4-attested response payload (with the G4 reason-code field empty for non-refusal cases).
- **σ_conditional (recipient hardware authenticator / wallet)**: σ_conditional is produced **inside the recipient's plugin client process** (Mode 1: WebAuthn ceremony with hardware authenticator; Mode 2: wallet signature ceremony) and is therefore not transmitted over any wire — it is generated in-process and handed directly to the combiner library function.

The transport-layer details of these channels (TLS version pin, certificate validation policy, mutual-auth credential rotation cadence) are specified in S2-3 SDK version pins; §14 specifies only that the channels MUST be authenticated + encrypted to a degree that prevents in-flight σ disclosure to network observers.

#### 14.4.2 Memory-zeroize discipline post-combination

After §6.3 Shamir derives `file_key`, the combiner library MUST zeroize the following memory locations before returning:

1. **σ values**: σ_Lit, σ_G3, σ_G4, σ_conditional bytes.
2. **σ verification records**: parsed signature/quote verification records and authorization-status flags.
3. **Shamir interpolation state**: polynomial/interpolation intermediate state produced by `Shamir.combine`.
4. **Shamir share values**: each per-stanza decapsulated Shamir share bytes (after they are consumed into §6.4 AEAD decryption).
5. **per-stanza wrap intermediate state**: ML-KEM-768 + X25519 hybrid KDF state (per §6.2.3).

Zeroization MUST use a memory-clear primitive that is NOT removed by compiler optimization (e.g., `explicit_bzero` in C / `subtle::ZeroizeOnDrop` in Rust / equivalent in TypeScript via overwriting the underlying ArrayBuffer + GC pinning). The combiner library's σ-handling code paths MUST be reviewed for compiler-optimized-out zeroization paths during the sealed-binary release ceremony per S2-6.

After zeroization, the only remaining secret in the combiner library's memory is `file_key` (32 bytes) destined for the §6.4 AEAD decryption; the AEAD decryption library is responsible for zeroizing `file_key` after decryption completes.

#### 14.4.3 Operational hygiene — combiner delegation

If the recipient delegates to a combiner-as-a-service (per §14.1.2), the σ values are still delivered confidentially to the service over the per-gate channels of §14.4.1, and the service's combiner instance enforces the same memory-zeroize discipline of §14.4.2. The recipient's trust shifts from "my own hardware enforces share secrecy" to "the service's hardware + binary attestation enforce share secrecy" — the cryptographic discipline is identical; only the operational trust anchor changes.

S2-6 specifies the operational ceremonies for combiner-as-a-service deployment: TEE attestation requirements (e.g., AWS Nitro Enclaves with `nsm_attestation` quote), reproducible-build verification of the service's combiner binary, recipient-side share secrecy SLA requirements.

### 14.5 Combiner failure modes + abort discipline

The combiner implements **fail-closed** abort discipline: any failure during pre-verify (§14.2), σ-authorization consumption (§14.3), in-flight protection (§14.4), or §6.3 Shamir derivation results in immediate abort with a §16 error code, σ zeroization per §14.4.2, and no partial-state continuation.

#### 14.5.1 Failure mode taxonomy

| Failure category | §14 subsection | Example error codes (§16) | Abort path |
|---|---|---|---|
| Pre-verify check failures | §14.2 | ERR_COMBINER_BINARY_HASH_MISMATCH, ERR_CIPHERTEXT_DIGEST_MISMATCH, ERR_AAD_DIGEST_MISMATCH, ERR_H_COMMIT_MISMATCH, ERR_STANZA_MAC_VERIFY_FAIL, ERR_ENDPOINT_ATTESTATION_INVALID, ERR_SIGMA_LIT_VERIFY_FAIL, ERR_SIGMA_G3_VERIFY_FAIL, ERR_SIGMA_G4_VERIFY_FAIL, ERR_SIGMA_CONDITIONAL_VERIFY_FAIL, ERR_REGISTRY_DEPRECATED_PRE_AUTHORIZATION, ERR_COMMIT_SHREDDED, ERR_SUPERSEDED_COMMIT_LINEAGE_BROKEN | Abort before §6.3 Shamir; no `file_key` derivation; σ zeroization |
| Share authorization / reconstruction failures | §14.3 | `ERR_SHARE_UNAUTHORIZED`, `ERR_SHAMIR_THRESHOLD_NOT_MET`, `ERR_SHAMIR_COMBINE_FAIL` | Abort before §6.3 Shamir reconstruction; no `file_key` output; share/DEK zeroization |
| In-flight protection failures | §14.4 | ERR_SIGMA_DELIVERY_CHANNEL_AUTH_FAIL (TLS mutual-auth fails on σ delivery), ERR_SIGMA_DELIVERY_TIMEOUT (gate's σ delivery times out) | Abort during σ collection; partial σ values zeroized; reveal attempt fails |
| HKDF derivation failures | §6.2 + §6.4 + §14 | ERR_HKDF_EXTRACT_FAIL, ERR_HKDF_EXPAND_FAIL (HKDF library failure in wrap-key or nonce derivation — operational, not cryptographic) | Abort; σ + intermediate state zeroized |
| AEAD decryption failures | §6.4 + §14 | ERR_AEAD_TAG_VERIFY_FAIL (AEAD tag mismatch — indicates `commit_AAD` field drift between commit and reveal) | Combiner has already returned `file_key`; AEAD library aborts decryption + zeroizes `file_key` |

#### 14.5.2 Abort discipline normative properties

The fail-closed abort discipline has three normative properties:

1. **No partial-state DEK derivation.** A combiner implementation MUST NOT reconstruct `file_key` from a partial access-structure witness (e.g., a missing Lit/G3/G4 top-level share, a missing recipient branch where the profile requires one, or a recipient branch below `k`). Under A1+Shamir, verified σ values are authorization evidence for share admission, not Shamir inputs; a combiner that "best-effort reconstructs file_key from available shares" without satisfying §6.3's access predicate is non-compliant with §14 and breaks the V3 cryptographic enforcement model.
2. **No retry under partial failure.** A combiner that aborts on a σ verification failure (e.g., σ_G4 verify fail per §14.2.1 step 7) MUST NOT silently retry §6.3 Shamir with σ_G4 substituted by a different value; the recipient's plugin client may retry the entire reveal flow with re-collected σ values (e.g., if a gate's σ delivery had a transport error), but the combiner itself does not retry partial-state inputs.
3. **Error-code disclosure boundary.** The combiner's failure mode is communicated to the recipient's plugin client via the §16 error code; the error code SHOULD NOT leak σ-secret material in its body or context. Specifically: ERR_SIGMA_*_VERIFY_FAIL codes do not include the σ value bytes in the error context; ERR_AAD_DIGEST_MISMATCH does not include the partial AAD bytes in a debug context. The plugin client surfaces error codes to the recipient via the recipient-facing UI per S2-5 ingestion-delivery-API.

#### 14.5.3 Partial reveals are not a concept

Under V3 + A1+Shamir, "partial reveals" (e.g., decrypting only some recipients' stanzas; producing a `file_key` that decrypts only some payload fields) are NOT a supported concept. The combiner derives a single `file_key` per commit; the AEAD decryption produces the full plaintext; per-recipient delivery filtering happens at the **plaintext layer** per WP §D §432 (combiner filters per-recipient schema selectors after AEAD decryption produces full plaintext).

A combiner implementation that attempts to derive a partial `file_key` (e.g., combining fewer shares than the commit threshold to "give the recipient something to work with") is non-compliant with both §14 protocol AND the V3 cryptographic enforcement model. Failure must be a complete reveal abort, not a partial-state degradation.

### 14.6 A1+Shamir wrap-topology integration

Under §6.2 A1+Shamir LOCKED + §6.3 typed access-structure normative formula, the combiner's role is structurally:

1. Pre-verify all inputs per §14.2
2. Verify σ values as authorization evidence for matching share admission
3. Per-stanza wraps decapsulate INDEPENDENTLY per §6.2 to recover Shamir share values
4. Reconstruct `file_key` ONCE via §6.3 `Shamir.combine` over admitted typed shares satisfying the selected access predicate (NOT per-stanza)
5. AEAD decryption (§6.4) produces full plaintext under `file_key`
6. Per-recipient schema-selector filtering produces per-recipient delivery payloads

#### 14.6.1 Single file_key reconstruction

The §6.3 Shamir reconstruction produces a single 32-byte `file_key` per commit. Under A1+Shamir, the commit-time TEE generates one random DEK, splits it into indexed Shamir shares, and wraps each share into a stanza. At reveal, σ values authorize matching stanza decap/admission; once the combiner has recovered typed shares satisfying the configured access predicate (`FIXED_ONLY`, `RECIPIENT_1_OF_1`, or `RECIPIENT_K_OF_N`), `Shamir.combine` reconstructs the DEK and assigns it to `file_key`.

The combiner does NOT re-derive `file_key` per stanza, per recipient, per generation, or per any other partition. There is exactly one `file_key` per commit; all stanzas in the envelope carry shares of the same DEK, and §6.4 consumes the reconstructed DEK as the AEAD key.

#### 14.6.2 Per-stanza wrap independence

Per §6.2 A1+Shamir invariant, per-stanza hybrid PQ wraps decapsulate INDEPENDENTLY:

- Each gate stanza (LIT_ACC, G3_ID, G4_ATTESTATION_AUTHORITY) carries its own per-stanza wrap of a Shamir share under the gate recipient's key material.
- Each conditional-recipient stanza (variants 0x01/0x02) carries its own per-stanza wrap of a Shamir share under the recipient's key material (explicit X25519 delivery key + ML-KEM-768 hybrid for Mode 1 — the recipient's `entry_pubkey_at_commit` X25519 key from `PasskeyRotationLog` per §13; P-256 authenticates the WebAuthn assertion only and is NOT used for wrap derivation; recipient-provided X25519 + ML-KEM-768 hybrid for Mode 2 — the recipient's published X25519 delivery key per §6.2 + §6.1.6; secp256k1 authenticates the EIP-712 EOA recovery only and is NOT used for wrap derivation).
- Stanza-wrap failures at one stanza do NOT block decapsulation of other stanzas; the combiner attempts each stanza independently and records per-stanza wrap status
- Per-stanza wrap success is necessary to recover that stanza's Shamir share; `file_key` reconstruction requires the selected §6.3 access predicate to be satisfied after matching σ authorizations verify. Missing any mandatory top-level branch, or failing the nested recipient threshold where required, is a hard reveal abort.

This independence property is the load-bearing mechanism for multi-recipient delivery under A1+Shamir: each recipient's per-stanza wrap is decapsulated locally on their plugin client, and the combiner reconstructs the same `file_key` once the configured threshold of shares has been recovered. AEAD decryption then produces the same plaintext for all authorized recipients.

#### 14.6.3 file_key consumption by §6.4 AEAD

After `file_key` derivation, the combiner library hands `file_key` to the §6.4 AEAD decryption library (within the same in-process boundary per §14.1.3). The AEAD decryption uses:
- `file_key` (32 bytes) as the symmetric key
- `commit_AAD_0` SCALE-encoded bytes as the AAD (additional authenticated data), unless a future `commit_version` explicitly re-encrypts payload bytes
- Nonce = `HKDF(file_key, TAG_AEAD_V3 ‖ commit_context_digest_0)[:12]` per §6.4.3
- Ciphertext = the AEAD payload extracted from the `age_envelope` per §6.1

The AEAD decryption produces plaintext if and only if `file_key` is correct AND `commit_AAD` matches the AAD bound at commit time. Tag verification failure → `ERR_AEAD_TAG_VERIFY_FAIL` (§16); under A1+Shamir LOCKED, this would only occur if either (a) an admitted share is wrong or from the wrong commit, (b) `commit_AAD` field tampering occurred (which would have been caught by §14.2.1 step 3 round-trip check), or (c) ciphertext tampering occurred (which would have been caught by §14.2.1 step 2 ciphertext_digest check). The AEAD tag is therefore the **final cryptographic check** that confirms all upstream pre-verify checks were sufficient.

### 14.7 Re-key generation handling

Per §15, under a re-key generation the combiner protocol's behavior is:

#### 14.7.1 Generation-specific h_commit anchoring

The combiner verifies reveal authorization against the commit generation being revealed and walks `SupersededCommitRegistry` to confirm that generation belongs to the original commitment lineage. The original `h_commit_0` remains the lineage root and chain-of-custody anchor. `h_commit_vN` binds the generation-N envelope bytes, generation-N stanza-wrap context, and supersession lineage for audit and authorization; it does not change the payload AEAD binding unless a future `commit_version` explicitly re-encrypts payload bytes. `h_commit_vN` is not a salt for σ-derived key material because `commit_version = 0x0302` has no σ-derived DEK.

#### 14.7.2 Share-value invariance across generations

Per §15.6.1: re-key preserves Shamir share values by stanza index. A generation may add new wraps around the same indexed shares under newer primitives, but it does not regenerate the DEK, recompute the Shamir polynomial, or alter the AEAD payload bytes. The combiner may use authorized shares recovered from any non-deprecated generation in the lineage, provided all selected shares are for the same commit lineage and satisfy §6.3 share-index rules.

Gate authority key rotation changes which keys verify σ in a generation; it does not change share values. If a recipient uses generation-N stanzas, σ values are verified against generation-N registry state. If a recipient falls back to original-generation stanzas before deprecation, σ values are verified against original-generation registry state.

#### 14.7.3 BP-6 invariant preservation

Per BP-6 (WP §M lines 1067-1069 patched 2026-04-26): "the payload bytes are never touched. Only the key-wrapping gets re-done." The combiner protocol enforces this invariant operationally:
- The AEAD payload is unchanged across all re-key generations. Each generation's final `h_commit_vN` may bind a generation-N envelope digest containing appended stanza bytes, but the AEAD payload subset, payload nonce (`commit_context_digest_0`), and payload AAD (`commit_AAD_0`) remain the original generation's values unless a future `commit_version` explicitly re-encrypts payload bytes.
- `file_key` is byte-for-byte identical across all re-key generations because `Shamir.combine` reconstructs the same commit-time DEK from the same indexed share values
- AEAD decryption with the byte-identical `file_key` over the byte-identical AEAD payload produces byte-identical plaintext across all generations

Therefore: a recipient who onboards at generation 0 and never re-keys + a recipient who onboards at generation 0 and migrates to generation 5 + a recipient who first onboards at generation 5 all recover the SAME plaintext via the SAME `file_key`. The combiner protocol is generation-agnostic in its output behavior, modulo the §14.2.1 step 10 supersession lineage check.

#### 14.7.4 Per-generation σ verification

The combiner MUST verify σ values under the authority state valid for the generation whose stanza share is being used:

- If using ORIGINAL-generation stanzas → verify each σ under the original generation's gate authority keys, read from historical registry state per §12.
- If using generation-N stanzas → verify each σ under generation-N gate authority keys, read from historical registry state for that generation.
- The verified σ value authorizes decapsulation of its matching stanza share only; it does not enter `Shamir.combine`.

Authority-key rotation between generations does NOT break file_key invariance because file_key invariance comes from stable share values, not σ-byte identity.

### 14.8 Cross-reference index

| Cross-reference | Subsection | Purpose |
|---|---|---|
| §6.3 Shamir formula | §14.6.1 | file_key reconstruction under A1+Shamir normative formula |
| §6.4 AEAD payload | §14.6.3 | file_key consumption + AEAD tag verification |
| §6.2 per-stanza wrap | §14.6.2 | Shamir share decapsulation + per-stanza wrap independence |
| §6.1 stanza format | §14.2.1 step 5 | stanza format parsing + MAC-before-parse rule |
| §15 re-key ceremony | §14.7 | re-key generation handling + ORIGINAL h_commit anchoring |
| §13 walk-from-anchor | §14.2.1 step 7 (σ_conditional Mode 1 sub-step) | σ_conditional Mode 1 verification chain |
| §11 endpoint attestation | §14.2.1 step 6 | endpoint_attestation_digest 4-check |
| §12 registry verification | §14.2.1 steps 7 + 8 + 10 | gate authority registry historical lookup + deprecation snapshot + supersession lineage |
| §10 σ_conditional per-mode | §14.2.1 step 7 (σ_conditional sub-step) | per-mode σ_conditional verification protocols |
| §3.4 h_commit re-derivation | §14.2.1 step 4 | h_commit re-derivation against on-chain RevealAuthorized event |
| §4 commit_AAD round-trip | §14.2.1 step 3 | commit_AAD SCALE round-trip + aad_digest match |
| §1.7 error code conventions | §14.5 + §16 cross-link | error code naming + propagation conventions |
| §16 unified error model | §14.5.1 + §14.7 | combiner error codes integrate with broader §16 taxonomy |
| WP §J share secrecy framing | §14.3.1 + §14.3.2 + §14.4.1 | σ-as-authorization + share secrecy + confidential delivery |
| WP §B P22 σ-as-authorization | §14.3.1 | normative anchor for share secrecy discipline |
| WP §K item 3 closed-source vault | §14.1.1 | combiner sealed-binary + closed-source-by-explicit-commit |
| WP §M storage discipline | §14.1.1 | combiner location discipline inheritance from vault discipline |

### 14.9 PII content statement

PII content of every input + output of the combiner protocol: **NONE at the cryptographic-key-handling layer before decryption output.** The combiner consumes σ values, recovered Shamir shares, commit_AAD, ciphertext, endpoint_attestation, and registry state; produces `file_key` and then AEAD-decrypted plaintext. Inputs before plaintext release are authorization signatures, shares, hashed digests, attestation tokens, on-chain registry queries, or AEAD-encrypted ciphertext — none contains plaintext PII at the combiner-input layer.

#### 14.9.1 Plaintext-PII boundary at AEAD output

The AEAD-decrypted plaintext (per §6.4) MAY contain plaintext PII per the partner agreement's data scope (e.g., subject KYC artifacts under a KYC-lending PDA; testament contents under a testament PDA; medical records under a medical-records PDA). This plaintext PII is produced at the §6.4 AEAD output boundary, NOT at the combiner-input boundary; the combiner's role ends at handing `file_key` to the AEAD library, which produces plaintext within the same in-process boundary per §14.1.3.

The plaintext PII is then consumed by the per-recipient schema-selector filtering layer (per WP §D §432 + §14.6) and by the RevealArtifactBundle assembly layer (per WP §D §434). These downstream layers are NOT the combiner; they are the recipient's plaintext-handling layer that the combiner hands plaintext to. The combiner's share secrecy + memory-zeroize disciplines (§14.3 + §14.4) apply to σ-handling code paths; the plaintext-handling layer has its own discipline per S2-5 ingestion-delivery-API.

#### 14.9.2 Pseudo-identifier inputs to combiner

The combiner reads `commit_AAD` fields that may include pseudo-identifiers per §4.9 + §3.6 ¶3 framework. Specifically: `account_id` for Mode 1 PASSKEY_ACCOUNT recipients (per §13.10.1); `wallet_address` for Mode 2 WALLET_EOA recipients; `g4_authority_ref` and `qtsp_provider_ref` (per §4 commit_AAD). These pseudo-identifiers are bound into commit_AAD as already-hashed digests or opaque routing identifiers; the combiner treats them as opaque inputs without inspecting their semantic content.

Per §3.6 ¶3 + §4.9 ¶2 reusable PII-NONE template: the keccak abstraction (preimage-resistance assumption) means the combiner's exposure to pseudo-identifier digest values does not constitute exposure to the underlying pseudo-identifier values without brute-force search; the per-onboarding nonces (per §3.1) defeat brute-force per the V1 PRO-222 mitigation. The §14.9 PII-NONE claim therefore holds at the combiner-input layer; pseudo-identifier protection inherits transitively from §3.6.

#### 14.9.3 σ values as pseudo-identifier inputs

Although σ values are authorization evidence (per §14.3.1), they are NOT pseudo-identifiers under GDPR Art. 4(1) — σ values are cryptographic outputs of signature schemes operating on `h_commit` + authority keys, not subject-identifying derivations. The share secrecy discipline (§14.3) protects the released Shamir shares, DEK, and plaintext, not σ bytes themselves. The two protections are distinct: share secrecy at the reconstruction layer + PII-NONE at the commit_AAD layer.

---

## §15 — Re-key ceremony (P21)

This section specifies the operational and cryptographic mechanics of the periodic stanza-addition re-key ceremony — Cealis's response to cryptographic primitive aging across long-retention PDAs. The ceremony is **not** payload re-encryption: the `ChaCha20-Poly1305`-encrypted payload bytes (§6.4) are never touched. Re-key extends the wrap-material around unchanged Shamir share values; §6.3 reconstructs the same commit-time DEK regardless of how many re-key generations have accumulated on the envelope.

The architectural framing is **Δ12 A1+Shamir LOCKED (Simon 2026-04-26), revised by dek-lifecycle 2026-05-05** with **BP-6 patch** to WP §M lines 1067-1069 already applied: *wrap material grows additively at the stanza layer; file_key reconstruction is threshold-stable at the Shamir-share layer*. σ values authorize share release; they are not DEK material.

### 15.1 Architectural lock — what re-key is and is not

Re-key is an **additive-at-stanza-layer** ceremony that extends the wrap-material of an existing on-chain commitment with new stanzas under fresh primitives. It is **not** a payload re-encryption, **not** a fresh DEK generation, and **not** a replacement of the original commit-time DEK.

#### 15.1.1 What re-key does

1. **Adds a new generation of stanzas** (Mandatory + Conditional-Recipient per §6.1.2) to the existing `age_envelope`. Each new-generation stanza is constructed under the fresh primitive set selected by Cealis governance for this re-key generation (e.g., ML-KEM-1024 + X25519 if ML-KEM-768 weakens; or new symmetric primitives in the wrap-AEAD layer per §6.2.3 step 7).
2. **Preserves the same `Shamir share` VALUES** per stanza-index across all re-key generations (§6.2.7). The share bytes are recovered inside the re-key ceremony's hardened context via the existing primitive set, then re-wrapped under the new primitive set, then immediately zeroized in cleartext form. The share VALUES themselves do not change between generations.
3. **Maintains σ as authorization evidence.** Gate and conditional-recipient σ values are collected for the generation whose stanzas are being used and verified against that generation's authority state. The new h_commit_v2 (§15.2) exists for governance audit + AEAD-binding; it does NOT enter a σ-derived DEK construction because no such construction exists in `commit_version = 0x0302`.
4. **Records the supersession lineage on-chain** via a new `h_commit_v2` that references the original `h_commit` through the `superseded_commit_ref` field (§15.2) — providing a chain-verifiable lineage the recipient walks to reconstruct the full envelope state at the time of reveal.

#### 15.1.2 What re-key does NOT do

1. **Does not touch the AEAD payload bytes (§6.4).** The `ChaCha20-Poly1305`-encrypted payload remains byte-for-byte identical across all re-key generations. This is the BP-6 patched WP §M line 1067 invariant: *"the payload bytes are never touched. Only the key-wrapping gets re-done."*
2. **Does not regenerate the DEK.** The DEK = file_key (§6.3) reconstructed from Shamir shares of the **original** ceremony continues to validate the AEAD payload after re-key. Under A1+Shamir, the same indexed share values reconstruct the same 32-byte `file_key` whether the recipient walks the original-generation stanzas or the new-generation stanzas.
3. **Does not invalidate prior-generation stanzas.** Old stanzas continue to verify under their frozen primitives until governance-deprecated, providing a deprecation window for client upgrade and stanza retirement (per WP §M line 1069 + §6.2.7 A1+Shamir invariant). A recipient holding an original-generation stanza set can recover the same `file_key` as a recipient onboarding post-re-key with new-generation stanzas.
4. **Does not mutate the original `h_commit`.** The original commitment hash remains immutable on-chain. The re-key fires a fresh on-chain commit ceremony producing a new `h_commit_v2` that references the original via `superseded_commit_ref` — see §15.2 below.

The conceptual model: re-key adds **new recovery paths** to the envelope under fresh primitives, while leaving every prior recovery path intact and producing the same `file_key` regardless of which path is walked. The payload's relationship to the DEK is fixed at the original commit; re-key only refreshes the wrapping layer's resistance to primitive-aging.

### 15.2 BP-2 resolution — superseded_commit_ref shape

The **outline rev.2 SOFT-3 spec-author flag** identified that additive re-key mutates the `age_envelope` stanza set — which would, naïvely, break the `ciphertext_digest` binding inside `h_commit` (because `ciphertext_digest = keccak256(age_envelope_serialized)` per §3.4.1, and the serialized envelope has new bytes after re-key). Without an explicit resolution, an auditor would observe that re-key produces a stanza set whose hash does not match the original `h_commit` and conclude that re-key violates the commitment's integrity.

The resolution is **BP-2**: re-key fires a **fresh on-chain commit ceremony** producing a new `h_commit_v2` that **supersedes** the original `h_commit` through an explicit registry pointer.

#### 15.2.1 Resolution spec

When re-key fires:

1. The re-key ceremony produces a new `commit_AAD_v2` SCALE struct (§4) with all fields **identical to the original** `commit_AAD` **except** for two:
   - `superseded_commit_ref: bytes32` — the **previous** generation's `h_commit` (or `h_commit_v(N-1)` for the N-th re-key generation; chain-walked transitively to the original)
   - `commit_generation: uint16` — incremented from the previous generation (original = 0, first re-key = 1, second re-key = 2, etc.). This field is part of `commit_AAD_v2` but binds canonical preimage form per §4.

2. A new `h_commit_v2` is computed per §3.4 over the new `commit_AAD_v2` and the new (post-re-key) `age_envelope` byte string. Specifically: `ciphertext_digest_v2 = keccak256(age_envelope_post_rekey_bytes)` reflects the post-re-key serialized envelope including all new-generation stanzas; `h_commit_v2 = keccak256(TAG_COMMIT_V3 ‖ ...)` per §3.4.1 with the updated `aad_digest` reflecting `commit_AAD_v2`.

3. A registry-pointer record is written on-chain to the **`SupersededCommitRegistry`** (specified in S2-2 smart-contracts) mapping `superseded_commit_ref → h_commit_v2`. This makes the supersession lineage chain-verifiable: any recipient (or auditor) given an `h_commit` can walk the registry to find any successor `h_commit_vN` and confirm the supersession is governance-authorized (the registry write is gated on the same 7-day timelock as the re-key ceremony itself; see §15.3).

4. The original on-chain `h_commit` remains immutable. It is **not** marked invalid or removed. Its corresponding original-generation `age_envelope` remains a valid recovery path until governance-deprecated per §15.5.

#### 15.2.2 Field shape per BP-2 lock

Per Simon back-propagation lock (BP-2 owner: dw-lead, applied at S2-1 ship-time), the two fields are added to `commit_AAD` (NOT to `pda_root` — re-key is per-commit, not per-PDA-policy). See canonical §4.1 Group 4 — Supersession lineage for the byte-exact field shapes.

These two fields extend `commit_AAD` from 19 mandatory fields to **21 mandatory fields**. SCALE struct byte-budget impact: +34 bytes (32 + 2). Pre-BP-2 baseline was 457 bytes per SCALE-encoded instance / 489 bytes for aad_digest preimage with TAG_AAD_V3 prefix. **Post-BP-2 arithmetic: 491 bytes SCALE struct (457 + 34) / 523 bytes aad_digest preimage with TAG_AAD_V3 prefix (489 + 34).**

#### 15.2.3 Why commit_AAD, not pda_root

Re-key is **per-commit**, not per-PDA-policy. The PDA-config (per §3.3 `shred_authority_id` and policy enumeration in `pda_root`) does not change at re-key — same partner agreement, same gate set, same condition module, same retention policy. What changes is the wrap-primitive era applied to the specific commit's envelope. Therefore the supersession pointer belongs in `commit_AAD` (per-commit ceremony state) not in `pda_root` (per-PDA-policy state). This also avoids invalidating the entire pool of commits under a PDA when only a subset enter the re-key cycle (re-key triggers per-commit based on retention horizon vs governance-detected primitive-weakening signal — see §15.3).

#### 15.2.4 New TAG — BP-11 LOCKED

A new TAG `TAG_SUPERSEDED_COMMIT_REGISTRY_V3` is introduced for the on-chain `SupersededCommitRegistry` lookup hash discipline (per §2.3.5 BP-11 LOCKED 2026-04-26 by dw-lead per generalized D6 V3 TAG-prefix discipline).

Spec preimage:

```
supersession_lookup_hash = keccak256(
    TAG_SUPERSEDED_COMMIT_REGISTRY_V3
  ‖ contract_address                    [bytes20, BE]
  ‖ superseded_commit_ref               [bytes32]
  ‖ commit_generation                   [uint16, BE]
)
```

Recipients use this hash to query the on-chain registry for the supersession record. The TAG-prefix discipline (§1.3) ensures preimage-domain separation from other on-chain registry lookups in §2.

### 15.3 Governance trigger + 7-day timelock

#### 15.3.1 Trigger mechanism

Re-key fires only on **governance trigger**. The decision is not automated by the ceremony itself — Cealis governance (per S2-6 operational-ceremonies-spec) monitors the following primitive-weakening signals continuously:

1. NIST post-quantum guidance updates affecting any of {ML-KEM-768, X25519, BLS12-381, Ed25519, Keccak-256, ChaCha20-Poly1305, P-256}
2. Hardware-vendor cryptanalytic advisories (Intel SGX, AMD SEV-SNP, etc.) affecting G2 Lit V3 attestation infrastructure
3. Published academic research advances on any primitive in the V2 cryptographic stack (per §1 conventions)
4. Vendor-specific advisories from `noble-curves`, `noble-hashes`, `@polkadot/util-crypto`, `@noble/post-quantum` (per §1 SDK pin discipline)

When a signal crosses a documented risk-register threshold (the threshold table is specified in S2-6 — examples: NIST issues "deprecate ML-KEM-768 by year X+5"; published cryptanalytic advance reduces ML-KEM-768 security margin by ≥40 bits; etc.), Cealis governance evaluates whether to fire a re-key ceremony.

#### 15.3.2 7-day timelock

Once governance authorizes a re-key, a **7-day timelock on ceremony initiation** applies before the on-chain `SupersededCommitRegistry` write (§15.2 step 3) is executable. The timelock is enforced by the on-chain TimelockController (per S2-2 contracts spec). During the 7-day window:

1. The proposed `h_commit_v2` set (one per commit being re-keyed) is published on-chain in pending state with the supersession-pointer mapping draft.
2. Recipients (or any third party) can audit the proposed re-key parameters before they take effect.
3. Conditional-recipient holders (Mode 1 PASSKEY_ACCOUNT + Mode 2 WALLET_EOA per §15.4) are notified to schedule their interactive participation window.

After the 7-day timelock expires, the supersession-pointer write is executed on-chain and the new `age_envelope` (with new-generation stanzas appended) is written to the off-chain vault. The original `h_commit` and original `age_envelope` remain immutable and recoverable until governance-deprecated per §15.5.

#### 15.3.3 Per-commit batching

A single governance-authorized re-key event typically batches **multiple commits** sharing the same primitive-weakening exposure. Example: if NIST issues a deprecation notice on ML-KEM-768 in year X+5, governance authorizes re-key of **all commits with retention horizon ≥ year X+5 + 1 still using ML-KEM-768** in a single ceremony. The 7-day timelock applies to the entire batch; the per-commit timelocks are aligned. Per-commit batching is operational efficiency, not a cryptographic requirement.

#### 15.3.4 Authority

Governance authority for triggering re-key resides with the on-chain `RekeyGovernance` role per S2-2 contracts spec (distinct from PDA-config governance which uses PolicyEngine + TimelockController per S2-2). Specifically: the multi-signature governance set holding `RekeyGovernance` role on the Cealis on-chain control contract. Operational mechanics — quorum thresholds, member rotation, signing key custody — are S2-6 territory and not specified here. This section specifies only the **cryptographic** and **structural** discipline; **operational** runbook (who signs what when, vendor coordination protocols, rotation comms templates) lives in S2-6.

### 15.4 Per-conditional-recipient impact

The §6.1.2 stanza ordering makes re-key participation requirements per-recipient mode-dependent. The 3 mandatory gate stanzas (LIT_ACC + G3_ID + G4_ATTESTATION_AUTHORITY) require **gate-operator** participation (Lit V3 + dcipher/drand + Cealis G4); the variable-count CONDITIONAL_RECIPIENT_* stanzas require **per-recipient** participation depending on mode.

#### 15.4.1 Gate-operator participation (mandatory)

The three gate operators participate in **every** re-key ceremony per the BP-6-patched WP §M line 1069:

> *"The three gate operators (Lit, G3, G4) plus any conditional_recipients configured on the PDA (§C) participate. Each signs a fresh σ over the existing `h_commit` under the newer primitive."*

**"The existing `h_commit`" remains the lineage root, but not a DEK-derivation salt.** Gate operators produce generation-appropriate σ over the reveal authorization context for the stanza generation being used. Those σ values authorize decapsulation of the corresponding generation's wrapped Shamir shares. They do not feed §6.3 as IKM.

The new on-chain commit lineage (`h_commit_v2`, `commit_AAD_v2` per §15.2) exists for **governance audit + lineage anchoring + new-generation stanza-wrap context only** — it lets recipients walk the supersession registry forward to confirm governance authorization of the re-key, and it binds the new generation's stanza-wrap derivation context per §6.2.3 + IB-1 acyclic h_commit schedule. It is **NOT** the AEAD additional-data block for the payload. **Per IB-3 re-key AEAD invariant (`designs/rekey-aead-invariant.md`): the payload AEAD AAD remains `commit_AAD_0` and the AEAD nonce remains derived from `commit_context_digest_0` for the unchanged payload bytes — forever, across every re-key generation, unless a future `commit_version` explicitly re-encrypts payload bytes.** `h_commit_v2` binds the new envelope's stanza-wrap material and the supersession lineage anchor; it does not change the underlying DEK, the share values, the payload ciphertext, or the AEAD AAD/nonce.

Gate authority key rotation is an orthogonal ceremony per §15.6.3. If it occurs between generations, recipients verify each generation's σ values under that generation's gate authority keys per the gate-authority registry historical lookup (§11 endpoint attestation). File_key invariance is unaffected because invariance comes from stable Shamir share values.

For Mode 1 conditional-recipients (PASSKEY_ACCOUNT) and Mode 2 conditional-recipients (WALLET_EOA), the gate-operator participation is necessary but **not sufficient** — see §15.4.2 below.

#### 15.4.2 Mode 1 PASSKEY_ACCOUNT — interactive WebAuthn assertion

Per BP-6 patched WP §M line 1069:

> *"Mode 1 PASSKEY_ACCOUNT requires interactive WebAuthn assertion."*

Mode 1 conditional-recipients hold their access via an on-device WebAuthn passkey (per §13 PasskeyRotationLog ABI Δ12-A 4-field expansion). The re-key ceremony requires the recipient to **interactively** authenticate via WebAuthn assertion to participate in their own stanza re-wrap. The flow:

1. Recipient receives notification (per S2-6 rotation comms protocol) during the 7-day timelock window of §15.3.2.
2. Recipient initiates WebAuthn assertion ceremony in a user-facing client (web + mobile per S2-5 ingestion-delivery-API).
3. Recipient's hardware authenticator produces a fresh σ_subject over the ORIGINAL `h_commit_preimage` + ORIGINAL PDA_terms_digest per §5.1 σ_subject construction (the same input bytes the original ceremony produced). Under stable subject authenticator keys, the σ_subject bytes are byte-deterministic; the re-collection serves as fresh-consent witness rather than a different signature payload.
4. Recipient's authenticator also produces or receives a fresh ML-KEM-768 (or new-era ML-KEM-1024) wrap of the recipient's existing `Shamir share_s` for their CONDITIONAL_RECIPIENT_PASSKEY_ACCOUNT stanza. This is where the passkey-bound key pair (per §13 PasskeyRotationLog entry's `entry_pubkey_at_commit` + `entry_mlkem_pubkey_at_commit`) participates in the new-generation stanza wrap.
5. The new-generation stanza is added to the envelope, carrying a new `rotation_log_anchor` snapshot reflecting the recipient's current rotation-log head at re-key time (per §13.8.1 — the PasskeyRotationLog itself is NOT mutated; log mutation happens only on recipient passkey rotation, which is an independent event per §13; re-key adds a new-generation stanza with a new anchor snapshot over the unchanged log state).

**This is a user-coordinated event, not a fully automated one** — acceptable for rare long-horizon events (re-key cycles measured in years, not weeks), not for routine operation. If a Mode 1 recipient does not respond within a governance-defined response window after the 7-day timelock expires, the re-key proceeds without that recipient's stanza being included in the new generation. The recipient's original-generation stanza remains valid until original-generation deprecation per §15.5 — providing a deprecation grace period for stragglers — but the recipient must complete the interactive participation before original-generation deprecation or lose access.

#### 15.4.3 Mode 2 WALLET_EOA — wallet interaction

Per BP-6 patched WP §M line 1069:

> *"Mode 2 WALLET_EOA requires wallet interaction."*

Mode 2 conditional-recipients hold their access via a wallet EOA (Ethereum Externally-Owned Account) per §6.1.6 stanza variant 0x02. The re-key ceremony requires the recipient to **interactively** sign with their wallet's private key to participate. The flow mirrors Mode 1 except:

1. Recipient signs with their wallet (MetaMask / Rabby / Frame / hardware wallet per §6.1.6) producing a fresh σ_conditional EIP-712 signature per §10 (Mode 2 σ_conditional spec) over the ORIGINAL h_commit-binding inputs. Under stable wallet keys + ECDSA-RFC6979 deterministic nonces, the σ_conditional bytes are byte-deterministic; the re-collection serves as fresh-consent witness rather than a different signature payload.
2. The recipient's stanza wrap mechanics depend on the Mode 2 conditional-recipient construction in §6.2 (per-recipient hybrid PQ wrap of the recipient's `Shamir share_s`). For Mode 2, the recipient's per-stanza pubkey is the recipient's per-stanza X25519 + ML-KEM-768 hybrid pubkey published per §6.2 (recipient-provided; not derived from the wallet's secp256k1 key — the wallet signs σ_conditional EIP-712 only, not delivery-key derivation).
3. Fallback if the recipient does not respond: same as Mode 1 — original-generation stanza remains valid until governance-deprecated; recipient must complete participation before deprecation.

The user-coordination consideration is identical to Mode 1 — acceptable for rare long-horizon events, not for routine operation. The practical consequence: a PDA configured with Mode 1 or Mode 2 conditional-recipients that may persist across a primitive-weakening era should set partner expectations that recipient interactive participation will be required during re-key cycles, ideally encoded in the partner agreement governing the PDA.

#### 15.4.4 Mode 3 RESERVED — out of scope

Mode 3 conditional-recipient stanza variant is RESERVED at V2 launch (per Stage-0 lock; see internal project-rules §0 Reconfirm B). Re-key impact for Mode 3 is deferred to post-V2 spec along with the Mode 3 ceremony itself.

#### 15.4.5 σ_subject re-collection

For PDAs with `subject_authenticator_class != UNSET` (per §3.3 + §5), re-key requires fresh σ_subject collection over the **ORIGINAL** `h_commit_preimage` + **ORIGINAL** PDA_terms_digest per §5.1. The subject signs the same input bytes the original ceremony produced; the new signature reflects the new authenticator era (e.g., upgraded P-256 → P-384 if WebAuthn evolves) but is otherwise byte-deterministic under stable subject authenticator keys. `σ_subject_digest_v2 = keccak256(σ_subject_v2)` is bound into `commit_AAD_v2` per §4.1 Group 2.

This piggybacks on the WebAuthn assertion ceremony of §15.4.2 (Mode 1) or wallet interaction of §15.4.3 (Mode 2), or — for PDAs without conditional-recipients but with subject participation — fires a standalone σ_subject collection event per the partner agreement. Operational details in S2-6.

### 15.5 Old-generation deprecation

Old stanzas continue to verify under their frozen primitives **until governance-deprecated** (per WP §M line 1069 + A1+Shamir invariant per §6.2.7). This provides a deprecation window for client upgrade and stanza retirement.

#### 15.5.1 Deprecation trigger

Old-generation deprecation fires on **independent governance trigger** — distinct from the re-key trigger of §15.3.1. Deprecation is triggered when:

1. The new-generation primitive has been live for ≥ a deprecation grace period (governance-defined; typically 18-36 months — long enough for all conditional-recipients to complete interactive participation per §15.4.2/§15.4.3 and for clients to upgrade their plugin SDKs to handle the new primitive era).
2. The risk register confirms that continuing to support the old primitive era exposes commitments to a known-imminent break (rather than a theoretical risk that originally triggered the re-key).
3. The fraction of recipients still holding only original-generation stanzas (per the on-chain registry signal of which recipients participated in the re-key) has fallen below a governance-defined threshold — typically ≤ 5% of the relevant commit population.

#### 15.5.2 Deprecation mechanism

Deprecation **does not** delete the old-generation stanzas — those bytes remain in the off-chain vault per crypto-aging discipline (the past-state evidence value is operationally important for §371a ZPO chain-of-custody continuity, per WP §K legal-context items). What deprecation does:

1. Marks the original `h_commit` as **deprecated-recovery** in the on-chain registry, signaling that recipients should walk the supersession lineage to the latest `h_commit_v2N` for their recovery path.
2. Sets a hard deadline after which the plugin client SDKs no longer attempt original-primitive recovery (per S2-3 SDK version pins). Recipients on stale clients will receive an upgrade prompt at the deadline.
3. Triggers final notifications (per S2-6 rotation comms protocol) to any recipients still on original-generation stanzas to complete migration.

#### 15.5.3 Post-deprecation invariant

After deprecation:
- The original `h_commit` remains immutable on-chain (per §15.1.2).
- The original `age_envelope` remains in the vault (per §15.5.2).
- Plugin SDKs no longer attempt recovery via original-generation stanzas.
- Recipients must walk the supersession lineage to the current generation `h_commit_vN` and use new-generation stanzas for Shamir-share recovery (defense-in-depth at wrap layer per §6.2.7) plus generation-appropriate σ verification for share admission per §6.3.
- The `file_key` produced by either path remains byte-for-byte identical (A1+Shamir invariant) — deprecation is a client-side operational gate, not a cryptographic invalidation.

#### 15.5.4 Long-retention PDAs and operational continuity

For long-retention PDAs (testament, archival, evidence — typical retention > 10 years), multiple re-key cycles may accumulate over the PDA's lifetime. The supersession lineage chains through `h_commit → h_commit_v2 → h_commit_v3 → … → h_commit_vN` — each generation's `commit_AAD_vK.superseded_commit_ref` pointing to generation K-1's `h_commit_v(K-1)`. The recipient walks the chain forward (most-recent-first) when initiating recovery. The depth of the chain is bounded only by `commit_generation: uint16` (65535 generations), which exceeds any realistic operational horizon.

### 15.6 Cryptographic invariants — share-value invariance + file_key invariance across generations

Under A1+Shamir, re-key preserves the indexed Shamir share values generated at commit time. The resulting `file_key` is therefore byte-for-byte identical across generations because `Shamir.combine` reconstructs the same commit-time random DEK from the same threshold share set. This subsection makes the invariant chain explicit for auditor verification.

#### 15.6.1 Share-value invariance across generations

For each stanza index `i`, generation N wraps the same share value as generation 0:

```
generation 0: share_i_0 = ShamirShare(DEK_commit, i)
generation 1: share_i_1 = share_i_0, re-wrapped under generation-1 primitives
generation N: share_i_N = share_i_0, re-wrapped under generation-N primitives
```

New generations may change wrapper primitives, recipient pubkeys, endpoint attestations, and authority registries. They MUST NOT change the DEK, Shamir polynomial, threshold, or indexed share values for the existing commit lineage.

#### 15.6.2 file_key invariant

The byte-identity chain:

- Re-key preserves the same indexed Shamir share values.
- `Shamir.combine` is deterministic over the same ordered threshold share set.
- Therefore `file_key` is byte-for-byte identical across all re-key generations.
- The AEAD-encrypted payload (§6.4) decrypts to the same plaintext across all generations.
- BP-6 "payload bytes never touched" holds by construction.

The security bound for `file_key` uniqueness is the 32-byte commit-time random DEK plus the Shamir threshold property. σ values contribute authorization, not entropy for DEK derivation.

#### 15.6.3 Gate authority key rotation (orthogonal ceremony — out of scope of §15)

Gate authority key rotation is a **separate** ceremony from re-key. Authority key rotation affects **who** can sign σ_Lit / σ_G3 / σ_G4 going forward; re-key affects **which primitives** wrap Shamir share values at the per-stanza layer (§6.2). The two ceremonies are orthogonal because σ values authorize decapsulation but do not derive the DEK.

Detailed authority-rotation operational ceremony — quorum, signing key custody, vendor coordination, rotation comms — lives in S2-6 (specifically: G4 authority key rotation per internal project-rules §0 Table A; Lit V3 + dcipher/drand authority management per S2-3 + S2-6 cross-spec). S2-6 may impose its own operational coordination discipline between re-key and authority-rotation ceremonies, but this is operational hygiene, not a cryptographic requirement at the §15 layer.

### 15.7 Recipient-side recovery walk

This subsection specifies the order of operations a recipient (or their plugin client) executes to recover plaintext from a re-keyed envelope.

#### 15.7.1 Steps

1. **Receive the original `h_commit` and `authorizationId`** from the partner (per S2-5 ingestion-delivery-API onboarding flow). This is the same starting point as the non-re-key recovery flow.
2. **Walk the supersession lineage on-chain.** Query the `SupersededCommitRegistry` (§15.2 step 3) for any successor `h_commit_vN` that supersedes the recipient's known `h_commit`. The query is repeated transitively until the chain head (most recent `h_commit_vN`) is reached.
3. **Verify supersession authorization.** For each supersession step, verify that the on-chain registry write was governance-authorized per S2-2 contracts spec — i.e., the supersession-pointer was written by the `RekeyGovernance` role per S2-2.
4. **Retrieve the chain-head `age_envelope`** from the off-chain vault (or from the partner who delivered it) — this contains all generations' stanzas appended additively.
5. **Verify σ values for the selected generation** (per §7-§10 and §14). Each verified σ authorizes decapsulation of its matching stanza share under the selected generation's registry state.
6. **Recover threshold Shamir shares** by decapsulating authorized stanzas from the selected generation. The combiner may mix generations only if S2-6 explicitly permits it and the share indices are identical; the default implementation uses one generation's stanza set to reduce audit complexity.
7. **Reconstruct `file_key` per §6.3** via `Shamir.combine` over recovered typed shares that satisfy the selected access-structure profile.
8. **Decrypt the AEAD payload per §6.4** using the `file_key`. The payload is byte-for-byte unchanged across generations; the AAD used for unchanged payload bytes is `commit_AAD_0`, and the nonce uses `commit_context_digest_0`. The selected generation's `commit_AAD_vN` and `commit_context_digest_N` bind generation-N stanzas and supersession lineage, not payload AEAD, unless a future `commit_version` explicitly re-encrypts payload bytes.

#### 15.7.2 Fallback to original generation

If a recipient has not migrated to the new generation (per §15.4.2 / §15.4.3 — they did not complete interactive participation), they retain the original-generation stanzas. Their recovery walk may use the original `h_commit` + original `age_envelope` + original-generation σ verification until original-generation deprecation per §15.5. The `file_key` produced is byte-for-byte identical to the chain-head `file_key` because both paths reconstruct the same DEK from the same indexed share values.

After deprecation, plugin client SDKs no longer support the original primitives, and the recipient must complete migration (typically by re-engaging the conditional-recipient interactive flow per §15.4). The bytes may persist for audit, but the SDK is the operational gate.

#### 15.7.3 Multi-recipient consistency

Per §6.2.4 A1+Shamir LOCKED + A1+Shamir invariant: all recipients of a given commit (across all generations) recover **the same `file_key`**. This includes:

- A recipient who onboards at generation 0 and never re-keys (uses generation-0 stanzas to recover Shamir shares)
- A recipient who onboards at generation 0 and migrates to generation 5 (uses generation-5 stanzas to recover the same indexed Shamir shares)
- A recipient who first onboards at generation 5 (uses generation-5 stanzas only)

All three recover the same `file_key` and therefore decrypt the same payload bytes. This is the multi-recipient delivery consistency property that §15 inherits from §6.2.7 + §6.3 under A1+Shamir LOCKED.

### 15.8 Operational mechanics — pointer to S2-6

This section specifies the **cryptographic + structural** discipline of re-key. The **operational runbook** lives in S2-6 (operational-ceremonies-spec). The S2-6 sections that re-key spans:

1. **Signal monitoring** — the documented risk register, threshold-crossing detection mechanics, primitive-weakening signal aggregation across NIST + vendor advisories + academic research.
2. **Governance trigger workflow** — quorum thresholds, signing key custody, multi-signature flow per `RekeyGovernance` role.
3. **Ceremony coordination** — vendor coordination protocols with Lit V3 operator network + dcipher/drand thresholds + Cealis G4 swap discipline (especially Phase 1 → Phase 2 G4 swap if it coincides with re-key).
4. **Recipient notification protocols** — Mode 1 PASSKEY_ACCOUNT + Mode 2 WALLET_EOA notification windows, escalation paths, response tracking.
5. **Conditional-recipient interactive participation flows** — UX mechanics for WebAuthn assertion + wallet signing during the 7-day timelock window.
6. **Old-generation deprecation rollout** — final notification cadence, SDK upgrade prompts, recipient migration tracking.
7. **Emergency-response interaction** — how re-key ceremony interacts with shred-mid-reveal, conditional-recipient mutation, and the `NOT post_challenge_reveal_in_progress` guardrail (per internal project-rules §0 Table A on-chain shred + emergency-response design).

S2-6 is the source of truth for those operational details. §15 is the source of truth for the cryptographic + structural framing those operations must respect.

### 15.9 Error model

Re-key-specific error conditions during the ceremony or during recipient-side recovery walk:

| Error code | Trigger | Recovery |
|---|---|---|
| `ERR_REKEY_GOVERNANCE_UNAUTHORIZED` | Supersession-pointer write attempted without `RekeyGovernance` role authorization | Re-key ceremony aborts; original `h_commit` remains chain-head; no envelope mutation |
| `ERR_REKEY_TIMELOCK_NOT_EXPIRED` | Supersession-pointer write attempted before 7-day timelock expiry | Re-key ceremony retries after timelock expiry; pending state preserved |
| `ERR_SUPERSEDED_COMMIT_LINEAGE_BROKEN` | Recipient-side walk encounters a missing supersession-pointer registry record at an intermediate generation | Recipient recovery aborts; recipient escalates via partner support per S2-5; partner queries on-chain registry directly to confirm chain-head |
| `ERR_REKEY_GENERATION_OVERFLOW` | `commit_generation: uint16` exceeds 65535 | Cryptographically impossible in practice; sentinel for catastrophic operational failure (governance must initiate fresh PDA + commit migration if encountered) |
| `ERR_GATE_AUTHORITY_KEY_MISMATCH` | σ verification at recovery step 5 fails because gate authority key has rotated between the recipient's last sync and the re-key ceremony | Recipient client SDK must re-sync gate authority registry per §11 endpoint attestation, then retry recovery |

These are re-key-specific extensions to the §16 unified error model. The §16 spec consumes this table and integrates with the broader error taxonomy.

### 15.10 PII content statement

PII content of every byte-layout introduced by §15 (re-key ceremony — supersession-pointer registry, generation lineage walk, generation-N stanza wrap, rotation-log anchor snapshot, governance authorization preimages): **NONE in any commit-time keccak preimage, AEAD AAD, or on-chain registry payload**. Re-key does not add new subject-PII surfaces beyond what §6 already exposes (Mode 1 `account_id`, Mode 2 `wallet_address`, Mode 2 `delivery_url`, recipient pubkeys), and the re-key ceremony does not export any subject-PII into the supersession-pointer registry, the generation lineage walk, or the σ-recollection workflow. Per-construct defense:

- **`commit_generation: uint16` (§15.2 BP-2):** Monotonic counter per commit lineage. Carries no subject-PII content; structurally a sequence number identifying which generation of the lineage a given envelope belongs to. Cross-partner unlinkability holds because `commit_generation` is per-`h_commit_0` lineage (each PDA's commit lineage has its own counter starting at 0).

- **`superseded_commit_ref: bytes32` (§15.2):** Reference to the prior generation's `h_commit_{N-1}`. Carries no subject-PII content; it is a cryptographic identifier (chain-anchored final h_commit hash) of the prior generation. The supersession lineage walk uses these refs to verify generation-N authorization without exposing subject identity at any step.

- **`h_commit_vN` / `commit_AAD_vN` (§15.2):** Generation-N versions of the canonical h_commit and commit_AAD constructions. PII content scope inherits §3.6 (h_commit_N) + §4.9 (commit_AAD) PII-NONE dispositions: all inputs are 32-byte digests of upstream constructions, configuration enum values, version markers, or per-PDA scalar policy fields. Generation-N stanza-wrap context (`commit_context_digest_N` per IB-1 acyclic schedule) carries the same PII-NONE inheritance — no new subject-PII surface is created by the re-generation.

- **`rotation_authorization_digest` (§13.3, consumed by §15 governance authorization):** Per §13.10 PII-NONE disposition — the rotation-authorization preimage covers monotonic counters, on-chain platform addresses, cryptographic pubkeys, and timestamp metadata only. No subject-PII content.

- **`rotation_log_anchor` snapshot (§6.1.5 + §13):** Per IB-3 re-key invariant + §13 PasskeyRotationLog append-only discipline: re-key generations snapshot a NEW `rotation_log_anchor` over the unchanged on-chain `PasskeyRotationLog` state at the re-key block, **without mutating any prior log entry**. The append-only PasskeyRotationLog is preserved across re-key generations; new generations consume the rotation-log head at re-key time as input to their generation-N stanza wraps. PII content of the rotation log inherits §13.10's PII-NONE-with-Breyer-precedent disposition for the cross-partner-stable `account_id` field; no new subject-PII surface is created by the re-key snapshot.

- **σ_subject re-collection (§15.4.5):** Per §5.11 σ_subject PII-NONE disposition — σ_subject's keccak-preimage-bound `sigma_subject_digest` field carries no subject-PII; σ_subject's pubkey IS PII (passkey pubkeys + EOA addresses are identity-bearing pseudo-identifiers under EU GDPR Art. 4(1)) but the pubkey lives in vault-only off-chain storage rather than on-chain anchored. Re-collection over the **ORIGINAL** `h_commit_preimage` + **ORIGINAL** PDA_terms_digest preserves the vault-only storage discipline; the new σ_subject_v2 reflects the new authenticator era but does not export new subject-PII to chain.

- **Generation lineage walk (§15.7.1 step 2):** The recipient-side lineage walk traverses `SupersededCommitRegistry` from `superseded_commit_ref` forward to chain head, verifying each step's governance authorization via `RekeyGovernance` role state. The walk consumes only cryptographic identifiers (h_commit hashes, governance role bitmaps, block numbers) — no subject-PII enters the walk at any step. Walk failure aborts recovery without leaking lineage state to the recipient artifact (per §14.4.2 zeroization on abort).

**Re-key invariant: NO new subject-PII enters the chain layer.** The re-key ceremony is a generation-version bump on the cryptographic-layer envelope state and the on-chain governance state; it adds new versioned identifiers (`h_commit_vN`, `commit_AAD_vN`, `commit_generation`, `superseded_commit_ref`) but does NOT add new subject-identifying fields. The cross-partner-stable property of `account_id` (Mode 1) + the EOA-address visibility of `wallet_address` (Mode 2) are preserved across generations under the same disposition as §6.6 — re-key does not introduce a new linkability surface beyond commit-time §6.6 framing.

---

## §16 — Error model + abort discipline

This section defines the unified error model for the V2 system / V3 custody cryptographic layer: ERR taxonomy organization, abort discipline normative behavior, forensic-layering vs wrap-around discipline, share secrecy + PII safety in error blobs, and cross-section consolidation index. The unified error model crypto-enforces the §1.7 fail-closed default + §14.5.2 second normative property (auditable failure semantics under V3 cryptographic enforcement model).

**Scope:** §16 enumerates **all `ERR_*` codes** introduced across §1-§15 normative sections. Per worker-3's pre-handoff consolidation index baseline (51 codes writer-B span + §10) + §11 absorption (3 new) + §12 absorption (16 new) + §6.1/§6.2 confirmed canonical codes. §16 is the canonical-naming + cross-reference + severity-disclosure-boundary anchor; per-section subsections retain primary-definition ownership per §16.18 cross-reference index.

**Count discipline (NORMATIVE — for auditor reproducibility):** the V2 system / V3 custody cryptographic layer carries **93 unique `ERR_*` symbol references** total in §16 (verified via `grep -oE "ERR_[A-Z_0-9]+" docs/specs/cryptography-spec.md | sort -u | wc -l` over the §16 span). Of these, **90 are unique fully-qualified ERR codes enumerated in per-layer tables** (§16.2-§16.12); the remaining 3 reference-only mentions are: (a) `ERR_SIGMA_*` wildcard prefix mention in §16.7 wrap-around-vs-forensic narrative, (b) `ERR_SIGMA_DELIVERY_*` wildcard prefix mention in §16.15 anti-pattern call-out 2 narrative, (c) `ERR_SIGMA_CONDITIONAL_INVALID` deprecated reference at §16.18 canonical-definition deduplication table (per worker-3 §14 verdict — replaced by canonical `ERR_SIGMA_CONDITIONAL_VERIFY_FAIL`). The 90 fully-qualified ERR codes are the authoritative per-layer enumeration; the 3 narrative-only mentions are not separate codes.

### §16.1 Organizational principle (NORMATIVE)

The V2 system / V3 custody error taxonomy organizes by **cryptographic layer**, not by source section. This matches the spec's primitive-stack ordering (§1 conventions → §2 TAGs → §3 composite identifiers → §4 commit_AAD → §5 σ_subject → §6 envelope → §7-§10 gate signatures → §11 endpoint attestation → §12 registries → §13 PasskeyRotationLog → §14 combiner → §15 re-key) and reflects the architectural truth that V3 cryptographic enforcement aborts at the layer the failure surfaces, not at the section whose contract failed.

**11 cryptographic layers (NORMATIVE):**

1. **Layer 1: Cryptographic primitive errors** — Ed25519 / BLS12-381 / P-256 / secp256k1 / X25519 / ML-KEM-768 verification failures
2. **Layer 2: SCALE encoding errors** — canonicality-check failures + decode failures
3. **Layer 3: HKDF errors** — Extract/Expand failures (operational-not-cryptographic)
4. **Layer 4: AEAD errors** — ChaCha20-Poly1305 tag verification + truncation defense
5. **Layer 5: Per-stanza wrap errors** — hybrid PQ wrap-AEAD failures + stanza MAC failures
6. **Layer 6: Per-σ verification errors** — σ_subject / σ_Lit / σ_G3 / σ_G4 / σ_conditional gate-signature verification at combiner-side
7. **Layer 7: Pre-verify checklist errors** — combiner pre-verify checklist (§14.2.1 10 ordered checks) failures BEFORE file_key reconstruction
8. **Layer 8: Governance + registry errors** — 5 V3 registries (Plugin / G4Authority / DSL / Oracle / QTSP) + DeprecationFlag verification
9. **Layer 9: Re-key ceremony errors** — supersession lineage + governance + timelock failures
10. **Layer 10: Rotation-log errors** — PasskeyRotationLog walk-from-anchor failures
11. **Layer 11: Delivery + transport errors** — σ delivery channel + timeout failures

**Per-layer abort discipline:** ALL `ERR_*` codes in the V2 system / V3 custody cryptographic layer are **fail-closed under V3 cryptographic enforcement model**. There is no "degraded-graceful" or "informational-only" code. Any failure aborts the reveal at the layer the failure surfaces — caller's plugin client surfaces the ERR code without fallback recovery (recovery semantics are operational; the cryptographic layer has no soft-fail path per §1.7 + §14.5.2).

### §16.2 Layer 1 — Cryptographic primitive errors

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_AUTHENTICATOR_LOW_S_VIOLATION` | EIP-2 low-s normalization fails on ECDSA signature (P-256 / secp256k1) | §5.6 + §10.3.4 |
| `ERR_AUTHENTICATOR_CLASS_MISMATCH` | `subject_authenticator_class` field does not match recovered authenticator type | §5.7 |
| `ERR_HYBRID_KEM_DECAPS_FAIL` | ML-KEM-768 decapsulation fails (PQ-wrap layer) | §6.2 |

### §16.3 Layer 2 — SCALE encoding errors

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_SCALE_ENCODE_FAIL` | SCALE encoding of `commit_AAD` for AAD input fails (canonicality check) | §6.4 |
| `ERR_SCALE_DECODE_FAIL` | SCALE decoding of an on-the-wire structure fails (untrusted input parsing) | §1.3.2 + §14.5.1 |
| `ERR_SHARE_SET_INVALID_ENCODING` | recovered share set or stanza-share metadata fails canonicality check before Shamir reconstruction | §14.5.1 |

### §16.4 Layer 3 — HKDF errors

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_HKDF_EXTRACT_FAIL` | HKDF-SHA256 Extract step fails in per-stanza wrap-key or AEAD nonce derivation (operational, not cryptographic) | §6.2 + §6.4 |
| `ERR_HKDF_EXPAND_FAIL` | HKDF-SHA256 Expand step fails in per-stanza wrap-key or AEAD nonce derivation (operational, not cryptographic) | §6.2 + §6.4 |
| `ERR_HKDF_FAIL` | Generic HKDF library failure (catches both Extract + Expand) | §6.2 + §6.4 |

**Granularity decision (NORMATIVE):** §16 retains BOTH granular `ERR_HKDF_EXTRACT_FAIL` + `ERR_HKDF_EXPAND_FAIL` AND umbrella `ERR_HKDF_FAIL` per worker-B preference (matches per-curve σ verification split discipline at §14.2.1 step 7 + per-gate asymmetric DCAP discipline at §11.3.2 — granular forensic codes for diagnostics + umbrella codes for caller-side handling).

### §16.5 Layer 4 — AEAD errors

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_AEAD_TAG_VERIFY_FAIL` | AEAD tag mismatch — indicates `commit_AAD` field drift between commit and reveal | §6.4 (canonical owner) + §6.3.7 + §14.5.1 |
| `ERR_AEAD_TRUNCATED_PAYLOAD` | AEAD ciphertext payload shorter than expected (truncation attack defense) | §6.4 |

**Canonical-definition deduplication (per §16.18):** `ERR_AEAD_TAG_VERIFY_FAIL` has single canonical definition at §6.4 (AEAD layer); §6.3.7 + §14.5.1 are cross-references.

### §16.6 Layer 5 — Per-stanza wrap errors

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_STANZA_VARIANT_TAG_INVALID` | Stanza variant tag (e.g., 0x01 / 0x02 / 0x03) does not match enumerated valid set | §6.1 |
| `ERR_STANZA_LENGTH_INVALID` | Stanza length-prefix exceeds payload bounds | §6.1 |
| `ERR_STANZA_MAC_VERIFY_FAIL` | Per-stanza MAC verification fails (`TAG_STANZA_MAC_V3` OR `TAG_CONDITIONAL_RECIPIENT_BINDING_V3`) | §6.1 (canonical owner) + §14.2.1 step 5 + §14.5.1 |
| `ERR_STANZA_WRAP_AEAD_FAIL` | Stanza wrap-AEAD fails after Shamir share wrap-key derivation | §6.2.4 |
| `ERR_CONDITIONAL_RECIPIENT_STANZA_MAC_FAIL` | Conditional-recipient stanza MAC under `TAG_CONDITIONAL_RECIPIENT_BINDING_V3` fails | §6.1.7 + §10.5 step 2 |
| `ERR_GATE_STANZA_MAC_FAIL` | Gate-stanza MAC under `TAG_STANZA_MAC_V3` fails at §6.1.4 step 3 (subject-side verifier discovers stanza-MAC mismatch BEFORE further field parsing) | §6.1.4 step 3 + §6.5 |

### §16.7 Layer 6 — Per-σ verification errors

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_SIGMA_SUBJECT_DIGEST_MISMATCH` | σ_subject_digest field bound in `commit_AAD` does not match recomputed digest | §5 |
| `ERR_SIGMA_LIT_VERIFY_FAIL` | σ_Lit fails BLS12-381 verification against Lit V3 serving TEE per-op signing key | §7.6 + §14.2.1 step 7 + §14.5.1 |
| `ERR_SIGMA_LIT_SIGNATURE_INVALID` | σ_Lit signature byte format invalid (length / curve point validity) | §7.6 |
| `ERR_LIT_DCAP_INVALID` | Lit V3 per-op DCAP quote signature verification fails (Intel SGX root) | §7.6 step 2 |
| `ERR_LIT_DCAP_USER_DATA_MISMATCH` | Lit V3 DCAP `user_data` field does not match recomputed 32-byte keccak digest per §11.3.2 96-byte preimage | §7.6 step 3 |
| `ERR_LIT_TEE_ASSIGNMENT_MISMATCH` | Lit V3 `assigned_tee_id` from `LitV3Assignment` does not match DCAP enclave measurement | §7.6 step 4 + §11.2 |
| `ERR_LIT_V3_ASSIGNMENT_MISSING` | No `LitV3Assignment` record exists for this `authorizationId` at commit's block | §11.2 |
| `ERR_SIGMA_G3_VERIFY_FAIL` | σ_G3 fails verification against G3AuthorityRegistry state at `RevealAuthorized` block (umbrella) | §14.2.1 step 7 + §14.5.1 |
| `ERR_SIGMA_G3_DCIPHER_INVALID` | σ_G3 dcipher path verification fails (Randamu Threshold Association registry pubkey) | §8.2.4 |
| `ERR_SIGMA_G3_DRAND_INVALID` | σ_G3 drand path verification fails (League of Entropy beacon pubkey) | §8.3.4 |
| `ERR_SIGMA_G4_VERIFY_FAIL` | σ_G4 fails verification against G4AuthorityRegistry state at `RevealAuthorized` block (umbrella) | §14.2.1 step 7 + §14.5.1 |
| `ERR_SIGMA_G4_PHASE1_INVALID` | σ_G4 Phase 1 Ed25519 signature fails verification against `G4AuthorityRegistry.entry.authority_pubkey + binary_hash` | §9.5.1 |
| `ERR_SIGMA_G4_PHASE2_DCAP_INVALID` | σ_G4 Phase 2 DCAP quote signature verification fails (cross-vendor TEE root) | §9.5.2 step 1 |
| `ERR_SIGMA_G4_PHASE2_USER_DATA_MISMATCH` | σ_G4 Phase 2 DCAP `user_data` field does not match recomputed 32-byte keccak digest per §11.3.2 128-byte preimage | §9.5.2 step 2 |
| `ERR_SIGMA_G4_AUTHORITY_REGISTRY_MISMATCH` | G4AuthorityRegistry entry not found at commit's block (any phase) | §9.5 + §12.3.3 |
| `ERR_SIGMA_G4_PHASE2_CROSS_VENDOR_VIOLATION` | Lit V3 + G4 Phase 2 cross-vendor mandate (A11) violated — both TEEs Intel SGX | §7.7 + §9.3.4 + §11.3.3 |
| `ERR_SIGMA_CONDITIONAL_VERIFY_FAIL` | σ_conditional fails per-mode verification (umbrella) | §14.2.1 step 7 + §14.5.1 |
| `ERR_SIGMA_CONDITIONAL_PASSKEY_INVALID` | Mode 1 WebAuthn assertion fails P-256 verification under `current_passkey_pubkey` | §10.2.4 step 6 |
| `ERR_SIGMA_CONDITIONAL_WALLET_RECOVER_MISMATCH` | Mode 2 ECDSA.recover yields address ≠ stanza-pinned `wallet_address` | §10.3.4 step 6 |
| `ERR_SIGMA_CONDITIONAL_EIP1271_INVALID` | Mode 3 (post-V2) `eth_call` to `contract_address.isValidSignature` does NOT return EIP-1271 magic value `0x1626ba7e` | §10.4.2 step 7 |
| `ERR_SIGMA_CONDITIONAL_EIP1271_BYTECODE_CHANGED` | Mode 3 (post-V2) bytecode integrity check: `extcodehash(contract_address) != contract_bytecode_hash_at_commit` AND `reject_on_bytecode_change = true` | §10.4.2 step 4 |
| `ERR_SIGMA_CONDITIONAL_THRESHOLD_INSUFFICIENT` | Fewer than `k` valid σ_conditional values present per `conditional_recipients_policy.k` | §10.5 step 4 |
| `ERR_SIGMA_CONDITIONAL_CARDINALITY` | σ_conditional Vec cardinality mismatch between commit and reveal | §15.9 |
| `ERR_SHAMIR_THRESHOLD_NOT_MET` | Configured §6.3 access-structure predicate is not satisfied by admitted shares | §6.3.6 |
| `ERR_SIGMA_MISSING` | A required σ authorization-evidence value is absent for a mandatory share-admission branch at re-key recovery | §15.9 |
| `ERR_SIGMA_G3_PATH_MISMATCH` | `g3_choice` value not 0 (dcipher) or 1 (drand) — `commit_AAD` corruption or schema-violation case caught at §14.1 pre-verify | §8.1 + §14.1 |
| `ERR_SIGMA_G4_PHASE_MISMATCH` | `phase` value not 1 (Phase 1 server) or 2 (Phase 2 TEE) — `commit_AAD` corruption | §9.3 + §14.1 |
| `ERR_SIGMA_G4_REFUSED` | G4 emitted refusal code 0x01-0x09 (per §9.4 enum) instead of σ_G4 — combiner reads the code from `G4RefusalRegistry` and aborts fail-closed | §9.4 + §9.5 + §12.3 |

**Per-σ wrap-around-vs-forensic layering (NORMATIVE — §11.5 + §14.5 carry-forward):** umbrella codes (`ERR_SIGMA_LIT_VERIFY_FAIL` / `ERR_SIGMA_G3_VERIFY_FAIL` / `ERR_SIGMA_G4_VERIFY_FAIL` / `ERR_SIGMA_CONDITIONAL_VERIFY_FAIL`) carry the gate-specific forensic sub-codes per the per-curve split discipline. Combiner-side wrap-around codes at §14.2.1 step 7 surface forensic per-gate codes from §7 / §8 / §9 / §10 verification protocols. **Wrap-around-vs-forensic pattern stable at 5 instances:** §10 + §11 + §12 + §13 + §14 — see §16.13 wrap-around-vs-forensic discipline.

### §16.8 Layer 7 — Pre-verify checklist errors (combiner §14.2.1)

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_COMBINER_BINARY_HASH_MISMATCH` | Combiner binary hash fails verification against `plugin_version_digest` | §14.2.1 step 1 |
| `ERR_CIPHERTEXT_DIGEST_MISMATCH` | Loaded `age_envelope` keccak does not match `ciphertext_digest` from `commit_AAD` | §14.2.1 step 2 |
| `ERR_AAD_DIGEST_MISMATCH` | Recomputed `aad_digest` does not match field bound in `h_commit` | §14.2.1 step 3 |
| `ERR_ATTESTATION_CONTEXT_MISMATCH` | Recomputed `attestation_context_digest_N` does not match endpoint-attestation evidence under the acyclic §3.4 schedule | §3.4 + §14.2.1 step 4 |
| `ERR_COMMIT_CONTEXT_MISMATCH` | Recomputed `commit_context_digest_N` does not match generation-N stanza-wrap context (or `commit_context_digest_0` does not match the generation-0 payload-AEAD nonce schedule — unchanged payload AEAD is always generation-0) under the acyclic §3.4 schedule | §3.4 + §14.2.1 step 4 |
| `ERR_H_COMMIT_MISMATCH` | Re-derived `h_commit` does not match on-chain `h_commit` value | §14.2.1 step 4 |
| `ERR_ENDPOINT_ATTESTATION_INVALID` | `endpoint_attestation_digest` from `commit_AAD` fails §11 4-check (umbrella) | §14.2.1 step 6 + §11.7 |
| `ERR_ENDPOINT_ATTESTATION_DIGEST_MISMATCH` | Commit-time DCAP digest mismatch (Phase 2 EndpointAttestation SCALE-decode + recompute fails) | §11.3.3 step 1 |
| `ERR_REGISTRY_VERIFICATION_FAILED` | Registry verification umbrella code (any of 5 V3 registries fail) | §14.2.1 step 8 + §12.9 |
| `ERR_REGISTRY_DEPRECATED_PRE_AUTHORIZATION` | A registry entry pinned in `commit_AAD` has DeprecationFlag set BEFORE `RevealAuthorized` | §14.2.1 step 8 |
| `ERR_COMMIT_SHREDDED` | Current ShredRegistry state for `h_commit` shows `shredded == true` | §14.2.1 step 9 |
| `ERR_SUPERSEDED_COMMIT_LINEAGE_BROKEN` | Recipient-side walk encounters missing supersession-pointer registry record | §15.9 (canonical owner) + §14.2.1 step 10 |

### §16.9 Layer 8 — Governance + registry errors (5 V3 registries)

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_PLUGIN_REGISTRY_MISMATCH` | PluginHashRegistry entry not found at commit's block | §12.2.3 |
| `ERR_PLUGIN_NOT_YET_EFFECTIVE` | PluginHashRegistry `effective_block > commit_block` | §12.2.3 |
| `ERR_PLUGIN_TOMBSTONED` | PluginHashRegistry `tombstone_block != 0 AND tombstone_block ≤ commit_block` | §12.2.3 |
| `ERR_G4_AUTHORITY_REGISTRY_MISMATCH` | G4AuthorityRegistry entry not found at commit's block | §12.3.3 + §9.5 |
| `ERR_G4_AUTHORITY_NOT_YET_EFFECTIVE` | G4AuthorityRegistry `effective_block > commit_block` | §12.3.3 |
| `ERR_G4_AUTHORITY_TOMBSTONED` | G4AuthorityRegistry `tombstone_block != 0 AND tombstone_block ≤ commit_block` | §12.3.3 |
| `ERR_DSL_VERSION_REGISTRY_MISMATCH` | DSLVersionRegistry entry not found at commit's block | §12.4.3 |
| `ERR_DSL_NOT_YET_EFFECTIVE` | DSLVersionRegistry `effective_block > commit_block` | §12.4.3 |
| `ERR_DSL_TOMBSTONED` | DSLVersionRegistry `tombstone_block != 0 AND tombstone_block ≤ commit_block` | §12.4.3 |
| `ERR_ORACLE_ROOT_MISMATCH` | Recomputed `MerkleRoot(SortedUnion({oracle_id_i}))` does not match `oracle_references_root` | §12.5.3 step 3 |
| `ERR_ORACLE_REGISTRY_MISMATCH` | OracleRegistry entry not found for any pinned oracle | §12.5.3 |
| `ERR_ORACLE_NOT_YET_EFFECTIVE` | OracleRegistry `effective_block > commit_block` | §12.5.3 |
| `ERR_ORACLE_TOMBSTONED` | OracleRegistry `tombstone_block != 0 AND tombstone_block ≤ commit_block` | §12.5.3 |
| `ERR_QTSP_REGISTRY_MISMATCH` | QTSPRegistry entry not found at commit's block | §12.7.3 |
| `ERR_QTSP_NOT_YET_EFFECTIVE` | QTSPRegistry `effective_block > commit_block` | §12.7.3 |
| `ERR_QTSP_TOMBSTONED` | QTSPRegistry `tombstone_block != 0 AND tombstone_block ≤ commit_block` | §12.7.3 |

**G4 reason code enum (canonical owner: §9 G4 reason-code enum + brief-07 §5):** the 10-code enum (`0x01`-`0x0A`) is governance-driven refusal signaling, NOT cryptographic-layer ERR codes. Reason codes are class-wide / per-commit refusal state recorded in `G4RefusalRegistry` per §9.4; ERR codes are combiner-side abort signals. The two layers are distinct — `0x06`-`0x09` deprecation refusals trigger combiner-side `ERR_REGISTRY_DEPRECATED_PRE_AUTHORIZATION` per §14.2.1 step 8 carry-forward.

### §16.10 Layer 9 — Re-key ceremony errors

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_REKEY_GOVERNANCE_UNAUTHORIZED` | Supersession-pointer write attempted without `RekeyGovernance` role | §15.9 |
| `ERR_REKEY_TIMELOCK_NOT_EXPIRED` | Supersession-pointer write attempted before 7-day timelock expiry | §15.9 |
| `ERR_REKEY_GENERATION_OVERFLOW` | `commit_generation: uint16` exceeds 65535 | §15.9 |
| `ERR_GATE_AUTHORITY_KEY_MISMATCH` | σ verification at recovery step fails because gate authority key has rotated since recipient's last sync | §15.9 |

### §16.11 Layer 10 — Rotation-log errors (PasskeyRotationLog)

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_ROTATION_ANCHOR_MISMATCH` | Recomputed `rotation_log_anchor` per §13.4 does not equal stanza's field | §13.7 |
| `ERR_ROTATION_WEBAUTHN_INVALID` | An `entry[i].webauthn_assertion` fails P-256 signature verification under `entry[i-1].new_pubkey` | §13.7 |
| `ERR_ROTATION_ENTRY_INDEX_NONMONOTONIC` | An `entry[i].entry_index != entry[i-1].entry_index + 1` | §13.7 |
| `ERR_ROTATION_PASSKEY_CHAIN_BROKEN` | An `entry[i].prev_pubkey != entry[i-1].new_pubkey` (passkey chain inconsistency) | §13.7 |
| `ERR_ROTATION_DELIVERY_X25519_CHAIN_BROKEN` | An `entry[i].prev_delivery_pubkey_x25519 != entry[i-1].new_delivery_pubkey_x25519` (X25519 delivery-key chain inconsistency) | §13.7 |
| `ERR_ROTATION_MLKEM_CHAIN_BROKEN` | An `entry[i].prev_mlkem_pubkey != entry[i-1].new_mlkem_pubkey` (mlkem chain inconsistency) | §13.7 |
| `ERR_ROTATION_LOG_UNREACHABLE` | The `contract_address` does not respond to on-chain query | §13.7 |
| `ERR_ROTATION_LOG_HEAD_UNAVAILABLE` | The `rotation_log_anchor` references an `entry_index_at_commit` that exceeds the contract's current head | §13.7 |
| `ERR_PASSKEY_ROTATION_WALK_FAIL` | Wrap-around code at §10 layer; surfaces §13.7's 5 forensic codes per worker-3 SHOULD-FIX-3 path (b) wrap-around-vs-forensic discipline | §10.2.4 step 4 |

### §16.12 Layer 11 — Delivery + transport errors

| Code | Trigger | Source / consumer |
|---|---|---|
| `ERR_SIGMA_DELIVERY_CHANNEL_AUTH_FAIL` | TLS mutual-auth fails on σ delivery channel | §14.5.1 |
| `ERR_SIGMA_DELIVERY_TIMEOUT` | Gate's σ delivery times out | §14.5.1 |
| `ERR_PDA_CONFIG_MODE_3_RESERVED` | Configurator-side, NOT combiner-side: configurator REJECTS PDA configuration containing variant 0x03 conditional_recipient stanza at V2 launch per Stage-0 Reconfirm B | §10.4.3 |
| `ERR_MODE_3_NOT_SHIPPED_AT_V2` | Combiner-side defense-in-depth: §10.5 step 3 encounters variant 0x03 stanza at V2 launch (configurator bypass case); fail-closed per §14.5.2 | §10.5 step 3 |

### §16.13 Wrap-around-vs-forensic discipline (NORMATIVE)

The V2 system / V3 custody error model uses a **layered ERR pattern** — each cryptographic layer carries umbrella codes that wrap-around forensic sub-codes from sub-protocols + per-curve / per-mode / per-registry forensic granularity. Per §11.5 + §14.5 + §14.7.4 carry-forward + worker-3 SHOULD-FIX-3 path (b) discipline:

**Wrap-around code:** combiner-side abort signal at the parent layer (e.g., `ERR_SIGMA_LIT_VERIFY_FAIL` at §14.2.1 step 7 — combiner aborts with this ERR when σ_Lit verification fails for any reason).

**Forensic sub-code:** sub-protocol-level diagnostic at the child layer (e.g., `ERR_LIT_DCAP_INVALID` / `ERR_LIT_DCAP_USER_DATA_MISMATCH` / `ERR_LIT_TEE_ASSIGNMENT_MISMATCH` at §7.6 — diagnostics for forensic root-cause).

**Layering pattern stable at 5 instances:** §10 (per-mode σ_conditional sub-codes wrap-around to `ERR_SIGMA_CONDITIONAL_VERIFY_FAIL`) + §11 (per-DCAP sub-codes wrap-around to `ERR_ENDPOINT_ATTESTATION_INVALID`) + §12 (per-registry sub-codes wrap-around to `ERR_REGISTRY_VERIFICATION_FAILED`) + §13.7 (per-walk-step sub-codes wrap-around to `ERR_PASSKEY_ROTATION_WALK_FAIL`) + §14 (combiner-side step-N sub-codes wrap-around to per-step ERR codes at §14.2.1).

**§13.7 vs §13.6 distinction (cross-section precision):** the §13.7 entry above is the per-walk-step ERR layering substrate (forensic codes at the rotation-log walk layer); the §13.6 entry at §16.14 architectural-truth-template multi-substrate-variant INSTANCE enumeration is the Cealis-as-infrastructure-not-authority architectural-truth-template framework. The two are distinct phenomena at distinct subsection-level granularity within §13 — §13.7 = ERR-layer wrap-around; §13.6 = architectural-truth-template framework.

**Caller-side handling discipline:** caller's plugin client surfaces the forensic sub-code if available (root-cause diagnostic) AND the wrap-around umbrella code (caller-side classification). Both are returned in fail-closed semantics — there is no soft-fail / retry / fallback recovery at the cryptographic layer.

### §16.14 Architectural-truth-template multi-substrate-variant INSTANCE enumeration

Per worker-3 ERR consolidation index §16 SHOULD organizational-anchor item 5 + dw-lead PP-12-A1 absorption: §16 enumerates 5 architectural-truth-template multi-substrate-variant INSTANCEs surfacing the same architectural truth across different substrate variants. Each INSTANCE represents a multi-layer-defense pattern where independent enforcement substrates converge on the same architectural property:

1. **§14.7.4 combiner — per-generation σ authorization-evidence verification framing:** re-key generation supersession lineage; substrate variants distinguished without auxiliary invariants (cross-generation byte-identity holds via stable share values, while gate-authority-key-stability is an operational S2-6 property, not a §15 cryptographic constraint per §15.6.3 retraction).

2. **§13.6 Cealis-as-infrastructure-not-authority:** ABI standard (not singleton) PasskeyRotationLog; recipient self-publish via permissionless contract; censorship mitigation as substrate variant. Three independent substrate variants enforce "Cealis cannot forge rotations": (a) ABI-standard contract publication openness, (b) recipient self-publish path, (c) WebAuthn assertion under prior passkey (Cealis-not-custody).

3. **§10.9 Mode 3 RESERVED enforcement chain:** three independent enforcement layers all enforce "no V2 reveal consumes Mode 3 σ_conditional" under different substrate variants — (a) configurator-side rejection at PDA-config time (`ERR_PDA_CONFIG_MODE_3_RESERVED`), (b) envelope-load-time subject-side verifier rejection (`ERR_MODE_3_NOT_SHIPPED_AT_V2` defense-in-depth), (c) reveal-time combiner rejection at §14.5.2 fail-closed default.

4. **§11.4 endpoint attestation 6-substrate enumeration:** six independent registry/assignment substrates (LitV3Assignment + 5 V3 registries) all enforce "historical commits remain verifiable across registry rotations" under different substrate variants (Lit V3 governance contract + Cealis-governed registries with `(hash, effective_block, tombstone_block)` tuples + threshold-network registries with epoch-pubkey rotations + QTSPRegistry with provider-metadata entries).

5. **§12.6 5-registry historical-lookup:** five independent Cealis-governed registry substrates (PluginHashRegistry / G4AuthorityRegistry / DSLVersionRegistry / OracleRegistry / QTSPRegistry) all enforce "historical commits remain verifiable across registry rotations" under different substrate variants. §12.6 + §11.4 together carry 6 historical-lookup substrates total under one architectural truth (§11.4 = 6 with LitV3Assignment; §12.6 = 5 Cealis-governed only).

**Organizational principle (NORMATIVE):** when a §16-listed code has multiple substrate origins (e.g., `ERR_PASSKEY_ROTATION_WALK_FAIL` wraps 5 forensic sub-codes from §13.7), the wrap-around-vs-forensic discipline (§16.13) + multi-substrate-variant INSTANCE pattern (§16.14) jointly distinguish **single-layer-enforcement codes** (single source per code) from **multi-layer-defense codes** (multiple enforcement substrates per architectural truth). §16 preserves both patterns as the organizational principle that distinguishes per-code semantics.

### §16.15 share secrecy + PII safety in error blobs (NORMATIVE)

Per §14.3 + §14.4 share secrecy discipline + §9.4.4 + §12.5.5 + §12.8.4 encrypted-reason mode pattern + worker-3 ERR consolidation index share secrecy carry-forward:

**5 anti-pattern call-outs (NORMATIVE — error contexts MUST NOT contain):**

1. **σ value bytes in error context** — `ERR_SIGMA_*_VERIFY_FAIL` codes MUST NOT include the σ value bytes. Surfacing σ bytes in caller-side error logs is not sufficient to derive `file_key`, because σ values are authorization evidence rather than Shamir inputs; the ban remains because raw σ logs create unnecessary replay/forensic ambiguity and can be correlated with authorization events.
2. **Partial σ bytes in retry context** — `ERR_SIGMA_DELIVERY_*` codes MUST NOT include partial σ bytes in retry context. Same disclosure boundary as (1), without implying σ bytes are DEK material.
3. **Partial AAD bytes in debug context** — `ERR_AAD_DIGEST_MISMATCH` MUST NOT include partial `commit_AAD` bytes in debug context. AAD field drift can leak subject_commitment_v3 / sigma_subject_digest / pda_root which transitively leak PII via the §3.6 + §4.9 framework.
4. **Plaintext PII in any error context** — caller's plugin client receives ONLY ERR codes + structurally-PII-free metadata (`authorizationId`, `h_commit`, registry entry IDs). Decoded plaintext from a partially-decrypted AEAD payload MUST NOT enter error contexts.
5. **Encrypted-reason mode default for sensitive G4 reason codes** — codes `0x02 Art. 17 erasure` + `0x03 Art. 18 restriction` per §9.4.4 + §12.5.5 + §12.8.4 trigger `G4RefusalRegistry.encrypted_reason_blob` rather than plaintext for the on-chain refusal signal. On-chain event emits ONLY `RefusalSignal(authorizationId, "refused")`; decryption is partner-resolver-key controlled, and missing resolver key fails closed with no plaintext fallback.

**PII content boundary (matching §11.8 + §12.12 inverse-Breyer framing):** ERR codes themselves are operator-side cryptographic identifiers (no natural-person PII). The error model's 11 layers carry only operator-side substrate failures (gate operators, registry operators, plugin operators, governance operators) — NOT subject-side identifiers. Subject-side fields entering error contexts (`subject_commitment_v3`, `wallet_address`, `passkey_pubkey`) are protected by the 5 anti-pattern call-outs above.

**Strict GDPR interpretation (Breyer C-582/14 + Recital 26): EXPLICITLY NOT APPLICABLE to §16 substrates** (matching §11.8 + §12.12 inverse-Breyer framing). §16 ERR codes carry only operator-side failure signals — NONE are natural-person identifiers, cross-partner-stable or otherwise. The Breyer C-582/14 third-party-observer-vs-controller-scope distinction at §10.10 + §13.10.1 framework does NOT apply to §16 ERR codes because there is no natural-person identifier in ERR's substrate set to which the third-party-observer reachability surface could attach. The §16 inverse-Breyer note here at §16.15 + the parallel statement at §16.19 jointly constitute the **§16 inverse-Breyer instance** (single 3rd inverse-Breyer instance for the V2 system / V3 custody cryptographic layer; §16.15 + §16.19 are joint anchors of the same instance, not two separate instances).

**Symmetric-framework pattern stabilized at 5 substrate-distinguishing PII-NONE consolidations (per dw-lead PP-12-A2 absorption + worker-3 supplement count correction):** 3 inverse-Breyer NOT APPLICABLE substrates (§11.8 endpoint attestation + §12.12 registries + §16 ERR codes via §16.15 + §16.19 joint anchor) + 2 Breyer-applies substrates (§10.10 Mode 2 wallet_address + §13.10.1 PasskeyRotationLog third-party-observer reachability) = 5 substrate-distinguishing PII-NONE consolidations comprising the comprehensive PII consolidation framework per §3.6 ¶3 + §4.9 ¶2 + §10.10 + §13.10.1 anchor.

### §16.16 Abort discipline (NORMATIVE)

Per §1.7 fail-closed default + §14.5.2 second normative property:

**Abort semantics (NORMATIVE):** any `ERR_*` from §16.2-§16.12 aborts the V2 system / V3 custody cryptographic operation at the layer the failure surfaces. The caller's plugin client receives the ERR code(s) — both wrap-around umbrella + forensic sub-code where applicable per §16.13 — and surfaces the abort to the recipient/subject for human-readable display.

**No fail-open default:** §1.7 requires fail-closed. There is no soft-fail / retry-with-degraded-security / fallback-to-V1-crypto path at the cryptographic layer. Operational retries (re-fetch envelope from vault, re-collect σ from gate operators if delivery channel failed pre-verify) are caller-side concerns, NOT cryptographic-layer concerns.

**No σ-or-plaintext-in-error-context default:** per §16.15, error contexts MUST NOT carry σ values or partial plaintext. Combiner-side abort produces ERR code(s) + structurally-PII-free metadata only.

**Caller-side recovery boundary (NORMATIVE):**

- **Cryptographic-layer abort = absolute** — caller cannot bypass via retry / fallback / degraded-mode. The cryptographic layer is fail-closed by V3 enforcement model.
- **Operational-layer retry = permitted** — caller may re-collect σ values if delivery channel timeout fired BEFORE per-σ verification; caller may re-walk PasskeyRotationLog from anchor if intermediate `ERR_ROTATION_LOG_UNREACHABLE` resolves; caller may re-fetch envelope if `ERR_CIPHERTEXT_DIGEST_MISMATCH` resolves with retry-after-cache-eviction. **These retries DO NOT bypass cryptographic abort — they re-invoke verification at the same fail-closed default.**

### §16.17 Cross-section integration

§16's 11-layer ERR taxonomy is INVOKED across all V2 system / V3 custody cryptographic sections:

- **§5 σ_subject** — invokes Layer 1 (cryptographic primitive errors) + Layer 6 (per-σ verification errors)
- **§6.1 stanza format** — invokes Layer 5 (per-stanza wrap errors)
- **§6.2 hybrid PQ wrapping** — invokes Layer 1 + Layer 5
- **§6.3 Shamir reconstruction** — invokes Layer 3
- **§6.4 ChaCha20-Poly1305 AEAD** — invokes Layer 4
- **§7-§9 gate signatures (σ_Lit / σ_G3 / σ_G4)** — invokes Layer 6
- **§10 σ_conditional Mode 1/2/3** — invokes Layer 6 + Layer 11 (Mode 3 RESERVED enforcement)
- **§11 endpoint attestation** — invokes Layer 6 + Layer 7 (combiner pre-verify checklist)
- **§12 Registry verification** — invokes Layer 8 (governance + registry errors)
- **§13 PasskeyRotationLog** — invokes Layer 10
- **§14 Combiner protocol** — invokes ALL 11 layers (combiner is the convergence point); Layers 1-10 run in §14.2.1 pre-verify checklist sequence, Layer 11 runs in parallel with per-σ collection BEFORE combiner pre-verify (per Layer-11-parallel-vs-sequential framing below)
- **§15 Re-key ceremony** — invokes Layer 9
- **§17 Cross-references** — final integration pass for §16 cross-section anchors

**§14 combiner is the convergence point for all 11 layers.** Per §14.2.1's 10 ordered pre-verify checks, the combiner runs ALL Layer 1-Layer 10 checks BEFORE §6.3 file_key reconstruction fires. **Layer 11 (delivery + transport) runs alongside per-σ collection BEFORE combiner pre-verify** — Layer 11 is the only layer with parallel-rather-than-sequential ordering vs the §14.2.1 checklist, per the per-σ delivery-channel + timeout discipline being a precondition (not a checklist step) for combiner pre-verify entry. Any layer failure aborts the combiner with the wrap-around umbrella code + forensic sub-code per §16.13.

### §16.18 Cross-reference index

**Absorption annotations (Phase 1 → Phase 3 trace):** §16's 11-layer organizational principle absorbs two dw-lead-routed dispositions per the Phase 1 → Phase 2 → Phase 3 propagation chain: **PP-12-A1** (5-instance architectural-truth-template multi-substrate-variant INSTANCE enumeration — anchored at §16.14, instances at §14.7.4 + §13.6 + §10.9 + §11.4 + §12.6) and **PP-12-A2** (symmetric-framework Breyer pattern stabilized at 5 substrate-distinguishing PII-NONE consolidations — anchored at §16.15 + §16.19 joint, with 3 inverse-Breyer NOT APPLICABLE substrates at §11.8 + §12.12 + §16 + 2 Breyer-applies substrates at §10.10 + §13.10.1). Both absorptions are integrated into §16's organizational anchor framing rather than carried as standalone normative call-outs — the canonical-definition ownership table below operates over codes; the architectural patterns are anchored at §16.14 + §16.15 + §16.19.

**Canonical-definition ownership (per worker-3 ERR index deduplication recommendations):**

- `ERR_AEAD_TAG_VERIFY_FAIL` — §6.4 (AEAD layer canonical owner); §6.3.7 + §14.5.1 cross-references
- `ERR_SUPERSEDED_COMMIT_LINEAGE_BROKEN` — §15.9 (supersession lineage canonical owner); §14.5.1 cross-reference
- `ERR_STANZA_MAC_VERIFY_FAIL` — §6.1 (stanza format canonical owner); §14.5.1 cross-reference
- `ERR_HKDF_FAIL` vs `ERR_HKDF_EXTRACT_FAIL` + `ERR_HKDF_EXPAND_FAIL` — §16.4 retains BOTH granular + umbrella per worker-B preference (matches per-curve σ verification split discipline)
- `ERR_SIGMA_CONDITIONAL_VERIFY_FAIL` — §16.7 + §14 (canonical wrap-around naming); deprecated `ERR_SIGMA_CONDITIONAL_INVALID` removed per worker-3 §14 verdict
- `ERR_REGISTRY_VERIFICATION_FAILED` — §16.8 + §12.9 (registry-class umbrella canonical owner); §14.2.1 step 8 cross-reference

This section consumes the following primitives and sections:

- **§1.7** fail-closed error model — anchors §16.16 abort discipline normative behavior
- **§3.6 ¶3 + §4.9 ¶2** PII protection framework — anchors §16.15 PII content boundary
- **§5** σ_subject — Layer 6 verification (σ_subject_digest mismatch + authenticator_class)
- **§6.1-§6.4** envelope + stanza + HKDF + AEAD — Layers 3, 4, 5
- **§7.6 / §8.2.4 / §8.3.4 / §9.5** gate signature verification protocols — Layer 6
- **§9.4.4 + §12.5.5 + §12.8.4** encrypted-reason mode pattern — anchors §16.15 anti-pattern call-out 5
- **§10.2.4 / §10.3.4 / §10.4.2 / §10.5** σ_conditional Mode 1/2/3 verification protocols — Layer 6
- **§10.4.3** configurator-side Mode 3 RESERVED enforcement — Layer 11
- **§10.9** Mode 3 RESERVED enforcement chain INSTANCE — §16.14 instance 3
- **§10.10 + §13.10.1** Breyer-applies framework — symmetric-framework pattern at §16.15
- **§11.3.3 / §11.5 / §11.8** endpoint attestation 4-check + wrap-around discipline + inverse-Breyer note — Layer 6 + §16.13 + §16.15
- **§11.4** at-commit-block 6-substrate enumeration INSTANCE — §16.14 instance 4
- **§12.2.3 / §12.3.3 / §12.4.3 / §12.5.3 / §12.7.3** registry verification protocols — Layer 8
- **§12.6 / §12.9** at-commit-block 5-registry enumeration INSTANCE + cross-section integration — §16.14 instance 5
- **§12.8.4 + §12.12** halt-scope table + inverse-Breyer note — §16.15 + §16.13
- **§13.5 + §13.6 + §13.7 + §13.10.1** PasskeyRotationLog walk-from-anchor + Cealis-as-infrastructure-not-authority + Breyer-applies framework — Layer 10 + §16.14 instance 2 + §16.15
- **§14.2.1** combiner pre-verify checklist 10 ordered checks — convergence point for all 11 layers
- **§14.3 + §14.4 + §14.5.1 + §14.5.2** share secrecy discipline + 5 anti-pattern call-outs + fail-closed default + auditable-failure normative property — anchors §16.15 + §16.16
- **§14.7.4** architectural-truth-template multi-substrate-variant INSTANCE — §16.14 instance 1
- **§15.6 + §15.9** re-key ceremony cryptographic invariants + supersession lineage governance — Layer 9

Forward-references (consumed by later sections):

- **§17 Cross-references** — final integration pass for §16 cross-section anchors
- **App. A SCALE schema reference** — ERR codes are cryptographic-layer; SCALE schemas are wire-format layer; cross-references where ERR codes derive from SCALE-decode failures (Layer 2)
- **App. B test vectors** — per-ERR test vectors for forensic root-cause validation (S2-1 lock; vector authoring per S2-3)
- **App. C scope-out enumeration** — operational ERR codes (caller-side retry / log archival / monitoring) explicitly out of S2-1 cryptographic-layer scope; tracked at S2-6 operational ceremonies + S2-7 monitoring + observability spec

S2-2 contract interface details (`G4RefusalRegistry`, `ShredRegistry`, `SupersededCommitRegistry` contract surfaces) are S2-2 territory. Library SDK version pins are S2-3 territory. Caller-side error handling + observability + alerting are S2-7 territory.

### §16.19 PII content statement

§16 ERR codes are PII-NONE at the cryptographic-construct layer. The 11-layer ERR taxonomy contains:

- **Layer 1-Layer 4 codes** — cryptographic primitive failure signals (signature verification + SCALE encoding + HKDF derivation + AEAD tag verification) — operator-side substrate failures, non-PII.
- **Layer 5 codes** — per-stanza wrap failure signals (variant tag + length + MAC + wrap-AEAD) — operator-side substrate failures, non-PII.
- **Layer 6 codes** — per-σ verification failure signals (σ_subject / σ_Lit / σ_G3 / σ_G4 / σ_conditional) — gate-operator-side substrate failures, non-PII per §11.8 + §12.12 inverse-Breyer framing.
- **Layer 7 codes** — combiner pre-verify checklist failure signals — combiner-side substrate failures, non-PII.
- **Layer 8 codes** — registry verification failure signals — governance-operator-side substrate failures, non-PII per §12.12 inverse-Breyer framing.
- **Layer 9 codes** — re-key ceremony failure signals — governance-operator-side substrate failures, non-PII.
- **Layer 10 codes** — PasskeyRotationLog walk failure signals — substrate-operator-side failures (Cealis-as-infrastructure-not-authority per §13.6); subject-side natural-person identifiers (passkey pubkeys) protected by §16.15 anti-pattern call-out 1 (no σ-or-pubkey bytes in error context).
- **Layer 11 codes** — delivery + transport failure signals — operator-side substrate failures, non-PII.

The σ/share transport discipline per §7.1 + §9.1 + §10.1 protects share-admission integrity; the ERR codes are operator-side abort signals that support the σ-as-authorization model (combiner aborts when σ values fail to verify) WITHOUT introducing subject-side PII surface. The two protection layers are orthogonal: PII is protected by AEAD payload encryption per §6.4; ERR semantics are protected by §16.15 share secrecy + PII safety + §16.16 abort discipline (no σ-or-PII-in-error-context default).

**Strict GDPR interpretation (Breyer C-582/14 + Recital 26): EXPLICITLY NOT APPLICABLE to §16 substrates** (matching §11.8 + §12.12 inverse-Breyer framing — joint §16.15 + §16.19 statements constitute the single §16 inverse-Breyer instance per §16.15 disambiguation note). §16 ERR codes carry only operator-side failure signals; the §10.10 + §13.10.1 third-party-observer-vs-controller-scope distinction does NOT apply because there is no natural-person identifier in ERR's substrate set. Subject-side natural-person identifiers entering error contexts (passkey pubkeys at Layer 10, wallet addresses at Layer 6 σ_conditional Mode 2) are protected by §16.15 anti-pattern call-outs (no σ-or-pubkey bytes in error context, no plaintext PII in any error context).

---

## §17 — Cross-references to other Stage-2 specs

This section enumerates the cross-references between S2-1 cryptography-spec.md and the other six Stage-2 specs (S2-2 smart-contracts, S2-3 custody-integration, S2-4 configurator-PDA, S2-5 ingestion-delivery-API, S2-6 operational-ceremonies, S2-7 SD v2). The discipline is forward-looking: S2-1 fixes wire-format identifiers (RFC, FIPS, EIP, IRTF draft, W3C standard) and byte-exact preimage layouts; the other Stage-2 specs consume these fixed identifiers and add their layer-specific surfaces. **S2-1 is foundational — it consumes none of the other Stage-2 specs and is consumed by all of them.** Per §0 line 6.

The cross-reference index here is the canonical map from S2-1 sections to their consumer-side S2-N home and from S2-1's "this spec does NOT cover" enumeration to the actual S2-N spec where each scope-out item lands. Conformance to S2-1 alone is necessary but not sufficient for a complete Cealis deployment; cross-spec coordination is binding per the cross-spec author-lock disciplines enumerated at §6.1.3, §6.1.5, §9.5, §12.2.

### §17.1 Stage-2 doc dependency graph

S2-1 is the foundational cryptography spec. The dependency graph is one-way: S2-1 → all others; no other Stage-2 spec is consumed by S2-1.

```
                        S2-1 (cryptography-spec) — THIS SPEC
                                        │
              ┌────────────┬────────────┼────────────┬────────────┬────────────┐
              ▼            ▼            ▼            ▼            ▼            ▼
            S2-2         S2-3         S2-4         S2-5         S2-6         S2-7
       smart-contracts  custody-      configurator- ingestion-    ops-        SD v2
                        integration   PDA           delivery-API  ceremonies
```

Per-S2-N consumption summary:

| Stage-2 doc | What it consumes from S2-1 | What it adds beyond S2-1 |
|---|---|---|
| **S2-2 smart-contracts** | TAG_*_V3 byte layouts, h_commit + authorizationId + pda_root + endpoint_attestation_digest preimages, σ authorization-evidence verification semantics, registry contract interfaces | Solidity contract interfaces (G4AuthorityRegistry, PluginHashRegistry, OracleRegistry, QTSPRegistry, DSLVersionRegistry, ConditionEngine, Vault, DisclosureRegistry, RekeyGovernance, SupersededCommitRegistry), 7-day TimelockController governance, on-chain event semantics (RevealAuthorized, RekeyTriggered) |
| **S2-3 custody-integration** | wire-format identifiers (RFC/FIPS/EIP/IRTF), §1.8 no-SDK-pin discipline, BLS12-381 variant assignment deferrals (Lit V3, dcipher) | Library version pins (`@noble/curves`, `@noble/hashes`, `@noble/ciphers`, `@simplewebauthn/server`, `@polkadot/util`, `filippo.io/age`, `drand/kyber`, Randamu dcipher SDK, Lit V3 SDK, Automata zkDCAP), Lit V3 ACC parser, explicit X25519 key publication / derivation paths, vendor TEE SDK selection (Intel SGX / AMD SEV-SNP / AWS Nitro) |
| **S2-4 configurator-PDA** | conditional_recipients_policy struct (§4 + §10), role_tag/delivery_hint byte values (§6.1.5 line 1404, 1449), commit_AAD field set (§4), Mode 3 RESERVED enforcement layer (§10.4.3), qes_subject_required flag (§4) | PDA configuration UI/CLI, configurator-side enforcement of Mode 3 rejection + QES preconditions + cealis_class_wide_halt_opt_out gating per §F PDA+ guardrail, k ≥ 1 enforcement, partner-pubkey registration, schema selectors per §D §432 |
| **S2-5 ingestion-delivery-API** | RevealArtifactBundle structure, AEAD payload byte layout (§6.4), per-recipient X25519 wrap (§10.3.5), envelope-size budget (~19 KB per BP-8 §6.2 line 1635) | REST API surfaces (POST /reveal, POST /ingest), webhook event payloads, IPFS gateway pulls, crypto-shred coordination at vault layer |
| **S2-6 operational-ceremonies** | Re-key ceremony cryptographic discipline (§15), key rotation orthogonal-ceremony framing (§15.6.3), DCAP attestation root bootstrapping per §11.2 | DKG ceremony runbooks, key rotation operational procedures, plugin distribution channel, vendor coordination protocols, RekeyGovernance multisig operational mechanics |
| **S2-7 SD v2** | TAG_SD_* tags (disjoint namespace from CEALIS_V3_*), Poseidon + PLONK + TEE pipeline architecture | SD field commitment construction, ZKP circuit specs, salt derivation HKDF context, nullifier construction, day-one delivery semantics |

### §17.2 Cross-reference table per S2-N target

#### §17.2.1 S2-2 smart-contracts-spec consumption surfaces

S2-2 consumes the following S2-1 surfaces normatively. Author-lock discipline applies — S2-2 contract interfaces MUST honor S2-1 byte layouts; coordinated update across both specs is required for any field change.

| S2-1 surface | Section | What S2-2 inherits | Author-lock |
|---|---|---|---|
| `TAG_G4_ATTESTATION_AUTHORITY_V3` derivation | §2.3.5 | G4AuthorityRegistry contract storage key encoding | YES (§9 line 899: "S2-2 G4AuthorityRegistry contract interface MUST honor this byte layout") |
| `authority_pubkey_ref` SCALE sum-type | §6.1.3 | G4AuthorityRegistry registry-reference variant byte layout | YES (§6.1.3 line 1354: "S2-2 G4AuthorityRegistry contract interface MUST honor this byte layout") |
| `pda_root` 29-field preimage | §3.3 | PluginHashRegistry storage key + condition-engine module ABI | YES |
| `h_commit` 15-field preimage | §3.4 | ConditionEngine on-chain commit anchor | YES |
| `authorizationId` 5-field preimage | §3.2 | ConditionEngine RevealAuthorized event indexed param | YES |
| `endpoint_attestation_digest` SCALE sum-type | §3.4.3 | On-chain endpoint attestation storage discipline | YES (Simon D10) |
| `g4_authority_ref` derivation | §3.4 + §9 | G4AuthorityRegistry registry-walk discipline | YES |
| `SupersededCommitRegistry` lookup hash | §15.6.3 + TAG_SUPERSEDED_COMMIT_REGISTRY_V3 | Registry storage layout + 7-day TimelockController gating | YES (BP-11 LOCKED 2026-04-26) |
| `RekeyGovernance` role | §15 | Multisig governance role on Cealis on-chain control contract | NO (operational mechanics S2-6, contract surface S2-2) |
| `ShredRegistry` current-state read at RevealAuthorized block | §6.4 line 1931 + §14.1 step 5 | Vault-side coordination + on-chain shred state read | YES |
| `OracleRegistry`, `QTSPRegistry`, `DSLVersionRegistry`, `PluginHashRegistry` | §12 (when drafted) | Per-registry contract interface + at-commit-block reading discipline | YES |

S2-2 MUST also implement the on-chain event semantics that S2-1's combiner pre-verify protocol (§14.1) reads from chain state — `RevealAuthorized` event with indexed `authorizationId` + `block_hash` binding for A14 anti-replay; `RekeyTriggered` event for re-key supersession lineage walks per §15.

#### §17.2.2 S2-3 custody-integration-spec consumption surfaces

S2-3 absorbs all library version pin churn. S2-1 carries wire-format identifiers; S2-3 carries the binding to specific library implementations + version pins per §1.8. The library catalog below is normative — S2-3 MUST provide a version pin for each entry.

| S2-1 wire format | Library family | S2-3 pin obligation |
|---|---|---|
| BLS12-381 (FIPS) | `@noble/curves` BLS12-381 module | Library version + Lit V3 hash-to-curve ciphersuite identifier |
| BLS12-381 minimum-pubkey-size variant (drand) | `drand/kyber` Go library + `@noble/curves` for verification | Library versions; variant assignment ALREADY locked (drand = G1 pubkey + G2 sig per §1.1.4) |
| BLS12-381 variant assignment (Lit V3, dcipher) | Lit V3 SDK + Randamu dcipher SDK | **Variant assignment + library version per §1.1.4 line 38 deferral** (BP-5 LOCKED on drand path; Lit V3 + dcipher pending S2-3 SDK confirmation) |
| P-256 (FIPS 186-5 / WebAuthn) | `@simplewebauthn/server` + browser WebAuthn API | Library version + assertion verification ciphersuite |
| Ed25519 (RFC 8032) | `@noble/curves` Ed25519 module + Cealis G4 sealed-code daemon | Library version + daemon binary hash |
| secp256k1 (SEC 2) | `viem` / `ethers.js` / `@noble/curves` | Library version + EIP-2 low-s normalization API |
| ML-KEM-768 (FIPS 203) | (S2-3 selects FIPS 203 reference impl) | Library version + FIPS 203 conformance certification |
| X25519 (RFC 7748) | `@noble/curves` X25519 module | Library version + RFC 7748 conformance |
| ChaCha20-Poly1305 (RFC 8439) | `@noble/ciphers ^1.0` per `flows-spec-final.md:250` | Library version + Cure53 audit reference |
| keccak-256 / SHA-256 / HKDF | `@noble/hashes ^1.4` | Library version + Cure53 noble-hashes audit Sep 2024 reference |
| SCALE codec (Polkadot) | `@polkadot/util ≥13` | Library version + SCALE specification conformance |
| age envelope | `filippo.io/age` | Library version + age v1 wire format conformance |
| DCAP attestation (Intel) | Automata zkDCAP on-chain verifier + per-vendor TEE SDK | Verifier circuit version + per-vendor SDK selection (Intel SGX SDK / AMD SEV-SNP SDK / AWS Nitro NSM SDK) per A11 cross-vendor mandate |
| Explicit G3 X25519 recipient-key publication | G3 vendor SDK / registry publication path | S2-3 pins how dcipher/drand expose or wrap to the explicit X25519 recipient key used by §6.2; no BLS-to-X25519 conversion is permitted |
| Explicit Ed25519-authority-to-X25519 separation | `@noble/curves` Ed25519 + X25519 modules | S2-3 pins separate Ed25519 verification and X25519 wrap-key APIs; no Ed25519-to-X25519 conversion is consumed by S2-1 |
| JCS canonicalization (RFC 8785) | (S2-3 selects RFC 8785-conformant impl) | Library version + RFC 8785 conformance for RevealArtifactBundle per Simon D4b |

S2-3 must additionally pin **Lit V3 ACC parser** + **dcipher IBE encoding** + **drand round encoding** library / vendor SDK per §3.4.5 line 584 protocol-canonical-encoding deferral.

#### §17.2.3 S2-4 configurator-PDA-spec consumption surfaces

S2-4 implements the partner-facing PDA configuration UI/CLI. S2-1's author-lock disciplines for byte-level enums and the configurator's preconditions enforcement layer:

| S2-1 surface | Section | S2-4 obligation |
|---|---|---|
| `role_tag` enum (`uint8`) | §6.1.5 line 1404 + line 1449 | Honor byte values (`0x01 HEIR` … `0x07 SUBJECT_SELF`); coordinate update across §6.1.5 + §10 + S2-4 for new role_tags |
| `delivery_hint` enum (`Option<uint8>`) | §6.1.5 line 1405 | Honor byte values per §6.1.5 line 1405; weaker downstream binding (delivery_hint not in any cryptographic preimage) |
| `g3_choice` selection | §4 + §8 | dcipher OR drand per-PDA selection at config time |
| `commit_AAD` 22-field structure | §4 | Field-set validation at PDA-config time, including `sdMerkleRoot` |
| `qes_subject_required` flag | §4 + §5 | Per-PDA QES election at PDA-config time; §286 is default and §371a/QTSP posture applies only when this flag is true |
| `cealis_class_wide_halt_opt_out` | §3.3.4 D1 + §9.4 | Legal-effect PDAs MUST set this to `false`; configurator rejects opt-out under legal-effect PDAs |
| Mode 3 RESERVED enforcement | §10.4.3 (3-layer defense-in-depth chain) | Layer 1 of the chain — configurator rejects `delivery_mode = WALLET_EIP1271` at PDA-config time |
| `k ≥ 1` for conditional_recipients_policy | §10.6 + §4.1 conditional_recipients_policy_digest | Configurator-side validation of conditional_recipients_policy.k field |
| `chain_condition` ACC validation | §6.1.3 line 1319 | Lit V3 ACC parser at PDA-config time validates chain_condition syntax (parser library S2-3 territory) |
| `subject_authenticator_class` + `qtsp_provider_ref` | §3.3.4 D1 lines 520-521 | Per-PDA configuration of subject signing surface (passkey vs wallet vs QES) + QTSP provider selection |
| Schema selectors per §D §432 | §10.2.5 + §14.6 + §14.9.1 | Per-recipient PDA-config-time schema selector definition |
| Legal-effect PDA gating | §6.1.3 + §11 + §F PDA+ guardrail | Configurator enforces all legal-effect preconditions (Phase 2 G4 only, QES elected, halt-opt-out forbidden, default disclosure-mode) |

#### §17.2.4 S2-5 ingestion-delivery-API-spec consumption surfaces

S2-5 implements the REST API + delivery surfaces between Cealis and partners + recipients. S2-1 fixes the cryptographic structure of objects that travel over the API; S2-5 fixes the wire transport.

| S2-1 surface | Section | S2-5 obligation |
|---|---|---|
| RevealArtifactBundle structure | §15 + §16 | JCS-canonicalized JSON wire format per Simon D4b; per-recipient bundles |
| AEAD payload byte layout | §6.4 | API treats payload as opaque ciphertext bytes; no parsing at API layer |
| Per-recipient X25519 wrap | §10.3.5 + §6.1 + §6.2 | API delivery via HTTPS POST or IPFS pull per recipient `delivery_url` |
| Envelope size budget (~19 KB k=5) | §6.2 line 1635 | API size limits + ingestion-bandwidth planning per BP-8 |
| Webhook event semantics | §11 + §15 | RevealAuthorized → API-side webhook delivery; rate limiting + retry discipline |
| Crypto-shred coordination | §6.4 line 1931 + §14.1 step 5 | Vault-side ciphertext deletion + chain-side shred-state read coordination |

#### §17.2.5 S2-6 operational-ceremonies-spec consumption surfaces

S2-6 handles operational mechanics — runbooks, vendor coordination, key custody. S2-1 fixes the cryptographic discipline; S2-6 fixes the human + operational layer.

| S2-1 surface | Section | S2-6 obligation |
|---|---|---|
| Re-key ceremony triggering + supersession lineage | §15 | RekeyGovernance multisig operational mechanics, quorum thresholds, member rotation, signing key custody |
| Gate authority key rotation | §15.6.3 | Orthogonal-ceremony operational runbook (out-of-scope of §15) |
| Plugin distribution channel | §11 (PluginHashRegistry) | Plugin signing + distribution OTA channel + version coordination |
| DKG ceremonies (when applicable) | §11 + §12 | Initial gate-authority DKG + key-rotation DKG runbooks |
| Vendor coordination protocols | §11 (Lit V3 + dcipher + drand + G4) | Off-chain coordination with rented commodity gate operators |
| Rotation comms templates | §15.6.3 + §13 | Subject-facing notification copy for re-key + passkey rotation events |
| Mode 3 post-V2 activation ceremony | §10.4.2 | Configurator carve-out removal + activation runbook |

#### §17.2.6 S2-7 SD v2-spec consumption surfaces

S2-7 specifies the Selective Disclosure pipeline V2. S2-1 + S2-7 share Cealis namespace conventions but use disjoint TAG_* prefixes (`CEALIS_V3_*` for V3-custody escrow core; `CEALIS_SD_*` for SD pipeline) — cross-namespace label collisions are a specification defect (§2.7).

| S2-1 surface | Section | S2-7 obligation |
|---|---|---|
| TAG_SD_* prefix discipline | §2.7 + §2.8 | All SD pipeline tags carry `CEALIS_SD_` prefix; disjoint from `CEALIS_V3_*` namespace |
| TAG-prefix construction rule | §2.1 (`TAG_<NAME> = keccak256(bytes(<LABEL>))`) | SD tags follow same construction discipline at S2-7-namespace LABEL form |
| Pipeline architecture (Poseidon + PLONK + TEE) | §B WP P5 reference | S2-7 specifies SD field commitment construction + ZKP circuit + salt derivation HKDF context + nullifier construction |
| Day-one delivery semantics | (parallel to V3-custody escrow) | S2-7 specifies how SD pipeline outputs cleartext + ZKP at onboarding without breaching escrow |
| SD-side TAG namespace | §2.7 (`TAG_SD_*_V3`, owned by S2-7) | S2-7 V2 refresh of the parallel SD pipeline tag family |

### §17.3 "This spec does NOT cover" enumeration → S2-N home matrix

Items explicitly scoped out of S2-1, with their actual S2-N home:

| Scope-out item | S2-1 reference | Actual S2-N home |
|---|---|---|
| Library version pins (all) | §1.8 | S2-3 |
| BLS12-381 variant assignment (Lit V3, dcipher) | §1.1.4 line 38, BP-5 LOCKED | S2-3 SDK confirmation |
| Lit V3 ACC parser | §6.2 line 1519 + §S2-3 / S2-6 | S2-3 (parser library) + S2-6 (operational validation) |
| Explicit G3 X25519 key publication / derivation path | §6.2 | S2-3 |
| Explicit Ed25519-authority-to-X25519 separation | §6.2 | S2-3 |
| Selective Disclosure pipeline tags | §2.7 + §2.8 | S2-7 |
| Plugin distribution channel | (deferred to S2-6 by Stage-0) | S2-6 |
| RekeyGovernance operational mechanics | §15 line 3717 | S2-6 |
| Gate authority key rotation operational runbook | §15.6.3 line 3864 | S2-6 |
| Mode 3 RESERVED post-V2 enable timeline + activation ceremony | §10.4.2 | S2-6 |
| DKG ceremony runbooks | §11 + §12 | S2-6 |
| API REST surfaces | (entire delivery layer) | S2-5 |
| Webhook event payloads | (entire delivery layer) | S2-5 |
| PDA configuration UI/CLI | (entire configurator surface) | S2-4 |
| Configurator-side `k ≥ 1` enforcement | §10.6 line 248 | S2-4 |
| Configurator Mode 3 rejection | §10.4.3 | S2-4 |
| Configurator legal-effect PDA preconditions (QES, halt-opt-out) | §3.3.4 D1 + §9.4 | S2-4 |
| Smart contract Solidity interfaces (G4AuthorityRegistry, etc.) | §12 | S2-2 |
| 7-day TimelockController governance | §11 + §15.6.3 | S2-2 |
| ShredRegistry contract surface | §14.1 step 5 | S2-2 |
| On-chain event semantics (RevealAuthorized, RekeyTriggered) | §11 | S2-2 |

### §17.4 §16 ERR consolidation index — 87-code reference for consumer-side error handling

§16 enumerates **93 unique `ERR_*` symbol references** total in the V2 system / V3 custody cryptographic layer (verified via `grep -oE "ERR_[A-Z_0-9]+" cryptography-spec.md | sort -u | wc -l`). Of these, **90 are unique fully-qualified ERR codes enumerated in per-layer tables** at §16.2-§16.12; the remaining 3 mentions are narrative-only wildcard prefixes per §16 Count discipline normative note. The 90 fully-qualified codes are organized across **11 cryptographic layers** per §16.1 organizational principle (NORMATIVE):

| Layer | §16 subsection | Count | Coverage |
|---|---|---|---|
| Layer 1: Cryptographic primitive errors | §16.2 | 3 | Ed25519 / BLS12-381 / P-256 / secp256k1 / X25519 / ML-KEM-768 verification |
| Layer 2: SCALE encoding errors | §16.3 | 3 | Canonicality-check + decode failures |
| Layer 3: HKDF errors | §16.4 | 3 | Extract / Expand failures (operational-not-cryptographic) |
| Layer 4: AEAD errors | §16.5 | 2 | ChaCha20-Poly1305 tag verification + truncation defense |
| Layer 5: Per-stanza wrap errors | §16.6 | 6 | Hybrid PQ wrap-AEAD failures + stanza MAC failures (incl. gate-stanza MAC) |
| Layer 6: Per-σ verification errors | §16.7 | 28 | σ_subject / σ_Lit / σ_G3 / σ_G4 / σ_conditional gate-signature verification + path / phase / refusal forensics |
| Layer 7: Pre-verify checklist errors | §16.8 | 12 | Combiner pre-verify checklist (§14.2.1 10 ordered checks) |
| Layer 8: Governance + registry errors | §16.9 | 16 | 5 V3 registries (Plugin / G4Authority / DSL / Oracle / QTSP) |
| Layer 9: Re-key ceremony errors | §16.10 | 4 | Supersession lineage + governance + timelock |
| Layer 10: Rotation-log errors | §16.11 | 9 | PasskeyRotationLog walk-from-anchor + per-walk-step wrap-around |
| Layer 11: Delivery + transport errors | §16.12 | 4 | σ delivery channel + timeout + Mode 3 RESERVED enforcement |

Wrap-around-vs-forensic discipline (NORMATIVE per §16.13) stable at **5 instances**: §10 + §11 + §12 + §13.7 + §14. Each instance carries umbrella code + forensic sub-codes per per-curve / per-mode / per-registry / per-walk-step granularity.

**Consumer-side handling (S2-2 + S2-3 + S2-5 + S2-6 + S2-7):** consumer-specs MUST consume the §16 ERR codes as fail-closed abort signals at the layer the failure surfaces per §16.16 abort discipline normative behavior. There is no soft-fail / retry / fallback recovery at the cryptographic layer — operational retries are caller-side concerns (S2-5 + S2-6) per §16.16 caller-side recovery boundary. Consumer-spec ERR semantics MUST inherit §16.15 share secrecy + PII safety 5 anti-pattern call-outs (no σ values in error context, no partial AAD bytes in debug context, no plaintext PII in any error context, encrypted-reason mode default for sensitive G4 reason codes per §9.4.4 + §12.5.5 + §12.8.4).

### §17.5 Library version pin deferrals per §1.8 — concrete S2-3 pin discipline

Per §1.8 wire-format-only discipline, S2-1 carries no library version pins. The following concrete pins live in S2-3 (custody-integration-spec) per the explicit forward-references in S2-1:

| S2-1 reference | Library | S2-3 pin task |
|---|---|---|
| §1.8 + multiple sites | `@noble/curves` (BLS12-381, P-256, Ed25519, X25519) | Pin specific version + audit reference (Cure53) |
| §1.8 + §6.4 line 1825 | `@noble/ciphers ^1.0` | Pin specific version per `flows-spec-final.md:250` |
| §1.8 + §6.3 line 1774 | `@noble/hashes ^1.4` | Pin specific version per Cure53 noble-hashes audit Sep 2024 |
| §1.8 + §6.5 line 1735 | `@polkadot/util ≥13` | Pin specific version + SCALE codec conformance |
| §1.8 | `filippo.io/age` | Pin specific version + age v1 wire format conformance |
| §1.8 + §10.2.2 line 2694 | `@simplewebauthn/server` | Pin specific version + WebAuthn Level 2 + CTAP2 conformance |
| §1.8 + §10.3.2 line 2758 | `viem` / `ethers.js` (recipient-side wallet) | Pin specific version + EIP-2 + EIP-712 conformance |
| §1.8 + §8.3 line 2182 | `drand/kyber` Go library | Pin specific version + drand minimum-pubkey-size BLS conformance |
| §1.8 + §8.2 line 2132 | Randamu dcipher SDK | Pin specific version + variant assignment confirmation (BP-5 LOCKED deferral) |
| §1.8 + §11 + §S2-3 | Lit V3 SDK (Chipotle SDK) | Pin specific version + variant assignment + ACC parser version |
| §1.8 + §9.3 line 2429 | Automata zkDCAP on-chain verifier | Pin verifier circuit version + per-vendor TEE SDK selection per A11 |
| §1.8 + §15 | RFC 8785 JCS implementation | Pin specific library + RFC 8785 conformance for RevealArtifactBundle per Simon D4b |
| §1.8 + §1.3 line 87 | SCALE codec (Polkadot) | Pin specific version + canonical Polkadot SCALE specification conformance |
| §1.8 + §6.2 | Explicit Ed25519-authority-to-X25519 separation | Pin separate Ed25519 verification and X25519 wrap-key APIs; no conversion function is consumed by S2-1 |

S2-3 MUST track library version compatibility against the wire-format identifiers in S2-1. CVE patches + minor-version bumps absorbed at S2-3 layer; S2-1 stays stable.

### §17.6 Phase 1 → Phase 2 transition surfaces

Phase 1 (G4 dev-scaffold) → Phase 2 (G4 partner-ready DCAP attestation) transition discipline per Stage-0 Q-0-2 LOCKED + §9.4. The following surfaces transition from Phase 1 to Phase 2 as the partner-facing pilot signs (≈ funding milestone):

| Surface | Phase 1 | Phase 2 | S2-N coordination |
|---|---|---|---|
| σ_G4 signing scheme | Ed25519 (RFC 8032), 64 bytes | DCAP attestation quote (Intel + cross-vendor per A11) | S2-3 (library pins) + S2-6 (transition ceremony) |
| σ_G4 signing input layer | Direct keccak preimage (§9.2.3) with TAG-prefix | DCAP user_data (32 bytes keccak-compressed per Simon D11) | S2-1 unchanged; binding format same |
| `endpoint_attestation_digest` SCALE sum-type | `Phase1` variant | `Phase2` variant with full DCAP quote | S2-1 (§3.4.3) handles both; S2-2 contracts honor sum-type |
| `commit_AAD.phase` | `1` (Phase 1) | `2` (Phase 2) | S2-1 (§4) handles both; S2-4 configurator gating |
| Legal-effect PDAs | REJECTED at PDA-config (§F PDA+ guardrail) | ACCEPTED at PDA-config | S2-4 configurator enforcement |
| §371a ZPO presumption | Not baseline (§286 free evaluation is baseline) | Available only when QTSP/QES is elected (`qes_subject_required = true`) | Legal counsel coordination |
| Cross-vendor mandate (A11) | N/A (single-vendor Ed25519 server) | MANDATORY (Lit V3 ≠ G4 vendor) | S2-3 + S2-6 |
| Subject-facing notice | Explicit non-partner-use notice | Standard reveal notice | S2-5 (delivery layer copy) |

Transition ceremony: S2-6 specifies the operational runbook for Phase 1 → Phase 2 cutover. Cryptographic discipline is constant across phases at the §6.3 Shamir derivation layer; only the σ_G4 signing scheme + its `endpoint_attestation_digest` SCALE variant changes.

Reverse transition (Phase 2 → Phase 1) is forbidden — once a partner commits under Phase 2, no Phase 1 σ_G4 may be substituted. Per §9.4 + Stage-0 Q-0-2 LOCKED.

### §17.7 Open architectural questions deferred to later stages

The following architectural questions surfaced during S2-1 drafting are deferred to specific later stages:

| Open question | S2-1 surface | Deferral home | Status |
|---|---|---|---|
| BLS12-381 variant assignment for Lit V3 + dcipher | §1.1.4 line 38 | S2-3 SDK confirmation | BP-5 LOCKED on drand path; Lit V3 + dcipher pending Randamu + Lit V3 SDK |
| DCAP user_data byte budget (96 raw vs 32 keccak-compressed) | §1.1.5 line 52 + Simon D11 | S2-3 (Intel SGX 64-byte report-data limit verification) | Default applied: keccak-compress to 32 bytes |
| Lit V3 ACC parser library + version | §6.2 line 1519 | S2-3 | Pending |
| Explicit G3 X25519 key publication / derivation path | §6.2 | S2-3 | Pending |
| `ShredRegistry` contract surface | §6.4 line 1931 + §14.1 step 5 | S2-2 | Pending |
| RekeyGovernance multisig structure | §15 line 3717 | S2-2 + S2-6 | Pending |
| Mode 3 post-V2 activation timeline + ceremony | §10.4.2 + §10.4.3 | S2-6 | Pending (configurator carve-out removal) |
| Plugin distribution OTA channel | §11 (PluginHashRegistry) | S2-6 (Stage-0 deferral) | Pending |
| Subject-facing privacy notice copy | §5 + §10.10 + §13.10.1 | S2-5 (delivery layer) + counsel coordination | Pending PRO-452 |
| MiCA tokenization-asset compliance scoping | (legal-conform pass) | Counsel coordination | Pending PRO-453 |
| Rule 33 propagation patches (BP-3 + BP-4 + BP-10 + BP-11 + BP-12) | §2.3.4 + various | Simon ack at first-canonical-section checkpoint | Pending Simon ack |
| BP-13 resolved: `TAG_DSL_VERSION_V3` for `dsl_version_ref` preimage | §12.4.1 + §4 line 720 | REJECT per §12.0 NORMATIVE class rule (class-CATALOG); see `designs/v3-registry-class-discipline.md` | **REJECTED 2026-05-04** (class-CATALOG; raw 32-byte ref retained; no preimage role anywhere in V3) |
| BP-14 resolved: `TAG_ORACLE_REGISTRY_V3` for `oracle_id_i` per-leaf preimage | §12.5.1 + §4 line 721 | ACCEPT per §12.0 NORMATIVE class rule (class-CRYPTO via Merkle-leaf preimage role); §2.3.4 + §12.5.1 patched 2026-05-04 under §2.8.5 carve-out | **ACCEPTED 2026-05-04** (class-CRYPTO; `TAG_ORACLE_REGISTRY_V3` added to active table; per-leaf preimage form locked at §12.5.1) |
| BP-15 resolved: `TAG_QTSP_PROVIDER_V3` for `qtsp_provider_ref` preimage | §12.7.1 + §3 line 523 | REJECT per §12.0 NORMATIVE class rule (class-CATALOG); see `designs/v3-registry-class-discipline.md` | **REJECTED 2026-05-04** (class-CATALOG; raw 32-byte ref retained; eIDAS legal force at entry-payload Trust List layer per §5.5.3) |

### §17.8 Architectural-truth-template multi-substrate-variant INSTANCE pattern (5 instances)

Per §16.14 organizational-principle anchor (per dw-lead PP-12-A1 absorption), §17 enumerates the 5 architectural-truth-template multi-substrate-variant INSTANCEs as the spec's outward-facing organizational anchor for consumer-spec multi-layer-defense pattern recognition. Each INSTANCE represents independent enforcement substrates converging on the same architectural property:

| # | INSTANCE | Architectural truth | Substrate variants |
|---|---|---|---|
| 1 | **§14.7.4 combiner per-generation σ authorization-evidence verification framing** | "Share-value invariance holds across re-key generations; σ evidence is generation-specific" | Re-key supersession lineage; gate authority key stability is operational property (S2-6), not §15 cryptographic constraint per §15.6.3 retraction |
| 2 | **§13.6 Cealis-as-infrastructure-not-authority** | "Cealis cannot forge rotations" | (a) ABI-standard contract publication openness + (b) recipient self-publish path + (c) WebAuthn assertion under prior passkey (Cealis-not-custody) |
| 3 | **§10.9 Mode 3 RESERVED enforcement chain** | "No V2 reveal consumes Mode 3 σ_conditional" | (a) configurator-side rejection at PDA-config time (`ERR_PDA_CONFIG_MODE_3_RESERVED`) + (b) envelope-load-time subject-side verifier rejection (`ERR_MODE_3_NOT_SHIPPED_AT_V2` defense-in-depth) + (c) reveal-time combiner rejection at §14.5.2 fail-closed default |
| 4 | **§11.4 endpoint attestation 6-substrate enumeration** | "Historical commits remain verifiable across registry rotations" | LitV3Assignment + 5 Cealis-governed V3 registries (Lit V3 governance contract + Cealis-governed registries + threshold-network registries + QTSPRegistry) |
| 5 | **§12.6 5-registry historical-lookup** | "Historical commits remain verifiable across registry rotations" (5 Cealis-governed substrates) | PluginHashRegistry / G4AuthorityRegistry / DSLVersionRegistry / OracleRegistry / QTSPRegistry; combined with §11.4 = 6 historical-lookup substrates total |

**Consumer-spec recognition:** S2-2 + S2-3 + S2-4 + S2-5 + S2-6 + S2-7 implementations MUST honor the multi-layer-defense pattern at the substrate-variant layer. Single-layer enforcement at any of these INSTANCEs would break the architectural truth — e.g., S2-4 configurator-side Mode 3 rejection alone is insufficient (defense-in-depth requires §10.9 chain layers (b) + (c) at S2-5 envelope-load-time + S2-1 reveal-time combiner).

### §17.9 Symmetric-framework PII-Breyer pattern (5 substrate-distinguishing PII-NONE consolidations)

Per §16.15 + §16.19 organizational-principle anchor (per dw-lead PP-12-A2 absorption + worker-3 supplement count correction), §17 enumerates the 5 substrate-distinguishing PII-NONE consolidations as the spec's outward-facing PII consolidation framework anchor. **Row-count framing for auditor reproducibility:** the table below carries 5 rows = 2 Breyer-applies + 3 inverse-Breyer-NOT-APPLICABLE. The 3 inverse-Breyer rows include the §16.15 + §16.19 joint anchor as a single instance (rows 4 + 5 below are §11.8 + §12.12 distinct registries; row 5 covers the §16.15 + §16.19 joint anchor as the third inverse-Breyer substrate-distinguishing instance, matching the §16 organizational-principle anchor disambiguation note that the joint statement constitutes a single instance, not two).

| # | Substrate | Breyer C-582/14 + Recital 26 stance | Anchor |
|---|---|---|---|
| 1 | **§10.10 Mode 2 wallet_address** | APPLIES (third-party-observer reachability via public Ethereum ledger; cross-partner-stable natural-person pseudo-identifier) | Carry-forward from §13.10.1 |
| 2 | **§13.10.1 PasskeyRotationLog account_id** | APPLIES (third-party-observer-vs-Cealis-controller-scope distinction; cross-partner-stable opaque identifier) | Anchor of carry-forward framework |
| 3 | **§11.8 endpoint attestation 4-check substrates** | EXPLICITLY NOT APPLICABLE (operator-side cryptographic identities only; no natural-person identifiers in substrate set) | First inverse-Breyer instance |
| 4 | **§12.12 5 V3 registries entries** | EXPLICITLY NOT APPLICABLE (operator-side governance substrates only; no natural-person identifiers in substrate set) | Second inverse-Breyer instance (matching §11.8 framing) |
| 5 | **§16.15 + §16.19 ERR codes (joint anchor)** | EXPLICITLY NOT APPLICABLE (operator-side failure signals only; no natural-person identifiers in ERR's substrate set; subject-side natural-person identifiers entering error contexts protected by §16.15 5 anti-pattern call-outs) | Third inverse-Breyer instance (single instance via §16.15 + §16.19 joint anchors) |

**Consumer-spec recognition:** S2-4 + S2-5 + S2-7 implementations MUST honor the PII consolidation framework at the substrate-distinguishing layer. Subject-side natural-person identifiers entering downstream contexts (PDA configurator UI at S2-4, REST API logs at S2-5, SD pipeline outputs at S2-7) are protected by inheriting §16.15 5 anti-pattern call-outs (no σ values in error context + no partial AAD bytes in debug context + no plaintext PII in any error context + encrypted-reason mode default for sensitive G4 reason codes + DCAP-attested non-custody at the gate operator layer) per §3.6 ¶3 + §4.9 ¶2 + §10.10 + §13.10.1 framework.

### §17.10 Cross-spec author-lock disciplines (consolidated)

The following surfaces in S2-1 carry explicit cross-spec author-lock disciplines — coordinated update across S2-1 + named consumer-spec is required for any change. This list is the consolidated author-lock index. **Source enumeration for auditor reproducibility:** the 13 surfaces below derive from 5 source-of-truth categories — (a) TAG-prefix discipline locks per BP-3/BP-4/BP-10/BP-11/BP-12 (rows 1-2 + 6-9 = 6 surfaces tracking BP-locked TAG_*_V3 prefixes against `designs/` + `flows-spec-final.md` + S2-2 contracts); (b) SCALE-byte-layout locks (rows 3-5 = 3 surfaces tracking enum byte values + sum-type variants against S2-4 configurator + S2-2 contracts); (c) cross-spec namespace disjointness (row 10 = `TAG_SD_*` prefix discipline against S2-7); (d) defense-in-depth chain locks (row 11 = Mode 3 RESERVED 3-layer enforcement against S2-2/S2-4/S2-5). Coordinated `commit_version` bump per §2.8 is the discipline-binding step for any author-lock surface change.

| S2-1 surface | Section | Locked-against |
|---|---|---|
| `TAG_G4_ATTESTATION_AUTHORITY_V3` derivation + `g4_authority_ref` byte layout | §9 line 899 | S2-2 G4AuthorityRegistry contract interface |
| `authority_pubkey_ref` SCALE sum-type byte layout | §6.1.3 line 1354 | S2-2 G4AuthorityRegistry contract interface |
| `role_tag` enum byte values | §6.1.5 line 1404 + 1449 | S2-4 configurator-pda-spec validation surface + §10 σ_conditional verification protocols |
| `delivery_hint` enum byte values | §6.1.5 line 1405 | S2-4 configurator-pda-spec (weaker binding — not in cryptographic preimage) |
| `endpoint_attestation_digest` SCALE sum-type | §3.4.3 + Simon D10 | S2-2 contracts honor sum-type variants |
| `TAG_ROTATION_LOG_ANCHOR_V3` (BP-4) | §2 line 256 + §6.1.5 line 1403 | `designs/conditional-recipient.md §2 line 51` Rule 33 propagation patch + S2-2 PasskeyRotationLog contract surface |
| `TAG_CONDITIONAL_RECIPIENTS_POLICY_V3` (BP-10) | §2.3 + §4 | `designs/conditional-recipient.md §11` Rule 33 propagation patch |
| `TAG_SUPERSEDED_COMMIT_REGISTRY_V3` (BP-11) | §2 + §15.6.3 | `flows-spec-final.md §SupersededCommitRegistry` Rule 33 propagation patch + S2-2 SupersededCommitRegistry contract |
| `TAG_ROTATION_AUTHORIZATION_V3` (BP-12) | §2.3 | `designs/conditional-recipient.md §2 line 72` Rule 33 propagation patch |
| `TAG_ORACLE_REGISTRY_V3` (BP-14, NEW 2026-05-04) | §2.3.4 + §12.5.1 | S2-2 §9.8 OracleRegistry contract surface — per-leaf preimage form `keccak256(TAG_ORACLE_REGISTRY_V3 ‖ oracle_pubkey_or_addr)` for `oracle_references_root` Merkle leaves |
| `TAG_SD_*` prefix discipline | §2.7 + §2.8 | S2-7 SD pipeline tag namespace disjointness |
| Mode 3 RESERVED 3-layer defense-in-depth | §10.4.3 | S2-4 (configurator-rejection layer) + S2-2 + S2-5 (envelope-load-time + reveal-time layers) |
| `§12.0` registry class-discipline (BP-13 REJECT / BP-14 ACCEPT / BP-15 REJECT, 2026-05-04) | §12.0 + `designs/v3-registry-class-discipline.md` | S2-2 §9.7/§9.8/§9.9 — DSL + QTSP raw-ref shapes locked per class-CATALOG; Oracle TAG-prefixed per class-CRYPTO |

Adding or removing locked surfaces requires coordinated update across S2-1 + the named consumer-spec + a `commit_version` bump per §2.8.

### §17.11 Cross-reference index summary

This section is the canonical map of S2-1's outward-facing edges to the rest of the Stage-2 spec corpus. **S2-1 conformance + S2-N conformance for each consumer-spec is jointly necessary for a complete Cealis deployment.** Implementers reading S2-1 alone have wire-format detail sufficient for cryptographic correctness; the remaining concrete bindings (libraries, contracts, configurator surfaces, API endpoints, operational runbooks, SD pipeline) live in the consumer-specs per the per-S2-N consumption surfaces enumerated at §17.2 + §17.3.

The reverse direction is empty — **S2-1 consumes nothing from S2-2..S2-7.** This is by construction: cryptography spec is foundational, and downstream specs cannot inject new cryptographic primitives or alter S2-1 byte layouts. Library churn is absorbed at S2-3; contract surfaces at S2-2; configurator surfaces at S2-4; delivery surfaces at S2-5; operational surfaces at S2-6; SD pipeline surfaces at S2-7. All bidirectional coordination points are author-locked per §17.10.

---

## App. A — SCALE schema reference

Backprop note 2026-05-05: App. C.6 inherits the `0x0302` DEK-lifecycle transition and does not introduce an additional open writer slot.

## App. B — Test vectors

Backprop note 2026-05-05: App. C.7 is populated by the cross-spec author-lock table below; no placeholder implementation text is required in S2-1.

## App. C — What this spec does NOT cover (scope-out enumeration)

This appendix consolidates all explicit scope-outs from S2-1 cryptography-spec.md into a single structured matrix. It is the authoritative reference for items deliberately deferred to other Stage-2 specs (S2-2 through S2-7), pending Simon ack via Rule 33 BP-N propagation patches, or out of S2-1's wire-format-only discipline scope per §1.8.

**Discipline:** every item in this enumeration MUST have (a) a canonical S2-1 reference, (b) a target deferral home (S2-N or BP-N or operational), (c) a deferral rationale. No item is scope-out without explicit canonical justification.

**Cross-reference anchors (consumed):** §17.3 scope-out matrix (19 items) + §17.5 library version pin deferrals (14 items) + §17.6 Phase 1→2 transition surfaces (8 items) + §17.7 remaining open architectural questions (8 items) + §16.18 forward-references + §12.11 forward-references + §11.7 forward-references + §1.8 wire-format-only discipline.

BP-13/14/15 dispositions are tracked in App. C.5.

### App. C.1 Stage-2 sibling spec carve-outs (top-level)

The following item categories are explicitly out of S2-1 scope by Stage-2 corpus design — each Stage-2 sibling spec owns its layer:

| S2-N target | Owner-of-record | What S2-N owns (vs S2-1) |
|---|---|---|
| **S2-2 smart-contracts-spec** | Solidity contract surfaces + on-chain governance | All registry contract interfaces (G4AuthorityRegistry / PluginHashRegistry / OracleRegistry / QTSPRegistry / DSLVersionRegistry / RekeyGovernance / SupersededCommitRegistry / G4RefusalRegistry / ShredRegistry / ConditionEngine / Vault / DisclosureRegistry); 7-day TimelockController governance contract; on-chain event semantics (RevealAuthorized / RekeyTriggered / RefusalSignal / DisclosurePublished / DeprecationFlagSet); CealisSecurityMultisig (2-of-3) + EmergencyGovernance (3-of-3) contract surfaces; per-registry Solidity ABI |
| **S2-3 custody-integration-spec** | Library version pins + vendor SDK selections | All `@noble/curves` + `@noble/ciphers` + `@noble/hashes` + `@simplewebauthn/server` + `@polkadot/util` + `filippo.io/age` + `drand/kyber` + Randamu dcipher SDK + Lit V3 SDK (Chipotle SDK) + Automata zkDCAP version pins; BLS12-381 variant assignment for Lit V3 + dcipher (per BP-5 LOCKED on drand path; Lit V3 + dcipher pending S2-3 SDK confirmation); Lit V3 ACC parser library; explicit X25519 key publication / derivation paths; RFC 8785 JCS implementation pin; per-vendor TEE SDK selection (Intel SGX / AMD SEV-SNP / AWS Nitro NSM SDK) per A11 cross-vendor mandate; CVE patches + minor-version bumps |
| **S2-4 configurator-PDA-spec** | PDA configuration UI/CLI + configurator-side enforcement | Partner-facing PDA configuration UI/CLI; configurator-side enforcement of Mode 3 RESERVED rejection at PDA-config time + QES preconditions + cealis_class_wide_halt_opt_out gating per §F PDA+ guardrail + k ≥ 1 enforcement per conditional_recipients_policy; partner-pubkey registration; schema selectors per §D §432; Lit V3 chain_condition ACC parser at PDA-config time |
| **S2-5 ingestion-delivery-API-spec** | REST API + delivery-layer wire transport | All POST /reveal + POST /ingest REST API surfaces; webhook event payloads (RevealAuthorized → API-side webhook delivery + rate limiting + retry discipline); IPFS gateway pulls; HTTPS POST per recipient delivery_url; crypto-shred coordination at vault layer (vault-side ciphertext deletion + chain-side shred-state read coordination); subject-facing privacy notice copy (PRO-452 counsel coordination pending); 2-phase ingestion API spec |
| **S2-6 operational-ceremonies-spec** | Operational mechanics + runbooks + vendor coordination | DKG ceremony runbooks (initial gate-authority DKG + key-rotation DKG); key rotation operational procedures per §15.6.3 orthogonal-ceremony framing; plugin distribution OTA channel + signing + version coordination per Stage-0 deferral; vendor coordination protocols (Lit V3 + dcipher + drand + G4 off-chain coordination); RekeyGovernance multisig operational mechanics (quorum thresholds + member rotation + signing key custody); Phase 1 → Phase 2 cutover ceremony per §9.4 + Stage-0 Q-0-2 LOCKED; Mode 3 post-V2 activation ceremony per §10.4.2 + §10.4.3 (configurator carve-out removal); rotation comms templates (subject-facing notification copy for re-key + passkey rotation events) |
| **S2-7 SD v2-spec** | Selective Disclosure pipeline V2 | All TAG_SD_* tag namespace (disjoint from CEALIS_V3_*); SD field commitment construction; ZKP circuit specs; salt derivation HKDF context; nullifier construction; day-one delivery semantics (cleartext + ZKP at onboarding without breaching escrow); Poseidon + PLONK + TEE pipeline architecture |

### App. C.2 Library version pin deferrals (per §1.8 wire-format-only discipline → S2-3)

Per §1.8 wire-format-only discipline: S2-1 carries no library version pins. The following 14 concrete pins live in S2-3:

| # | Library | S2-1 reference | S2-3 pin obligation |
|---|---|---|---|
| 1 | `@noble/curves` (BLS12-381 + P-256 + Ed25519 + X25519 modules) | §1.8 + multiple sites | Pin specific version + Cure53 audit reference |
| 2 | `@noble/ciphers ^1.0` | §1.8 + §6.4 line 1825 | Pin specific version per `flows-spec-final.md:250` |
| 3 | `@noble/hashes ^1.4` | §1.8 + §6.3 line 1774 | Pin specific version per Cure53 noble-hashes audit Sep 2024 |
| 4 | `@polkadot/util ≥13` | §1.8 + §1.3 line 87 + §6.5 line 1735 | Pin specific version + canonical Polkadot SCALE specification conformance |
| 5 | `filippo.io/age` | §1.8 | Pin specific version + age v1 wire format conformance |
| 6 | `@simplewebauthn/server` | §1.8 + §10.2.2 line 2694 | Pin specific version + WebAuthn Level 2 + CTAP2 conformance |
| 7 | `viem` / `ethers.js` (recipient-side wallet) | §1.8 + §10.3.2 line 2758 | Pin specific version + EIP-2 + EIP-712 conformance |
| 8 | `drand/kyber` Go library | §1.8 + §8.3 line 2182 | Pin specific version + drand minimum-pubkey-size BLS conformance per BP-5 LOCKED |
| 9 | Randamu dcipher SDK | §1.8 + §8.2 line 2132 | Pin specific version + variant assignment confirmation (BP-5 LOCKED deferral) |
| 10 | Lit V3 SDK (Chipotle SDK) | §1.8 + §11 + S2-3 | Pin specific version + variant assignment + ACC parser version |
| 11 | Automata zkDCAP on-chain verifier | §1.8 + §9.3 line 2429 | Pin verifier circuit version + per-vendor TEE SDK selection per A11 cross-vendor mandate |
| 12 | RFC 8785 JCS implementation | §1.8 + §15 | Pin specific library + RFC 8785 conformance for RevealArtifactBundle per Simon D4b |
| 13 | Explicit Ed25519-authority-to-X25519 separation | §1.8 + §6.2 | Pin separate Ed25519 verification and X25519 wrap-key APIs; no conversion function is consumed by S2-1 |
| 14 | Explicit G3 X25519 key publication / derivation path | §1.8 + §6.2 | Pin the vendor SDK / registry path that yields the explicit X25519 wrap key; no BLS-to-X25519 conversion is permitted |

**Discipline:** S2-3 MUST track library version compatibility against the wire-format identifiers in S2-1. CVE patches + minor-version bumps absorbed at S2-3 layer; S2-1 stays stable across library churn.

### App. C.3 Phase 1 → Phase 2 transition surfaces (per Stage-0 Q-0-2 LOCKED)

Per Stage-0 Q-0-2 LOCKED + §9.4 + §17.6: the following 8 surfaces transition from Phase 1 (G4 dev-scaffold) to Phase 2 (G4 partner-ready DCAP attestation) as the partner-facing pilot signs (≈ funding milestone). S2-1 handles BOTH phases at the binding format level; transition operational mechanics live at S2-3 + S2-6:

| # | Surface | Phase 1 | Phase 2 | Transition home |
|---|---|---|---|---|
| 1 | σ_G4 signing scheme | Ed25519 (RFC 8032), 64 bytes | DCAP attestation quote (Intel + cross-vendor per A11) | S2-3 (library pins) + S2-6 (transition ceremony) |
| 2 | σ_G4 signing input layer | Direct keccak preimage (§9.2.3) with TAG-prefix | DCAP user_data (32 bytes keccak-compressed per Simon D11) | S2-1 unchanged; binding format same |
| 3 | `endpoint_attestation_digest` SCALE sum-type | `Phase1` variant (binary_hash + effective_block) | `Phase2` variant (full DCAP quote bytes) | S2-1 (§3.4.3) handles both; S2-2 contracts honor sum-type |
| 4 | `commit_AAD.phase` | `1` (Phase 1) | `2` (Phase 2) | S2-1 (§4) handles both; S2-4 configurator gating |
| 5 | Legal-effect PDAs | REJECTED at PDA-config (§F PDA+ guardrail) | ACCEPTED at PDA-config | S2-4 configurator enforcement |
| 6 | §371a ZPO presumption | Not baseline (§286 free evaluation is baseline) | Available only when QTSP/QES is elected (`qes_subject_required = true`) | Legal counsel coordination + S2-4 |
| 7 | Cross-vendor mandate (A11) | N/A (single-vendor Ed25519 server) | MANDATORY (Lit V3 ≠ G4 Phase 2 vendor) | S2-3 + S2-6 |
| 8 | Subject-facing notice | Explicit non-partner-use notice | Standard reveal notice | S2-5 (delivery layer copy + counsel coordination) |

**Reverse transition (Phase 2 → Phase 1) is FORBIDDEN** per §9.4 + Stage-0 Q-0-2 LOCKED. Once a partner commits under Phase 2, no Phase 1 σ_G4 may be substituted. Cryptographic discipline is constant across phases at the §6.3 Shamir derivation layer; only the σ_G4 signing scheme + its `endpoint_attestation_digest` SCALE variant changes.

### App. C.4 Open architectural questions deferred to later stages

Per §17.7: the following 11 architectural questions surfaced during S2-1 drafting are deferred to specific later stages or pending Simon ack via Rule 33 BP-N propagation patches:

| # | Open question | S2-1 reference | Deferral home | Status |
|---|---|---|---|---|
| 1 | BLS12-381 variant assignment for Lit V3 + dcipher | §1.1.4 line 38 | S2-3 SDK confirmation | BP-5 LOCKED on drand path; Lit V3 + dcipher pending Randamu + Lit V3 SDK |
| 2 | DCAP user_data byte budget (96 raw vs 32 keccak-compressed) | §1.1.5 line 52 + Simon D11 | S2-3 (Intel SGX 64-byte report-data limit verification) | Default applied: keccak-compress to 32 bytes |
| 3 | Lit V3 ACC parser library + version | §6.2 line 1519 | S2-3 | Pending S2-3 SDK + ACC parser pin |
| 4 | Explicit G3 X25519 key publication / derivation path | §6.2 | S2-3 | Pending |
| 5 | `ShredRegistry` contract surface | §6.4 line 1931 + §14.1 step 5 | S2-2 | Pending S2-2 contract spec |
| 6 | RekeyGovernance multisig structure | §15 line 3717 | S2-2 + S2-6 | Pending S2-2 contract + S2-6 operational mechanics |
| 7 | Mode 3 post-V2 activation timeline + ceremony | §10.4.2 + §10.4.3 | S2-6 (configurator carve-out removal) | Pending |
| 8 | Plugin distribution OTA channel | §11 (PluginHashRegistry) | S2-6 (Stage-0 deferral) | Pending |
| 9 | Subject-facing privacy notice copy | §5 + §10.10 + §13.10.1 | S2-5 (delivery layer) + counsel coordination | Pending PRO-452 |
| 10 | MiCA tokenization-asset compliance scoping | (legal-conform pass) | Counsel coordination | Pending PRO-453 |
| 11 | Rule 33 propagation patches — split status: 5 LOCKED at S2-1 with back-prop pending Simon ack (BP-3 + BP-4 + BP-10 + BP-11 + BP-12); BP-13 REJECT, BP-14 ACCEPT, BP-15 REJECT resolved 2026-05-04 | §2.3.4 + various | Simon ack at first-canonical-section checkpoint | Pending Simon ack — 5 LOCKED-with-back-prop-pending remain |

### App. C.5 Back-propagation (BP) queue — Simon ack-pending Rule 33 patches

Per Rule 33 propagation discipline + §17.7 BP list: the following BP entries are tracked at first-canonical-section checkpoint. BP-3/4/10/11/12 remain locked-with-back-prop-pending. BP-13/14/15 are resolved by `designs/v3-registry-class-discipline.md` and retained here only as disposition history:

| BP # | Anchor | Construction | Source | Status |
|---|---|---|---|---|
| BP-3 | `plugin_version_digest` preimage | `keccak256(TAG_PLUGIN_VERSION_V3 ‖ canonical_binary_hash)` | §2.3.5 + §4.6.1 line 891 + §12.2.1 (Q-W2-30 LOCKED 2026-04-25) | LOCKED (back-prop to `flows-spec-final.md:172` raw-bytes V1-cargo-cult) |
| BP-4 | `rotation_log_anchor` preimage | TAG-prefixed per generalized D6 V3 discipline | §2 line 256 + §6.1.5 line 1403 | LOCKED (back-prop to `designs/conditional-recipient.md §2 line 51`) |
| BP-10 | `conditional_recipients_policy_digest` preimage | `keccak256(TAG_CONDITIONAL_RECIPIENTS_POLICY_V3 ‖ SCALE(conditional_recipients_policy))` | §2.3 + §4.6.3 + §4 (BP-10 LOCKED 2026-04-26) | LOCKED (back-prop to `designs/conditional-recipient.md §11`) |
| BP-11 | `SupersededCommitRegistry` lookup hash preimage | TAG_SUPERSEDED_COMMIT_REGISTRY_V3 prefix | §2 + §15.6.3 (BP-11 LOCKED 2026-04-26) | LOCKED (back-prop to `flows-spec-final.md §SupersededCommitRegistry` + S2-2 SupersededCommitRegistry contract) |
| BP-12 | `rotation_authorization_digest` preimage | TAG_ROTATION_AUTHORIZATION_V3 prefix | §2.3 (BP-12 LOCKED) | LOCKED (back-prop to `designs/conditional-recipient.md §2 line 72`) |
| **BP-13** | `dsl_version_ref` preimage | No TAG preimage; raw class-CATALOG ref retained | §12.4.1 + §4 line 720 | **REJECTED 2026-05-04** |
| **BP-14** | `oracle_id_i` per-leaf preimage | `keccak256(TAG_ORACLE_REGISTRY_V3 ‖ oracle_pubkey_or_addr)` | §12.5.1 + §4 line 721 + §3 line 505 | **ACCEPTED 2026-05-04** |
| **BP-15** | `qtsp_provider_ref` preimage | No TAG preimage; raw class-CATALOG ref retained | §12.7.1 + §3 line 523 + §3.3.4 | **REJECTED 2026-05-04** |

**Discipline:** BP-3 + BP-4 + BP-10 + BP-11 + BP-12 are LOCKED — the §2 + §4.6 + §15.6.3 canonical entries reproduce the TAG-prefixed formulas as the registry-verification anchor. BP-13 + BP-15 are REJECTED class-CATALOG cases; BP-14 is ACCEPTED and active as `TAG_ORACLE_REGISTRY_V3`.

**BP-CU-1 — Controlled-use byte-exact authoring (LANDED-pending-Phase-D-cross-review)**

Source: A21 /design pipeline closure (`designs/controlled-use.md`) + S2-8 §11 propagation surface table.

Status at this amendment: TAG labels (§2.3.5) + commit_AAD field set extension (§4.1.1) + σ_conditional Mode T sketch (§10.11) + commit_version bump (§2.8.6) are normative. Byte-exact constructions for `h_envelope`, Mode T preimage final ordering, audit-event tuple structure, and cosign-gate co-signing wire format are pending in a coordinated S2-1 amendment after first pilot partner validation per S2-8 §12. App. B test-vector placeholders extend with controlled-use vectors on byte-exact lock.

Coordination: S2-2 amendment (`CredentialAnchorRegistry`, `SliceLayoutRegistry`, `MasterTokenRevocationRegistry`, opt-in `TokenRevocationRegistry`; PresentedTokenCondition module §4.11.5; H-6 composition matrix), S2-3 amendment (G4 Phase 2 TEE scope extension, cross-vendor cosign protocol), S2-4 amendment (`token_policy_config` PDA field family, ControlledUseAccessPolicy PDA+ sub-classification, slice-layout evolution).

**Deferred byte-exact authoring within S2-1 itself (Phase D cross-review residuals — R6 CS-2 + CS-3):**

- **§9 G4 signing catalog extension** — controlled-use introduces two auxiliary G4 signing operations anchored in the existing `G4AuthorityRegistry`: `K_G4_write_attest` (signs write-validation attestations per S2-8 §4.1 — preimage form `keccak256(TAG_CU_WRITE_ATTEST_V3 ‖ h_envelope_proposed ‖ slice_id ‖ actor_token_digest ‖ block_hash ‖ policy_hash)`; signature length per the vendor TEE family) and `K_G4_audit_stream2` (signs Stream 2 audit-stream root commitments per S2-8 §1.8 — preimage form `keccak256(TAG_CU_AUDIT_STREAM2_V3 ‖ stream2_merkle_root ‖ pepper_epoch_number ‖ block_hash)`). Both keys are referenced at S2-2 §15 access control + S2-2 §9.16A registry write authority + S2-3 §7.X.6 G4AuthorityRegistry extension + S2-3 App. A.5 DCAP coverage + WP §D extension; their byte-exact preimage layouts, attestation report-data binding, and rotation discipline are pending coordinated authoring in S2-1 §9 alongside the canonical Mode T form in §10.11.

- **§13 PasskeyRotationLog extension for non-passkey holder-binding rotation** — S2-8 §2.3 names four architecturally first-class holder-binding forms (passkey-bound default; hardware-bound; app-session-issued; EOA-bound via EIP-712). The existing §13 PasskeyRotationLog covers passkey-bound holder rotation. The three non-passkey holder-binding forms each have their own rotation semantics: hardware-bound credentials follow the holder's hardware-key rotation cadence; app-session-issued credentials TTL-expire and are re-derived (no explicit rotation log); EOA-bound credentials rotate via EIP-712 wallet-key replacement events. Byte-exact specification of a unified `HolderRotationLog` or per-form rotation extensions is pending coordinated authoring in S2-1 §13 amendment after first pilot validation. Until then, controlled-use deployments using non-passkey holder-binding forms operate under the §13 passkey rotation surface for passkey holders and rely on the off-chain credential issuance discipline (PDA-bound) for non-passkey holders.

Disposition: LANDED-pending-Phase-D-cross-review for the architectural locks in §2.3.5 / §4.1.1 / §10.11 / §2.8.6. The two deferred items above (§9 + §13 byte-exact extensions) are explicit App. C BP-CU-1 sub-items pending byte-exact lock at first pilot validation gate per S2-8 §12.

### App. C.6 Operational + caller-side scope-outs (per §16.16)

Per §16.16 caller-side recovery boundary NORMATIVE: the V3 cryptographic enforcement layer is fail-closed by construction. The following operational concerns are explicitly out of S2-1's cryptographic-layer scope:

| # | Operational concern | S2-1 reference | Operational home |
|---|---|---|---|
| 1 | Caller-side ERR retry/fallback recovery | §16.16 NORMATIVE + §1.7 fail-closed default | S2-5 (caller-side retry) + S2-7 (observability + monitoring) |
| 2 | Operational-layer retry semantics | §16.16 (re-collect σ values + re-walk PasskeyRotationLog + re-fetch envelope) | S2-5 (REST API retry discipline) + S2-6 (operational coordination) |
| 3 | Log archival + monitoring | §16.18 forward-references (App. C scope-out enumeration) | S2-7 monitoring + observability spec |
| 4 | Caller-side error handling + alerting | §16.18 forward-references | S2-7 monitoring + alerting spec |
| 5 | Performance + latency monitoring | (out of scope of cryptographic correctness) | S2-7 observability spec |
| 6 | Audit log retention + replay | (operational; cryptographic verification is stateless) | S2-6 ops + S2-7 audit log retention |

**Discipline:** §1.7 + §16.16 establish that cryptographic-layer aborts are absolute. Caller-side recovery + operational coordination + audit + observability are explicitly downstream of the cryptographic layer. S2-1 does not specify operational mechanics; S2-5 + S2-6 + S2-7 provide that layer.

### App. C.7 Wire-format-only discipline anchors

Per §1.8 wire-format-only discipline + §17.5 library pin deferrals: S2-1 fixes the following identifier categories as wire-format references; library implementations are S2-3 territory:

| # | Wire-format identifier category | S2-1 reference | Why wire-format-only |
|---|---|---|---|
| 1 | RFC-published cryptographic primitives | §1.1.3 + §1.8 | Implementation-agnostic per RFC; library pin churn absorbed at S2-3 |
| 2 | FIPS-published primitives (BLS12-381 + ML-KEM-768 + P-256) | §1.1 + §1.8 | Standards-anchored; library pin churn absorbed at S2-3 |
| 3 | EIP-published primitives (EIP-2 + EIP-712 + EIP-1271 + EIP-2098) | §5.6 + §10.3 + §10.4 + §1.8 | Standards-anchored; library pin churn absorbed at S2-3 |
| 4 | IRTF draft (BLS hash-to-curve + DLEQ) | §7 + §1.8 | Implementation-agnostic per IRTF; library pin churn absorbed at S2-3 |
| 5 | W3C standard (WebAuthn) | §10.2 + §1.8 | Implementation-agnostic per W3C; library pin churn absorbed at S2-3 |
| 6 | Polkadot canonical SCALE codec | §1.3 + §1.8 | Implementation-agnostic per Polkadot specification; library pin churn absorbed at S2-3 |

**Discipline:** S2-1 cites the standards anchor; S2-3 binds to specific library implementations. CVE patches + minor-version bumps absorbed at S2-3 layer; S2-1 stays stable across library churn.

### App. C.8 Cross-spec author-lock surfaces (vs scope-out)

Per §17.10: the following S2-1 surfaces are NOT scope-out — they are **author-locked** cross-spec coordination points where S2-1 + the named consumer-spec MUST update jointly. Listed here for clarity that author-lock ≠ scope-out:

| # | S2-1 surface | Section | Author-locked against | Status |
|---|---|---|---|---|
| 1 | `TAG_G4_ATTESTATION_AUTHORITY_V3` derivation + `g4_authority_ref` byte layout | §9 line 899 + §12.3.1 | S2-2 G4AuthorityRegistry contract interface | Locked; coordinated update required |
| 2 | `authority_pubkey_ref` SCALE sum-type byte layout | §6.1.3 line 1354 | S2-2 G4AuthorityRegistry contract interface | Locked |
| 3 | `role_tag` enum byte values | §6.1.5 line 1404 + 1449 | S2-4 configurator-pda-spec validation surface + §10 σ_conditional verification protocols | Locked |
| 4 | `delivery_hint` enum byte values | §6.1.5 line 1405 | S2-4 configurator-pda-spec (weaker binding — not in cryptographic preimage) | Locked |
| 5 | `endpoint_attestation_digest` SCALE sum-type | §3.4.3 + Simon D10 | S2-2 contracts honor sum-type variants | Locked |
| 6 | `TAG_ROTATION_LOG_ANCHOR_V3` (BP-4) | §2 line 256 + §6.1.5 line 1403 | `designs/conditional-recipient.md §2 line 51` Rule 33 propagation patch + S2-2 PasskeyRotationLog contract surface | Locked (back-prop applied) |
| 7 | `TAG_CONDITIONAL_RECIPIENTS_POLICY_V3` (BP-10) | §2.3 + §4 | `designs/conditional-recipient.md §11` Rule 33 propagation patch | Locked |
| 8 | `TAG_SUPERSEDED_COMMIT_REGISTRY_V3` (BP-11) | §2 + §15.6.3 | `flows-spec-final.md §SupersededCommitRegistry` Rule 33 propagation patch + S2-2 SupersededCommitRegistry contract | Locked |
| 9 | `TAG_ROTATION_AUTHORIZATION_V3` (BP-12) | §2.3 | `designs/conditional-recipient.md §2 line 72` Rule 33 propagation patch | Locked |
| 10 | `TAG_SD_*` prefix discipline | §2.7 + §2.8 | S2-7 SD pipeline tag namespace disjointness | Locked |
| 11 | Mode 3 RESERVED 3-layer defense-in-depth | §10.4.3 | S2-4 (configurator-rejection layer) + S2-2 + S2-5 (envelope-load-time + reveal-time layers) | Locked |

**Distinction (NORMATIVE):** App. C.8 surfaces are NOT scope-out — they are author-locked cross-spec coordination points where S2-1 + consumer-spec are jointly normative. App. C.1-C.6 are scope-outs where S2-1 explicitly defers ownership. Adding or removing locked surfaces requires coordinated update across S2-1 + the named consumer-spec + a `commit_version` bump per §2.8.

### App. C.9 Protocol `commit_version` transition log

Per §2.8 + the IB-1/IB-2/IB-3/IB-4 repair batch landing on 2026-05-06: the canonical `commit_version` history is enumerated below. Each prior version is historical/invalid for new partner-ready commits unless explicitly migrated; old envelopes verify under their commit-time version per §2.8 multi-version verification discipline.

| `commit_version` | Status | Landed | What changed | Why retired |
|---|---|---|---|---|
| `0x0300` | RETIRED | pre-2026-05-05 | σ-as-IKM (σ-derived HKDF/DEK construction) | Realizability gap — σ values not available at commit time; flipped to σ-as-authorization per `designs/dek-lifecycle.md` |
| `0x0301` | HISTORICAL/INVALID for new commits | 2026-05-05 backprop wave | A1+Shamir DEK lifecycle introduced (commit-time random DEK + flat Shamir split + per-stanza hybrid PQ wrap); `sdMerkleRoot` AAD binding; σ-as-authorization doctrine | Flat top-level Shamir broken under 4-gate AND for surplus conditional-recipient access structures (IB-2 build-blocker — `RECIPIENT_K_OF_N` with `n > k` collapses to flat threshold and admits any `k`-of-N recovery, including paths missing one of the four mandatory gate σ values) |
| `0x0302` | **CANONICAL (current, non-controlled-use)** | 2026-05-06 IB-1/IB-2/IB-3/IB-4 repair batch + Phase D regression cleanup | IB-2 typed hierarchical Shamir access structure (`FIXED_ONLY` 3-of-3, `RECIPIENT_1_OF_1` 4-of-4, `RECIPIENT_K_OF_N` 4-of-4 with nested aggregate split); IB-1 acyclic h_commit schedule (`commit_context_digest_N` + `attestation_context_digest_N` separate from final `h_commit_N`); IB-3 re-key AEAD invariant (payload AEAD bound to `commit_AAD_0` + `commit_context_digest_0` forever); IB-4 SD salt cycle break (pre-root SD context outside `commit_AAD`); 2 new TAG additions (`TAG_COMMIT_CONTEXT_V3` + `TAG_ATTESTATION_CONTEXT_V3`) for the acyclic schedule | — (remains canonical for NE/TP/CR profiles without controlled-use) |
| `0x0303` | **CANONICAL (controlled-use deployments only)** | 2026-05-23 | controlled-use profile added: 8 new TAG_*_V3 entries (§2.3.5); commit_AAD extended with `slice_id` + `slice_preceding_envelope_ref` + `slice_position` (§4.1.1); σ_conditional Mode T introduced (§10.11); applies ONLY to PDAs electing the controlled-use configuration profile per S2-8 — `commit_version = 0x0302` PDAs remain canonical. Byte-exact construction details for `h_envelope`, Mode T preimage final ordering, and audit-event tuple structures pending coordinated S2-1 amendment after first pilot partner validation per S2-8 §12 (App. C BP-CU-1) | canonical-pending-byte-exact-authoring |

**Discipline:** any future `commit_version` bump requires (a) a TAG-registry version bump per §2.8.2 + (b) a coordinated Stage-2 cross-review per §2.8.3 + (c) an App. C.9 row added before the bump lands. Combiner libraries MUST refuse to verify any envelope whose `commit_version` is not in the canonical row set above (post-bump, the prior row is moved to historical with multi-version-verification carve-outs at §2.8 documenting which historical versions a given S2-3 SDK release continues to support).

### App. C.10 Summary

Per §17.11 cross-reference index summary:

- **6 Stage-2 sibling specs** own non-S2-1 layers (App. C.1)
- **14 library version pin deferrals** to S2-3 (App. C.2)
- **8 Phase 1→2 transition surfaces** with S2-3 + S2-6 transition home (App. C.3)
- **11 open architectural questions** deferred to later stages (App. C.4)
- **8 BP entries** tracked in App. C.5 (5 locked-backprop pending, BP-13 rejected, BP-14 accepted, BP-15 rejected)
- **6 operational + caller-side scope-outs** to S2-5 + S2-6 + S2-7 (App. C.6)
- **6 wire-format-only discipline anchors** per §1.8 (App. C.7)
- **11 cross-spec author-lock surfaces** (App. C.8 — NOT scope-out, but cross-spec coordination)
- **3 `commit_version` rows** (`0x0300` retired, `0x0301` historical/invalid, `0x0302` canonical) per App. C.9

**S2-1 conformance + each consumer-spec conformance is jointly necessary for a complete Cealis deployment.** Implementers reading S2-1 alone have wire-format detail sufficient for cryptographic correctness; the remaining concrete bindings (libraries at S2-3, contracts at S2-2, configurator at S2-4, REST API at S2-5, operational runbooks at S2-6, SD pipeline at S2-7) live in the consumer-specs per the per-S2-N consumption surfaces enumerated at §17.2 + §17.3 + this appendix.
