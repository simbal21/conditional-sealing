# S2-8 Cealis Controlled-Use Access Sessions Specification

**Version:** 1.0 (Phase 5 anti-drift PASS-WITH-RESIDUALS 2026-05-22; awaiting Simon voice-pass)
**Status:** Stage-2 mandatory specification. Architecturally locked at coherence depth. Byte-exact normativization deferred to Stage-3 validation against first pilot partner per §12.
**Audience:** Cealis-internal architects and engineers implementing controlled-use access sessions; Stage-2 cross-review; future Cealis engineers maintaining the configuration profile across protocol-version bumps.
**Relationship to other Stage-2 specs:** Consumer of S2-1 (cryptography), S2-2 (smart-contracts), S2-3 (custody-integration), S2-4 (configurator-PDA). Triggers normative additions to those four specs (see §11). Honors but does not yet integrate with S2-7 (SD v2); SD-on PDAs under controlled-use are forbidden until the A21-SD-integration `/design` fork (App. C).
**Relationship to WP:** WP §B P4 (ConditionEngine) extends from nine modules to ten; WP §D (custody surface) extends G4 Phase 2 TEE scope; WP §K extends with two new banned phrasings (§10 of this spec). The WP itself stays the prose-framing source-of-truth; this spec is the architectural-coherence contract.
**Naming discipline:** V2 is the system version; V3 is the custody subsystem within V2 per internal Rule 29. Controlled-use is a PDA-configuration profile at the category layer (alongside NE, TP, CR), NOT an 8th row in the seven-view system register at internal Table B. The meta-layer descriptor "conditional sealing" stays singular.

---

## §0 — Front matter

### §0.1 Document identity

**Title:** Cealis V2 System, V3 Custody — Controlled-Use Access Sessions Specification (S2-8).

**Stage:** Stage-2 mandatory specification, configuration-profile tier. The eight Stage-2 specs (S2-1 through S2-8) compose the byte-exact engineering contract for the V2 system, V3 custody architecture. S2-8 is a consumer at the leaf of the dependency graph: it consumes S2-1 normative cryptographic constructions, S2-2 smart-contract surfaces, S2-3 custody-integration SDKs, and S2-4 PDA-configurator semantics. It does NOT feed back into any of them; it triggers additive amendments enumerated in §11.

**Protocol-version semantics:** the additions normatively introduced by this spec bump the protocol version from `commit_version = 0x0302` (S2-1 §0.1) to `commit_version = 0x0303`. The bump is required because §5 adds three fixed-width fields to `commit_AAD` (`slice_id`, `slice_preceding_envelope_ref`, `slice_position`) and §1 registers eight new tags in the TAG_*_V3 registry. The `0x0303` version covers controlled-use deployments only; partners running pure NE / TP / CR configurations without the controlled-use profile continue on `0x0302` until they elect the controlled-use profile in PDA.

**Discipline origin:** the architecture in this spec is the synthesis-v2 output of the `/design` pipeline run on design-capture item A21 (2026-05-20 raw capture; 2026-05-22 closure). The pipeline ran the full five-phase cycle: orient, six-alternative divergence, synthesis-v1 (§1–§12), destructive stress-test (8 HARDs + 12 SOFTs + 6 COSMETIC), synthesis-v2 with all 8 HARDs resolved (§H-1..§H-8), and anti-drift four-pane PASS-WITH-RESIDUALS. The underlying pipeline working records are internal and not included in this repository. Seven residuals are honored as authoring disciplines per §0.7.

### §0.2 Audience and reading order

**Three primary audiences:**

1. **Cealis-internal architects** consuming the controlled-use profile to brief partners, configure pilot PDAs, and shape downstream Stage-3 implementation work. Reads §0 (front matter) → §1 (conventions) → §2 (token model) → §3 (PDA extensions) → §6 (reveal flow under PresentedTokenCondition) → §9 (security model). §11 (propagation surface) for downstream coordination.

2. **Stage-2 cross-reviewers** validating coherence across the S2-1..S2-8 spec stack. Reads §0 → §11 (propagation surface) → §1 (conventions) → §5 (controlled-use sealed-envelope chain) → §4 (write-validation gate) → §10 (legal interactions). §0.4 scope-out matrix for boundary questions; App. C for back-propagation surface enumeration.

3. **Future Cealis engineers** maintaining the configuration profile across protocol-version bumps and integrating it with later configuration profiles. Reads §0 → §1 → §3 → §11. §14 (open questions) anchors what is deferred; §15 (error model) catalogs the custom errors introduced by the profile; §16 (cross-references) routes to all consumer and producer surfaces.

**Recommended reading order for first-time readers:** §0 → §1 → §2 → §3 → §6 → §9 → §10 → §11 → App. A. The architecture is most legible when token model and PDA extensions precede the reveal flow; the reveal flow then concretizes both. §5 (controlled-use sealed-envelope chain) is denser and benefits from §3 having established the slice vocabulary first.

### §0.3 Terminology discipline

**V2 vs V3 — strict naming per internal Rule 29:** identical to S2-1 §0.3. Controlled-use rides on the V3 custody subsystem; no change.

**σ as authorization (P22 doctrine, locked 2026-05-05):** identical to S2-1 §0.3. Controlled-use plugs into σ-as-authorization unchanged: a PresentedTokenCondition evaluation triggers gate signatures over the authorization tuple; gate signatures authorize per-stanza wrap-decap; HKDF-over-σ pipeline is untouched. The doctrine extends to write events (the write-validation TEE attests authorization; gates sign the authorization tuple; the writer-bound σ_holder is the holder's authorization signature, not key material). The doctrine extends to Stream 2 audit events (G4 counter-signs an authorization-shape attestation; co-signing gate from {G2, G3} signs the same tuple; neither sees content).

**Controlled-use discipline:** the controlled-use profile is a PDA-layer configuration that rides the existing 4-gate AND substrate without modification. It refines and composes existing system-architecture views (Tamper-proof + Use-case-flex + Conditional-reveal) under one configuration profile; it does not add a row to the seven-view register at internal Table B. At the value-prop category layer, controlled-use sits alongside NE, TP, and CR. The meta-layer descriptor for the operation Cealis performs across every configuration remains the single locked phrase "conditional sealing." When this spec uses "controlled-use," it always refers to the PDA-configuration profile, never to a separate product or substrate.

**Same-system clarification (binding):** controlled-use is not a second product or a new architecture family. The four gates (G1 Chain + G2 Lit V3 + G3 dcipher/drand + G4 Cealis verification) compose the same AND-substrate that the NE / TP / CR profiles ride. Controlled-use adds one ConditionEngine module (PresentedTokenCondition), three new on-chain registries (`CredentialAnchorRegistry`, `SliceLayoutRegistry`, `MasterTokenRevocationRegistry`), one opt-in registry (`TokenRevocationRegistry`), eight TAGs, one new PDA field family (`token_policy_config`), and one new client-shape contract. It does not change σ doctrine, does not introduce a fifth gate, does not introduce new staked custody, and does not introduce a new vendor relationship.

**Token vocabulary discipline:** this spec uses "credential" and "token" by convention. A **credential** is the off-chain signed structure produced when a master is issued; an **anchor** is the on-chain SSTORE recording first presentation of a credential; a **sub-token** is an off-chain TTL-derived child capability with strict scope-subset of its master. "Credential" denotes the holder-binding artifact; "anchor" denotes the chain-side handle; "sub-token" denotes the short-lived derived capability. The synthesis predecessor vocabulary used "token" interchangeably; this spec separates the layers.

**Sealed-envelope vocabulary discipline:** the controlled-use sealed-envelope chain (§5) describes a per-slice append-only linear chain of sealed envelopes. The synthesis-vocabulary terms "slice head," "slice_prev_commit_ref," "parent," "commit graph," and "merge-commit" have been replaced throughout this spec by "slice latest sealed envelope ref," "slice_preceding_envelope_ref," "preceding sealed envelope," "envelope chain," and the matching non-Git constructions. The chain is not a Git repository; the vocabulary cannot be Git-shaped without the analogue-reach reflex (internal operating rules) leaking into reader inference.

**Cosign-gate discipline:** the cross-vendor disjoint mandate that S2-3 establishes for σ_Lit and σ_G3 in the read/write path extends to Stream 2 audit anchors. The PDA-selected `audit_policy.stream2_cosign_gate` enum takes one of `{G2_lit, G3_dcipher, G3_drand}`; the spec uses the term **cosign-gate** to mean the PDA-selected gate that countersigns Stream 2 alongside G4. The cosign-gate is always a real existing gate; the spec does not introduce a fifth gate to serve audit signing.

**PresentedTokenCondition naming:** the synthesis predecessor name was "TokenPresented." This spec renames the module to **PresentedTokenCondition** (the form S2-2 §4-style condition modules use; the name avoids OAuth/OIDC "token presentation" overload that the destructive flagged at COSMETIC F-COS-3). All uses of "TokenPresented" in cross-spec discussion refer to this module by its renamed identifier.

**Emergency-elevation token:** the synthesis predecessor used "break-glass token" to denote a holder credential carrying elevated authority for use under defined emergency circumstances (typically: a clinician needs access to a patient's record outside the patient-consent window because the patient is incapacitated). The HL7 break-the-glass procedure documents this access pattern in healthcare IAM. This spec aligns with that prior art: §2 references HL7 BTG once as the existing convention, then uses **emergency-elevation token** as the Cealis-internal label to avoid the implicit claim that Cealis coined the access pattern. Where the spec previously read "break-glass policy" or "break-glass authority" it now reads "emergency-elevation policy" and "emergency-elevation authority." A future deployment may, at PDA configurator time, label the operational artifact "BTG" externally for clinician-facing UI alignment; the spec-internal name stays "emergency-elevation."

**Holder-binding vocabulary:** "holder" denotes the natural-person or operational-actor whose credential is presented at PresentedTokenCondition evaluation time. "Holder-binding" denotes the cryptographic primitive that ties the credential to the holder. Default holder-binding is **passkey-bound** (WebAuthn / RIP-7212 via the V3 PasskeyRotationLog discipline). The full holder-binding catalog enumerated in §2 also includes **hardware-bound** (cold-wallet, smartcard, hardware-key-resident credentials), **app-session-issued** (short-lived session capability derived from a master via the partner's session manager), and **EOA-bound** (EVM address producing EIP-712 typed-data signatures). All four bindings are architecturally first-class in §2 even though pilot deployments will favor passkey-bound for non-technical holders.

### §0.4 What this spec does NOT cover (cross-ref App. C)

S2-8 is the controlled-use configuration profile — architectural-coherence-locked normativization of how a PDA elects controlled-use, what new chain surfaces and PDA fields it activates, and how the reveal flow composes under PresentedTokenCondition. It does NOT cover:

- **Byte-exact cryptographic constructions** for credential digests, anchor entries, sub-token derivation, audit-event content-shape digests, write-attestation byte layouts, or canonical presentation digests. S2-1 owns byte-exact construction; this spec specs the new TAGs additively (§1) and defers the byte-exact construction to a coordinated S2-1 amendment after Simon voice-pass of this spec.
- **Smart-contract Solidity source** for `CredentialAnchorRegistry`, `SliceLayoutRegistry`, `MasterTokenRevocationRegistry`, opt-in `TokenRevocationRegistry`, the PresentedTokenCondition module, the composition-compatibility matrix enforcement, or any storage-layout decisions. S2-2 owns smart-contract surfaces; this spec specs the registry semantics + ABI shapes additively (§4 + §5) and defers Solidity authoring to a coordinated S2-2 amendment.
- **SDK + attestation envelope details** for the G4 Phase 2 TEE write-validation path, the cross-vendor cosign protocol for Stream 2, the new G4 ingest API for read-event tuples, and the version pins for any new SDKs. S2-3 owns SDK + attestation. This spec normativizes the API shape (§4, §6, §7) and defers SDK authoring to a coordinated S2-3 amendment.
- **PDA-configurator UI and operational ceremonies** for instantiating a controlled-use PDA, electing a slice topology, electing a recommended client profile, configuring emergency-elevation authority. S2-4 owns the configurator surface and PDA+ governance discipline. This spec specifies the field family additions (§3) and the governance sub-classification (ControlledUseAccessPolicy under PDA+); S2-4 owns UI + workflow.
- **SD pipeline integration.** S2-7 owns SD constructions. SD-on PDAs under controlled-use are forbidden until the cross-reference design is authored. App. C names this as `/design` fork "A21-SD-integration." This spec normatively forbids controlled-use × SD elections at PDA validation time (§3).
- **Ingestion and delivery API surfaces** for controlled-use read/write events. S2-5 (ingestion-delivery-API) is the home for HTTP-layer API design; this spec normativizes the ingest-API contract shape (§4, §7) and defers HTTP authoring to a coordinated S2-5 amendment.
- **Operational ceremonies** including DKG for new gate-authority keys (`K_G4_write_attest`, `K_G4_audit_stream2`, cosign-gate keys) and rotation orchestration. S2-6 owns operational-ceremony protocols; this spec specifies key-registry semantics (§4, §10) and defers ceremony authoring to a coordinated S2-6 amendment.
- **DRM, secure-sandbox, or device-side anti-extraction guarantees.** Out of scope per the orient (§3 scope-out) and per WP §K (no "sandbox," no "secure container," no "DRM"). The client SDK is a thin helper, not a fortress (§7). The authorized recipient is not the adversary; the spec defends against ambient copies, uncontrolled persistence, silent onward transfer, and unmanaged device sprawl, not against screenshot, rooted-device extraction, or OS-level keylog.
- **V3 custody redesign.** The four gates are the substrate; controlled-use rides on it unchanged. Any architectural drift toward "Cealis-CU as separate" or "controlled-use needs a fifth gate" is rejected.
- **σ-doctrine flip.** σ-as-authorization (S2-1 §0.3, May 5 2026 lock) is binding. Controlled-use plugs into the doctrine; it does not renegotiate it.
- **Pilot-subset scoping.** Per Rule 31, the spec normativizes the full controlled-use engine. All nine token classes (§2.2) are architectural; partner deployments elect which subset they activate. The full holder-binding catalog (§2.3) is architectural; pilot deployments may favor passkey-bound. The full PDA field family (§3) is normative; partners cannot author raw, but Cealis-internal configurator review can leave fields at default.

App. C enumerates the scope-out matrix in detail.

### §0.5 Status of this document

**Phase 5 anti-drift status (2026-05-22):** the architecture is locked at coherence-level depth per the synthesis-v2 architecture record (internal). The four-pane anti-drift check returned PASS-WITH-RESIDUALS; the seven residuals are honored as authoring disciplines per §0.7 of this spec. Phase 5 explicitly notes that the residuals carry into authoring, not into a re-divergence.

**Architectural locks (NOT subject to relitigation absent Tier-1 escalation):**
- B-1 lazy-anchor passkey credential primitive (synthesis §2 row B-1)
- B-2 G4 TEE attestation + on-chain policy-hash replay (renamed from "hybrid attestation" per F-COS-2)
- B-3 per-slice independent envelope chains + cross-slice anchor (renamed terminology per F-COS-1, F-COS-4, F-COS-5)
- B-4 hybrid web + native client with PDA-bound profile (synthesis §2 row B-4)
- B-5 master credential + TTL sub-token; opt-in per-sub-token CRL (synthesis §2 row B-5)
- B-6 two-tier audit retention (Stream 1 + Stream 2) + content-shape digest survives shred + cross-vendor cosign-gate (synthesis §2 row B-6 + H-3 + H-4)
- All 8 HARD resolutions H-1 through H-8 from synthesis-v2

**Open architectural questions (deferred to Stage-3 validation):**
- byte-exact construction details for the eight new TAGs (`TAG_CU_CREDENTIAL_V3` byte-layout; canonical presentation digest schema; content-shape digest input set) → S2-1 amendment after first pilot
- Solidity storage-layout decisions for the three new registries → S2-2 amendment
- HTTP API ingestion contracts for read-event tuples and Stream 2 batching → S2-5 amendment
- Volume-modeling of cross-slice composed-presentation gas cost → `/design` fork "A21-batched-presentation" (App. C)
- SD integration cross-reference → `/design` fork "A21-SD-integration" (App. C)

These are enumerated normatively at §14 + §16. Phase 3 trigger condition is Simon voice-pass on §0 + §11 + §0.7 anchors.

### §0.6 Source-of-truth ordering (per internal Rule 0)

Per internal Rule 0, when this spec disagrees with reference docs (closure documents, WP, docs/designs/*.md):

- **For controlled-use configuration semantics:** S2-8 (this spec) is the source of truth.
- **For cryptographic construction byte-exactness:** S2-1 governs after coordinated amendment; until that amendment lands, this spec's normative TAG enumeration (§1) is the source for which TAGs are added, but the byte layouts are S2-1 authority.
- **For on-chain registry semantics:** S2-2 governs after coordinated amendment; until that amendment lands, this spec's normative registry enumeration (§5) is the source for which registries are added.
- **For project-level architectural framing:** design-capture items A21..A24 + this spec's §0 take precedence over reference-only closure documents.

When an implementer reads a discrepancy, this spec's normative text wins for controlled-use configuration questions; the discrepancy should be reported back via the §11 propagation surface.

### §0.7 Document discipline anchors

The seven authoring disciplines carried from the Phase 5 anti-drift residuals (anti-drift Residuals 1–7). These are normative across every section of this spec.

1. **F-COS-1..6 rename pass is mandatory.** Synthesis-vocabulary Git terms (`slice head`, `slice_prev_commit_ref`, `parent`, `commit_graph`) have been renamed to non-Git constructions (`slice latest sealed envelope ref`, `slice_preceding_envelope_ref`, `preceding sealed envelope`, `envelope chain`). The synthesis predecessor name "TokenPresented" has been renamed to `PresentedTokenCondition`. "Hybrid attestation" has been renamed to "G4 TEE attestation + on-chain policy-hash replay." `slice_topology_root` has been renamed to `pda_slice_layout_anchor`. "Sealed versioned vault" has been renamed to "controlled-use sealed-envelope chain." "Break-glass" has been aligned with HL7 BTG convention then replaced spec-internally with "emergency-elevation token."

2. **Non-passkey holder identity enumerated as architecturally first-class** in §2.3, even when pilot favors passkey-bound. Hardware-bound, app-session-issued, and EOA-with-EIP-712 are each named with their binding primitive, their lifecycle, and their composition with PresentedTokenCondition. Rule 31 full-engine discipline applies.

3. **Propagation surface tracked, `commit_version` bumps to `0x0303`.** §11 enumerates every downstream amendment obligation against S2-1, S2-2, S2-3, S2-4, S2-7, and WP §K. Status flip of design-capture A21 from `captured` to `committed` does not happen at spec commit; it happens after the §11 amendments are in motion per internal Rule 33.

4. **Extended Rule-35 industry-collision scan list** enumerated in §14. The list combines the synthesis-v1 §10 terms with the Phase 4/5-surfaced new terms; external use of any of these (grant copy, partner outreach, landing page) requires the four-query collision scan per internal Rule 35 before promotion to external normative status.

5. **View-register vs category-layer distinction held.** Controlled-use is a PDA-configuration profile at the category layer (alongside NE, TP, CR). It is not an eighth row in internal Table B; it composes the Tamper-proof, Use-case-flex, and Conditional-reveal views simultaneously. The meta-layer descriptor "conditional sealing" stays singular. §2.1 + §10 hold this distinction explicit.

6. **F-9 SD integration deferred via `/design` fork A21-SD-integration.** §3 normatively forbids SD-on PDAs under controlled-use until the cross-reference is authored. App. C names the fork.

7. **WP §K compliance — banned phrasings absent from this spec.** §10 enumerates two new banned-phrasing candidates (no "secure container / sandbox / DRM" claim for the client SDK; no "Cealis prevents authorized recipients from extracting data once displayed"). The thirteen pre-existing WP §K patterns are honored throughout this spec. The post-authoring grep verification listed in §16 confirms absence.

The universal tripwire ("no release path exists that bypasses the on-chain-verified predefined condition") is held across every read and write path enumerated in §6 and §8; the explicit time-of-check / time-of-use boundary (H-7) names what the tripwire does and does not promise.

The two-axis on-chain shred guardrail (authority axis × condition axis, with mandatory `NOT post_challenge_reveal_in_progress`) extends to controlled-use slice-shred paths (§5).

### §0.8 Cross-reference index

- §1 conventions establishes encoding rules, the eight new TAGs, the scope grammar, the schema language, the envelope hash construction, the audit-event tuple structure, the cosign-gate enum encoding.
- §2 token model establishes the nine token classes, the four holder-binding forms, the credential lifecycle, the master-vs-sub split, the scope-narrowing rule, the lazy-anchor presentation digest, and the transaction-atomic first-presentation rule (A22).
- §3 PDA extensions establishes the `token_policy_config` field family, the ControlledUseAccessPolicy PDA+ governance sub-classification, the intent-translation flow, the evolution-policy semantics, the SD-forbidden rule, the gas-attribution default, the profile-strengthen direction, the recommended-client-profile values.
- §4 write-validation gate establishes the G4 Phase 2 TEE scope for write claims, the on-chain policy-hash replay verification, the refusal model, the cross-vendor cosign for Stream 2.
- §5 controlled-use sealed-envelope chain establishes the per-slice independent linear chains, the `SliceLayoutRegistry` and `pda_slice_layout_anchor`, the supersession-invariant slice latest sealed envelope ref rule (H-2), the `commit_AAD` field additions, the re-key composition, the two-axis shred composition, the topology evolution policy.
- §6 reveal flow under PresentedTokenCondition establishes the ten-step normative flow + the read-vs-write path split + composition under H-6.
- §7 client SDK + reference client establishes the hybrid web/native split, the PDA-binding via `recommended_client_profile`, the wipe-by-default normative, the OS-residuals catalog, the partner-SDK contract.
- §8 token revocation establishes the master-token revocation, the sub-token TTL, the in-flight halt semantics, the opt-in per-sub-token CRL, the chain-confirmation depth normative.
- §9 security model establishes the threat catalog, the time-of-check / time-of-use boundary, the authorized-recipient-not-adversary clause, the off-chain credential-metadata correlation residual, the seven-view cycle.
- §10 GDPR + legal interactions establishes the consent / health / accountability bases, the Art. 17 erasure semantics with content_shape_digest, the Art. 18 freeze interaction, the Art. 26 joint controllership analysis with deeper-erasure forbidden by default, the §286 ZPO default + §371a path.
- §11 propagation surface enumerates every downstream amendment.
- §12 implementation phasing establishes the Stage-3 markers + validation-gate-against-first-pilot.
- §13 test taxonomy enumerates the normative test categories.
- §14 open questions + extended Rule-35 scan list.
- §15 error model enumerates the custom errors.
- §16 cross-references routes to consumer and producer surfaces.
- App. A enumerates four example PDAs.
- App. B enumerates test-vector category placeholders.
- App. C enumerates the scope-out matrix, back-propagation queue, commit_version log, open-questions table, author-lock surfaces, SD-integration fork.

### §0.9 PII content statement

§0 carries no PII. The front matter establishes meta-architectural framing and the seven authoring disciplines. Specific data flows and field-level PII statements live in §2 (credential digest, presentation digest), §3 (PDA field semantics), §5 (envelope AAD fields), §6 (reveal flow per-step), §9 (threat-model PII residuals), §10 (legal annex per-basis PII), §15 (error context fields).

Controlled-use deployments process PII routinely (the entire profile is for sensitive operating data); the per-section PII statements name which fields carry PII inside the controlled-use envelope, which fields carry hashed identifiers and digests that are not direct PII but may be linkable under Breyer C-582/14, and which fields are non-PII operational metadata. The two-stream audit retention (§10) plus deployment-scoped audit-pepper plus content-shape digest (Stream 2) plus DEK-keyed Stream 1 set the legal-cryptographic boundary at which PII enters and leaves the controlled-use surface.

---

## §1 — Conventions

This section fixes the vocabulary, primitives, encoding rules, and notation used throughout this specification. Encoding rules inherit from S2-1 §1 unchanged; this section enumerates only the additive constructs.

### §1.1 Cryptographic primitives — wire-format identifiers

All primitives used by this spec are already normative in S2-1 §1.1: keccak-256 for domain-separated hashing, BLAKE3 for high-throughput keyed hashing, HKDF-SHA-256 for key derivation, Ed25519 for offline credential signing, Ed25519 + RIP-7212 for passkey-bound holder signatures, ChaCha20-Poly1305 + AES-256-GCM for AEAD, ML-KEM-768 hybrid X25519 wrap for post-quantum key encapsulation, SCALE encoding for binary structs, JSON Canonicalization Scheme (RFC 8785) for off-chain canonical representations. This spec adds no new primitive families.

### §1.2 Endianness, byte order, integer width

Inherited from S2-1 §1.2 unchanged: big-endian for keccak preimages; little-endian for SCALE-encoded structs; unsigned integer widths (`u8`, `u16`, `u32`, `u64`, `u128`) named explicitly per field.

### §1.3 SF-3 normative encoding rule discipline

Inherited from S2-1 §1.3 unchanged: every byte-exact construction follows the SF-3 normative encoding rule discipline. Fixed-width concatenation with TAG_*_V3 prefix per generalized D6 V3 TAG-prefix discipline. SCALE encoding for SCALE structs.

### §1.4 New TAGs (additive to S2-1 §2.3)

The TAG_*_V3 registry at S2-1 §2.3 currently enumerates 30 active rows. This spec adds eight rows; the active count after coordinated S2-1 amendment becomes 38. The eight new rows are:

| Constant | Label | Semantic role |
|----------|-------|---------------|
| `TAG_CU_CREDENTIAL_V3` | `"CEALIS_V3_CU_CREDENTIAL_V3"` | Domain-separated hash for the off-chain master credential digest |
| `TAG_CU_ANCHOR_V3` | `"CEALIS_V3_CU_ANCHOR_V3"` | Domain-separated hash for the on-chain credential anchor entry |
| `TAG_CU_SUB_TOKEN_V3` | `"CEALIS_V3_CU_SUB_TOKEN_V3"` | Domain-separated hash for the sub-token derivation from a master |
| `TAG_CU_SLICE_COMMIT_V3` | `"CEALIS_V3_CU_SLICE_COMMIT_V3"` | Domain-separated hash for the per-slice sealed envelope commit |
| `TAG_CU_SLICE_LAYOUT_V3` | `"CEALIS_V3_CU_SLICE_LAYOUT_V3"` | Domain-separated hash for the pda_slice_layout_anchor Merkle root (renamed from synthesis `TAG_CU_SLICE_TOPOLOGY_V3`) |
| `TAG_CU_WRITE_ATTEST_V3` | `"CEALIS_V3_CU_WRITE_ATTEST_V3"` | Domain-separated hash for the G4 Phase 2 TEE write-validation attestation |
| `TAG_CU_AUDIT_STREAM1_V3` | `"CEALIS_V3_CU_AUDIT_STREAM1_V3"` | Domain-separated hash for the Stream 1 data-event entry (DEK-keyed) |
| `TAG_CU_AUDIT_STREAM2_V3` | `"CEALIS_V3_CU_AUDIT_STREAM2_V3"` | Domain-separated hash for the Stream 2 metadata-event entry (audit-keyed, content-shape) |

Byte-exact construction details (input field set, ordering, fixed-width padding, length prefix discipline) are deferred to the coordinated S2-1 amendment per §11. Until that amendment lands, the TAG labels and their semantic roles are normative at this spec; the byte layouts are spec-locked-pending.

### §1.5 Scope grammar

Credential scope is encoded as a `ScopeSet`:

```
ScopeSet :=
  | Wildcard               # master credential scope; equals "*"
  | Set<SliceId>           # explicit slice-id set; ordered canonical form
```

`SliceId` is a 32-byte identifier defined in the PDA's `token_policy_config.slice_layout.slices[]`. Sub-token derivation enforces `sub.scope ⊆ master.scope` (set-subset, with wildcard satisfying any subset). The PresentedTokenCondition evaluation in §6 enforces scope-subset at every presentation against the master credential's on-chain anchor.

Cross-slice composed operations require multiple sub-token presentations under the existing Composed condition module (§6 + §H-6); except where the master credential itself satisfies the composed predicate per F-15 disposition (master satisfies multi-slice when `scope` covers all named slices AND `slice_atomicity_allowed: true` in PDA).

### §1.6 Schema language

Per-slice schemas are referenced by `schema_hash` — a 32-byte content hash over the canonical schema representation for that slice. Schema authoring is a Cealis-internal configurator step under PDA+ governance; partners cannot author raw schemas. The canonical schema representation is JSON Schema (Draft 2020-12) under JCS canonicalization (RFC 8785). Schema-hash is recomputed at PDA-evolution time; existing slice references stay stable per §5 supersession-invariance rule (the slice latest sealed envelope ref tracks the original `h_commit`, not the schema-hash).

The write-validation gate (§4) consumes the schema-hash and validates the proposed write payload's canonical form against the schema. The client-side schema validator (§7) consumes the same schema-hash and validates the payload before transmission as a UX layer; this is help, not enforcement.

### §1.7 Envelope hash construction (sketch)

The per-slice sealed envelope hash extends S2-1 §3 composite identifier semantics:

```
h_envelope = keccak256(
    TAG_CU_SLICE_COMMIT_V3 ||
    pda_root ||
    slice_id ||
    slice_position (u64 BE) ||
    slice_preceding_envelope_ref ||  # 32 bytes; zero for slice-initial envelope
    h_commit                          # the underlying S2-1 §3 commit identifier
)
```

Byte-exact width, padding, and ordering deferred to S2-1 amendment per §11. The S2-1 amendment co-authors this construction into S2-1 §3.

### §1.8 Audit-event tuple structure (sketch)

Stream 1 (data-event, DEK-keyed) entries carry:
- `event_timestamp` (u64 BE Unix seconds)
- `actor_token_digest` (32 bytes — keccak256 of the sub-token presentation digest)
- `slice_id` (32 bytes)
- `op_kind` (u8 enum: `READ`, `WRITE`, `COMPOSED_READ`, `COMPOSED_WRITE`)
- `content_ref` (32 bytes — for write events, the new envelope's `h_envelope`; for read events, the slice latest sealed envelope ref at read time)

Stream 1 entries are encrypted under the slice's PDA-bound DEK, so they shred with the data on Art. 17 fire.

Stream 2 (metadata-event, audit-keyed) entries carry:
- `event_timestamp` (u64 BE Unix seconds)
- `actor_token_digest` (32 bytes)
- `slice_id` (32 bytes)
- `op_kind` (u8 enum)
- `content_shape_digest` (32 bytes — HMAC-SHA-256 keyed under deployment-scoped audit-pepper, over (schema_hash || scope_subset || op_kind); NEVER over content)
- `pepper_epoch_number` (u32 BE)

Stream 2 entries are signed by `K_G4_audit_stream2` AND co-signed by the PDA-selected cosign-gate (§1.9). Byte-exact ordering deferred to S2-1 amendment.

### §1.9 Cosign-gate enum encoding

The PDA field `audit_policy.stream2_cosign_gate` takes one of:

```
CosignGate :=
  | G2_LIT       # u8 = 0x01; cosign by Lit V3 attested TEE under Lit signing authority
  | G3_DCIPHER   # u8 = 0x02; cosign by dcipher threshold network
  | G3_DRAND     # u8 = 0x03; cosign by drand League of Entropy
```

The choice MUST match the PDA's `g3_choice` field if `G3_*` is selected (a PDA selecting `g3_choice = G3_dcipher` for the read path cannot select `stream2_cosign_gate = G3_DRAND` for audit cosign; cross-vendor-disjoint requires the cosign-gate's vendor family be different from G4, which is satisfied by all three choices, but family-consistency with the read path is required so the disjoint-vendor analysis composes coherently).

The cosign-gate is normative at every Stream 2 entry; absence of cosign at validation time triggers `CU_ERR_STREAM2_COSIGN_MISSING` (§15).

### §1.10 PII content statement (§1)

§1 conventions carry no PII directly. The TAG labels, scope grammar, schema language, envelope hash construction sketch, audit-event tuple structure sketch, and cosign-gate enum encoding are meta-architectural framing.

The `content_shape_digest` field is explicitly designed to be PII-free: it is a one-way HMAC over `schema_hash || scope_subset || op_kind`, NEVER over content. Under Breyer C-582/14 strict interpretation, the digest may be linkable to a specific PDA + slice + op-class combination by a partner holding the deployment-scoped audit-pepper, but it does not directly disclose personal data. Partners are responsible for treating the digest as pseudonymous data under GDPR Art. 4(5) when retaining Stream 2 for the accountability period.

The `actor_token_digest` field is a keccak256 over the sub-token presentation digest, which is itself derived from holder-binding material (passkey public key, hardware token public key, EOA address, or app-session identifier). Under Breyer it qualifies as personal data when correlated with off-chain credential issuance records held by the partner. Partners are responsible for treating actor token digests as personal data when retained beyond their operational lifecycle.

---

## §2 — Token model

This section establishes the credential / token model normatively. The B-1 alternative locks the primitive: a passkey-bound credential, signed off-chain at issuance, anchored on-chain only at first presentation (lazy-anchor), with chain-side revocation enforced via `MasterTokenRevocationRegistry` per §8. The model carries four holder-binding forms (passkey-bound default; hardware-bound, app-session-issued, EOA-bound as architecturally first-class), nine token classes, a master-vs-sub-token split with TTL-derived sub-tokens, and a transaction-atomic first-presentation discipline (design-capture A22) for the lazy-anchor primitive.

### §2.1 Position within the system

Controlled-use is a PDA-configuration profile at the category layer alongside NE, TP, CR. It composes existing system-architecture views: Tamper-proof (the per-slice sealed envelope chain, §5), Use-case-flex (the same primitives serve health-record, sealed-team-repo, M&A diligence, archival), Conditional-reveal (the PresentedTokenCondition module is one more ConditionEngine condition module, additive to the nine existing modules). It does NOT add an eighth row to the seven-view register at internal Table B. The meta-layer descriptor for the operation Cealis performs across every configuration remains the singular phrase "conditional sealing." The category-layer reading "controlled-use" is one of N category-layer readings (alongside custody-minimized data escrow, enforcement infrastructure, conditional digital legacy, and other category-layer descriptors per the internal meta-vs-category naming analysis).

This positioning is normative: future spec consumers reading "controlled-use" should not infer a new product line, a new substrate, a new view in the system register, or a canonical fourth category that subordinates NE/TP/CR. Controlled-use is one PDA configuration profile, riding the existing 4-gate AND substrate, exposing additional surfaces at PDA + smart-contract + custody-integration layers, holding the same universal tripwire ("no release path exists that bypasses the on-chain-verified predefined condition") that the other profiles hold.

### §2.2 Token class catalog (nine classes, full engine per Rule 31)

The full catalog of token classes architecturally accommodated by the controlled-use profile. Pilot deployments may activate a subset; the spec normativizes all nine.

1. **Master credential** — long-lived, chain-anchored at first presentation. Holds the holder-binding key, the wildcard or wide-scope authorization, and the parent-authority for sub-token derivation. Revocation via `MasterTokenRevocationRegistry` is irreversible (matches `DisclosureRevocationRegistry` discipline). Master credentials are the only credentials with on-chain anchors; sub-tokens derive off-chain.

2. **Temporary-read sub-token** — short-lived (default TTL 300 seconds; PDA-configurable via `recommended_sub_token_max_ttl_seconds`), read-only over a slice subset of the master's scope. Off-chain TTL-derived from the master. Presentation triggers the master's revocation check.

3. **Renewable-read sub-token** — same as temporary-read but the partner's session manager may re-issue a successor sub-token at TTL expiry within an envelope of renewal-policy (PDA field; default disabled). Each renewal is a fresh derivation; the master's revocation propagates to renewals.

4. **Append-only writer sub-token** — write authority over a slice subset; the writer may append new sealed envelopes to the slice latest sealed envelope ref, never rewrite history. Schema-conformance enforced by the write-validation gate (§4); history-immutability enforced by the envelope chain (§5).

5. **Scoped-slice sub-token** — narrow read OR write authority over a specific slice (or named subset). The most common production form for non-master use; doctors and pharmacists in the health-record archetype operate primarily via scoped-slice sub-tokens.

6. **One-shot consumption sub-token** — usable exactly once; consumption is enforced by chain-side nonce-tracking (consumed-token-nonce in the per-slice envelope chain). Pharmacy-dispensing one-shot prescriptions fit this class.

7. **Team-member sub-token** — long-lived (TTL extended via PDA), read-write within a defined team scope. Sealed-team-codebase archetypes use this class for developer access; the team-membership list is partner-managed off-chain, but each member's presentation triggers master-token revocation check.

8. **Emergency-elevation token** — credential carrying elevated authority for use under defined emergency circumstances. Aligned with HL7 BTG (break-the-glass) convention from healthcare IAM. Activation requires the emergency-elevation policy from PDA (`emergency_elevation_policy.enabled = true` + `authority` list + `audit_class = STREAM2_ALWAYS_LOGGED`). Every emergency-elevation presentation produces a Stream 2 entry even if `stream1_retention_class = ART17_SHREDDABLE` would otherwise prune access traces. Emergency elevation is NOT a sub-token derivation; it is a separately-issued credential with its own holder-binding and its own anchor.

9. **Hardware-bound credential** — credential whose holder-binding material is bound to a hardware-key (cold-wallet, smartcard, hardware token, FIDO security key). Architecturally first-class; activation is via a hardware-bound holder-binding choice at credential issuance time (§2.3). Hardware-bound credentials raise the bar for token theft compared to passkey-bound credentials and are appropriate for high-stakes team / enterprise workflows.

### §2.3 Holder-binding forms (four forms, architecturally first-class)

The holder-binding form is named at credential issuance time; once bound, the form cannot be changed without re-issuance. All four forms are architecturally first-class per Rule 31; pilot deployments will favor passkey-bound for non-technical holders, but spec consumers MUST accommodate all four.

#### §2.3.1 Passkey-bound

Default holder-binding. The credential's holder-binding key is a WebAuthn public key registered via the V3 PasskeyRotationLog discipline. Presentation signatures are produced via WebAuthn `navigator.credentials.get()` from a passkey held in the holder's authenticator (platform authenticator on mobile/desktop, cross-platform authenticator for portability). RIP-7212 enables on-chain ECDSA verification on Base.

Per-deployment passkeys are required (per-RP-ID derivation per F-18 disposition). A subject using Cealis at deployment D1 (hospital) and deployment D2 (law firm) has two distinct passkeys; the PasskeyRotationLog discipline is per-deployment.

#### §2.3.2 Hardware-bound

The credential's holder-binding key is bound to a hardware key (cold-wallet, smartcard, hardware security key) producing signatures via the hardware key's signing API. The hardware key's public key is the credential's holder-binding key. Presentation signatures are produced by the hardware key directly.

Hardware-bound credentials accommodate two operational patterns: (a) a single hardware key holds one credential (high-stakes team workflow, M&A diligence); (b) a hardware key holds multiple credentials across deployments via per-RP-ID derivation. Pattern (b) requires hardware support for hierarchical key derivation (BIP-32-style); spec consumers MUST verify hardware capability before activating pattern (b).

#### §2.3.3 App-session-issued (short-lived session capability)

The partner's session manager (running in a partner-owned environment) holds a master credential AND issues short-lived session capabilities to operational actors via off-chain derivation. The session capabilities are sub-tokens (per §2.4) bound to ephemeral session keys held by the partner's session manager.

App-session-issued is structurally a sub-token primitive with the partner's session manager as the issuance origin. The master's holder-binding form is one of {passkey-bound, hardware-bound, EOA-bound}; the session capability holder-binding is ephemeral.

App-session-issued is appropriate when an operational actor has no direct credential and instead acts through a partner-mediated session (insurance claim-processor workflow, third-party auditor session). The session capability cannot exceed the master's scope and cannot live beyond the master's revocation.

#### §2.3.4 EOA-bound with EIP-712 attestation

The credential's holder-binding key is an EVM address; presentation signatures are EIP-712 typed-data signatures over the canonical presentation digest. The EOA is the holder-binding key; signing is via the EOA's wallet.

EOA-bound is appropriate for technical users with established wallet infrastructure (developer accessing a sealed-team codebase, on-chain treasury operator accessing an M&A diligence room). EIP-712 typed-data signing is the same primitive S2-2 uses for other EVM signing surfaces.

### §2.4 Credential lifecycle

Master credentials follow a four-stage lifecycle:

1. **Issuance (off-chain).** The partner's configurator generates the master credential structure: holder-binding key, scope (wildcard or initial slice set), policy fields (TTL, revocation authority, emergency-elevation flag if applicable), and the issuer's signature. The credential is delivered to the holder via the partner's onboarding channel. No chain operation occurs at issuance.

2. **First presentation (chain-anchored).** At the first PresentedTokenCondition evaluation that consumes this master, the transaction-atomic first-presentation discipline (§2.6, A22) applies: revocation check FIRST, σ_holder verification, anchor SSTORE, condition evaluation, in that order. After successful first presentation, the master's anchor exists at `CredentialAnchorRegistry[H(master_credential_digest)]` forever (absent revocation).

3. **Sub-token derivation (off-chain).** Holders derive sub-tokens for narrower-scope operations from the master. Sub-token derivation is off-chain; the derived sub-token carries a derivation proof linking it to the master, the scope subset, the TTL, and the sub-token-specific holder-binding material if any. The master's anchor must already exist (post-first-presentation) for sub-tokens to be presentable.

4. **Sub-token presentation (chain-evaluated, no chain write).** Each sub-token presentation reads the master's anchor + revocation, validates the derivation proof, validates the σ_holder signature, evaluates the PresentedTokenCondition module. No new chain write occurs unless the operation requires a Stream 1 anchor write (the Stream 1 batched Merkle root anchor lands on a flush cadence, not per-presentation).

5. **Revocation (chain-anchored).** Master revocation writes to `MasterTokenRevocationRegistry[H(master_credential_digest)] = (revocation_timestamp, revoker_authority_address)`. After revocation, the master's anchor lookup composes with the revocation lookup; subsequent presentations of this master OR any sub-token derived from it fail at step 1 of the transaction-atomic discipline.

### §2.5 Master + TTL sub-token relationship

Sub-tokens are off-chain TTL-derived from a master without any chain operation at derivation time. The chain check happens at sub-token presentation, not at derivation. This composition is core to the B-5 winner.

Sub-token scope MUST be subset of master scope (`sub.scope ⊆ master.scope`). The PresentedTokenCondition evaluation at each presentation enforces scope-subset against the master credential's on-chain anchor.

Sub-token TTL is bounded by `recommended_sub_token_max_ttl_seconds` from the PDA (default 300 seconds, partner-configurable via S2-4 configurator review). Long-lived sub-tokens are NOT supported as a class; long-lived authority is master-credential territory. The TTL bound exists to limit the time-of-check / time-of-use boundary (H-7); see §9.

Sub-token derivation proof carries:
- `master_anchor_ref` (32 bytes — H(master_credential_digest))
- `sub_scope` (ScopeSet — must be subset of master.scope)
- `sub_ttl_expires_at` (u64 BE Unix seconds)
- `sub_holder_binding_pubkey` (variable width — passkey pubkey, hardware-key pubkey, ephemeral session pubkey, or EOA address)
- σ_master over the above tuple (signature by the master's holder-binding key)

At sub-token presentation, the chain-side check validates σ_master (proves derivation from master), reads master anchor (proves master exists), reads master revocation (proves master not revoked), validates σ_holder over the canonical presentation digest (proves current presenter holds the sub-token holder-binding key).

### §2.6 Lazy-anchor first-presentation discipline (A22)

Per design-capture A22 (transaction-atomic first-presentation discipline for lazy-anchor primitives), the first-presentation transaction MUST bundle four operations in this exact order, all within one atomic transaction:

1. **Revocation check.** `SLOAD MasterTokenRevocationRegistry[H(master_credential_digest)]`. If `revocation_timestamp != 0`, REVERT with `CU_ERR_REVOKED_MASTER` (§15). No state writes occur before this check.

2. **σ_holder verification.** Verify the σ_holder signature over the canonical presentation digest. If invalid, REVERT with `CU_ERR_INVALID_HOLDER_SIGNATURE` (§15).

3. **Anchor SSTORE.** Write to `CredentialAnchorRegistry[H(credential_digest)] = (block.number, block.timestamp, holder_binding_pubkey_ref)`. For a master's first presentation, the entry records the master's anchor; for a sub-token's first presentation, the entry records the sub-token's anchor pointing at the master's anchor.

4. **PresentedTokenCondition evaluation.** The 10th ConditionEngine module evaluates: anchor exists (just-written), revocation absent (just-checked), σ_holder valid (just-verified), scope-subset (if sub-token), token-class permissions (per the operation kind). On PASS, the 4-gate AND substrate signs the σ ensemble for the operation; on FAIL, the entire transaction reverts (the SSTORE at step 3 is rolled back).

The four-step discipline closes the F-1 HARD (lazy-anchor revocation race). `CredentialAnchorRegistry.write` is implemented as a function that internally performs step 1; partner contracts cannot bypass the revocation check.

Subsequent presentations skip step 3 (the anchor already exists; the SSTORE is unnecessary). Steps 1, 2, and 4 still execute at every presentation. The discipline generalizes: any future lazy-anchor primitive in Cealis follows the same four-step order.

### §2.7 Scope-narrowing rule

Sub-tokens MUST be scope-narrowing relative to their master. Wider-scope sub-tokens are rejected at derivation time by the partner's configurator AND at presentation time by the chain-side check. Specifically:

- If `master.scope = Wildcard` (master credential), any `sub.scope` is valid (Wildcard is the universal set).
- If `master.scope = Set<SliceId>`, `sub.scope` MUST be either `Set<SliceId>` with `sub.scope ⊆ master.scope` (subset, possibly equal), OR a single SliceId from `master.scope`.

Composed cross-slice operations require multiple sub-tokens presented under the Composed condition module (§6 + §H-6); except where the master credential itself satisfies the composed predicate per F-15 disposition (master satisfies multi-slice if `slice_atomicity_allowed: true` in PDA AND `scope` covers all named slices).

### §2.8 Canonical presentation digest

The canonical presentation digest is the input that σ_holder signs at every presentation. It is computed as:

```
canonical_presentation_digest = keccak256(
    TAG_CU_CREDENTIAL_V3 ||
    credential_digest ||                  # 32 bytes
    presentation_block_hash ||            # 32 bytes — block.hash at the block of the presentation tx
    presentation_nonce ||                 # 32 bytes — chain-side anti-replay nonce
    canonical_op_tuple                    # variable — the operation being authorized: slice_id, op_kind, content_ref (if write)
)
```

Byte-exact construction deferred to S2-1 amendment. The presentation digest binds the σ_holder signature to a specific block (anti-replay across blocks), a specific operation (anti-replay across operations), and the credential being presented (anti-replay across credentials).

### §2.9 Holder-rotation discipline

When a holder rotates their holder-binding key (passkey rotation via WebAuthn re-registration, hardware-key rotation via re-binding, etc.), the rotation is recorded in the V3 PasskeyRotationLog (per S2-1 §13 — extended for non-passkey holder bindings via an analogous HolderRotationLog or a unified rotation registry per S2-2 coordinated amendment). Rotation does NOT invalidate existing master credentials; the credential's holder-binding key reference is updated, and subsequent presentations use the rotated key.

Rotation does NOT propagate to anchored sub-tokens. A sub-token's holder-binding pubkey is recorded at the sub-token's first presentation; if the holder rotates after the sub-token's first presentation, the sub-token remains valid under the original holder-binding key until TTL expiry. To enforce immediate sub-token invalidation on rotation, the holder must explicitly revoke the master.

### §2.10 PII content statement (§2)

§2 token model carries PII at multiple layers. The credential digest, the canonical presentation digest, and the sub-token derivation proof include holder-binding material (passkey public key, hardware-key public key, EOA address, or app-session pubkey). Under Breyer C-582/14 strict interpretation, these qualify as personal data when correlated with off-chain credential issuance records held by the partner.

Per-deployment passkey discipline (§2.3.1) limits cross-deployment correlation by partners. The PasskeyRotationLog is per-deployment; a subject's passkey at deployment D1 and deployment D2 are distinct credentials with distinct anchors and distinct rotation logs.

The off-chain credential structure held by the partner at issuance time (master credential pre-first-presentation) is partner-held personal data subject to GDPR Art. 4(1) treatment. Partners are responsible for the issuance-time storage; this spec defines only the on-chain anchor + chain-evaluation surfaces.

---

## §3 — PDA extensions

This section establishes the PDA field family `token_policy_config` that a partner deployment elects to enable the controlled-use profile. The field family is a new class-CATALOG PDA field family per S2-4 §5 PDA+ governance discipline; partners cannot author raw, but Cealis-internal configurator review can instantiate the fields with deployment-specific values.

### §3.1 Position in the PDA layering

S2-4 establishes two PDA layering models: PDA+ (platform configuration model, Cealis-internal) and PDA (per-deployment model, partner-elected within PDA+ constraints). The controlled-use field family lives at the PDA layer; the governance sub-classification it falls under at the PDA+ layer is **ControlledUseAccessPolicy** (a new PDA+ governance sub-classification, joining the five existing PDA+ governance sub-classifications enumerated in S2-4 §5).

Partner election of the controlled-use profile is a PDA-layer decision. Once elected, the partner's PDA carries the `token_policy_config` field family with values filled in by the Cealis-internal configurator review per S2-4's 5-stage layered verification gate.

### §3.2 `token_policy_config` field family (full enumeration)

```
token_policy_config:
  enabled: bool                                    # required; activates controlled-use profile on this PDA
  master_token_classes: [list of TokenClass]       # required; subset of §2.2 nine classes
  recommended_sub_token_max_ttl_seconds: u64       # default 300; per H-7
  sub_token_lifetime_default_seconds: u64          # default 300
  scope_field_grammar:                             # required
    allowed_forms: [SINGLE_SLICE, MULTI_SLICE_SUBSET, MASTER_WILDCARD]
    slice_atomicity_allowed: bool                  # default false; per F-15
  slice_layout:                                    # required if enabled
    slices: [list of SliceDeclaration]
    pda_slice_layout_anchor: bytes32               # computed Merkle root over slices
    evolution_policy: EvolutionPolicy              # default FROZEN_SCOPE; per F-10
  cache_policy: CachePolicy                        # default EPHEMERAL_ONLY
  recommended_client_profile: ClientProfile        # default WEB_ONESHOT; per F-13
  partner_may_strengthen_profile: bool             # default true; per F-13 renamed disposition
  web_profile_write_allowed: bool                  # default true for WEB_ONESHOT; per H-8
  audit_policy:
    stream1_retention_class: Stream1Retention      # default ART17_SHREDDABLE
    stream2_retention_class: Stream2Retention      # default ART5_ACCOUNTABILITY
    stream2_content_shape_digest_enabled: bool     # default true; per H-3
    stream2_pepper_root: bytes32                   # deployment-scoped pepper-epoch-0 root; partner-held off-chain
    stream2_cosign_gate: CosignGate                # required; per H-4
    subject_checkpoint_mode: SubjectCheckpointMode # default DISABLED; Alt-D overlay
    regulator_anchor_mode: RegulatorAnchorMode     # default DISABLED; Alt-E overlay
  revocation_mode: RevocationMode                  # default MASTER_ONLY
  emergency_elevation_policy:                      # renamed from break_glass_policy
    enabled: bool                                  # default false
    authority: [list of address]                   # required if enabled
    audit_class: STREAM2_ALWAYS_LOGGED             # forced when enabled
  first_presentation_gas_attribution: GasAttribution # default PARTNER_META_TX; per F-12
  sd_election: SDElection                          # required; MUST be DISABLED per F-9
```

#### §3.2.1 `master_token_classes`

The subset of nine token classes (§2.2) the partner activates. Partners commonly activate a subset of {Master, Temporary-read, Append-only-writer, Scoped-slice} for read-heavy deployments; high-stakes deployments add {Hardware-bound, Emergency-elevation}. One-shot tokens are activated for pharmacy and consumption-tracking deployments.

#### §3.2.2 `slice_layout.slices[]` — SliceDeclaration enumeration

Each `SliceDeclaration` carries:
- `slice_id` (32 bytes — unique per PDA)
- `slice_label` (string — UI-only, no normative semantic)
- `schema_hash` (32 bytes — per §1.6)
- `write_authority_matrix` (list of `(TokenClass, allowed_op_kinds)` tuples)
- `read_authority_matrix` (list of `(TokenClass, allowed_scope_predicates)` tuples)
- `slice_dek_policy` (DekPolicy enum: `PER_SLICE_DEK` for slice-shred independence; `PER_PDA_DEK` for atomic-shred across slices)

The slice layout is a tree-structured set of slices. Per-slice DEK independence (B-3 winner) enables slice-shred without cross-slice DEK destruction.

#### §3.2.3 `evolution_policy` — FROZEN_SCOPE | REISSUE_REQUIRED (F-10 normative)

`FROZEN_SCOPE` (default): existing master credentials whose `scope` references a slice that has evolved continue to cover the legacy slice-id under the legacy slice definition forever. Slice-id collisions across evolutions are FORBIDDEN — `slice_topology_evolution_authority` (Cealis-internal-only) enforces that new slice-ids never reuse retired slice-ids. Legacy credentials effectively become read-only-historical as new writes go to the renamed/successor slice; the legacy slice remains valid for read-against-frozen-content.

`REISSUE_REQUIRED`: existing master credentials whose `scope` references a slice that has evolved become inert; holders must request new credentials under the new slice layout. Partners electing this policy accept the operational burden of credential re-issuance.

The default `FROZEN_SCOPE` preserves read-continuity for existing credentials; partners electing `REISSUE_REQUIRED` accept the operational burden in exchange for write-continuity across slice topology evolutions.

#### §3.2.4 `recommended_client_profile` and `partner_may_strengthen_profile` (F-13 normative)

`recommended_client_profile ∈ {WEB_ONESHOT, NATIVE_SESSION, NATIVE_HEADLESS}` — set by Cealis-internal configurator review based on the deployment archetype. Web-oneshot for pharmacy / consumption-tracking; native-session for doctor / long-form sessions; native-headless for sealed-team-codebase / CI workflows.

`partner_may_strengthen_profile: bool` — when true (default), the partner may force a stronger client profile than the Cealis-recommended profile (e.g., force `NATIVE_SESSION` where Cealis recommended `WEB_ONESHOT`). "Strengthen" means "wipe-assurance is stronger or equal; integration friction is greater or equal." The partner may NOT force a profile with weaker wipe assurance than Cealis recommendation; `partner_may_strengthen_profile = false` locks the partner to the Cealis-recommended profile.

The semantics are explicit: stronger ≡ greater wipe assurance ≡ tighter cache constraints ≡ less integration flexibility. The synthesis predecessor field name `partner_may_narrow_profile` was ambiguous (per F-13); the renamed field name removes the ambiguity.

#### §3.2.5 `web_profile_write_allowed` (H-8 normative)

Default true for `WEB_ONESHOT` profile, partner-narrowable to false for read-only deployments. Activates the §7 web SDK write path with its normative 100ms wipe + cache constraints. Inactive when `recommended_client_profile = NATIVE_*`.

#### §3.2.6 `audit_policy` field family (H-3, H-4, F-14, Alt-D, Alt-E)

`stream1_retention_class ∈ {ART17_SHREDDABLE, DEEPER_ERASURE_OPT_IN, PDA_DEFAULT}` — Stream 1 retention. `ART17_SHREDDABLE` (default) means Stream 1 entries shred with the underlying data on Art. 17 fire. `DEEPER_ERASURE_OPT_IN` means Stream 1 shreds even more aggressively (e.g., includes erasure of the slice-shred audit entries themselves); discouraged for partners with regulator-audit exposure (see F-19 + §10).

`stream2_retention_class ∈ {ART5_ACCOUNTABILITY, DEEPER_ERASURE_OPT_IN}` — Stream 2 retention. `ART5_ACCOUNTABILITY` (default) means Stream 2 retained per Art. 5(2)/(f) for accountability. `DEEPER_ERASURE_OPT_IN` means Stream 2 also crypto-shreds via separate audit-key destruction; **DEFAULT-FORBIDDEN at configurator review** per F-19 normative. Counsel sign-off gate is required for any partner request to enable `DEEPER_ERASURE_OPT_IN` for Stream 2.

`stream2_content_shape_digest_enabled: bool` — DEFAULT TRUE for any partner subject to regulator audit. The digest is HMAC keyed under deployment-scoped audit-pepper, over `(schema_hash || scope_subset || op_kind)`, NEVER over content. After Stream 1 shred destroys the data + access events, Stream 2 retains the content-shape digest so the partner can prove "an op of shape S occurred against this PDA at time T by holder H" without ever recovering content. Partners may set FALSE for max-subject-privacy deployments at their regulatory risk.

`stream2_pepper_root: bytes32` — the root commitment to the deployment-scoped audit-pepper at pepper-epoch-0. Per F-14, the pepper is keyed by `(deployment_id, pepper_epoch_number)`; rotation creates a new epoch and partners retain past pepper-epochs for the retention window. The Merkle anchor commits to `pepper_epoch_number`. Blast radius of a single pepper-epoch leak is bounded: linkability of one pepper-epoch's Stream 2 events; partners rotate to limit exposure.

`stream2_cosign_gate: CosignGate` — required; per §1.9 + H-4. The PDA-selected gate that countersigns Stream 2 entries alongside G4. Cross-vendor-disjoint with G4 by construction.

`subject_checkpoint_mode ∈ {DISABLED, OPT_IN, MANDATORY}` — Alt-D overlay. When `OPT_IN` or `MANDATORY`, subjects receive a periodic witness of their Stream 2 entries via a partner-side delivery (off-chain signed delivery; subject can verify against the Stream 2 Merkle anchor). Provides subject-side visibility into access patterns.

`regulator_anchor_mode ∈ {DISABLED, OPT_IN, MANDATORY}` — Alt-E overlay. When `OPT_IN` or `MANDATORY`, Stream 2 Merkle anchors are co-published to a regulator-readable channel (regulator-held anchor mirror) on a batched cadence. Provides regulator-side verifiability of audit history.

#### §3.2.7 `revocation_mode` (B-5 + H-1)

`revocation_mode ∈ {MASTER_ONLY, MASTER_AND_SUB_CRL}`:

`MASTER_ONLY` (default): only master credentials have on-chain revocation entries (`MasterTokenRevocationRegistry`). Sub-tokens cannot be revoked individually; they expire via TTL or fail via master-revocation propagation.

`MASTER_AND_SUB_CRL`: high-stakes deployments wanting per-sub-token CRL. Opt-in registry `TokenRevocationRegistry` records sub-token-specific revocations. Per-sub-token revocation latency is per-block (chain-write); pattern for deployments where a revoked sub-token must be killed immediately even before TTL expires.

#### §3.2.8 `emergency_elevation_policy` (F-COS-6, HL7 BTG alignment)

```
emergency_elevation_policy:
  enabled: bool                                  # default false
  authority: [list of address]                   # required if enabled — authorities that may activate emergency-elevation tokens
  audit_class: STREAM2_ALWAYS_LOGGED             # forced when enabled — every emergency-elevation presentation produces a Stream 2 entry regardless of stream1_retention_class
```

The emergency-elevation policy is the Cealis-internal mechanism for HL7 break-the-glass (BTG) convention. Partners may externally label the operational artifact "BTG" for clinician-facing UI alignment; the spec-internal label stays `emergency_elevation_policy`.

#### §3.2.9 `first_presentation_gas_attribution` (F-12 normative)

`first_presentation_gas_attribution ∈ {HOLDER, PARTNER_META_TX, SUBJECT, NONE_CHAIN_SUBSIDIZED}` — DEFAULT `PARTNER_META_TX`. The first-presentation transaction pays gas for the anchor SSTORE; the field declares who pays.

`PARTNER_META_TX` (default): partner relays the first-presentation transaction via a meta-tx pattern and sponsors the gas. The partner contract holds a per-credential gas budget; holders submit the presentation via a meta-tx relayer the partner runs.

`HOLDER`: holder pays the first-presentation gas directly. Returns the credential to an asset-like feel from the holder's perspective; spec consumers should warn the partner if this is selected.

`SUBJECT`: the subject (data principal) pays. Appropriate for deployments where the subject is the credential issuer (e.g., personal health record where the subject mints credentials for doctors).

`NONE_CHAIN_SUBSIDIZED`: chain subsidy from Cealis or partner via a chain-level gas-station mechanism. Specifics deferred to S2-2 amendment.

#### §3.2.10 `sd_election` — DISABLED per F-9 normative

`sd_election: SDElection` — required field; MUST be `DISABLED` for any controlled-use PDA. The S2-7 SD pipeline produces per-field Poseidon commitments + PLONK predicates at commit time; a controlled-use deployment with SD enabled is unspecified. App. C names this as `/design` fork "A21-SD-integration." Until the fork is authored and a coordinated S2-7 amendment lands, controlled-use × SD is forbidden at PDA validation time; the configurator REJECTS any PDA with `sd_election != DISABLED` AND `token_policy_config.enabled = true`.

### §3.3 PDA+ governance sub-classification — ControlledUseAccessPolicy

The PDA+ layer (per S2-4 §5) introduces a new governance sub-classification: **ControlledUseAccessPolicy**. This joins the five existing PDA+ governance sub-classifications.

Under ControlledUseAccessPolicy:
- The `token_policy_config` field family is class-CATALOG (Cealis-internal review required to instantiate; partner cannot author raw).
- Cross-field rules from S2-4 §5 apply: scope grammar consistency with slice layout (`scope_field_grammar.allowed_forms` must be consistent with `slice_layout.slices[]` cardinality); cosign-gate consistency with G3 choice (per §1.9); cache policy consistency with client profile (web profile must not elect `ENCRYPTED_CACHE_OPT_IN`); emergency-elevation policy authority list must be non-empty if `enabled = true`.
- The 5-stage layered verification gate from S2-4 §5 applies: PDA validation, dependency validation, governance validation, security validation, deployment validation.
- The PDA+ evolution-policy semantics (S2-4 two-layer PDA evolution) apply.

### §3.4 Intent-translation flow extension

S2-4 §5 establishes an intent-translation flow from partner intent to PDA+ template instantiation. The controlled-use profile extends the intent-translation surface with the following intents:

- **"My partners need to read sensitive operating data routinely"** → ControlledUseAccessPolicy elected; recommended_client_profile per archetype; emergency-elevation policy disabled unless intent surfaces emergency access.
- **"Subjects need to control who accesses their data and for what"** → revocation_mode = `MASTER_ONLY` with subject as revocation authority; subject_checkpoint_mode = `OPT_IN`.
- **"We need court-presentable accountability of all access"** → stream2_retention_class = `ART5_ACCOUNTABILITY`; stream2_content_shape_digest_enabled = true; regulator_anchor_mode = `OPT_IN`.
- **"Some data needs to be appended but past entries are court-evidence"** → write_authority_matrix includes append-only writer tokens; evolution_policy = `FROZEN_SCOPE`; emergency_elevation_policy.enabled = false (no override of audit history).
- **"Emergency access matters more than perfect privacy"** → emergency_elevation_policy.enabled = true; authority list per deployment; subject acknowledgment in onboarding flow.

The intent-translation flow lives in the S2-4 configurator UI; this spec defines the intent-mapping table normatively.

### §3.5 Evolution policy semantics

Per F-10, evolution policy is normative at PDA+ governance level. `FROZEN_SCOPE` means LEGACY slice-id forever; `REISSUE_REQUIRED` means inert legacy credentials. Slice-id collisions across evolutions are FORBIDDEN by `slice_topology_evolution_authority` (Cealis-internal-only).

Slice layout evolution is a Cealis-internal configurator step. Partners cannot author raw slice layouts; partners cannot retire slice-ids unilaterally. The configurator review at evolution time validates: (a) no slice-id collision with retired slice-ids; (b) evolution_policy stays consistent; (c) write_authority_matrix and read_authority_matrix updates do not silently expand or contract existing token coverage in ways inconsistent with `partner_may_strengthen_profile` semantics.

### §3.6 PII content statement (§3)

§3 PDA extensions carry PII at the schema layer indirectly. The `schema_hash` references the schema definition for a slice; the schema definition typically declares the fields that will hold PII at runtime (patient name, medical record field, payment record field, M&A document field). The schema itself is NOT PII; the data conforming to the schema IS PII.

The `stream2_pepper_root` is a commitment to the deployment-scoped audit-pepper. The audit-pepper itself is partner-held off-chain; the root commitment is on-chain at PDA registration time. Under Breyer, the root commitment is not directly PII; the audit-pepper is partner-held secret used to compute Stream 2 content-shape digests.

The `emergency_elevation_policy.authority` field is a list of EVM addresses authorized to activate emergency-elevation tokens. These addresses are pseudonymous on-chain; their off-chain mapping to specific clinicians or operational actors is partner-held data subject to GDPR Art. 4(1) treatment.

---

## §4 — Write-validation gate

This section establishes the G4 Phase 2 TEE-resident write-validation gate that runs at every controlled-use write operation. The B-2 winner locks the primitive: G4 Phase 2 TEE attests the write claim; the chain independently re-verifies the policy hash against a published PDA artifact. No new staked component is introduced; the existing G4 authority registry holds the new write-attest key (`K_G4_write_attest`).

### §4.1 G4 Phase 2 TEE scope (write-validation)

The G4 Phase 2 TEE (rented commodity TEE per S2-3 §3, attested via DCAP) is the only enforcement boundary for write validation. The TEE-resident write-validation gate runs the following normative checks at every write operation:

1. **Schema conformance.** The proposed write payload, in canonical form, conforms to the slice's `schema_hash` (per §1.6). Schema-level validation runs inside the TEE; failure produces `CU_ERR_SCHEMA_VIOLATION` (§15).

2. **Scope conformance.** The presented sub-token's `scope` includes the target slice; the sub-token's class is in the slice's `write_authority_matrix` for the proposed `op_kind`. Failure produces `CU_ERR_SCOPE_OUT_OF_TOKEN` (§15).

3. **History immutability.** The proposed write does not modify existing sealed envelopes; it produces a new envelope with `slice_preceding_envelope_ref` set to the slice's latest sealed envelope ref AT WRITE-VALIDATION TIME (per §5 supersession-invariance: the ref is the original `h_commit`; supersession is walked forward via `SupersededCommitRegistry`). Failure produces `CU_ERR_HISTORY_REWRITE_ATTEMPT` (§15).

4. **Policy-allow check.** The PDA's policy admits the proposed write under the slice's `write_authority_matrix` AND the sub-token's class AND the current time (TTL not expired). Failure produces `CU_ERR_POLICY_DENIES_WRITE` (§15).

5. **Token-authorizes-this-exact-write check.** The σ_holder signature over the canonical presentation digest binds to the specific write being proposed (slice_id, op_kind, content_ref). Failure produces `CU_ERR_HOLDER_SIGNATURE_NOT_BOUND_TO_WRITE` (§15).

On all five checks PASSING, the TEE produces the write-validation attestation:

```
write_attest = sign_K_G4_write_attest(
    keccak256(
        TAG_CU_WRITE_ATTEST_V3 ||
        h_envelope_proposed ||
        slice_id ||
        actor_token_digest ||
        block_hash ||
        policy_hash
    )
)
```

The `policy_hash` is the keccak hash of the slice's authority-matrix + schema_hash + current PDA state digest. It is published to a PDA-side artifact registry (specifics deferred to S2-2 amendment per §11); the chain-side replay (§4.2) re-verifies the policy_hash independently.

The TEE never sees the write payload in plaintext outside its boundary. The G4 ingestion path (for write operations) accepts the encrypted commit ciphertext + commit AAD; the TEE decrypts inside its boundary, validates, re-encrypts under the slice DEK if needed, and seals the new envelope. **G4 sees write commit ciphertext + AAD, NEVER plaintext content outside the TEE boundary.** This is the σ-as-authorization-doctrine-consistent path.

### §4.2 On-chain policy-hash replay verification

After the TEE produces the write-validation attestation, the chain-side write transaction re-verifies the `policy_hash` against the PDA-side artifact independently of the TEE. The chain reads the PDA's current authority-matrix + schema_hash + state digest, recomputes the policy_hash, and compares against the attested `policy_hash`. Mismatch produces `CU_ERR_POLICY_HASH_REPLAY_FAIL` (§15) and rejects the write.

This is the "G4 TEE attestation + on-chain policy-hash replay" pattern (renamed from synthesis "hybrid attestation" per F-COS-2). The two-source verification means a malicious or compromised G4 TEE cannot land an attestation against an out-of-date or fabricated policy without the chain catching the mismatch.

The PDA-side artifact carrying the policy hash is stored in `PDARegistry` (per S2-2 coordinated amendment) or, if `PDARegistry` does not exist as a standalone registry today, in a PDA-bound artifact reference inside the existing `pda_root`. Resolution of this question is deferred to S2-2 amendment per §11 + §14 question 7.

### §4.3 Refusal model

G4 refusal is the existing closed 5-reason-code enum at WP §D + S2-3 §3 + flows-spec-final.md §425:
- `0x01` legal compel
- `0x02` Art. 17 erasure
- `0x03` Art. 18 freeze
- `0x04` integrity fail
- `0x05` chain mismatch

The closed enum extends to controlled-use write operations:
- `0x01` legal compel — refuse the write because the partner is under legal compulsion not to accept writes to this slice (e.g., court-ordered freeze)
- `0x02` Art. 17 — refuse the write because the subject has Art. 17 erasure pending; writes against pending-erasure PDAs are refused
- `0x03` Art. 18 — refuse the write because of an Art. 18 reveal freeze covering the slice
- `0x04` integrity fail — schema violation, policy violation, scope violation, history rewrite attempt, holder signature failure (any of §4.1 checks 1-5 fails)
- `0x05` chain mismatch — chain state seen by G4 does not match the chain state at the proposed write block (e.g., a re-org affected the slice latest sealed envelope ref between G4's read and the proposed write)

The refusal is encoded in σ_G4 as the gate refusal envelope per S2-3; the on-chain replay verification at §4.2 surfaces the refusal alongside the write transaction's rejection.

Refusal is crypto-enforced via σ_G4 absence: G4 does not sign the σ_G4 contribution, and the 4-gate AND fails, blocking the write at the gate-composition layer. This is the σ-as-authorization-doctrine-consistent halt mechanism.

### §4.4 Cross-vendor cosign for Stream 2 (H-4)

Per H-4, Stream 2 events are signed by `K_G4_audit_stream2` AND co-signed by the PDA-selected `audit_policy.stream2_cosign_gate ∈ {G2_LIT, G3_DCIPHER, G3_DRAND}`. This extends the cross-vendor disjoint mandate from the read/write path (S2-3 §3, §5) to Stream 2 audit anchoring.

The cosign-gate's signing key for Stream 2 lives in:
- For `G2_LIT`: G2 Lit V3 attested TEE; the Stream 2 cosign uses the same Lit signing authority as the read path's σ_Lit, with a domain-separated input.
- For `G3_DCIPHER`: dcipher threshold network; the cosign uses the same dcipher BLS aggregate as σ_G3, with a domain-separated input.
- For `G3_DRAND`: drand League of Entropy; the cosign uses the same drand aggregate as σ_G3.

The domain separation for the cosign input is via `TAG_CU_AUDIT_STREAM2_V3`; the cosign signs:

```
stream2_cosign_input = keccak256(
    TAG_CU_AUDIT_STREAM2_V3 ||
    stream2_merkle_root ||
    pepper_epoch_number ||
    block_hash
)
```

A single G4 TEE key compromise can no longer forge Stream 2 log roots; the attacker would need to compromise the cosign-gate's signing infrastructure in the same time window. This is the same disjoint-vendor security envelope (3-of-4 or 2-of-2-cross-vendor floor) as the read path.

Cosign-gate absence at validation time produces `CU_ERR_STREAM2_COSIGN_MISSING` (§15); the Stream 2 anchor cannot land on-chain without both signatures.

### §4.5 Two distinct G4 ingest paths

The G4 Phase 2 TEE has two distinct ingest paths under controlled-use, which the spec keeps explicit per H-5:

1. **Write-validation ingest path (§4.1).** G4 receives encrypted commit ciphertext + commit AAD. The TEE decrypts inside its boundary, runs the five checks, produces the write-validation attestation, signs Stream 2 entry, posts the new envelope to the slice DEK lifecycle. G4 sees ciphertext + AAD + (briefly, inside boundary) plaintext.

2. **Read-event ingest path (§6 + §7).** G4 receives a read-event tuple from the client SDK (the tuple carries `actor_token_digest`, `slice_id`, `op_kind=READ`, `timestamp`, `content_shape_digest`), signed by σ_holder. The TEE validates σ_holder against the anchor + revocation, counter-signs with `K_G4_audit_stream2`, and includes the entry in the next Merkle batch. **G4 sees only shape + actor, NEVER plaintext content for read events.**

The asymmetric ingest scope is a normative design discipline: writes must pass through the TEE for schema/history enforcement (the partner needs the assurance the write is valid), but reads can be client-side-decrypted because the read authorization is bound to the σ ensemble that authorized release; G4's role at read time is audit signing, not content-mediation.

### §4.6 G4AuthorityRegistry extension

The existing `G4AuthorityRegistry` (per S2-1 §10 + S2-2 §9) records the G4 authority public keys per deployment. The controlled-use profile adds two new key entries per deployment:

- `K_G4_write_attest_pubkey` — the public verification key for write-validation attestation signatures
- `K_G4_audit_stream2_pubkey` — the public verification key for Stream 2 audit-stream signing

Both are anchored in the same `G4AuthorityRegistry` (no new registry per §3 propagation table) with deployment-specific identifiers. Key rotation discipline inherits from S2-6 operational ceremonies; controlled-use does not introduce new rotation semantics.

### §4.7 PII content statement (§4)

§4 write-validation gate processes PII inside the G4 Phase 2 TEE boundary. The TEE briefly handles plaintext write payloads during the schema-conformance check; under §10 the TEE-internal handling is the controllership boundary at which Cealis is a GDPR controller for the signing-operation processing step.

The `write_attest` signed value carries the proposed envelope hash + slice_id + actor_token_digest + block_hash + policy_hash. None of these are direct PII; the envelope hash carries the data via commitment but is one-way; the actor_token_digest is pseudonymous under Breyer.

The Stream 2 cosign input carries the Stream 2 Merkle root + pepper_epoch_number + block_hash. None of these are direct PII; the Merkle root commits to Stream 2 entries which themselves carry content-shape digests (not content).

The read-event tuple G4 receives carries actor_token_digest + slice_id + op_kind + content_shape_digest + timestamp. Under Breyer, actor_token_digest is pseudonymous when correlated with off-chain issuance records; the content_shape_digest is one-way HMAC under deployment-scoped pepper; the slice_id is per-PDA non-PII.

---

## §5 — Controlled-use sealed-envelope chain

This section establishes the per-slice independent sealed-envelope chain that controlled-use uses as its storage primitive. The B-3 winner locks the model: each PDA declares its slice layout at config time; each slice is its own linear chain of sealed envelopes with `SliceLayoutRegistry` tracking the slice layout root; a per-slice `slice latest sealed envelope ref` tracks the head of each slice's chain.

The synthesis-vocabulary terms "slice head," "slice_prev_commit_ref," "parent," and "commit graph" have been renamed throughout this section to non-Git constructions per F-COS-1: "slice latest sealed envelope ref," "slice_preceding_envelope_ref," "preceding sealed envelope," and "envelope chain." The chain is not a Git repository.

### §5.1 Per-slice linear chains

Each slice defined in `token_policy_config.slice_layout.slices[]` (§3.2.2) is the root of an independent linear chain of sealed envelopes. The chain is append-only: writes produce new envelopes; existing envelopes are immutable. The chain has no branching; merge operations across slices are not supported (cross-slice atomic operations use Composed sub-token presentation per §6 + H-6, not merge envelopes).

Each sealed envelope in a slice's chain carries:
- `h_envelope` (32 bytes) — the envelope hash per §1.7
- `slice_id` (32 bytes)
- `slice_position` (u64 BE) — monotonically increasing position counter within the slice
- `slice_preceding_envelope_ref` (32 bytes) — the `h_envelope` of the preceding envelope in the same slice; zero for the slice-initial envelope
- `h_commit` (32 bytes) — the underlying S2-1 §3 commit identifier; this is what the slice latest sealed envelope ref tracks
- Standard commit fields per S2-1 §3 (commit_AAD, AEAD ciphertext, σ ensemble, etc.)

### §5.2 SliceLayoutRegistry and pda_slice_layout_anchor

The on-chain `SliceLayoutRegistry` (renamed from synthesis predecessor `SliceHeadRegistry`; see naming note below) maps `(pda_root, slice_id) → slice_latest_sealed_envelope_ref + slice_position_counter`. This is a class-CRYPTO registry per the V3 registry class discipline.

**Naming note on SliceLayoutRegistry vs SliceHeadRegistry:** the synthesis predecessor used `SliceHeadRegistry` to denote the registry mapping per-slice head pointers. Per F-COS-1 rename discipline, "head" is Git vocabulary. This spec uses `SliceLayoutRegistry` for the registry name (consistent with `pda_slice_layout_anchor` renamed from `slice_topology_root` per F-COS-4). The per-slice latest sealed envelope ref is the value stored at each `(pda_root, slice_id)` key; "slice layout" is the per-PDA collection of (slice_id, latest_sealed_envelope_ref) tuples.

The `pda_slice_layout_anchor` is a periodic Merkle root over the SliceLayoutRegistry entries for a given PDA. The anchor is committed to on-chain at slice topology evolution checkpoints (per §3.5) and at periodic cadence (per S2-6 operational ceremonies). The anchor provides a single 32-byte commitment to the entire per-PDA slice layout, enabling efficient verification of slice membership.

### §5.3 Supersession-invariant slice latest sealed envelope ref rule (H-2 normative)

The entry in `SliceLayoutRegistry[(pda_root, slice_id)]` is the ORIGINAL-GENERATION `h_commit` of the slice's latest sealed envelope. Re-key ceremonies (per S2-1 §15) write `h_commit_vN` into the existing `SupersededCommitRegistry` (per S2-1 §15.3) but DO NOT touch `SliceLayoutRegistry`. **Re-key never modifies SliceLayoutRegistry; the slice latest sealed envelope ref is supersession-invariant.**

When a downstream consumer (writer, reader, write-validation TEE, audit-stream signer) needs the active commit for a slice:
1. Read the slice latest sealed envelope ref from `SliceLayoutRegistry[(pda_root, slice_id)]`.
2. Walk `SupersededCommitRegistry` forward from the original ref to the current generation.
3. Bind σ against the current generation while storing `slice_preceding_envelope_ref` against the original ref.

This composes cleanly with the re-key AEAD invariant (S2-1 §6 IB-3): the payload AEAD AAD remains `commit_AAD_0` forever; re-key produces stanza-level supersession entries that downstream walks resolve.

Concurrent writer-versus-rekey case: the writer's TEE write-validation reads `SliceLayoutRegistry(slice_A) → h_commit_42` (original). The re-key ceremony lands `h_commit_42_v2` in `SupersededCommitRegistry` afterward. The writer's new commit `h_commit_43` succeeds `h_commit_42` in the slice chain with `slice_preceding_envelope_ref = h_commit_42` (original). Later re-key of `h_commit_43` produces `h_commit_43_v2` in `SupersededCommitRegistry`. References stay stable; supersession is observable but does not break references. Test vectors for this composition are in App. B.

### §5.4 commit_AAD field additions

The S2-1 §4 `commit_AAD` structure carries the fields necessary to bind a commit to its cryptographic context. Controlled-use adds three fixed-width fields:

- `slice_id` (32 bytes) — the slice this commit belongs to
- `slice_preceding_envelope_ref` (32 bytes) — the `h_envelope` of the preceding envelope in the same slice; zero for slice-initial
- `slice_position` (u64 BE) — monotonically increasing position counter within the slice

These three fields are appended to `commit_AAD` at a coordinated S2-1 amendment per §11. The amendment bumps `commit_version` from `0x0302` to `0x0303`. Controlled-use PDAs MUST use `0x0303`; non-controlled-use PDAs continue on `0x0302`.

### §5.5 Re-key composition rules

The crypto-aging re-key ceremony (S2-1 §15) operates on commits within a slice without breaking slice chain integrity:

- Re-key produces stanza-level supersession entries in `SupersededCommitRegistry`.
- Re-key does NOT touch `SliceLayoutRegistry`.
- Re-key does NOT modify `slice_preceding_envelope_ref` in any existing commit's AAD (commit_AAD is immutable; supersession is a separate registry layer).
- A writer concurrent with re-key reads the slice latest sealed envelope ref from `SliceLayoutRegistry`, validates against current σ-generation via `SupersededCommitRegistry` walk, and produces a new commit whose AAD references the original ref.

Re-key composition with controlled-use is normative; spec consumers MUST honor the supersession-invariance discipline.

### §5.6 Two-axis shred composition (B-3 × B-6 × shred design)

The two-axis on-chain shred guardrail (authority axis × condition axis, with mandatory `NOT post_challenge_reveal_in_progress`) composes with controlled-use slice-shred:

- **Slice-shred** is shred against the slice latest sealed envelope ref + the slice's DEK family (if `slice_dek_policy = PER_SLICE_DEK`) + Stream 1 entries DEK-keyed under the same family. The on-chain authority axis (subject / joint / operator / timelock / disabled) and condition axis (Mode P predicate / Mode F FSM) apply per slice.
- **PDA-shred** is shred against all slices in the PDA simultaneously when `slice_dek_policy = PER_PDA_DEK` is elected.
- The mandatory `NOT post_challenge_reveal_in_progress` guardrail extends to controlled-use writes: a write-mid-shred race is foreclosed because slice-shred cannot land while a gate-signing window is open on the slice.

The two-axis shred composition is normative. Spec consumers MUST NOT introduce shred paths that race a gate-signing window or that bypass the authority/condition axes for controlled-use slices.

### §5.7 Topology evolution policy

Per §3.5 + F-10, slice layout evolution is a Cealis-internal configurator step. The `evolution_policy` field on `token_policy_config.slice_layout` is normative:

- `FROZEN_SCOPE` (default): legacy slice-ids remain valid; existing credentials cover the legacy slice forever; slice-id collisions across evolutions FORBIDDEN.
- `REISSUE_REQUIRED`: legacy credentials become inert at slice layout evolution; partners accept the operational burden of re-issuance.

Slice layout evolution updates the `pda_slice_layout_anchor` Merkle root. The anchor's update is timelock-gated per PDA+ governance (S2-2 coordinated amendment); partners cannot evolve slice layouts unilaterally or instantaneously.

### §5.8 PII content statement (§5)

§5 controlled-use sealed-envelope chain processes PII at the envelope content layer. Each envelope's AEAD ciphertext contains slice-content (medical record fields, prescription text, M&A document text, sealed-code-repo file content, etc.) which is PII or sensitive operating data by deployment archetype.

The `slice_id`, `slice_preceding_envelope_ref`, `slice_position`, and `pda_slice_layout_anchor` are non-PII operational metadata; they carry no direct or indirect personal data linkage independent of the deployment context.

The `SliceLayoutRegistry` entries are non-PII; they carry per-PDA per-slice operational state.

Stream 1 entries (DEK-keyed audit events) shred with the slice's DEK on Art. 17 erasure; Stream 2 entries (audit-keyed, content-shape) retain across Art. 17 per §10.

---

## §6 — Reveal flow under PresentedTokenCondition

This section establishes the normative ten-step reveal flow when the ConditionEngine evaluates a PresentedTokenCondition module. The flow covers both read paths and write paths; the two paths diverge at step 7 (write-validation TEE vs read-event-ingest). Composition with other condition modules under H-6 is normative.

### §6.1 The 10-step normative flow

For every controlled-use operation (read OR write), the chain-side transaction executes the following ten-step flow:

**Step 1 — Anchor presence check.**
- IF first-presentation of this credential: proceed to Step 2 (revocation check first per A22; anchor write happens at Step 4).
- ELSE: SLOAD `CredentialAnchorRegistry[H(credential_digest)]`; if absent, REVERT with `CU_ERR_ANCHOR_NOT_FOUND` (§15).

**Step 2 — Revocation check.**
- For master credentials: SLOAD `MasterTokenRevocationRegistry[H(master_credential_digest)]`. If `revocation_timestamp != 0`, REVERT with `CU_ERR_REVOKED_MASTER` (§15).
- For sub-tokens: SLOAD `MasterTokenRevocationRegistry[H(master_credential_digest)]` (the master's revocation). If revoked, REVERT. ADDITIONALLY: if `revocation_mode = MASTER_AND_SUB_CRL`, SLOAD `TokenRevocationRegistry[H(sub_token_digest)]`; if revoked, REVERT.

**Step 3 — σ_holder verification over canonical presentation digest.**
- Verify σ_holder against the holder-binding pubkey recorded in the credential's anchor (for sub-tokens, the sub-token's holder-binding pubkey).
- For first-presentation: the holder-binding pubkey comes from the credential's off-chain issuance structure; verification proceeds against the in-tx-presented pubkey.
- Failure produces `CU_ERR_INVALID_HOLDER_SIGNATURE` (§15).

**Step 4 — Anchor SSTORE (first-presentation only).**
- For first-presentation: SSTORE `CredentialAnchorRegistry[H(credential_digest)] = (block.number, block.timestamp, holder_binding_pubkey_ref)`.
- For subsequent presentations: skipped.

**Step 5 — PresentedTokenCondition module evaluation.**
- The 10th ConditionEngine module evaluates:
  - Anchor exists (Step 1 / Step 4).
  - Revocation absent (Step 2).
  - σ_holder valid (Step 3).
  - Scope conformance (for sub-tokens: scope ⊆ master.scope AND scope covers the operation's target slice).
  - Token-class permissions (the operation kind is in the slice's `write_authority_matrix` or `read_authority_matrix` for the token's class).
  - TTL not expired (for sub-tokens).
  - Composition with other condition modules (H-6 matrix): per the matrix, fire the bound conditions.
- Failure produces a specific error per the failed sub-check.

**Step 6 — 4-gate AND substrate σ ensemble collection.**
- On PresentedTokenCondition PASS, the ConditionEngine emits `RevealAuthorized` for read or `WriteAuthorized` for write.
- The 4-gate AND substrate collects σ_Lit (G2), σ_G3, σ_G4 per S2-3 §3. For controlled-use read: σ_G4 attests at the audit-signing scope; for controlled-use write: σ_G4 attests at the write-validation scope.
- Cross-vendor disjoint mandate from S2-3 applies; failure of any gate produces the gate-specific σ_G4 refusal envelope (§4.3) or σ_Lit / σ_G3 failure per S2-3.

**Step 7 — Path split (READ vs WRITE).**
- IF op_kind ∈ {READ, COMPOSED_READ}: proceed to Step 7-R (read-event ingest path).
- IF op_kind ∈ {WRITE, COMPOSED_WRITE}: proceed to Step 7-W (write-validation TEE path).

**Step 7-R — Read-event ingest path (per H-5).**
- Client SDK decrypts via WebCrypto / native crypto locally (no plaintext to G4).
- Client SDK produces the read-event tuple `(actor_token_digest, slice_id, op_kind=READ, timestamp, content_shape_digest)` and signs with σ_holder.
- Client posts to thin G4 ingest API.
- G4 validates σ_holder against anchor + revocation; counter-signs with `K_G4_audit_stream2`.
- Cosign-gate (per §1.9, §4.4) co-signs the Stream 2 entry tuple.
- Stream 2 entry is added to the next Merkle batch; the batch root anchors on-chain on flush cadence.

**Step 7-W — Write-validation TEE path (per §4).**
- Client posts the encrypted commit ciphertext + commit AAD to G4 Phase 2 TEE.
- TEE decrypts inside boundary, runs §4.1 five-check validation.
- TEE produces `write_attest` (§4.1).
- TEE counter-signs Stream 2 entry with `K_G4_audit_stream2`; cosign-gate co-signs.
- Stream 2 entry is added to the next Merkle batch.

**Step 8 — Audit emission (Stream 1).**
- For both paths, Stream 1 (data-event, DEK-keyed) entry is produced. For read: Stream 1 records the read event under the slice's DEK; for write: Stream 1 records the write event under the slice's DEK.
- Stream 1 is encrypted under the slice's DEK; it shreds with the data on Art. 17 fire (§5.6, §10).

**Step 9 — Seal new envelope (write path only) OR deliver decrypted slice (read path only).**
- For write: the TEE seals the new envelope per §5.1, writes the new envelope to off-chain ciphertext storage, and updates `SliceLayoutRegistry[(pda_root, slice_id)]` to point at the new envelope's `h_commit`.
- For read: the σ ensemble derives the per-stanza wrap-decap; the recipient combiner produces the cleartext slice content via S2-3 combiner SDK.

**Step 10 — On-chain emission.**
- `RevealAuthorized` (read) or `WriteAuthorized` (write) event emitted on-chain.
- Stream 2 batch flush emits the new Stream 2 Merkle root anchor (on flush cadence per PDA configuration).

### §6.2 Read path vs write path explicit

The 10-step flow above carries two distinct paths after step 6:

**Read path (Step 7-R):**
- G4 sees only event-shape (actor_token_digest, slice_id, op_kind=READ, timestamp, content_shape_digest) + σ_holder signature.
- G4 NEVER sees plaintext content.
- Client SDK is the trust root for "what plaintext did I see?" — but the chain authorization at Step 5 + Step 6 means the read was an authorized presentation.
- Stream 1 records the read with the slice DEK; Stream 2 records the read-event-shape with the cosign-gate signature.

**Write path (Step 7-W):**
- G4 sees encrypted commit ciphertext + commit AAD.
- G4 briefly sees plaintext content inside the TEE boundary during schema validation.
- G4 produces `write_attest`; chain re-verifies policy_hash independently (§4.2).
- Stream 1 records the write with the slice DEK; Stream 2 records the write-event-shape with the cosign-gate signature.

The asymmetric ingest scope reflects the asymmetric trust requirements: writes need schema/scope/history enforcement (the partner needs assurance the write is valid), reads need authorization-binding (the chain ensures the read was authorized; the recipient holds the bytes per H-7 time-of-check / time-of-use boundary).

### §6.3 Composition under H-6 matrix

The composition-compatibility matrix from H-6 is normative at PresentedTokenCondition module evaluation:

| Other module | Composition status | Binding rule |
|---|---|---|
| PaymentObligation | composes-cleanly | block-timestamp lock at PresentedTokenCondition evaluation start |
| TimeLock | composes-cleanly | same (block-timestamp lock at start) |
| SubjectInitiated | composes-cleanly | σ_subject required alongside σ_holder |
| HeartbeatMissed | requires-additional-binding | `block.timestamp` and `HeartbeatMissed.lastBeat` locked at PresentedTokenCondition evaluation start; subsequent beats within the same tx do not retroactively validate |
| OracleAttestation | requires-additional-binding | oracle reading consumed at PresentedTokenCondition start; mid-tx oracle update ignored |
| MultiPartySignal | composes-cleanly | all required signals captured at PresentedTokenCondition start |
| DeadManSwitch | **FORBIDDEN** | PresentedTokenCondition requires σ_holder (proof of life); DeadManSwitch fires on holder absence (proof of death). Logically self-canceling per design-capture A24. If a deployment needs "trustee acts on behalf of incapacitated subject," use SubjectInitiated(trustee_passkey) + ConsentGate instead. |
| ConsentGate | composes-cleanly | consent token snapshotted at PresentedTokenCondition start; revocation mid-tx aborts pending writes but does not unread completed reads (per H-7) |
| Composed (recursive) | composes-cleanly (recursive) | for Composed-of-Composed, evaluation strictly tree-walks; one PresentedTokenCondition sub-condition per leaf |

The PDA configurator REJECTS DeadManSwitch + PresentedTokenCondition composition at PDA validation time per §3.3 ControlledUseAccessPolicy cross-field rules. This is enforced before deployment; mis-composition is foreclosed at configuration, not discovered at runtime.

For composed condition modules, the audit-log emits ONE Stream 1 entry (data-event for the underlying op) and ONE Stream 2 entry (metadata-event noting which composed condition fired, with content-shape digest reflecting the composition predicate hash). Composed conditions are not double-logged.

### §6.4 Cross-slice composed presentation

A logical "cross-slice operation" (doctor reads `slice_diagnosis` AND writes to `slice_prescription` in one logical action) requires presenting TWO sub-tokens (one per slice) under a Composed condition, OR presenting the master credential where `slice_atomicity_allowed: true` in PDA AND the master's scope covers all named slices (per F-15 + §2.7).

Each sub-token presentation in the cross-slice composition incurs the §6.1 ten-step flow individually; the Composed module aggregates the per-sub-token PresentedTokenCondition results. Audit-log: ONE Stream 1 entry per affected slice, ONE Stream 2 entry per affected slice, with the Composed predicate hash embedded in each Stream 2 entry's content-shape digest.

Cross-slice composed gas cost is non-trivial; volume modeling is deferred to App. C + `/design` fork "A21-batched-presentation" per §14 + F-11.

### §6.5 PII content statement (§6)

§6 reveal flow processes PII at multiple layers. The encrypted slice content is PII or sensitive operating data by deployment archetype; the read path delivers PII cleartext to the recipient; the write path briefly handles PII plaintext inside the G4 TEE boundary.

The σ_holder signatures, the canonical presentation digests, the actor token digests, and the credential anchors are pseudonymous under Breyer; their correlation with off-chain credential issuance records by the partner constitutes personal data processing.

The Stream 1 entries carry PII (data-event records under the slice DEK); Stream 2 entries carry pseudonymous metadata (event-shape under deployment-scoped audit-pepper).

Per S2-1 §13.10.1 Breyer cross-domain framing, the spec treats holder-binding identifiers as personal data when partner-held correlation is feasible; the per-deployment passkey discipline (§2.3.1) limits cross-deployment correlation.

---

## §7 — Client SDK contract and reference client architecture

This section establishes the client-side surface for controlled-use deployments. The B-4 winner locks the model: a hybrid web + native SDK sharing a Rust core, with PDA-bound recommended_client_profile selecting which surface is appropriate, with wipe-by-default normative discipline and explicit OS-residual catalog. The client is a thin helper, not a fortress.

### §7.1 Hybrid web + native split

Two SDK targets share a Rust core:

- **Web SDK (`@cealis/controlled-use-web`)** — JavaScript/TypeScript wrapper around the Rust core compiled to WebAssembly. Targets browsers; integrates via the partner's web app. Uses WebAuthn for passkey-bound presentations, WebCrypto for decryption, IndexedDB / sessionStorage / memory for transient state (with strict constraints per §7.4). Default for `WEB_ONESHOT` profile.

- **Native SDK (`@cealis/controlled-use-native`)** — native library wrapping the Rust core. Targets desktop and mobile applications; integrates via the partner's native app. Uses platform authenticator APIs (Touch ID / Face ID / Windows Hello) for passkey-bound presentations, OS Keychain / Keystore for credential storage, zeroize discipline for in-memory secrets. Default for `NATIVE_SESSION` and `NATIVE_HEADLESS` profiles.

The Rust core owns the cache, the credential storage, the σ_holder signing flow, and the read/write event tuple production. The platform shells (JavaScript wrapper for web; native wrapper for native) expose only:
- `present_token(credential, op_descriptor) → presentation_result`
- `query(slice_id, ...) → encrypted_slice_data`
- `write_pending_payload(payload) → write_result`

Per F-17 normative: the Rust core owns the cache; the platform shell cannot bypass cache invalidation. Partners cannot manipulate cache via FFI or reflection; a lint tool (specifics deferred to S2-6 amendment per §11) checks partner integrations for FFI cache manipulation.

### §7.2 PDA-binding via recommended_client_profile

The PDA's `recommended_client_profile ∈ {WEB_ONESHOT, NATIVE_SESSION, NATIVE_HEADLESS}` (per §3.2.4) binds the client SDK behavior:

- `WEB_ONESHOT`: web SDK with one-shot read flows + one-shot write flows (per H-8). No persistent cache; ephemeral sessionStorage only; mandatory 100ms wipe of write-pending payload.
- `NATIVE_SESSION`: native SDK with long-form session flows. Encrypted cache mode allowed (encrypted under session-derived key; cleared on session close). Suitable for doctor / consultation workflows.
- `NATIVE_HEADLESS`: native SDK without UI (server-side or daemon use). Token presentation via headless authenticator (hardware key or app-issued session capability per §2.3); cache discipline per partner's daemon lifecycle. Suitable for sealed-team-codebase CI workflows.

Partners electing `partner_may_strengthen_profile: true` may force a stronger client profile (e.g., `NATIVE_SESSION` where Cealis recommended `WEB_ONESHOT`); they may NOT force a weaker profile (e.g., `WEB_ONESHOT` where Cealis recommended `NATIVE_SESSION`).

### §7.3 Wipe-by-default normative discipline

The client SDK enforces wipe-by-default discipline across all profiles. The Rust core owns the cache and the credential storage; the platform shell cannot bypass wipe.

**General rules:**
- Credential material (master credentials, sub-tokens, σ_holder signing material) is held in memory only during the active operation. On operation completion, the Rust core zeroize's the memory region.
- Decrypted slice content is held in memory only during display/use. On session close or window close, the Rust core zeroize's the memory region.
- Persistent storage of credential material is partner-elected via PDA `cache_policy`; default is `EPHEMERAL_ONLY` (no persistent storage). Partners electing `ENCRYPTED_CACHE_OPT_IN` accept a documented trust trade.

**Web SDK specific (§7.4):** §7.4 normativizes the 100ms write-pending wipe, the storage forbiddens, and the cache mode mutex.

**Native SDK specific:**
- Credentials stored in OS Keychain (macOS) / Keystore (Android) / Credential Manager (Windows iOS Keychain) on long-form sessions.
- Decrypted slice content held in zeroize-able buffers; explicit zeroize on session close.
- Process suspension (mobile background) triggers immediate wipe of decrypted slice content; re-authentication required on foreground resume.

### §7.4 Web SDK normative requirements (H-8)

Per H-8, the web SDK supports writes for one-shot operations under the following normative requirements:

1. **100ms write-pending wipe.** Web SDK clears the write-pending payload from JS memory + closes any IndexedDB / sessionStorage handles within **100ms** of TEE write-acknowledgment-or-rejection. The 100ms window is normative; implementations exceeding this window fail conformance.

2. **No cache mode during write-pending.** Web SDK MUST refuse to enter encrypted-cache mode while a write is pending. No overlap of write-state and persistence-state; the mutex is normative.

3. **Storage forbiddens.** Web SDK MUST NOT use:
   - `localStorage` (any use is forbidden)
   - Persistent IndexedDB (any use beyond ephemeral session-scoped is forbidden)
   - Service Worker Cache API (any use is forbidden)
   - Allowed storage: in-memory + ephemeral sessionStorage only

4. **`web_profile_write_allowed: bool` (PDA field).** DEFAULT TRUE for `WEB_ONESHOT` profile. Partner-narrowable to FALSE for read-only deployments (e.g., regulator-audit read-only access).

5. **OS-layer residuals enumerated.** Per F-16 + §7.5, the web SDK documents OS-layer residuals as known limitations.

### §7.5 OS-layer residuals catalog (F-16 normative)

The client SDK wipe claim is bounded by OS-layer behavior. The following residuals are explicitly named as OUTSIDE SDK control:

- **Browser tab suspension snapshot.** Mobile Safari and Chrome may deep-freeze suspended tabs, including their memory contents. Tab restoration restores the suspended state. The SDK cannot prevent this; spec consumers should warn web users to close tabs entirely (not just background) for sensitive sessions.
- **OS swap / pagefile.** Windows pagefile, macOS encrypted swap, and Linux swap may persist process memory to disk. The encryption is system-wide; if disk is captured the swap is a forensic artifact. SDK uses platform APIs to discourage swap-out of sensitive pages but cannot guarantee.
- **Android memory compression.** Android may memory-compress process pages including zeroize'd regions; the compressed copy survives in compressed memory until reclaimed. The SDK cannot intercept memory compression.
- **Compression / tab-suspension snapshot.** Browser tab suspension on mobile may serialize memory contents to a snapshot for restore.
- **Pagefile recovery via forensic disk imaging.** Disk-level forensics may recover swap / pagefile contents post-session-close.

The honest wipe claim per §10 + WP §K becomes: "no key material remains in addressable process memory or in keychain after session close; OS-level persistence in compressed/swapped/snapshotted memory is outside SDK control."

### §7.6 SDK partner usage agreement / banned-claims contract

The partner's integration of the SDK is governed by a partner usage agreement that includes a banned-claims contract:

- Partners MAY NOT externally claim "Cealis client prevents authorized recipients from extracting data once displayed."
- Partners MAY NOT externally claim "Cealis client is a secure container / sandbox / DRM."
- Partners MAY claim "Cealis client enforces scope, schema, and history immutability on writes via TEE."
- Partners MAY claim "Cealis client provides ephemeral-by-default session keys with explicit user-opt-in encrypted cache."
- Partners MAY claim "Cealis client wipes credential material and decrypted content on session close; OS-level residuals named in documentation."

The banned-claims contract propagates the WP §K discipline to partner deployments. Violation by a partner is a contract breach; remediation includes partner correction notice and (in extreme cases) PDA suspension.

### §7.7 Dual-validation discipline (normative)

Client-side schema validation is UX, not enforcement. The Rust core runs schema validation client-side before posting writes to G4; this provides fast feedback to users (rejected writes before TEE round-trip). The TEE-side write-validation gate (§4) is the only security boundary; the client cannot be relied on as a gate.

This split is binding for any future implementer: the client may never be relied on as a gate, the TEE schema check is the security boundary. Spec consumers who treat client-side validation as security commit a Rule 47 / Rule 33 violation.

### §7.8 Reference client architecture

For deployments without partner-side UI integration, Cealis ships a reference client. The reference client uses the Rust core directly with a default UI shell (Tauri-based for desktop, React Native for mobile). The reference client is a deployment convenience, not a mandatory artifact; partners may use the SDK in their own UIs.

The reference client honors the same wipe-by-default + storage-forbiddens + 100ms write-pending wipe discipline as partner-integrated deployments.

### §7.9 PII content statement (§7)

§7 client SDK processes PII at the decrypted slice content layer (during display/use), at the credential material layer (during signing), and at the write payload layer (during one-shot writes). All PII is held in memory only during the active operation; wipe discipline limits the persistence window.

The OS-layer residuals enumerated in §7.5 represent the boundary of SDK PII protection; PII may transiently persist in compressed memory, swap, pagefile, or tab-suspension snapshots after session close. The honest wipe claim is bounded by OS behavior.

The client SDK does NOT transmit plaintext PII to G4 for read events; the read-event tuple G4 receives carries content-shape digest only (per §6.1 Step 7-R).

---

## §8 — Token revocation

This section establishes the revocation primitives for master credentials and sub-tokens. The B-5 winner locks the model: chain-anchored irreversible master revocation; off-chain TTL-derived sub-tokens that die at master revocation OR TTL expiry; opt-in per-sub-token CRL for high-stakes deployments.

### §8.1 MasterTokenRevocationRegistry — per-master irreversible

`MasterTokenRevocationRegistry` is a class-CRYPTO on-chain registry mapping `H(master_credential_digest) → (revocation_timestamp, revoker_authority_address)`. Discipline:

- Revocation is irreversible at the crypto layer. Once written, the entry cannot be cleared. This matches `DisclosureRevocationRegistry` discipline from S2-7 (per BP-SD-3).
- The `revoker_authority_address` is the address that submitted the revocation transaction. Authority validation is enforced by the registry's write function against the PDA's revocation-authority list.
- Non-revoked masters have no entry (or an entry with `revocation_timestamp = 0` sentinel; final encoding choice deferred to S2-2 amendment).
- Revocation is read at every presentation (Step 2 of §6.1 ten-step flow) — for both master and sub-token presentations.

### §8.2 Sub-token TTL-derivation kills sub-tokens on master revoke

Sub-tokens are off-chain TTL-derived from a master without any chain operation at derivation time (§2.5). Sub-token validity is bounded by:

1. The sub-token's TTL (declared at derivation time, bounded by `recommended_sub_token_max_ttl_seconds`).
2. The master's revocation status (read at every sub-token presentation).
3. The derivation proof's validity (the σ_master signature in the derivation proof must verify against the master's holder-binding key).

When a master is revoked, all sub-tokens derived from it become invalid at next presentation regardless of their TTL. The PresentedTokenCondition evaluation at Step 2 reads master revocation; revoked → REVERT.

There is no separate sub-token CRL by default; sub-tokens fail because the derivation chain back to a revoked master fails verification.

### §8.3 In-flight halt is per-operation

Master revocation propagation to in-flight operations is **per-operation, not per-session**:

- **Completed reads stay valid.** The recipient has the decrypted bytes (per H-7 time-of-check / time-of-use boundary). Revocation cannot un-read what was already read.
- **Pending writes abort at next G4 check.** A write in flight when master revocation lands fails at the G4 Phase 2 TEE write-validation gate: the gate reads master revocation, finds revoked, refuses to sign σ_G4 with refusal code `0x04` integrity fail. The on-chain replay verification (§4.2) then fails; the write transaction reverts.
- **Subsequent reads on the same session fail.** Each read produces a fresh PresentedTokenCondition evaluation (Step 5 of §6.1); revocation propagates to the next read.

The honest framing: revocation prevents FUTURE presentations; it cannot recall bytes already released. Partners SHOULD configure session-scope sub-tokens with short TTL precisely to limit the already-released window (per H-7 + §3.2 `recommended_sub_token_max_ttl_seconds`).

### §8.4 Opt-in TokenRevocationRegistry (MASTER_AND_SUB_CRL mode)

For high-stakes deployments wanting per-sub-token CRL, PDA election `revocation_mode = MASTER_AND_SUB_CRL` activates a per-deployment `TokenRevocationRegistry` (class-CRYPTO).

`TokenRevocationRegistry` maps `H(sub_token_digest) → (revocation_timestamp, revoker_authority_address)`. The PresentedTokenCondition evaluation at Step 2 reads this registry IN ADDITION to MasterTokenRevocationRegistry; revoked → REVERT.

Per-sub-token revocation latency is per-block (chain-write). Pattern for deployments where a revoked sub-token must be killed immediately even before TTL expiry (e.g., a clinician's appointment is canceled mid-consultation; revoke the consultation sub-token immediately rather than wait for TTL expiry).

### §8.5 Revocation latency + chain-confirmation depth

Master revocation propagation latency is bounded by chain confirmation depth. From transaction submission to revocation visibility:
- Submitted → mempool: ~1 second
- Mempool → block inclusion: ~2 seconds on Base mainnet
- Block inclusion → finality: ~12 blocks (~24 seconds) on Base mainnet

Between submission and finality, an in-flight presentation may read an unrevoked state and pass PresentedTokenCondition. The normative discipline:

- PresentedTokenCondition evaluation at chain-confirmation depth N (default N=12 blocks on Base mainnet, partner-configurable via PDA `revocation_confirmation_depth` field). Below depth N, the chain treats master revocation reads as "unrevoked" (preliminary state); above depth N, the revocation is finalized.
- Partners with stricter requirements may set depth N=20 or higher; partners with lower-stakes deployments may set N=1.

The chain-confirmation-depth window is a known revocation latency residual. Honest deployment messaging: "revocation propagates within ~30 seconds on Base mainnet" rather than "revocation is instantaneous."

### §8.6 Revoker authority validation

Master revocation requires authority validation. The PDA carries a `master_revocation_authority` field (subset of PDA roles per S2-2 §16 access-control roles); only addresses in this set may submit revocation transactions.

Typical authority sets by archetype:
- Health-record archetype: subject is the master_revocation_authority (subject controls their own credentials).
- Sealed-team-codebase archetype: team admin role + subject (the team admin can revoke developer credentials; developers can revoke their own credentials).
- M&A diligence archetype: deal-room owner (the partner running the diligence room).
- Pharmacy one-shot archetype: subject (patient can revoke pharmacy credentials post-fulfillment).

### §8.7 PII content statement (§8)

§8 token revocation processes pseudonymous identifiers (master_credential_digest hashes, sub-token_digest hashes) at the chain layer. Under Breyer, these qualify as personal data when correlated with off-chain credential issuance records.

The `revoker_authority_address` field is an EVM address; pseudonymous on-chain; partner-held off-chain mapping makes it personal data.

The revocation timestamp is non-PII operational metadata.

---

## §9 — Security model

This section establishes the threat catalog, cycle the seven views per internal Rule 26, names the time-of-check / time-of-use boundary explicitly (per H-7), and enumerates the residuals named at synthesis-v2.

### §9.1 Threat-model catalog

Following WP §L two-sided treatment pattern.

#### §9.1.1 Threats defended-against

| Threat | Defense mechanism | Residual |
|---|---|---|
| Unauthorized read (no valid token) | PresentedTokenCondition Step 5 + 4-gate AND Step 6 | None; chain enforcement is hard. |
| Unauthorized write (no valid token) | PresentedTokenCondition + G4 Phase 2 TEE write-validation (§4) | None; TEE enforcement is hard, chain re-verifies policy_hash. |
| Out-of-scope read (token for slice A, read attempt slice B) | Scope-subset check in §6.1 Step 5 | None; chain enforces scope. |
| Out-of-scope write | Write-validation gate scope check (§4.1) | None; TEE enforces. |
| History rewrite (write attempts to modify existing envelope) | Write-validation gate history-immutability check (§4.1) | None; TEE enforces; envelope chain is append-only. |
| Schema violation in write | Write-validation gate schema-conformance check (§4.1) | None; TEE enforces against `schema_hash`. |
| Replay across blocks | Canonical presentation digest binds to block hash (§2.8) | None; per-block binding prevents cross-block replay. |
| Replay across operations | Canonical presentation digest binds to canonical_op_tuple (§2.8) | None; per-op binding prevents cross-op replay. |
| Revocation race (sub-token presented after master revoked but before on-chain confirmation) | Chain-confirmation-depth window (§8.5); PDA-configurable | Residual: presentations within the depth window may pass; mitigated by short sub-token TTL and high N. |
| Lazy-anchor revocation race (sub-token first-presentation against revoked master) | A22 transaction-atomic discipline; revocation check FIRST then anchor SSTORE (§2.6) | None; revocation check before any state write closes F-1. |
| Cross-vendor single-key forgery of Stream 2 | Cross-vendor cosign-gate (§4.4) | None; single-TEE-key compromise cannot forge log roots. |
| Stream 1 shred destroying partner accountability | Content-shape digest in Stream 2 (§10) | Partial: partner retains shape, not content; this is the honest GDPR Art. 17 ↔ Art. 5(2) trade. |
| Slice-shred race with gate-signing window | Two-axis on-chain shred guardrail mandatory `NOT post_challenge_reveal_in_progress` (§5.6) | None; race foreclosed at gate level. |
| Ambient copies / uncontrolled persistence / silent onward transfer / unmanaged device sprawl | Client SDK wipe-by-default + storage forbiddens + 100ms write-pending wipe (§7) | Residual: OS-layer compression / swap / pagefile / tab-suspension. |
| Front-running first-presentation with forged credential | σ_holder verification + revocation check before SSTORE (§2.6) | None; forging σ_holder requires compromising holder-binding key, which is the existing security envelope. |
| DeadManSwitch × PresentedTokenCondition logical contradiction | Forbidden at PDA configurator validation per §3.3 + H-6 + design-capture A24 | None; mis-composition is foreclosed before deployment. |
| Re-key race with slice-write | SliceLayoutRegistry stores ORIGINAL h_commit; supersession walked forward (§5.3, H-2) | None; references stay stable; supersession is observable but not breaking. |
| Cache leakage across token changes in native client | Rust core owns cache; token-change event invalidates per (slice_id, token_digest); platform shell cannot bypass | Residual: partner-controlled native shell intentional misuse — lint tool checks FFI manipulation; partner contract violation. |

#### §9.1.2 Threats with partial mitigation

| Threat | Partial mitigation | Residual reason |
|---|---|---|
| Authorized recipient extracting bytes once displayed | Wipe-by-default discipline; OS-layer residuals enumerated | Per Simon's honesty clause (raw capture line 89-93): the eligible recipient is not the adversary; the spec does not defend against screenshot, photograph-of-screen, OS-level keylog, rooted-device extraction, or post-display memory dump. |
| Time-of-check / time-of-use boundary (revoked-but-already-released) | Short sub-token TTL (`recommended_sub_token_max_ttl_seconds` default 300s); per-operation halt at next G4 check | Per H-7: bytes already released under a then-valid token cannot be cryptographically recalled. Revocation prevents FUTURE presentations. |
| Off-chain credential metadata correlation | Per-deployment passkeys (§2.3.1 + F-18); deployment-scoped audit-pepper (§3.6, F-14) | Per F-20: a chain observer with off-chain lawful access (partner breach, subpoena, litigation disclosure) can post-facto correlate anchor-write events with off-chain credential metadata. Privacy claim is bounded. |
| Stream 1 shred destroying content-level write-history | Content-shape digest in Stream 2 preserves op-shape (H-3) | Partner retains "an op of shape S happened" without recovering content. Content-level write-history is genuinely unrecoverable post-shred. This is the correct legal answer; the spec NAMES the trade. |
| Slice topology evolution silently expanding capability | FROZEN_SCOPE default + slice-id collision FORBIDDEN (§3.5, F-10) | Cealis-internal-only `slice_topology_evolution_authority`; partners cannot evolve unilaterally; legacy slice-ids stay valid forever. |
| Deeper-erasure-mode legal blast | DEFAULT-FORBIDDEN at configurator review; counsel sign-off gate required (F-19) | If a partner gets counsel sign-off and enables, Cealis layered controllership exposure under Art. 26 joint controllership may be real; spec normatively forbids by default to limit exposure. |
| Cross-deployment passkey linkability | Per-RP-ID passkeys + per-deployment PasskeyRotationLog (F-18) | Rotation-log timing correlation across deployments still possible if subject uses the SAME passkey (against best practice); per-RP-ID discipline mitigates but requires holder cooperation. |
| Stream 2 pepper-epoch leak | Pepper-epoch rotation discipline (§3.6, F-14); partner retains past epochs for retention window | One pepper-epoch leak limits linkability to that epoch's Stream 2 events; partners rotate to limit exposure. |

#### §9.1.3 Threats out-of-scope

- DRM / extraction-proof display claims. The client is a thin helper, not a fortress.
- Screenshot defense. Out of scope.
- Photograph-of-screen. Out of scope.
- Rooted-device extraction. Out of scope.
- OS-level keylog. Out of scope.
- Post-display memory dump. Out of scope (within OS-residuals catalog §7.5; explicitly not promised).
- Physical coercion of holder. Out of scope (the σ_holder signature is the cryptographic envelope; coerced signing is outside Cealis's mitigation surface).
- Partner-side breach of issuance records. Out of scope (partner is responsible for issuance-time storage discipline per §2.10).

### §9.2 Seven-view cycle (Rule 26)

Cycling the seven views per internal Table B and Rule 26:

- **Enforcement view.** PresentedTokenCondition + 4-gate AND substrate. The universal tripwire holds. Step 5 + Step 6 of §6.1 are the chain-enforcement layer. G4 refusal is crypto-enforced via σ_G4 absence.
- **Tamper-proof view.** The per-slice sealed-envelope chain (§5) preserves history immutability. Re-key composes via supersession-invariance (H-2). The content-shape digest in Stream 2 preserves op-shape across Art. 17 shred (H-3). The cross-vendor cosign-gate (H-4) makes Stream 2 forgery-resistant. §371a ZPO admissibility path via QTSP integration (§10.5).
- **SD view.** Forbidden under controlled-use until A21-SD-integration `/design` fork (App. C). Stage-0 Q-0-7 (SD-mandatory) honored at the meta-level via the explicit deferral pointer; SD-on PDAs are rejected at PDA validation rather than silently ignored.
- **Commercial view.** First-presentation gas attribution PDA-configurable (F-12); default `PARTNER_META_TX` removes holder gas burden. Cross-slice composed presentation gas modeling deferred to App. C + A21-batched-presentation fork. The configuration profile composes with existing commercial structure (per-identity + per-obligation + per-reveal + retainer, per the internal commercial-model notes).
- **Legal view.** Art. 6(1)(a) consent + Art. 9(2)(h) health (deployment-archetype-dependent) + Art. 5(2)/(f) accountability. Art. 17 erasure semantics under content_shape_digest two-tier retention (H-3). Art. 18 freeze via existing freezeReveals + G4 refusal `0x03`. Art. 26 joint controllership analysis with deeper-erasure forbidden by default (F-19). §286 ZPO free-evaluation default; §371a path via QTSP. Deployment-scoped audit-pepper rotation discipline (F-14).
- **Use-case-flex view.** Same primitives serve health-record, sealed-team-codebase, M&A diligence, pharmacy one-shot, archival, and other use cases (per App. A four archetypes). The PDA `token_policy_config` field family carries deployment-specific choices.
- **Partner-fit view.** Non-passkey holder bindings architecturally first-class (§2.3 four forms). Pilot deployments will favor passkey-bound; partners with hardware-key or EOA-bound workflows are accommodated. The configuration profile maps partner intent (§3.4) to PDA fields.

The spec does NOT collapse to a single view. Controlled-use refines and composes Tamper-proof + Use-case-flex + Conditional-reveal under one configuration profile; it does not subordinate the other views or canonicalize a new view.

### §9.3 Time-of-check / time-of-use boundary (H-7 normative paragraph)

**Release happens at σ-signing time.** When the 4-gate AND substrate signs the σ ensemble at §6.1 Step 6, the cryptographic authorization for the operation is complete. The downstream operation (read at Step 7-R / 9, write at Step 7-W / 9) consumes the σ ensemble to derive the per-stanza wrap-decap.

**Bytes already released under a then-valid token cannot be cryptographically recalled.** Once the recipient combiner has produced cleartext, the recipient holds the bytes. The chain cannot un-release. The TEE cannot un-display. The SDK cannot un-show.

**Revocation prevents FUTURE presentations from succeeding, including the next read within the same operational session.** A sub-token revoked mid-session fails at the next presentation; the next read attempt fails at Step 5 PresentedTokenCondition evaluation; pending writes fail at the next G4 check.

**Partners SHOULD configure session-scope sub-tokens with short TTL** (`recommended_sub_token_max_ttl_seconds` PDA field; default 300s; reduces the already-released window proportionally). Shorter TTL means fewer "already-released" bytes in flight at any moment; longer TTL means more.

This is honest framing per Rule 30 WP §K discipline. The spec does not promise "instant revoke kills the session"; the spec promises "revocation prevents future presentations; bytes already released stay released."

### §9.4 Authorized-recipient-not-adversary clause

Per Simon's honesty clause (raw capture line 89-93) and per the orient §3 scope-out: the eligible recipient is not the adversary. The Cealis client/access app is a protection that works with the person holding the token, not against them.

What controlled-use defends against:
- Ambient copies (data leaks into device-wide caches, photos roll, clipboard history)
- Uncontrolled persistence (data persists past intended session)
- Silent onward transfer (data forwarded to unauthorized parties via background sync, cloud backup)
- Unmanaged device sprawl (data accessible on devices outside the holder's primary device)
- Scope creep beyond entitlement (data accessed outside the slice the token authorizes)
- Write-history rewriting (writes silently modify past entries)
- Malicious-but-authorized over-reach within scope (writes outside schema; reads outside the time window)

What controlled-use does NOT defend against:
- The entitled recipient as adversary (screenshot, photograph-of-screen, OS-level keylog, post-display memory dump)
- Physical coercion of the holder
- Partner-side breach of issuance records or pepper
- Rooted-device extraction

This honesty is non-negotiable. The spec repeats it in §K addendum (§10 banned phrasings) and in the threat model (this section) so future readers do not accidentally promise more.

### §9.5 Off-chain credential metadata correlation (F-20 residual)

The lazy-anchor primitive's privacy win is bounded. Unused master credentials have zero on-chain trace until first presentation. But off-chain credential metadata (timing of issuance, scope, partner identity) is held by the issuer (partner TEE or partner-side configurator infrastructure). A chain observer correlating an anchor-write event with off-chain-leaked credential metadata (obtained via partner breach, subpoena, or honest disclosure during litigation) can post-facto deanonymize.

Mitigations:
- Partner-TEE attestation that credential metadata is not retained beyond first-presentation or expiry. Spec-level recommendation; not all partners may have TEE infrastructure for issuance.
- Partner-side log retention discipline. Best practices per S2-6 operational ceremonies amendment.

The privacy claim is "chain observer can't see issuance-time metadata"; it is not "no one can see issuance-time metadata."

### §9.6 PII content statement (§9)

§9 security model carries no PII directly. The threat catalog enumerates threats and mitigations; the PII content of each surface is named in the per-section PII statements of the affected sections (§2, §4, §5, §6, §7, §10).

---

## §10 — GDPR and legal interactions

This section establishes the GDPR and legal framework for controlled-use deployments, including Art. 6 / 9 lawful basis options, Art. 17 erasure semantics with content_shape_digest two-tier retention, Art. 18 freeze interaction, Art. 26 joint controllership analysis, German evidentiary law (§286 / §371a ZPO), and deployment-scoped audit-pepper rotation discipline.

### §10.1 Lawful basis options

Controlled-use deployments operate under one or more of:

- **Art. 6(1)(a) consent.** Subject consents to the partner processing personal data under a specific PDA configuration. Most appropriate for subject-centric deployments where the subject is the data principal and credentials authorize partner access.
- **Art. 6(1)(b) contract performance.** Same basis as the V2 escrow flagship use case. Appropriate where the partner has a contractual relationship with the subject (lending, employment, professional services) and controlled-use operations are necessary for contract performance.
- **Art. 6(1)(c) legal obligation.** Appropriate for deployments where partner data processing is mandated by law (regulatory record-keeping, healthcare reporting obligations).
- **Art. 9(2)(h) health and social care.** Required for health-record archetypes processing special-category data. Composes with Art. 6(1)(a) or Art. 6(1)(b) for the lawful-basis layer; Art. 9(2)(h) provides the special-category-data carve-out.
- **Art. 5(2)/(f) accountability.** All controlled-use deployments are subject to accountability; the Stream 2 two-tier retention serves this basis (§10.3).

Deployments combining bases (e.g., Art. 6(1)(a) + Art. 9(2)(h) for health-record subject-consented operations) elect the combination at PDA configuration time. The configurator review validates basis compatibility per S2-4.

### §10.2 Art. 17 erasure semantics under content_shape_digest two-tier retention (H-3)

When a subject exercises Art. 17 erasure for a controlled-use PDA:

1. **DEK destruction.** The slice DEK family (per `slice_dek_policy`) is destroyed. The slice's encrypted envelope content becomes mathematically unrecoverable.
2. **Vault deletion.** The off-chain ciphertext storage deletes the encrypted envelope blobs for the affected slices.
3. **Stream 1 shred.** Stream 1 entries (DEK-keyed audit events) shred WITH the slice DEK destruction. Content-level write-history is destroyed.
4. **Stream 2 retention.** Stream 2 entries (audit-keyed, content-shape digest) are RETAINED per Art. 5(2)/(f) accountability. The partner can prove "an op of shape S occurred against this PDA at time T by holder H" without ever recovering content.
5. **On-chain shred two-axis.** The mandatory `NOT post_challenge_reveal_in_progress` guardrail extends to controlled-use slice-shred. Authority axis (subject / joint / operator / timelock / disabled per PDA) AND condition axis (Mode P predicate / Mode F FSM per PDA) compose.

The two-tier retention resolves the apparent Art. 17 vs Art. 5(2) conflict without compromising either. Subjects retain Art. 17 right to erasure of content; partners retain Art. 5(2) accountability via op-shape.

`stream2_content_shape_digest_enabled` is DEFAULT TRUE for any partner subject to regulator audit; partners may set FALSE for max-subject-privacy deployments at their regulatory risk (the partner foregoes the op-shape evidence of erased operations).

`stream2_retention_class = DEEPER_ERASURE_OPT_IN` (Stream 2 also crypto-shreds) is DEFAULT-FORBIDDEN at configurator review per F-19. Counsel sign-off gate is required for any partner request to enable.

### §10.3 Art. 18 freeze interaction

The existing V2 Art. 18 reveal freeze (per WP §D) extends to controlled-use. A subject's Art. 18 freeze covers:
- Read operations: refused at G4 refusal code `0x03` Art. 18 freeze. PresentedTokenCondition evaluation may PASS, but the σ_G4 contribution is refused; 4-gate AND fails.
- Write operations: refused at write-validation gate. New writes against pending-freeze PDAs are refused.

The 90-day maximum and auto-expiry from V2 Art. 18 freeze apply. Operator role (OPERATOR_ROLE) holds the freeze/unfreeze authority per S2-2.

### §10.4 Art. 26 joint controllership analysis

Controlled-use deployments involve layered controllership:
- **Subject.** Data principal; controls identity attestation, holder-binding key, presentation signatures.
- **Partner.** Controller for the PDA configuration choices, the off-chain credential issuance, the deployment-scoped audit-pepper.
- **Cealis (G4 + commit-infrastructure).** Controller for the G4 signing-operation processing step (per WP §K replacement #7 + #8); the controlled-use profile EXTENDS G4's controllership scope to write-validation + audit-stream signing.
- **Cealis (vault).** Controller for sealed-ciphertext custody.
- **Recipient.** Controller for reveal-output handling and combiner operation (per WP §K replacement #8).

Under Art. 26 joint controllership, the partner and Cealis are joint controllers for the platform-wide means determined via PDA+ configuration (schema, condition, recipients, retention, shred — extended to slice layout, write authorities, audit policy).

**Deeper-erasure-mode under Art. 26.** Per F-19: deeper-erasure mode (Stream 2 shred) destroys the records that document G4's controller actions. Even if the partner triggers deeper-erasure, Cealis's accountability defense weakens because the Stream 2 trace of G4 refusal decisions is destroyed alongside.

Normative legal disposition: deeper-erasure mode is **DEFAULT-FORBIDDEN at configurator review**. Counsel sign-off gate is required. The PDA configurator REJECTS any PDA with `stream2_retention_class = DEEPER_ERASURE_OPT_IN` AND `token_policy_config.enabled = true` UNLESS the counsel sign-off attachment is present (S2-4 amendment).

If a partner obtains counsel sign-off and enables deeper-erasure, Cealis layered controllership exposure under Art. 26 may be real; the spec normatively forbids by default to limit exposure, and the partner assumes the regulatory risk per the counsel sign-off.

### §10.5 §286 ZPO default + §371a path

Per the existing V2 framing (WP §K replacement #13):
- **§286 ZPO free-evaluation admissibility (default).** Gate signatures + σ_holder + PDA configuration + on-chain commitment chain are admitted as documentary evidence; weight is evaluated alongside other evidence with full judicial discretion. This is the default evidentiary posture for controlled-use deployments without QTSP integration.
- **§371a ZPO Anscheinsbeweis admissibility (QTSP-elected).** Requires σ_holder to be a Qualified Electronic Signature (QES) under eIDAS Art. 25, sourced from a registered QTSP. Available when the PDA elects `qes_subject_required = true` (per S2-3 + S2-1 §10) AND the partner integrates QTSP-issued QES credentials for holder-binding.

For controlled-use, the QTSP-integration path involves the holder-binding key being a QES key issued by a QTSP. The §371a path is available for partners requiring presumed-authenticity admissibility (financial-services audit, regulatory enforcement); the §286 path is sufficient for general deployments (health records, sealed team codebases, M&A diligence).

### §10.6 Deployment-scoped audit-pepper rotation (F-14 normative)

The Stream 2 content_shape_digest is HMAC keyed under deployment-scoped audit-pepper. Per F-14, the pepper is keyed by `(deployment_id, pepper_epoch_number)`; rotation creates a new epoch and partners retain past pepper-epochs for the retention window.

Rotation discipline:
- Pepper-epoch-0 root is committed to on-chain at PDA registration (`stream2_pepper_root` per §3.2.6).
- Subsequent pepper-epoch roots are committed to on-chain at rotation events (S2-2 amendment).
- Stream 2 anchors (Merkle root anchors of Stream 2 batches) commit to `pepper_epoch_number` per batch.
- At verification time, the partner retrieves the relevant pepper-epoch from off-chain pepper storage and recomputes the content_shape_digest to verify a Stream 2 entry's integrity.

Blast radius of pepper-epoch leak:
- Linkability of one pepper-epoch's Stream 2 events is the bounded leak.
- Cross-pepper-epoch correlation cannot be performed by an attacker without compromising additional pepper-epochs.
- Partners SHOULD rotate periodically (e.g., quarterly or annually depending on volume) to limit exposure.

### §10.7 Banned phrasings (extending WP §K)

This spec extends WP §K (13 banned phrasings) with two new candidates for controlled-use deployments:

**14. NOT "the access app is a secure container / sandbox / DRM."** Replace with: the access client is a thin SDK helper, comparable in shape to Signal Desktop (transparent E2E, wipe-on-logout) / 1Password (helps the user do the secure thing, doesn't fight them) / MetaMask (key custody + signing helper, not a sandbox). The Cealis-native difference is that the helper is bound to a PDA-defined policy with a TEE-side write-validation backstop (§4), so the client-side schema check is a UX layer not a security layer.

**15. NOT "Cealis prevents authorized recipients from extracting data once displayed."** Replace with: authorized recipient is not the adversary; the spec defends against ambient copies, uncontrolled persistence, silent onward transfer, and unmanaged device sprawl; not against screenshot, rooted-device extraction, OS-level keylog, post-display memory dump (per §9.4 honesty clause).

The two new banned phrasings will be added to WP §K via the coordinated WP amendment per §11.

### §10.8 PII content statement (§10)

§10 GDPR and legal interactions discuss the legal handling of PII rather than producing or processing PII directly. The Art. 17 / Art. 18 / Art. 26 analyses establish the controllership boundaries and the rights surfaces.

Stream 2 content-shape digests are pseudonymous under Breyer; partners retain digests under Art. 5(2) accountability. After Art. 17 erasure, Stream 1 entries are destroyed alongside content; Stream 2 entries are retained.

The deployment-scoped audit-pepper is partner-held off-chain; the pepper itself is partner-side secret material. The pepper-epoch root commitment is on-chain; root commitments are non-PII.

---

## §11 — Interactions with S2-1..S2-7

This section enumerates every downstream propagation obligation triggered by this spec. Per internal Rule 33, the propagation chain runs in motion before design-capture A21 status flips from `captured` to `committed`.

### §11.1 S2-1 cryptography-spec — coordinated amendment

| Section | Amendment |
|---|---|
| §1 conventions | `commit_version` bumps from `0x0302` to `0x0303`; the new version covers controlled-use deployments. |
| §2.3 TAG_*_V3 registry | Add 8 new TAG rows per §1.4 of this spec: `TAG_CU_CREDENTIAL_V3`, `TAG_CU_ANCHOR_V3`, `TAG_CU_SUB_TOKEN_V3`, `TAG_CU_SLICE_COMMIT_V3`, `TAG_CU_SLICE_LAYOUT_V3` (renamed from synthesis SLICE_TOPOLOGY), `TAG_CU_WRITE_ATTEST_V3`, `TAG_CU_AUDIT_STREAM1_V3`, `TAG_CU_AUDIT_STREAM2_V3`. Active count moves from 30 to 38. |
| §3 composite identifiers | Add envelope hash construction (`h_envelope`) per §1.7 of this spec. |
| §4 commit_AAD | Add three fixed-width fields: `slice_id` (32 bytes), `slice_preceding_envelope_ref` (32 bytes), `slice_position` (u64 BE). |
| §6 envelope spec | Byte-exact construction details for the new TAGs and envelope hash. |
| §10 G4 signing | Extend G4 signing primitive enumeration with `K_G4_write_attest` and `K_G4_audit_stream2`. |
| §13 PasskeyRotationLog | Extend with non-passkey holder-binding rotation (HolderRotationLog or unified rotation registry). |
| §15 re-key ceremony | Document supersession-invariance of `SliceLayoutRegistry` per §5.3 of this spec. |

### §11.2 S2-2 smart-contracts-spec — coordinated amendment

| Section | Amendment |
|---|---|
| §4-§7 condition modules | Add PresentedTokenCondition as the 10th condition module. Composition-compatibility matrix per H-6 normative. |
| §9 registries | Add three new class-CRYPTO registries: `CredentialAnchorRegistry`, `SliceLayoutRegistry`, `MasterTokenRevocationRegistry`. Add one opt-in registry: `TokenRevocationRegistry` (PDA-elected per `MASTER_AND_SUB_CRL` mode). |
| §11 RevocationRegistry | Extend split to include master-token revocations and (opt-in) sub-token revocations. |
| §14 pause | Pause semantics extend to controlled-use writes (pausing the write-validation surface). |
| §16 access-control roles | No new role additions; existing roles (OPERATOR_ROLE, MODULE_ADMIN_ROLE, REGISTRY_ADMIN_ROLE, REKEY_GOVERNANCE_ROLE) cover the new surfaces. |
| App. A example PDAs | Add example PDAs for controlled-use archetypes per App. A of this spec. |

### §11.3 S2-3 custody-integration-spec — coordinated amendment

| Section | Amendment |
|---|---|
| §3 G2 Lit V3 | Extend Lit V3 attested TEE scope to Stream 2 cosign (when `stream2_cosign_gate = G2_LIT`). |
| §3 G3 dcipher / drand | Extend G3 signing scope to Stream 2 cosign (when `stream2_cosign_gate = G3_*`). |
| §3 G4 Phase 2 | Extend G4 TEE scope to write-validation (per §4 of this spec). Add `K_G4_write_attest` and `K_G4_audit_stream2` to G4 key catalog. Define the two G4 ingest paths (write-validation; read-event ingest) per §4.5 of this spec. |
| §5 cross-vendor disjoint mandate | Extend mandate to Stream 2 cosign (cosign-gate must be vendor-disjoint from G4). |
| §7 gate-recipient-pubkey lifecycle | Add per-deployment `K_G4_write_attest` and `K_G4_audit_stream2` lifecycle (ephemeral per-commit or long-lived per-deployment per S2-3 §7 patterns). |

### §11.4 S2-4 configurator-pda-spec — coordinated amendment

| Section | Amendment |
|---|---|
| §5 per-surface class table | Add `token_policy_config` field family (91-row table grows; new sub-classification ControlledUseAccessPolicy). |
| §5 PDA+ governance sub-classifications | Add ControlledUseAccessPolicy as the 6th PDA+ governance sub-classification. |
| §5 cross-field rules | Add 6 new cross-field rules: (a) scope grammar consistency with slice layout cardinality; (b) cosign-gate consistency with g3_choice; (c) cache policy consistency with client profile; (d) emergency-elevation policy authority non-empty if enabled; (e) sd_election MUST be DISABLED when token_policy_config.enabled = true; (f) deeper-erasure_opt_in requires counsel sign-off attachment. |
| Intent-translation flow | Extend with controlled-use intents per §3.4 of this spec. |
| Two-layer PDA evolution | Extend evolution-policy semantics with `FROZEN_SCOPE` vs `REISSUE_REQUIRED` per §3.5 of this spec. |
| App. A example PDAs | Add four controlled-use archetype PDAs per App. A of this spec. |

### §11.5 S2-7 sd-spec-v2 — deferral pointer

Controlled-use × SD integration is forbidden until the `/design` fork "A21-SD-integration" produces the cross-reference spec. App. C names the fork. No S2-7 amendment is triggered by this spec; S2-7 remains the SD authority. The cross-field rule preventing SD-on PDAs under controlled-use is normative at S2-4 (per §11.4 cross-field rule e).

### §11.6 WP — coordinated amendment

| Section | Amendment |
|---|---|
| §B P4 ConditionEngine | Extend the 9-module narrative to 10 modules; add PresentedTokenCondition. |
| §D custody surface | Extend G4 Phase 2 TEE narrative to include write-validation + audit-stream signing. |
| §K banned phrasings | Add the 2 new banned-phrasing candidates per §10.7 of this spec (the access app is not a secure container / sandbox / DRM; Cealis does not prevent authorized recipients from extracting data once displayed). The active count moves from 13 to 15. |

### §11.7 design-capture A21 status flip discipline

Per internal Rule 33: design-capture A21 status stays `captured` until:
1. This spec (`docs/specs/controlled-use-spec.md`) is committed.
2. The §11.1-§11.6 amendments are in motion (S2-1, S2-2, S2-3, S2-4 amendments authored or in pipeline; WP §B/§D/§K amendments authored or in pipeline; Linear PROs for each amendment created).

Only after both conditions hold does the A21 status flip to `committed`. Spec authoring alone does NOT flip the status.

The A22, A23, A24 entries (design-capture) are already `committed` per their authoring (2026-05-22 from `/design` Phase 4-resolution). They are design patterns abstracted from A21's resolution and can be applied to future Cealis work independently.

---

## §12 — Implementation phasing

This section establishes Stage-3 implementation phasing. The spec is architectural-coherence-locked; byte-exact normativization happens at Stage-3 against the first pilot partner.

### §12.1 Stage-3 markers

- **M-CU-1: Solidity stubs for new registries.** `CredentialAnchorRegistry`, `SliceLayoutRegistry`, `MasterTokenRevocationRegistry` Solidity contract stubs (no business logic; storage layout + ABI; per S2-2 coordinated amendment). Foundry tests for storage layout invariants.
- **M-CU-2: PresentedTokenCondition module.** Solidity implementation of the 10th condition module; composition-compatibility matrix enforcement; PDA configurator rejection at DeadManSwitch × PresentedTokenCondition. Foundry tests for composition matrix.
- **M-CU-3: G4 Phase 2 TEE write-validation gate.** Rust implementation of the TEE-resident write-validation gate; schema-conformance check; scope-conformance check; history-immutability check; policy-allow check; token-authorizes-this-exact-write check; write_attest signing. DCAP attestation per S2-3.
- **M-CU-4: Client SDK (Rust core).** Rust core implementing credential lifecycle, sub-token derivation, σ_holder signing, presentation digest computation, read-event tuple production, write-pending payload management, cache invalidation. Property-based tests for scope-subset, supersession-invariance, A22 first-presentation discipline.
- **M-CU-5: Client SDK (web wrapper + native wrapper).** JavaScript/TypeScript web SDK + native library; PDA-bound `recommended_client_profile` selection; 100ms write-pending wipe (web); storage-forbiddens enforcement (web); OS Keychain integration (native).
- **M-CU-6: G4 ingest API for read-event tuples.** Thin G4 ingest API; σ_holder validation; counter-signing with `K_G4_audit_stream2`; cosign-gate co-signing flow; Stream 2 batching cadence.
- **M-CU-7: SliceLayoutRegistry + pda_slice_layout_anchor.** SliceLayoutRegistry implementation; periodic Merkle anchor computation; supersession-invariance discipline integration with S2-1 §15 re-key ceremony.
- **M-CU-8: Internal E2E demo.** First pilot-partner-shaped end-to-end demo across all surfaces: web SDK + native SDK + G4 TEE + chain + audit streams + revocation.

### §12.2 Validation gate against first pilot partner

Per the orient + Phase 5 anti-drift: byte-exact normativization happens after architectural-coherence-locked spec is validated against the first pilot partner's deployment archetype. The spec is implementable at coherence depth; byte-exact construction details (envelope hash byte layout, canonical presentation digest schema, content-shape digest input set) are deferred to the S2-1 amendment after the first pilot partner's deployment shape is confirmed.

The validation gate ensures the spec does not over-specify byte-exact constructions that the first pilot partner's archetype turns out to forbid (e.g., a partner's KYC vendor requires a specific holder-binding form that breaks an over-rigid presentation digest layout).

### §12.3 No V3-conflict claims

Controlled-use does not conflict with V3 custody architecture. The 4-gate AND substrate is untouched; G1, G2, G3, G4 are extended in scope (G4 write-validation + audit-stream) but not in count. The controlled-use additions ride on the existing substrate.

---

## §13 — Test taxonomy

This section establishes the normative test categories for controlled-use. Specific test vectors are deferred to App. B + Stage-3 implementation.

### §13.1 Token-class round-trip vectors

For each of the nine token classes (§2.2):
- Issuance round-trip: credential generated by partner configurator → delivered to holder → first presentation lands anchor → subsequent presentation reads anchor.
- Revocation round-trip: master credential issued + first-presented → revoked → next presentation REVERTs at Step 2.
- Sub-token derivation: master first-presented → sub-token derived off-chain → sub-token first-presented → master revoked → next sub-token presentation REVERTs at Step 2.

### §13.2 Lazy-anchor revocation race vectors (A22 / H-1)

- Forged first-presentation against revoked master: REVERTs at Step 1 (revocation check FIRST).
- First-presentation tx with revocation tx in same block: revocation lands first → first-presentation REVERTs.
- First-presentation tx with revocation tx in same mempool but different blocks: per chain-confirmation-depth window (§8.5).

### §13.3 Composed-condition matrix vectors (H-6)

For each row of the §6.3 matrix:
- composes-cleanly rows: presentation under composition succeeds when sub-conditions satisfied.
- requires-additional-binding rows: presentation under composition succeeds with timestamp-lock + reading-snapshot semantics; mid-tx updates ignored.
- FORBIDDEN row (DeadManSwitch × PresentedTokenCondition): PDA configurator REJECTS at validation time.

### §13.4 Audit-stream cross-vendor cosign vectors

- Stream 2 entry signed by G4 only (no cosign): REVERTs at validation (`CU_ERR_STREAM2_COSIGN_MISSING`).
- Stream 2 entry signed by G4 + G2_LIT cosign: PASSES validation if PDA elects G2_LIT.
- Stream 2 entry signed by G4 + G3_DCIPHER cosign: PASSES validation if PDA elects G3_DCIPHER.
- Stream 2 entry signed by G4 + cosign-from-wrong-gate: REVERTs.

### §13.5 Wipe-on-close residual catalog vectors

For each OS-layer residual (§7.5):
- Web SDK wipe-on-close: verify no key material in JS memory + IndexedDB after session close.
- Native SDK wipe-on-close: verify no key material in process memory + OS Keychain after session close.
- Tab-suspension snapshot: documented as outside SDK control; no test asserts wipe through suspension snapshot.

### §13.6 First-presentation atomic-bundling vectors (A22)

- Revocation-fail-before-SSTORE: verify no SSTORE landed if revocation check fails.
- σ_holder-fail-after-revocation: verify revocation check passed and SSTORE did NOT happen (REVERT before SSTORE).
- All-passes: verify revocation → σ verify → SSTORE → condition eval order observable in transaction trace.

### §13.7 Slice topology evolution vectors

- FROZEN_SCOPE policy: legacy credential reads from legacy slice-id after slice layout evolution succeeds with frozen content; legacy credential read-against-successor-slice REVERTs (slice-id collision FORBIDDEN per §3.5).
- REISSUE_REQUIRED policy: legacy credential becomes inert at evolution; presentations REVERT.

### §13.8 Cross-slice composed presentation vectors

- Master credential satisfies multi-slice when `slice_atomicity_allowed: true` (per F-15): single master presentation covers Composed(slice_A, slice_B).
- Sub-tokens for multi-slice: Composed(sub_A, sub_B) presentation succeeds with each sub-token passing PresentedTokenCondition.

### §13.9 Re-key + slice-write concurrent vectors (H-2)

- Re-key in progress on slice A's latest sealed envelope; concurrent write to slice A: writer reads SliceLayoutRegistry → original h_commit; binds σ against current generation via SupersededCommitRegistry walk; writes new envelope with `slice_preceding_envelope_ref = original h_commit`. Test asserts: SliceLayoutRegistry NOT touched by re-key; references stay stable; supersession observable but not breaking.

### §13.10 PII content statement (§13)

§13 test taxonomy carries no PII. Test vectors should use synthetic data (per S2-1 §13 conventions); production data MUST NOT be used in test fixtures.

---

## §14 — Open questions and extended Rule-35 industry-collision scan list

This section enumerates the open architectural questions deferred to Stage-3 validation, the synthesis-emergent destructive attack surfaces requiring follow-up, and the extended Rule-35 industry-collision scan list per §0.7 discipline 4.

### §14.1 Open architectural questions

1. **PDA-side artifact reference for policy_hash replay (§4.2).** Where is the PDA-side artifact carrying the policy hash stored? `PDARegistry` (does it exist as a standalone registry today, or is the artifact reference inside `pda_root`)? Resolution deferred to S2-2 amendment.
2. **Cross-slice composed presentation gas modeling (F-11).** Volume modeling of cross-slice composed-presentation gas cost at hospital scale (~50k events/day). Mitigation candidate: batched-presentation primitive. Deferred to `/design` fork "A21-batched-presentation" + App. C.
3. **SD pipeline integration (F-9).** Controlled-use × SD interaction is unspecified. Deferred to `/design` fork "A21-SD-integration" + App. C.
4. **HolderRotationLog vs PasskeyRotationLog (non-passkey holder bindings).** Should hardware-bound and EOA-bound holder rotations log into PasskeyRotationLog (extended) or a separate HolderRotationLog? Deferred to S2-1 amendment + S2-2 amendment.
5. **Chain-confirmation-depth default per Base network.** Default N=12 for Base mainnet is conservative; specific deployments may elect higher or lower. Deferred to S2-2 amendment + partner per-archetype guidance.
6. **Stream 2 Merkle batch cadence default.** Default flush cadence (per N seconds or per N events) is partner-elected via PDA. Deferred to S2-5 amendment for HTTP-layer cadence.
7. **Gas attribution chain-subsidy mechanism (`NONE_CHAIN_SUBSIDIZED`).** Specifics of chain-level gas-station mechanism deferred to S2-2 amendment.
8. **Reference client UI shell.** Specific UI shell (Tauri vs Electron vs others) for desktop reference client deferred to S2-6 operational ceremonies amendment + product decision.
9. **DEEPER_ERASURE_OPT_IN counsel sign-off gate mechanism.** Specifics of the counsel sign-off attachment format and verification deferred to S2-4 amendment.
10. **Synthesis-emergent destructive attack surfaces (destructive stress-test §12 list).** Each of the 10 surfaces requires Stage-3 hardening: (1) first-presentation anchor write-race; (2) slice topology evolution + frozen-scope policy; (3) master revocation latency window; (4) Stream 2 deployment-scoped pepper key compromise; (5) Composed token atomicity gas-bomb; (6) audit-stream2 forgery under TEE-key compromise; (7) cache-invalidation bypass on native client; (8) lazy-anchor non-anchored credentials as oracle; (9) deeper-erasure-mode legal blast; (10) EUDI-passkey cross-deployment linkability.

### §14.2 Rule-35 industry-collision scan list (extended per §0.7 discipline 4)

The following terms are introduced by this spec OR by the synthesis it implements. External use of any term (grant copy, partner outreach, landing page, public messaging) requires the 4-query industry-collision web scan per internal Rule 35 BEFORE promotion. The 4-query template: (literal term) + (term + cryptography) + (term + healthcare or relevant domain) + (term + Web3).

From synthesis v1 §10:
- PresentedTokenCondition (renamed from synthesis predecessor "TokenPresented" per F-COS-3)
- Controlled-use access session
- Controlled-use sealed-envelope chain (renamed from "sealed versioned vault" per F-COS-5)
- Write-validation gate
- Lazy-anchor passkey credential
- Per-slice independent chain
- pda_slice_layout_anchor (renamed from `slice_topology_root` per F-COS-4)
- G4 TEE attestation + on-chain policy-hash replay (renamed from "hybrid attestation" per F-COS-2)
- Master + TTL sub-token
- Two-tier audit retention
- Deployment-scoped audit-pepper
- CredentialAnchorRegistry / SliceLayoutRegistry / MasterTokenRevocationRegistry

Newly introduced from Phase 4-5:
- `content_shape_digest`
- `cosign-gate` (PDA enum)
- `slice latest sealed envelope ref`
- `preceding sealed envelope`
- `pepper_epoch_number`
- `emergency-elevation token`
- `recommended_sub_token_max_ttl_seconds`
- `partner_may_strengthen_profile`
- `recommended_client_profile`
- `first_presentation_gas_attribution`
- `web_profile_write_allowed`
- `slice_atomicity_allowed`

These terms are normative within this spec but UNSCANNED for external industry collision; before any external use, Rule 35 4-query web scan is mandatory per term. The pre-flight scan results should be captured in a follow-up artifact prior to external use.

Particularly flagged for HIGH risk (require `/deep-signal` upgrade before external use):
- "G4 TEE attestation + on-chain policy-hash replay" — verbose but the previous "hybrid attestation" name was flagged HIGH-risk in confidential computing; the renamed term is clean but the underlying pattern overlaps with redundant-attestation literature.
- "Controlled-use access session" — overlaps with FIPS/NIST controlled-use cryptographic-module terminology AND HIPAA controlled-access terminology.
- "Two-tier audit retention" — overlaps with regulatory record-keeping literature.

---

## §15 — Error model

This section enumerates the custom errors introduced by the controlled-use profile. Per the project's Solidity custom-errors-only discipline: every error name listed here is implemented as a Solidity custom error (not a string revert), and per internal Rule 47 every error context carries the named fields enabling user-side debugging without recompilation.

### §15.1 Custom-errors-only discipline

All controlled-use errors are Solidity custom errors with named context fields. No string reverts; no `require(condition, "message")`. The error names use the `CU_ERR_` prefix to distinguish from other V2 system error families.

### §15.2 Error enumeration

```solidity
// Anchor + revocation errors
error CU_ERR_ANCHOR_NOT_FOUND(bytes32 credentialDigestHash);
error CU_ERR_REVOKED_MASTER(bytes32 masterCredentialDigestHash, uint64 revocationTimestamp);
error CU_ERR_REVOKED_SUB_TOKEN(bytes32 subTokenDigestHash, uint64 revocationTimestamp);

// σ_holder + presentation errors
error CU_ERR_INVALID_HOLDER_SIGNATURE(bytes32 credentialDigestHash, bytes32 presentationDigestHash);
error CU_ERR_PRESENTATION_REPLAY(bytes32 presentationNonce);
error CU_ERR_PRESENTATION_DIGEST_MISMATCH(bytes32 expected, bytes32 actual);

// Scope + token-class errors
error CU_ERR_SCOPE_OUT_OF_TOKEN(bytes32 subTokenDigestHash, bytes32 targetSliceId);
error CU_ERR_SCOPE_OUT_OF_MASTER(bytes32 subTokenDigestHash, bytes32 masterCredentialDigestHash);
error CU_ERR_TOKEN_CLASS_NOT_PERMITTED(uint8 tokenClassEnum, uint8 opKindEnum, bytes32 sliceId);
error CU_ERR_TTL_EXPIRED(bytes32 subTokenDigestHash, uint64 ttlExpiresAt, uint64 blockTimestamp);

// Composition errors
error CU_ERR_COMPOSITION_FORBIDDEN_DEADMANSWITCH(bytes32 pdaRoot);
error CU_ERR_COMPOSITION_BINDING_MISSING(uint8 composedModuleEnum, bytes32 expectedBindingHash);

// Write-validation errors
error CU_ERR_SCHEMA_VIOLATION(bytes32 sliceId, bytes32 schemaHash, bytes32 payloadShape);
error CU_ERR_HISTORY_REWRITE_ATTEMPT(bytes32 sliceId, bytes32 attemptedEnvelopeRef, bytes32 actualLatestRef);
error CU_ERR_POLICY_DENIES_WRITE(bytes32 sliceId, uint8 opKindEnum, uint8 tokenClassEnum);
error CU_ERR_HOLDER_SIGNATURE_NOT_BOUND_TO_WRITE(bytes32 presentationDigestHash, bytes32 writeOpDigestHash);
error CU_ERR_POLICY_HASH_REPLAY_FAIL(bytes32 attestedPolicyHash, bytes32 chainComputedPolicyHash);

// Audit-stream errors
error CU_ERR_STREAM2_COSIGN_MISSING(bytes32 stream2MerkleRoot, uint8 expectedCosignGateEnum);
error CU_ERR_STREAM2_COSIGN_WRONG_GATE(uint8 actualCosignGateEnum, uint8 expectedCosignGateEnum);
error CU_ERR_PEPPER_EPOCH_MISMATCH(uint32 entryEpoch, uint32 currentEpoch);

// Slice topology errors
error CU_ERR_SLICE_NOT_DECLARED(bytes32 pdaRoot, bytes32 sliceId);
error CU_ERR_SLICE_LAYOUT_EVOLUTION_MISMATCH(bytes32 pdaRoot, bytes32 expectedLayoutAnchor, bytes32 actualLayoutAnchor);
error CU_ERR_SLICE_ID_COLLISION_FORBIDDEN(bytes32 retiredSliceId, bytes32 attemptedNewSliceId);
error CU_ERR_SLICE_ATOMICITY_NOT_ALLOWED(bytes32 pdaRoot, bytes32 masterCredentialDigestHash);

// Chain-state errors
error CU_ERR_CHAIN_CONFIRMATION_DEPTH_INSUFFICIENT(uint64 blockNumber, uint64 confirmedDepth, uint64 requiredDepth);
error CU_ERR_BLOCK_HASH_MISMATCH(bytes32 expected, bytes32 actual);

// Emergency-elevation errors
error CU_ERR_EMERGENCY_ELEVATION_AUTHORITY_MISSING(address attemptedAuthority);
error CU_ERR_EMERGENCY_ELEVATION_DISABLED(bytes32 pdaRoot);

// PDA configuration errors (configurator-side, not chain-side)
error CU_ERR_SD_ELECTION_NOT_DISABLED(bytes32 pdaRoot);
error CU_ERR_DEEPER_ERASURE_REQUIRES_COUNSEL_SIGNOFF(bytes32 pdaRoot);
error CU_ERR_COSIGN_GATE_INCONSISTENT_WITH_G3_CHOICE(uint8 cosignGate, uint8 g3Choice);
error CU_ERR_EMERGENCY_ELEVATION_AUTHORITY_EMPTY(bytes32 pdaRoot);
```

### §15.3 Pre-declared error context fields (Rule 47 discipline)

Per Rule 47, every error context field is pre-declared at spec authoring time (not added incrementally at implementation). The fields above enumerate the user-debuggable context for each error class: credential digest hashes, slice IDs, presentation digests, payload shapes, token class enums, op kind enums, timestamp comparisons, signature bindings, policy hashes, epoch numbers, chain depths, block hashes, authority addresses.

Implementations adding ad-hoc context fields not enumerated here trigger a Rule 47 violation; the spec amendment is the path to add new context fields, not the implementation.

### §15.4 PII content statement (§15)

§15 error model carries no PII directly. Error context fields carry pseudonymous identifiers (credential digest hashes, sub-token digest hashes) that under Breyer qualify as personal data when correlated with off-chain credential issuance records. Reverting transactions with these errors emit the error data on-chain; chain observers can see the error context. Per S2-2 §16, errors that emit PII-correlatable context are revertable but the revert data is public; partners SHOULD design deployment archetypes such that error-triggering events are infrequent in normal operation.

---

## §16 — Cross-references

This section routes spec readers to consumer and producer surfaces across the Cealis spec stack.

### §16.1 Producer surfaces (this spec produces normative content consumed by:)

- **S2-1 cryptography-spec** — consumes new TAG_*_V3 rows (§1.4); consumes envelope hash construction (§1.7); consumes commit_AAD field additions (§5.4); consumes commit_version bump to `0x0303` (§0.1).
- **S2-2 smart-contracts-spec** — consumes PresentedTokenCondition module specification (§6); consumes three new registries + opt-in registry (§4, §5, §8); consumes composition-compatibility matrix (§6.3, H-6); consumes PDA configurator validation rules (§3.3, §10.4).
- **S2-3 custody-integration-spec** — consumes G4 Phase 2 TEE write-validation scope extension (§4); consumes cross-vendor cosign mandate extension to Stream 2 (§4.4); consumes two G4 ingest paths (§4.5); consumes K_G4_write_attest + K_G4_audit_stream2 key catalog additions (§4.6).
- **S2-4 configurator-pda-spec** — consumes `token_policy_config` field family (§3.2); consumes ControlledUseAccessPolicy PDA+ governance sub-classification (§3.3); consumes intent-translation flow extensions (§3.4); consumes evolution-policy semantics (§3.5).
- **S2-5 ingestion-delivery-api-spec** — consumes G4 ingest API contract shape (§4.5, §7); consumes Stream 2 batching cadence semantics (§4.4).
- **S2-6 operational-ceremonies-spec** — consumes K_G4_write_attest + K_G4_audit_stream2 + cosign-gate keys lifecycle and rotation discipline (§4.6, §10.6); consumes pda_slice_layout_anchor periodic anchor cadence (§5.2); consumes reference client UI shell (§7.8).
- **WP** — consumes §B P4 10-module extension (§11.6); consumes §D G4 scope extension (§11.6); consumes §K two new banned phrasings (§10.7).

### §16.2 Consumer surfaces (this spec consumes normative content from:)

- **S2-1 cryptography-spec** — §1 conventions, §2.3 TAG registry, §3 composite identifiers, §4 commit_AAD, §6 envelope spec, §10 G4 signing, §13 PasskeyRotationLog, §15 re-key ceremony, §16 error model, §17 cross-references.
- **S2-2 smart-contracts-spec** — §4-§7 condition modules, §9 registries, §11 RevocationRegistry, §14 pause, §16 access-control roles.
- **S2-3 custody-integration-spec** — §3 G2/G3/G4 SDKs, §5 cross-vendor disjoint mandate, §7 gate-recipient-pubkey lifecycle.
- **S2-4 configurator-pda-spec** — §5 per-surface class table, §5 PDA+ governance sub-classifications, §5 cross-field rules, intent-translation flow, two-layer PDA evolution.
- **Internal project rules (not included in this repository)** — §0 system parallelism (View Register Table B; Universal Tripwire), Rules 26, 28, 30, 31, 33, 35, 47.
- **Design-capture items (internal)** — A21, A22, A23, A24.
- **WP** — §B P4 (ConditionEngine), §D (custody surface), §K (banned phrasings 1-13), §L (threat catalog).
- **Internal design note: meta-vs-category naming** — meta-vs-category distinction (§0.3, §2.1).
- **Internal design note: system-locked discipline** — (§2.6, §9).
- **Internal design note: σ-as-key-material** (superseded by σ-as-authorization but principle of "σ is not public artifact" still applies) — §4.1, §6.
- **Internal design note: six-step flow as KYC composition** — composition specificity (§2.1).
- **Internal design note: full-engine scope (2026-04-24)** — Rule 31 anchor (§2.2, §2.3, §3).
- **Internal design note: EUDI integration framing** — EUDI-as-ingestion-source (§2.3 + §14 question 4).
- **Internal design note: G4 phase pilot decision** — Phase 2 G4 TEE (§4).
- **Internal design note: shred-condition design** — two-axis shred guardrail (§5.6, §10).
- **Internal design note: no-force-translate-primitives-across-pivots** — supersession-invariance discipline (§5.3).
- **Internal design note: V3 registry class distinction** — class-CRYPTO vs class-CATALOG (§3.1, §4.6, §5.2).
- **Internal design note: lazy-anchor revocation-check-first** — A22 discipline anchor (§2.6).

### §16.3 `/design` fork pointers

- **A21-SD-integration** — controlled-use × SD pipeline cross-reference; deferred per F-9 + App. C.
- **A21-batched-presentation** — cross-slice composed presentation gas optimization; deferred per F-11 + App. C.

### §16.4 Linear PRO surface

Each S2-1..S2-6 + WP amendment per §11 creates a Linear PRO under the Stage-2 spec stack:
- PRO `[stage-2-amendment] S2-1 controlled-use TAG registry + commit_AAD + envelope hash` (per §11.1)
- PRO `[stage-2-amendment] S2-2 PresentedTokenCondition + 3 new registries + opt-in CRL registry` (per §11.2)
- PRO `[stage-2-amendment] S2-3 G4 Phase 2 TEE write-validation + Stream 2 cosign extension` (per §11.3)
- PRO `[stage-2-amendment] S2-4 token_policy_config + ControlledUseAccessPolicy + cross-field rules` (per §11.4)
- PRO `[stage-2-amendment] WP §B P4 10-module + §D G4 scope + §K two new banned phrasings` (per §11.6)
- PRO `[/design fork] A21-SD-integration` (per F-9)
- PRO `[/design fork] A21-batched-presentation` (per F-11)

### §16.5 Post-authoring grep verification (per §0.7 discipline 7)

The following greps verify WP §K compliance + Discipline 1 rename pass:

```
grep -nE "slice_head|slice_prev_commit_ref|TokenPresented|slice_topology_root|sealed versioned vault|commit_parent" docs/specs/controlled-use-spec.md
# Expected: ZERO hits (rename failures absent)

grep -nE "<<<<<<<|>>>>>>>|TODO|FIXME|XXX" docs/specs/controlled-use-spec.md
# Expected: ZERO hits

grep -ciE "(cryptographically secure|mathematically impossible|GDPR.compliant|safe forever|sandbox|secure container)" docs/specs/controlled-use-spec.md
# Expected: ZERO hits (WP §K compliance)
```

If any grep returns hits, the spec section containing the hit is rewritten before commit.

### §16.6 PII content statement (§16)

§16 cross-references carry no PII.

---

## App. A — Example PDAs across four use-case archetypes

This appendix instantiates the controlled-use profile across four use-case archetypes. Each PDA carries `token_policy_config` field family per §3.2, with archetype-specific values. Defaults are inherited where not specified; class-table row references are to S2-4 §5.

### App. A.1 Pharmacy / prescription one-shot archetype

**Deployment shape:** patient has a health-record PDA; doctor writes a prescription slice; patient grants a one-shot consumption sub-token to a specific pharmacy for the prescription slice; pharmacy reads the prescription, appends a dispense-state-transition entry, and the sub-token is consumed.

```
pda_root: <archetype-specific>
g3_choice: G3_dcipher  # KYC/regulated-EU per Stage-0
sd_election: DISABLED  # per F-9
token_policy_config:
  enabled: true
  master_token_classes: [Master, One-shot consumption, Scoped-slice]
  recommended_sub_token_max_ttl_seconds: 86400  # 24h — pharmacy dispense window
  scope_field_grammar:
    allowed_forms: [SINGLE_SLICE]
    slice_atomicity_allowed: false
  slice_layout:
    slices:
      - slice_id: <prescription_slice_id>
        slice_label: "prescription"
        schema_hash: <prescription_schema_hash>
        write_authority_matrix: [(Doctor-master, WRITE), (Pharmacy-one-shot, WRITE_DISPENSE_TRANSITION)]
        read_authority_matrix: [(Pharmacy-one-shot, READ)]
        slice_dek_policy: PER_SLICE_DEK
    pda_slice_layout_anchor: <computed>
    evolution_policy: FROZEN_SCOPE
  cache_policy: EPHEMERAL_ONLY
  recommended_client_profile: WEB_ONESHOT
  partner_may_strengthen_profile: true
  web_profile_write_allowed: true  # pharmacy dispense-transition is a write
  audit_policy:
    stream1_retention_class: ART17_SHREDDABLE
    stream2_retention_class: ART5_ACCOUNTABILITY
    stream2_content_shape_digest_enabled: true  # regulator audit (BfArM prescription tracking)
    stream2_pepper_root: <pharmacy_deployment_pepper>
    stream2_cosign_gate: G3_DCIPHER
    subject_checkpoint_mode: OPT_IN  # patient can verify their pharmacy access trail
    regulator_anchor_mode: OPT_IN  # BfArM verification mirror
  revocation_mode: MASTER_ONLY
  emergency_elevation_policy:
    enabled: false  # no emergency-access pattern for pharmacy
  first_presentation_gas_attribution: PARTNER_META_TX  # pharmacy partner sponsors
```

Class-table row refs: ControlledUseAccessPolicy (PDA+); One-shot consumption + Scoped-slice token classes; Stream 1 ART17_SHREDDABLE; Stream 2 ART5_ACCOUNTABILITY.

### App. A.2 Doctor / health-record long-form archetype

**Deployment shape:** patient has a health-record PDA with multiple slices (diagnosis, prescription, history, lab-results); doctor holds a master credential authorizing read across slices + write to diagnosis + prescription; consultation session lasts ~30-60 minutes with multiple cross-slice ops.

```
pda_root: <archetype-specific>
g3_choice: G3_dcipher
sd_election: DISABLED
token_policy_config:
  enabled: true
  master_token_classes: [Master, Scoped-slice, Append-only writer, Emergency-elevation]
  recommended_sub_token_max_ttl_seconds: 1800  # 30-minute session-scope
  scope_field_grammar:
    allowed_forms: [MULTI_SLICE_SUBSET, MASTER_WILDCARD]
    slice_atomicity_allowed: true  # consultation = note + prescription + lab-order atomically
  slice_layout:
    slices:
      - slice_id: <diagnosis_slice_id>
        slice_label: "diagnosis"
        schema_hash: <diagnosis_schema_hash>
        write_authority_matrix: [(Doctor-master, WRITE), (Doctor-master, APPEND)]
        read_authority_matrix: [(Doctor-master, READ), (Patient-master, READ)]
        slice_dek_policy: PER_SLICE_DEK
      - slice_id: <prescription_slice_id>
        slice_label: "prescription"
        schema_hash: <prescription_schema_hash>
        write_authority_matrix: [(Doctor-master, WRITE), (Doctor-master, APPEND)]
        read_authority_matrix: [(Doctor-master, READ), (Patient-master, READ), (Pharmacy-scoped, READ)]
        slice_dek_policy: PER_SLICE_DEK
      - slice_id: <history_slice_id>
        slice_label: "history"
        schema_hash: <history_schema_hash>
        write_authority_matrix: []  # immutable history
        read_authority_matrix: [(Doctor-master, READ), (Patient-master, READ)]
        slice_dek_policy: PER_SLICE_DEK
      - slice_id: <lab_results_slice_id>
        slice_label: "lab-results"
        schema_hash: <lab_results_schema_hash>
        write_authority_matrix: [(Lab-master, APPEND)]
        read_authority_matrix: [(Doctor-master, READ), (Patient-master, READ)]
        slice_dek_policy: PER_SLICE_DEK
    pda_slice_layout_anchor: <computed>
    evolution_policy: FROZEN_SCOPE
  cache_policy: ENCRYPTED_CACHE_OPT_IN  # consultation may cache briefly
  recommended_client_profile: NATIVE_SESSION
  partner_may_strengthen_profile: true
  web_profile_write_allowed: false  # native-only writes for clinical-grade
  audit_policy:
    stream1_retention_class: ART17_SHREDDABLE
    stream2_retention_class: ART5_ACCOUNTABILITY
    stream2_content_shape_digest_enabled: true
    stream2_pepper_root: <hospital_deployment_pepper>
    stream2_cosign_gate: G3_DCIPHER
    subject_checkpoint_mode: MANDATORY  # patient sees all access
    regulator_anchor_mode: OPT_IN
  revocation_mode: MASTER_ONLY
  emergency_elevation_policy:
    enabled: true
    authority: [hospital_emergency_admin_address, attending_physician_role_address]
    audit_class: STREAM2_ALWAYS_LOGGED  # forced by enabled=true
  first_presentation_gas_attribution: PARTNER_META_TX  # hospital partner sponsors
```

Class-table row refs: ControlledUseAccessPolicy (PDA+); Master + Scoped-slice + Append-only writer + Emergency-elevation token classes; NATIVE_SESSION client profile; ENCRYPTED_CACHE_OPT_IN cache; subject_checkpoint_mode MANDATORY.

### App. A.3 Sealed team codebase / headless archetype

**Deployment shape:** team of developers working on a high-sensitivity codebase; codebase stored as a per-slice envelope chain (each top-level directory is a slice); developer master credentials grant read across all code slices + append-only write to code slices; CI infrastructure uses team-member tokens for headless build operations.

```
pda_root: <archetype-specific>
g3_choice: G3_dcipher
sd_election: DISABLED
token_policy_config:
  enabled: true
  master_token_classes: [Master, Team-member, Hardware-bound, Append-only writer]
  recommended_sub_token_max_ttl_seconds: 28800  # 8-hour developer workday
  scope_field_grammar:
    allowed_forms: [MULTI_SLICE_SUBSET, MASTER_WILDCARD]
    slice_atomicity_allowed: true  # commit = multiple-slice atomic
  slice_layout:
    slices:
      - slice_id: <src_main_slice_id>
        slice_label: "src/main"
        schema_hash: <code_schema_hash>  # generic code-content schema
        write_authority_matrix: [(Developer-master, APPEND), (Team-member, APPEND), (CI-bot, READ)]
        read_authority_matrix: [(Developer-master, READ), (Team-member, READ), (CI-bot, READ)]
        slice_dek_policy: PER_SLICE_DEK
      - slice_id: <src_tests_slice_id>
        slice_label: "src/tests"
        schema_hash: <code_schema_hash>
        write_authority_matrix: [(Developer-master, APPEND), (Team-member, APPEND)]
        read_authority_matrix: [(Developer-master, READ), (Team-member, READ), (CI-bot, READ)]
        slice_dek_policy: PER_SLICE_DEK
      - slice_id: <docs_slice_id>
        slice_label: "docs"
        schema_hash: <docs_schema_hash>
        write_authority_matrix: [(Developer-master, APPEND), (Team-member, APPEND)]
        read_authority_matrix: [(Developer-master, READ), (Team-member, READ)]
        slice_dek_policy: PER_SLICE_DEK
    pda_slice_layout_anchor: <computed>
    evolution_policy: REISSUE_REQUIRED  # team rotates credentials at slice topology evolution
  cache_policy: ENCRYPTED_CACHE_OPT_IN  # IDE-style workflows
  recommended_client_profile: NATIVE_HEADLESS  # CI workflows; developers may use NATIVE_SESSION via partner_may_strengthen
  partner_may_strengthen_profile: true
  web_profile_write_allowed: false
  audit_policy:
    stream1_retention_class: ART17_SHREDDABLE  # but typically retained for codebase integrity
    stream2_retention_class: ART5_ACCOUNTABILITY
    stream2_content_shape_digest_enabled: true
    stream2_pepper_root: <team_deployment_pepper>
    stream2_cosign_gate: G3_DCIPHER
    subject_checkpoint_mode: DISABLED  # codebase is not subject-data
    regulator_anchor_mode: DISABLED
  revocation_mode: MASTER_AND_SUB_CRL  # CI tokens may need immediate revocation on team-member exit
  emergency_elevation_policy:
    enabled: false
  first_presentation_gas_attribution: PARTNER_META_TX  # team partner sponsors
```

Class-table row refs: ControlledUseAccessPolicy (PDA+); Master + Team-member + Hardware-bound + Append-only writer token classes; NATIVE_HEADLESS client profile; MASTER_AND_SUB_CRL revocation mode.

### App. A.4 M&A diligence room archetype

**Deployment shape:** acquirer and target's M&A diligence; sealed diligence room with multiple document slices; acquirer's deal team holds master credentials authorizing read across slices; target's deal team holds master credentials authorizing append (data-room updates); closing event activates one-shot consumption tokens converting authority.

```
pda_root: <archetype-specific>
g3_choice: G3_dcipher  # regulated-EU per M&A jurisdiction
sd_election: DISABLED
token_policy_config:
  enabled: true
  master_token_classes: [Master, Scoped-slice, Hardware-bound, One-shot consumption]
  recommended_sub_token_max_ttl_seconds: 3600  # 1-hour session
  scope_field_grammar:
    allowed_forms: [SINGLE_SLICE, MULTI_SLICE_SUBSET]
    slice_atomicity_allowed: false  # diligence is non-atomic by slice
  slice_layout:
    slices:
      - slice_id: <financial_records_slice_id>
        slice_label: "financial-records"
        schema_hash: <financial_schema_hash>
        write_authority_matrix: [(Target-master, APPEND)]
        read_authority_matrix: [(Acquirer-master, READ), (Target-master, READ)]
        slice_dek_policy: PER_SLICE_DEK
      - slice_id: <legal_documents_slice_id>
        slice_label: "legal-documents"
        schema_hash: <legal_schema_hash>
        write_authority_matrix: [(Target-master, APPEND)]
        read_authority_matrix: [(Acquirer-master, READ), (Target-master, READ), (Counsel-scoped, READ)]
        slice_dek_policy: PER_SLICE_DEK
      - slice_id: <ip_documents_slice_id>
        slice_label: "ip-documents"
        schema_hash: <ip_schema_hash>
        write_authority_matrix: [(Target-master, APPEND)]
        read_authority_matrix: [(Acquirer-master, READ), (Target-master, READ)]
        slice_dek_policy: PER_SLICE_DEK
    pda_slice_layout_anchor: <computed>
    evolution_policy: FROZEN_SCOPE  # closing event freezes layout
  cache_policy: EPHEMERAL_ONLY  # no persistent caching for diligence
  recommended_client_profile: NATIVE_SESSION
  partner_may_strengthen_profile: true
  web_profile_write_allowed: false
  audit_policy:
    stream1_retention_class: ART17_SHREDDABLE  # post-deal cleanup
    stream2_retention_class: ART5_ACCOUNTABILITY
    stream2_content_shape_digest_enabled: true
    stream2_pepper_root: <deal_deployment_pepper>
    stream2_cosign_gate: G3_DCIPHER
    subject_checkpoint_mode: DISABLED  # diligence is non-subject-data
    regulator_anchor_mode: OPT_IN  # M&A regulator audit (BaFin, FCA, etc.)
  revocation_mode: MASTER_AND_SUB_CRL  # immediate revocation at deal-close or break
  emergency_elevation_policy:
    enabled: false
  first_presentation_gas_attribution: PARTNER_META_TX  # deal-room partner sponsors
```

Class-table row refs: ControlledUseAccessPolicy (PDA+); Master + Scoped-slice + Hardware-bound + One-shot consumption token classes; NATIVE_SESSION client profile; MASTER_AND_SUB_CRL revocation mode.

### App. A.5 PII content statement (App. A)

App. A enumerates example PDA configurations. The schema_hash fields reference schemas that, at runtime, hold PII (patient records, prescription details, code content, financial-records content, legal-documents content). The PDAs themselves are non-PII configuration artifacts. The stream2_pepper_root values are deployment-scoped audit-pepper root commitments; the underlying peppers are partner-held off-chain.

---

## App. B — Test-vector category placeholders

This appendix names normative test-vector categories. Specific vectors are deferred to Stage-3 implementation per §12.2 (validation gate against first pilot partner).

### App. B.1 Token-class round-trip vectors

For each of the nine token classes (§2.2): {issuance, first-presentation, subsequent-presentation, revocation, sub-token-derivation, sub-token-presentation, sub-token-master-revoked, TTL-expiry}.

### App. B.2 Lazy-anchor revocation race vectors

{Forged first-presentation against revoked master; race between first-presentation tx and revocation tx in same mempool; chain-confirmation-depth window boundary tests}.

### App. B.3 Composed-condition matrix vectors

For each row of the §6.3 H-6 matrix: {composition-passes; composition-fails-at-binding; FORBIDDEN-composition-rejected-at-PDA-validation}.

### App. B.4 Re-key + slice-write concurrent vectors

{Re-key in progress on slice A; concurrent write to slice A; verify SliceLayoutRegistry not modified by re-key; verify writer uses supersession walk; verify slice_preceding_envelope_ref points at original}.

### App. B.5 Audit-stream cross-vendor cosign vectors

{Stream 2 entry with G4-only signature: REVERTS; Stream 2 entry with correct cosign: PASSES; Stream 2 entry with wrong cosign-gate: REVERTS}.

### App. B.6 Wipe-on-close residual catalog vectors

{Web SDK wipe-on-close memory inspection; native SDK wipe-on-close memory + keychain inspection; OS-residual non-tests (suspension snapshot / swap / pagefile NOT asserted as wiped, documented as outside SDK)}.

### App. B.7 PDA configuration validation vectors

For each cross-field rule in §3.3: {valid configuration passes; invalid configuration rejected at validation with specific error}.

### App. B.8 Slice topology evolution vectors

{FROZEN_SCOPE: legacy credential reads legacy slice succeeds; REISSUE_REQUIRED: legacy credential REVERTs after evolution; slice-id collision: REJECTED at configurator}.

### App. B.9 Cross-slice composed presentation vectors

{Master with slice_atomicity_allowed: single presentation covers multi-slice; sub-tokens for multi-slice: Composed presentation succeeds; sub-tokens with one-sub-revoked mid-tx: REVERTs at next sub presentation}.

### App. B.10 Time-of-check / time-of-use boundary vectors

{Sub-token revoked after read started: read completes; sub-token revoked between two reads in same session: second read REVERTs; sub-token revoked during pending write: write REVERTs at G4 check}.

### App. B.11 PII content statement (App. B)

App. B test-vector categories carry no PII. Test vectors at Stage-3 implementation MUST use synthetic data.

---

## App. C — Scope-out matrix + back-propagation queue + commit_version log + open-questions table + author-lock surfaces + SD-integration fork

### App. C.1 Scope-out matrix

| Item | Out-of-scope reason | Deferred to |
|---|---|---|
| Byte-exact construction details for new TAGs | Architectural-coherence-locked depth; byte-exact follows pilot validation | S2-1 amendment per §11.1 |
| Solidity source for new registries | Smart-contract surface owned by S2-2 | S2-2 amendment per §11.2 |
| Storage-layout decisions for new registries | Smart-contract surface | S2-2 amendment per §11.2 |
| SDK version pins | Custody-integration surface | S2-3 amendment per §11.3 |
| HTTP API contracts for ingestion | Ingestion-delivery surface | S2-5 amendment |
| Operational ceremonies for new keys | Operational-ceremonies surface | S2-6 amendment |
| PDA-configurator UI | Configurator surface | S2-4 amendment |
| SD pipeline integration | Out-of-scope until cross-reference design | `/design` fork A21-SD-integration |
| Cross-slice composed gas optimization | Out-of-scope until volume modeling | `/design` fork A21-batched-presentation |
| DRM / secure-sandbox / anti-extraction | Out per orient + WP §K | Permanent — does not return to scope |
| V3 custody redesign | Out per orient | Permanent — 4-gate AND substrate untouched |
| σ-doctrine flip | Out per S2-1 §0.3 lock | Permanent — σ-as-authorization is locked |
| Pilot-subset scoping | Out per Rule 31 | Permanent — full engine spec |
| Cross-product CRDTs / real-time merge | Out per orient | Permanent — append-only commit graph |
| Live partner-self-serve UI for token issuance | Out per PDA+ governance discipline | Permanent — Cealis-internal configurator |
| Cealis-branded mandatory app | Out per orient client-shape clarification | Permanent — SDK + reference client only |
| New custody operator set | Out per V3 architecture | Permanent — zero new staked components |
| Reference client UI shell pick (Tauri vs Electron) | Product decision, not architectural | S2-6 amendment + product decision |
| Counsel sign-off attachment format | Operational + legal artifact format | S2-4 amendment + legal counsel input |

### App. C.2 Back-propagation queue

Per §11 propagation surface enumeration. Each entry creates a Linear PRO under the Stage-2 spec stack:

- BP-A21-1: S2-1 amendment (8 new TAGs + commit_AAD field additions + envelope hash + commit_version 0x0303 + G4 signing primitive extensions + HolderRotationLog discipline)
- BP-A21-2: S2-2 amendment (PresentedTokenCondition module + 3 new registries + opt-in CRL + composition-compatibility matrix + PDA-side artifact for policy_hash replay)
- BP-A21-3: S2-3 amendment (G4 Phase 2 TEE write-validation scope + cross-vendor cosign extension to Stream 2 + K_G4_write_attest + K_G4_audit_stream2 key catalog)
- BP-A21-4: S2-4 amendment (token_policy_config field family + ControlledUseAccessPolicy PDA+ governance sub-classification + intent-translation extensions + evolution-policy semantics + 6 new cross-field rules)
- BP-A21-5: S2-5 amendment (G4 ingest API + Stream 2 batching cadence)
- BP-A21-6: S2-6 amendment (operational ceremonies for new keys + pda_slice_layout_anchor cadence + reference client UI shell)
- BP-A21-7: WP amendment (§B P4 10-module extension + §D G4 scope extension + §K two new banned phrasings; active count 13→15)
- BP-A21-8: design-capture A21 status flip from `captured` to `committed` AFTER BP-A21-1..7 are in motion (per internal Rule 33)

### App. C.3 commit_version log

| Version | Date | Trigger | Reference |
|---|---|---|---|
| 0x0301 | Pre-2026-05-05 | Pre-A1+Shamir lifecycle; pre-σ-as-authorization | S2-1 §0.1 (historical) |
| 0x0302 | 2026-05-06 | A1+Shamir DEK lifecycle (dek-lifecycle design); σ-as-authorization doctrine; IB-1/2/3/4 repair batch | S2-1 §0.1 |
| 0x0303 | 2026-05-22 (pending S2-1 amendment) | Controlled-use additions: 8 new TAGs; 3 new commit_AAD fields; envelope hash construction | This spec §1.4, §5.4 |

### App. C.4 Open-questions table

See §14.1 for the 10 enumerated open questions.

### App. C.5 Author-lock surfaces

Sections of this spec that are author-locked at coherence depth (Stage-3 amends, never replaces):
- §0 (front matter and discipline anchors) — never amended; rewrites only with Simon sign-off
- §2.2 (token class catalog) — Rule 31 full-engine; amendments add classes never remove
- §2.3 (holder-binding catalog) — Rule 31 full-engine; amendments add forms never remove
- §3.3 (ControlledUseAccessPolicy PDA+ governance) — PDA+ layering discipline owned by S2-4
- §6.3 (H-6 composition matrix) — locked at synthesis-v2; amendments only with `/design` re-run
- §9.4 (authorized-recipient-not-adversary clause) — non-negotiable honesty clause; never removed
- §10.7 (WP §K extensions) — propagates to WP; locked here for consistency with §9.4

### App. C.6 SD-integration fork pointer

**Fork name:** A21-SD-integration

**Trigger:** when the first partner deployment archetype requires SD-on PDAs under controlled-use, OR when Cealis decides to ship SD integration before partner-driven demand, run the `/design` fork.

**Scope of fork:** cross-reference design between S2-7 (SD v2) and S2-8 (this spec). Questions to resolve:
- Are SD per-field Poseidon commitments per-slice, deployment-wide, or skipped under controlled-use?
- Does the sdMerkleRoot binding (BP-SD-1) extend to include slice_id?
- How does SD predicate revocation (PLONK verifier + DisclosureRevocationRegistry per BP-SD-3) compose with master-token revocation?
- Does SD pipeline failure (SD-D9 asymmetric isolation) extend to controlled-use writes?

**Deferral home:** App. C of this spec until the fork produces a coordinated S2-7 × S2-8 amendment.

### App. C.7 batched-presentation fork pointer

**Fork name:** A21-batched-presentation

**Trigger:** when cross-slice composed presentation gas cost at hospital scale (or equivalent volume archetype) crosses a partner-prohibitive threshold, OR when volume modeling confirms the F-11 concern is operationally real.

**Scope of fork:** batched-presentation primitive for multi-sub-token operations. Questions to resolve:
- Can N sub-token presentations share a single revocation SLOAD + a single Stream 2 entry?
- Can a master-session-token amortize the chain-side anchor-check cost across N sub-token presentations?
- What is the audit-log shape for batched presentations (one Stream 1 entry per sub-token? one per batch?)?

**Deferral home:** App. C of this spec until the fork produces a coordinated S2-2 × S2-8 amendment.

### App. C.8 PII content statement (App. C)

App. C carries no PII. The scope-out matrix, back-propagation queue, commit_version log, open-questions table, author-lock surfaces, and fork pointers are operational artifacts.

---

**End of S2-8 Controlled-Use Access Sessions Specification.**

**Source-of-truth chain:**
- Architectural design: internal `/design` pipeline records (orient, six-alternative divergence, synthesis, destructive stress-test, anti-drift; not included in this repository)
- Originating frame: design-capture item A21 (with A22, A23, A24 design patterns; internal)
- Raw capture: internal raw-capture note, 2026-05-20 (not included in this repository)
- Voice-pass status: **pending Simon voice-pass** per §0.5

**Post-authoring verification per §16.5 was run; results reported in commit/PR description.**
