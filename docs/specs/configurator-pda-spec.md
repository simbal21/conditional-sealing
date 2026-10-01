# Cealis V2 / V3 Custody — Configurator + PDA Specification (S2-4)

## §0 — Front Matter

### §0.1 Document identity

This document is the Stage-2 Configurator + Partner Deployment Agreement specification for the Cealis V2 system with V3 custody architecture. It is S2-4 in the Stage-2 specification stack and is the canonical home for:

- the PDA+ platform configuration model;
- the PDA per-deployment model;
- the boundary-decision rule that classifies every configuration surface as PDA+, PDA pick, PDA parameter, or non-configurable architectural fact;
- the configurator emission flow from partner intent to frozen `pda_root`;
- the verification gate that prevents partner intent from producing a PDA outside the platform's permitted envelope;
- the governance shape for PDA+ surface changes;
- partner-readable PDA inspection and audit discipline.

This is a pure specification. It defines what a Cealis-internal configurator implementation, future Cealis engineers, and auditors must be able to validate. It does not implement code, validation libraries, Solidity contracts, REST handlers, or UI screens.

### §0.2 Audience and reading order

The primary audience is the Cealis-internal configurator engineer. Read this document end-to-end, then implement the shared validation model before implementing CLI, API, or UI entry points.

The second audience is future Cealis engineers onboarding to configurator logic. Read §0-§4 first to understand the boundary discipline, then §5 for the canonical placement registry, then §8-§14 for emission and evolution behavior.

The third audience is an external auditor. Start with §3, §4, §5, §10, §16, and §17. Those sections answer the audit questions: who is allowed to choose what, what is cryptographically non-negotiable, how invalid choices are rejected, and whether a post-commit update can alter reveal behavior.

A fourth audience, partner technical liaisons, consumes a simplified form of §7 and §8 through S2-5's partner-readable inspection surface. Partners see the decoded PDA they received and the classification of each field. They do not self-serve raw FSMs, raw PDA JSON, or on-chain deployment actions.

### §0.3 Terminology discipline

**V2 / V3.** V2 is the system version. V3 custody is the key-holding and reveal substrate inside the V2 system. This document never uses bare "V3" as a system version.

**PDA+.** PDA+ is Cealis-set platform configuration: allowed surfaces, allowed values, platform guardrails, template libraries, registry membership, governance cadences, and validation predicates that must be identical across partners.

**PDA.** PDA is the partner deployment agreement: the per-partner, per-deployment selection of values inside PDA+ surfaces. A PDA is frozen into `pda_root` and related commit metadata at commit time.

**Partner-immutable / category (d).** Some facts are not PDA+ governance surfaces at all. They are protocol facts or cryptographic invariants. A partner cannot choose them, and Cealis cannot change them through PDA+ governance alone.

**Categories.**

- **Category (a): PDA+ platform-set.** Cealis chooses the allowed surface, value set, bound, template, registry membership, or validation rule. Partners may consume it only through downstream PDA picks or parameters.
- **Category (b): PDA per-deployment pick.** The PDA chooses one discrete value from a PDA+ allow-list.
- **Category (c): PDA per-deployment parameter.** The PDA supplies a continuous or numeric value inside PDA+ min/max bounds.
- **Category (d): non-configurable architectural fact.** The fact is outside the configurator's discretion. It changes only through the protocol's versioning process and, where byte layout changes, coordinated `commit_version` governance.

**Cascade tests.** Test 1 is the cryptographic-invariant test. Test 1.5 is the invariant-derived rule test. Test 2 is the cross-PDA-class-invariant test. Test 3 is the discrete-vs-continuous test.

**Verification gate stages.** Stage 1 syntax, Stage 2 crypto-invariant, Stage 3 PDA+ allow-list and bounds, Stage 4 cross-field rules, Stage 5 simulation plus human Cealis-operator review.

**PDA+ governance sub-classes.** Sub-class 1 is TimelockController-7d additions. Sub-class 2 is CealisSecurityMultisig deprecations. Sub-class 3 is CealisSecurityMultisig with circuit breaker. Sub-class 4 is PDA+ conditional-rule constraint adjustment. Sub-class 5 is PDA+ conditional-rule addition, codepath-bound.

### §0.4 What this spec does not cover

This document does not define cryptographic byte layouts, `pda_root` preimage bytes, `commit_AAD`, Shamir reconstruction, AEAD, stanza formats, or σ verification. Those are S2-1 (`docs/specs/cryptography-spec.md`).

This document does not define Solidity contract interfaces, ConditionEngine ABI, Registry storage, `RevealAuthorized`, `DeprecationFlag`, `GateRecipientPubkeyRegistry`, or Mode 3 on-chain rejection. Those are S2-2 (`docs/specs/smart-contracts-spec.md`).

This document does not define Lit, dcipher, drand, G4 SDK calls, gate-recipient pubkey attestation details, cross-vendor TEE verification libraries, or combiner SDK internals. Those are S2-3 (`docs/specs/custody-integration-spec.md`).

This document does not define the partner-facing HTTP endpoint details, ingestion upload endpoints, vault delivery payloads, webhooks, or rendered partner API response schemas. Those are S2-5.

This document does not define operator runbooks, governance ceremony execution steps, key-rotation procedures, Timelock queue operations, or production incident processes. Those are S2-6.

This document does not define Poseidon commitments, PLONK circuits, SD salts, SD proof verification, or SD revocation semantics. Those are S2-7 (`docs/specs/sd-spec-v2.md`). This document only defines how the PDA maps fields into SD policies.

### §0.5 Status

Status: drafted for Stage-2 codification after the May 5 configurator-PDA design lock. This document treats `configurator-pda.md` (internal design note, not in this export) as binding and does not reopen its architectural decisions.

The post-backprop locks are inherited: `commit_version = 0x0302`, A1+Shamir DEK lifecycle, σ-as-authorization, `sdMerkleRoot` bound in S2-1 §4 `commit_AAD`, gate-recipient-pubkey-publication primitive, Mode 3 RESERVED enforcement, expanded `IDisclosureRegistry`, and cross-vendor TEE vendor-family normalization.

### §0.6 Source-of-truth ordering

For this document, the source ordering is:

1. `configurator-pda.md` (internal design note, not in this export) for the boundary-decision rule, cascade, class table obligations, governance sub-classes, default precedence, two-layer evolution, and long-TTL handling.
2. S2-1 for `pda_root`, `commit_AAD`, Shamir threshold, Mode 3 byte-level implications, and cross-spec author-locks.
3. S2-2 for ConditionEngine modules, registry contract surfaces, `DeprecationFlag`, `RevealAuthorized`, Mode 3 contract rejection, and `registerPDA`.
4. S2-3 for G3/G4 eligibility, gate-recipient pubkey lifecycle, commit-time TEE boundary, cross-vendor TEE vendor-family normalization, and combiner SDK boundaries.
5. S2-7 §12 for SD PDA field mapping.
6. Stage-0 decisions for full-engine scope, G3 defaults, Phase 2 G4 partner posture, all 9 condition modules, Mode A/B, full DSL/WASM, CLI/API plus internal UI, SD mandatory, and launch oracle set.
7. WP §F for conceptual PDA+/PDA framing, two-level configurability, trust tiers, challenge-window guardrails, template defaults, oracle discipline, and configurator discipline.

Within S2-4, this document is canonical for configurator emission flow, PDA data model, class-table placement, validation message shape, default-table application, and PDA+ governance-shape classification. Downstream S2-5 and S2-6 consume this document; they do not redefine the boundary.

### §0.7 Document discipline anchors

Rule 3 is active: Cealis is a data escrow system, not only identity escrow. The class table includes non-KYC compositions: HeartbeatMissed, DeadManSwitch, evidence retention, testament, M&A, archival, commercial and partner-fit surfaces.

Rule 12 is active: this is production-grade spec text. No placeholder field is left for implementers to decide.

Rule 26 is active: the class table explicitly covers Enforcement, Tamper-proof, Selective Disclosure, Commercial, Legal, Use-case flexibility, and Partner-fit. A configuration surface that serves one view must still be checked against the others.

Rule 28 is acknowledged: the design pass already captured the cascade-classification-test, PDA+-conditional-rule, and default-table-as-metadata frames. S2-4 references them but does not re-capture them.

Rule 30 is active: §17 cross-checks this document's language against WP §K banned phrasing. This spec is internal, but it must not leak public-copy shortcuts into canonical terminology.

Rule 31 is active: this is full engine scope. All 9 condition modules, both G3 choices, Mode A and Mode B, full DSL plus WASM surface, SD mapping, CLI/API and internal UI are in the model. Phasing remains real for G4 Phase 1 vs Phase 2, but no feature is scoped down because the first partner is a pilot.

Rule 33 is active: the design lock is not closure. This document is one propagation step. Remaining closure steps are tracked in §1.5 and must be handled by the Stage-2 owner after S2-4 lands.

Rule 34 is active: /design locked the model; this document codifies it.

Universal tripwire: no release path exists that bypasses the on-chain-verified predefined condition. The configurator MUST reject any PDA whose condition, recipient set, shred path, SD mapping, challenge settings, or registry choices allow data release outside that path.

Mode 3 RESERVED: `WALLET_EIP1271` is architected but rejected at V2 launch. S2-4 is the configurator rejection layer in the three-layer defense.

Apr 13 platform-pivot operationalization is narrowed: this document operationalizes the PDA+ vs PDA boundary required by the platform pivot. The three extensibility vectors already operationalize the condition layer.

### §0.8 Cross-reference index

S2-1 imports: §3 `pda_root`, §4 `commit_AAD` with `sdMerkleRoot`, §6.3 Shamir threshold, §17 cross-spec author-locks.

S2-2 imports: §4 ConditionEngine and 9 modules, §9 V3 registries and `DeprecationFlag`, §11 Mode 3 RESERVED enforcement, §12 `RevealAuthorized`, App. A `PdaRootFields`, `HCommitFields`, and `registerPDA`.

S2-3 imports: §2.2 G3/G4 selection, §2.4 cross-vendor TEE disjointness, §2.5 gate-recipient pubkey lifecycle, §7.9 commit-time G4 ingestion TEE boundary, §9.3-§9.4 combiner pre-verification and Shamir reconstruction.

S2-7 imports: §12 PDA field mapping.

Forward consumers: S2-5 for partner-readable PDA inspection, ingestion/delivery, and partner API details; S2-6 for governance ceremony shapes and operational runbooks.

### §0.9 PII content statement

PDA values may contain or imply personal data in off-chain contexts. Examples include schema field declarations, recipient bindings, delivery URLs, jurisdiction, legal-entity identifiers, and Art. 9 processing posture. `pda_root` and `commit_AAD` bind only fixed-width digests, enum values, scalar windows, and policy flags, but the source PDA JSON and partner-readable decoded PDA are not PII-free by default.

The configurator MUST apply PII discipline at three boundaries:

1. **Configurator logs.** Logs carry correlation IDs, field names, validation codes, hash digests, and class-table row IDs. They do not carry plaintext subject data, recipient private details, delivery URLs, attestation payload plaintext, σ values, Shamir shares, DEK, SD salts, or raw KYC fields.
2. **Partner inspection.** Partners may see their own decoded PDA, including recipient labels and schema terms they provided. That inspection surface is authenticated and scoped to the partner.
3. **Audit artifacts.** External audit exports use redacted values plus hashes unless the audit engagement explicitly requires the full PDA JSON under confidentiality controls.

## §1 — Conventions

### §1.1 Field encoding conventions

Configurator source objects are canonical JSON documents before hashing, pinning, and audit export. Canonical JSON means deterministic key ordering, UTF-8 encoding, no insignificant whitespace in the hashed form, and typed scalar representation for booleans, integers, enum strings, bytes32 hex strings, and CID strings.

`pda_root` is not computed by canonical JSON. It is computed exactly as S2-1 §3.3 specifies: fixed-width byte concatenation under `TAG_PDA_ROOT_V3` with the 29 fields in the S2-1 order. The source PDA JSON is the human and audit form; S2-1 §3.3 is the cryptographic form.

On-chain anchors and registry ids follow S2-1 and S2-2. When this document says a field is "bound into `pda_root`," it means the value or a digest/ref derived from it is one of the S2-1 §3.3 fields. When it says "bound into `commit_AAD`," it means the value or digest is in S2-1 §4 directly, or is transitively bound through `pda_root`.

SCALE is used only where S2-1 or S2-7 specifies SCALE structures, including `commit_AAD`, `conditional_recipients_policy_digest`, and SD field-policy commitments. The configurator does not invent a second encoding for those objects.

### §1.2 Class-table schema

The class table in §5 is normative. Each row has:

- `surface_name`: stable identifier for the configuration surface.
- `test_exited_on`: `1`, `1.5`, `2`, or `3`.
- `category`: `(a) PDA+`, `(b) PDA pick`, `(c) PDA parameter`, or `(d) architectural fact`.
- `governance_sub_class`: sub-class 1-5 for PDA+ surfaces, or `N/A`.
- `default_table_index`: `use-case`, `archetype`, `both`, or `none`.
- `cross_ref_to_pda_root_field`: S2-1 §3.3 field, `commit_AAD` field, S2-2 contract surface, S2-7 field policy, or off-chain PDA JSON field.
- `rationale`: the substantive reason the test exited where it did.

Any new configurator surface must land as a new row before it can be implemented. A field hidden in code but absent from §5 is non-conformant.

### §1.3 Error model

Validation messages are stage-indexed:

```
S2_4_STAGE_<N>.<SURFACE_NAME>.<CODE>
```

The internal audit form includes:

- stage number;
- surface name;
- failed predicate;
- category;
- governance sub-class if applicable;
- source field path;
- sanitized value class, not raw PII value;
- relevant S2-1/S2-2/S2-3/S2-7 cross-reference;
- remediation path: adjust PDA value, request PDA+ expansion, or impossible under V2.

The partner-facing form includes a shorter message:

- the field or concept that failed;
- why the current configuration cannot deploy;
- whether the partner can choose a different allowed option or must request a Cealis-internal PDA+ change.

Partner-facing messages never say "cryptographic-invariant violation" without a plain-language explanation. Example: "This recipient mode is reserved in V2; choosing it would create a reveal path the current chain and combiner reject."

### §1.4 Logging discipline

The configurator audit trail is append-only. It records:

- input form digest;
- translated PDA JSON digest;
- template ids and version refs;
- validation result set;
- simulation result digest;
- human reviewer identity digest;
- emitted `pda_root`;
- IPFS CIDs;
- on-chain transaction refs.

It does not log plaintext subject data, raw attestation payloads, raw recipient secrets, σ values, Shamir shares, DEK, SD salts, plaintext refusal reasons for sensitive G4 codes, or delivery URL bodies. When a recipient binding must be identified in logs, use row id plus hash digest.

### §1.5 Rule 33 propagation chain

S2-4 landing is not the end of propagation. The required chain after this file is:

1. `docs/specs/configurator-pda-spec.md` lands as S2-4.
2. The internal Stage-2 audit tracker's S2-4 row is marked drafted, with this file as the reference.
3. The internal phase-1 verification checklist (not included in this export) is checked for any S2-4-relevant open item; none are expected, but the check must be recorded.
4. The internal project-context summary is updated only if Simon approves the doc-status summary update.
5. Linear receives a detailed pointer comment for the relevant S2-4 tracking issue.
6. WP §F receives no automatic edit. If Simon wants the WP to point to S2-4 as the normative class table, that is a separate Rule 33 step requiring explicit confirmation because WP voice-pass sensitivity applies.

## §2 — Scope and Relationship to Other Stage-2 Specs

### §2.1 What S2-4 owns

S2-4 owns the configurator boundary. The implementation may have a CLI, API, and UI, but all three consume the same PDA model, class table, validator, default table, and emission flow. It is non-conformant to implement a CLI path that can emit a PDA the UI would reject, or a UI path that silently applies a different default than the API.

S2-4 owns:

- PDA+ data model: schema library, condition primitive set, FSM template library, registry allow-lists, DSL/WASM admissibility, retention bounds, SD defaults, shred guardrails, ingestion-mode availability, G4/G3 eligibility, challenge-window floors, cross-field rules, governance cadence metadata, trust-tier rules, and default tables.
- PDA data model: schema selection, condition template selection, condition parameters, oracle refs, trust-tier declaration, G3 choice, G4 phase, recipients, conditional recipients, shred authority, challenge windows, retention window, issuer mode, attestation requirements, submitter sets, pause authority, legal flags, jurisdiction, SD field mapping, commercial metadata, and partner-fit metadata.
- Configurator emission: partner intent translation, template selection, parameterization, validation, simulation, human review, canonical JSON, IPFS multi-pin, `pda_root` computation, on-chain commit handoff, and partner inspection handoff.
- Boundary governance: which PDA+ changes are additions, deprecations, emergency circuit-breaker actions, data-only rule-constraint updates, or codepath-bound rule additions.

### §2.2 Surfaces consumed from S2-1, S2-2, S2-3, and S2-7

From S2-1, this document consumes the 29-field `pda_root` layout, 22-field `commit_AAD`, Shamir threshold formula, `commit_version = 0x0302`, Mode 3 RESERVED defense, and cross-spec author-locks. S2-4 cannot add a new cryptographic byte field silently. If §5 identifies a needed cryptographic anchor not present in S2-1 §3.3 or §4, that is a BP-N candidate and requires coordinated S2-1/S2-4 author-lock work.

From S2-2, this document consumes the 9 condition modules and their invariants, ConditionEngine lifecycle, five V3 registries, `GateRecipientPubkeyRegistry`, `DisclosureRegistry`, `DeprecationFlag`, Mode 3 on-chain rejection, and `registerPDA` contract surface. S2-4 may require richer off-chain PDA JSON than `registerPDA` accepts, but any chain-enforced guardrail must be visible to S2-2 through refs, roots, flags, or validation inputs.

From S2-3, this document consumes G3/G4 eligibility, Phase 2 partner posture, gate-recipient pubkey lifecycle, commit-time TEE boundary, cross-vendor TEE vendor-family normalization, and combiner SDK abort rules. S2-4 decides whether a PDA is allowed to choose a path; S2-3 proves the path's runtime evidence.

From S2-7, this document consumes per-field `cleartext`, `zkp`, and `escrow_only` SD policy mapping. S2-4 rejects SD mappings not allowed by schema family, Mode B, proof-cost, claim-id, or revocation constraints.

### §2.3 Configurator-internal-only at all phases

The configurator is Cealis-internal. Partners request configurations, review structured summaries, and inspect deployed PDA outputs. Partners do not author raw FSM JSON, raw Claim AST, raw WASM predicate bindings, on-chain `registerPDA` calls, registry additions, or PDA+ guardrail changes.

This is not a UX preference. It is a platform-security mechanism. PDA+ guardrails are meaningful only if every emitted PDA passes one enforcement point. If partners could self-serve raw templates, they could accidentally or deliberately create a PDA outside the allowed platform range.

CLI/API and internal UI both exist. The CLI/API serves engineers and automation. The internal UI serves BD, policy, legal, and operations authors. Both call the same validation engine and produce byte-identical PDA JSON for the same inputs.

### §2.4 Apr 13 platform-pivot operationalization claim

The Apr 13 platform pivot says Cealis is a configurable data escrow platform whose use cases are configuration artifacts on shared crypto and custody primitives. S2-4 does not re-argue that pivot. It makes one required layer mechanically enforceable: the boundary between PDA+ and PDA.

The condition layer is operationalized by the three extensibility vectors: template composition, oracle onboarding, and DSL/WASM extension. S2-4 operationalizes the boundary layer: which surfaces are Cealis platform invariants, which are partner selections, which are parameters, and which are not configurable at all. Together these layers make "platform" a deployed mechanism rather than a prose label.

## §3 — The Boundary-Decision Rule (NORMATIVE)

### §3.1 The cascade

For any configuration surface `S`, apply the tests below in order and exit at the first classification. The cascade is mandatory for new fields, template additions, UI controls, API parameters, validator predicates, registry entries, and partner-facing default-table values.

The cascade mirrors the V3 registry-class discipline (internal design note, not in this export) one layer up. That design asked whether a registry key was CRYPTO or CATALOG by testing the key's primitive role. S2-4 asks whether a configuration surface is architectural fact, PDA+ guardrail, PDA pick, or PDA parameter by testing how the value participates in the protocol.

### §3.2 Test 1 — cryptographic-invariant test

Question: does `S` participate as input to a cryptographic invariant anchoring `pda_root`, `h_commit`, AEAD, Shamir reconstruction, σ-as-authorization, Mode 3 rejection, SD isolation, or universal AND-composition; or does its value space define a cryptographic primitive whose change requires `commit_version` coordination?

If yes, classify as category (d), non-configurable architectural fact.

Examples:

- σ-as-authorization doctrine.
- `commit_version = 0x0302` for A1+Shamir lifecycle.
- fixed-gate threshold base of 3: Lit V3 + G3 + G4.
- Mode 3 RESERVED rejection at V2 launch.
- SD pipeline failure does not block escrow.
- two pipelines never cross.
- no release path bypasses chain-verified condition.
- Shamir single-share leak is not DEK leak.

Category (d) facts are not PDA+ fields. They can be described in PDA inspection output, but no partner or Cealis operator can choose them inside the configurator.

### §3.3 Test 1.5 — invariant-derived rule test

Question: is `S` a derived rule that follows from a Test-1 invariant but operates as a validator at PDA layer?

If yes, classify as category (a), PDA+, with an explicit derivation pointer to the category (d) invariant.

Example: mandatory `NOT post_challenge_reveal_in_progress` on every shred condition. The universal tripwire is category (d). The mandatory shred guardrail is the PDA+ validator that enforces the destruction-axis mirror of that invariant. It is not a partner choice, but it is implemented as a configurator and contract rule, so it is category (a) with derivation pointer.

Test 1.5 exists because otherwise Test 1 and Test 2 collide. A derived cross-field rule can be both "required by a cryptographic invariant" and "implemented as platform validation." The row must show that relation explicitly.

### §3.4 Test 2 — cross-PDA-class-invariant test

Question: does `S` need to be the same across all partners, or does the legal, security, registry-coherence, or platform-quality constraint on what is pickable need to be identical across all partners?

If yes, classify as category (a), PDA+.

Examples:

- schema library membership and schema-level SD availability;
- FSM template library;
- OracleRegistry, OracleSchemaRegistry, DSLVersionRegistry, PluginHashRegistry, QTSPRegistry, and G4AuthorityRegistry admissibility;
- retention min/max bounds;
- allowed shred-authority modes per archetype;
- ingestion-mode availability;
- cross-field rules;
- refusal-reason encrypted defaults;
- Art. 9 basis enum;
- subject authenticator guardrail;
- trust-tier-to-oracle-tier consistency;
- default tables;
- governance cadence.

Category (a) surfaces may be data-only or codepath-bound. §6 assigns the governance sub-class.

### §3.5 Test 3 — discrete-vs-continuous test

Question: after Test 1, Test 1.5, and Test 2 all return no, does the partner choose one discrete value from a PDA+ allow-list, or supply a continuous value inside PDA+ bounds?

Discrete choices are category (b), PDA per-deployment pick. Examples: G3 choice, G4 phase, condition module template, oracle references, trust tier declaration, issuer mode, subject authenticator class, pause authority, ceremony resolver, shred authority, delivery mode, SD policy enum per field.

Continuous or numeric values are category (c), PDA per-deployment parameter. Examples: retention window, challenge windows, heartbeat interval, grace period, time-lock timestamp, conditional-recipient `n` and `k`, recipient list cardinality, bond amount, usage quota, per-PDA price tier value, and expiry windows.

Category (b) and (c) values are still bounded by PDA+. A partner cannot use "PDA field" to escape the allow-list or bounds.

### §3.6 Cascade exit semantics and row requirements

Each row in §5 records exactly one `test_exited_on` value. A row may mention downstream tests in the rationale, but classification is by first exit. If a surface appears to pass two tests, it must be decomposed into two rows: the invariant or derived rule, and the specific value constrained by it.

Example: Shamir threshold decomposes into:

- fixed base `3` for Lit + G3 + G4: category (d), Test 1;
- `conditional_recipients_policy.k` with `k <= n`: category (c) parameter plus PDA+ bounds, Test 3;
- cross-field threshold sanity `1 <= k <= n`: category (a) validation rule, Test 2.

No row may have "mixed" category. Hybrid surfaces must be decomposed.

Decomposed child rows use stable child ids under the original root id, for example `56.1` and `56.2`. The integer root id remains reserved for the original surface family; only the child rows are executable registry rows. Each child row still has exactly one category, one `test_exited_on`, one validation owner, and one partner-facing message path.

### §3.7 Analogy to v3-registry-class-discipline

The May 4 registry discipline classified V3 registries by whether the lookup key participated as a preimage at any cryptographic construction site. That avoided ad hoc "TAG-prefix yes/no" decisions.

S2-4 uses the same style: do not ask whether a field "feels platform-like" or "feels partner-specific." Ask what role the surface plays. If it anchors a cryptographic invariant, it is category (d). If it implements a derived guardrail, it is category (a) with derivation pointer. If it must be uniform across partners, it is category (a). If the partner chooses inside a closed set, it is category (b). If the partner supplies a bounded scalar, it is category (c).

Worked example: three configurator surfaces can look identical in UI because each is a dropdown-like control, but the cascade classifies them differently. `pause_authority_allowed_modes` is category (a) because the platform defines the allowed authority set `Partner / Joint / None`. `pause_authority_pick` is category (b) because the PDA selects one allowed authority. `minimum_shred_latency_value` is category (c) because the PDA supplies a bounded duration. Visual similarity is irrelevant; primitive role decides the class.

## §4 — Verification Gate (NORMATIVE)

### §4.1 Five-stage layered architecture

The configurator validates every PDA through five ordered stages:

1. Syntax.
2. Crypto-invariant.
3. PDA+ allow-list and bounds.
4. Cross-field rules.
5. Simulation plus human Cealis-operator review.

Stages run in order because later stages rely on normalized structures produced by earlier ones. Stage 4 emits all cross-field failures together; it does not short-circuit. Stage 5 runs only after Stages 1-4 pass.

Each invalid condition has one canonical rejection owner. Stage 2 owns protocol-impossible or cryptographically impossible values that are invalid independent of partner policy. Stage 3 owns single-field allow-list, bounds, registry liveness, and template-availability failures. Stage 4 owns relational failures between two or more otherwise-valid fields, including archetype defaults, opt-outs, and legal-effect combinations. Earlier stages may attach explanatory context, but they MUST NOT emit a duplicate primary validation error for a condition canonically owned by a later stage.

### §4.2 Stage 1 — syntax

Stage 1 validates form and type:

- required fields are present;
- unknown fields are rejected unless the schema version explicitly allows extension metadata;
- enum strings map to known enum identifiers;
- bytes32 values are 32-byte hex strings;
- CIDs parse;
- durations are integer seconds;
- booleans are booleans;
- recipient arrays and policy arrays are well-formed;
- canonical JSON can be produced;
- every referenced field path in schema mapping resolves to the submitted schema.

Stage 1 does not decide whether a syntactically valid enum is allowed. Mode 3 is syntactically valid and Stage 2 rejects it.

### §4.3 Stage 2 — crypto-invariant catalog

Stage 2 rejects any value that violates the closed catalog below. This catalog is the S2-4 analog of S2-1's TAG registry: named, finite, and auditable.

| ID | Invariant | Configurator check |
|---|---|---|
| `CI-01` | `commit_version = 0x0302` for new V2/V3-custody commits | Reject any new PDA emission targeting another commit version unless an explicit versioned migration ceremony exists. |
| `CI-02` | σ-as-authorization, not σ-as-IKM | Reject fields or templates that treat σ values as DEK material, HKDF IKM, stored secrets, or required confidential logs. |
| `CI-03` | A1+Shamir lifecycle | Reject templates that wrap full DEK to any single gate instead of one Shamir share per stanza. |
| `CI-04` | Fixed base threshold is 3 | Reject PDA parameters that try to remove Lit, G3, or G4 from the fixed gate set for new partner-ready commits. |
| `CI-05` | Global threshold is `3 + k_conditional` | Reject conditional-recipient policies whose threshold is not mapped to Shamir `k = 3 + k_conditional`. |
| `CI-06` | `1 <= k <= n` when `n > 0`; `k = 0` only when `n = 0` | Reject impossible or degenerate conditional-recipient thresholds. |
| `CI-07` | Mode 3 RESERVED | Reject `delivery_mode = WALLET_EIP1271` for active V2 PDAs. |
| `CI-08` | SD and escrow pipelines never cross | Reject SD plans that read custody σ, require reveal-time plaintext, or cause SD failure to block escrow sealing. |
| `CI-09` | Mode B is incompatible with TEE-side SD | Reject non-`escrow_only` SD mappings when ingestion mode is Mode B. |
| `CI-10` | `sdMerkleRoot` binding through S2-1 §4 | Reject SD-enabled PDA without a non-zero SD root plan; reject SD-off PDA that assigns non-`escrow_only` policy. |
| `CI-11` | No release path bypasses on-chain condition | Reject templates with delivery, recipient, fallback, resolver, or override path that can produce plaintext before `RevealAuthorized` and gate-signing eligibility. |
| `CI-12` | Shred cannot bypass reveal gate-signing window | Enforce mandatory `NOT post_challenge_reveal_in_progress` guardrail on every shred condition. |
| `CI-13` | `pda_root` uses S2-1 §3.3 29-field order | Reject alternate pda_root preimage, missing field, optional field omission, or non-zero app-specific extra cryptographic field. |
| `CI-14` | `commit_AAD` uses S2-1 §4 22-field structure | Reject alternate AAD field set or missing `sdMerkleRoot`. |
| `CI-15` | G4 phase semantics are fixed | Reject unknown phase ids or templates that represent Phase 1 as a cryptographic non-custody or partner-ready guarantee. The per-PDA legal-effect/partner-ready mismatch is canonically rejected by CF-05 at Stage 4. |
| `CI-16` | Cross-vendor TEE disjointness is mandatory for Phase 2 | Reject configurations that preselect a Lit/G4 vendor-family pair known to be identical; mark ambiguous vendor family as fail-closed pending S2-6 classification. |
| `CI-17` | Gate-recipient pubkey lifecycle is fixed by gate kind | Reject drand per-commit ephemeral expectation; reject Lit/G4/Conditional long-lived KEM mode where S2-3 requires per-commit ephemeral. |
| `CI-18` | Registry historical lookup discipline | Reject templates requiring current-head registry substitution for historical commit verification. |
| `CI-19` | Reveal and shred axes are separated | Reject a condition template where reveal terminal state implies shred terminal state or the reverse. |
| `CI-20` | DisclosureRegistry cannot authorize escrow reveal | Reject SD proof success as any input to `RevealAuthorized`. |

Adding a new Stage-2 invariant requires sub-class 5 governance and coordinated author-lock review. If the new invariant changes S2-1 byte layout or commit semantics, it also requires S2-1 governance and likely `commit_version` coordination.

### §4.4 Stage 3 — PDA+ allow-list and bounds

Stage 3 checks category (b) and category (c):

- every discrete choice is in the PDA+ allow-list effective for the selected archetype, use-case, trust tier, and date;
- every continuous parameter sits inside PDA+ min/max bounds;
- every registry reference exists, is effective, and is not tombstoned at the intended commit block;
- every template id is content-addressed and active;
- every schema family allows the requested SD plan;
- every oracle reference matches the trust tier declared by the PDA;
- every delivery mode is enabled for the role tag and launch surface;
- every issuer mode is allowed for the schema and partner type;
- every shred authority mode is allowed for the PDA type.

Stage 3 failures are normally partner-adjustable: choose a different allowed option, widen/narrow a scalar, or request Cealis to expand PDA+ through governance.

### §4.5 Stage 4 — cross-field rules

Stage 4 evaluates all cross-field rules and emits all failures together. The seven V2 rules are:

**Rule CF-01 — Art. 22 legal-effect safeguard.** If `legal_effect_expected = true` and any relevant reveal-side condition module is Tier B/C, all five conjuncts must hold:

1. `reveal_challenge_window >= archetype_floor`.
2. `ceremony_resolver.type in {human_endpoint, judicial_address}`.
3. `subject` is in `eligible_challengers_reveal`.
4. `minimum_shred_latency >= archetype_floor`.
5. `cealis_class_wide_halt_opt_out = false`.

For Tier A legal-effect PDAs, the challenge window is forced zero and Art. 22 posture relies on pre-commit informed consent, chain-native trigger determinism, and PDA-permitted crypto-shred.

**Rule CF-02 — legal-effect halt opt-out forbid.** If `legal_effect_expected = true`, `cealis_class_wide_halt_opt_out` must be false regardless of trust tier.

**Rule CF-03 — long-TTL conditional-recipient redundancy.** If `fire_time_ttl_estimate > 5 years` and `conditional_recipients_updatable = false`, require `n >= 2k` or `emergency_response_bricking_acknowledgment = true`.

**Rule CF-04 — SUBJECT_SELF liveness interlock.** If any conditional recipient has `role_tag = SUBJECT_SELF`, require `delivery_mode = PASSKEY_ACCOUNT` and `subject_liveness_required_at_fire = true`. For testament-style conditions where the subject is not alive at fire, `SUBJECT_SELF` is rejected.

**Rule CF-05 — legal-effect Phase 1 G4 forbid.** If `legal_effect_expected = true` or the PDA is partner-ready, `g4_phase` must be Phase 2.

**Rule CF-06 — trust-tier-to-oracle-tier consistency.** A Tier A PDA cannot reference Tier B or Tier C oracles on the relevant axis. A Tier B PDA cannot reference Tier C oracles unless the partner explicitly upgrades the PDA to Tier C. Tier C is most permissive but carries explicit partner acknowledgment and k-of-n defaults where irreversible.

**Rule CF-07 — irreversible-archetype MultiPartySignal default.** If the PDA archetype is irreversible or high-consequence and the firing condition depends on an external event source, the PDA must use k-of-n MultiPartySignal with `k >= 2` across independent oracle operators unless the selected PDA+ archetype template explicitly permits per-PDA opt-out and the partner supplies explicit acknowledgment.

Validation code: `CF-07_MULTIPARTY_SIGNAL_DEFAULT`.

Pass: `k >= 2`, `k <= n`, independent oracle operators, no duplicate signer identities, oracle refs at or above declared trust tier, and signal-digest binding across all signers.

Fail: missing MultiPartySignal default, `k > n`, duplicate signer identities, non-independent oracle operators, oracle refs below declared trust tier, or missing signal-digest binding.

Opt-out branch: per-PDA opt-out is valid only when the PDA+ archetype template permits opt-out and the partner acknowledgment is bound into the inspection surface. Class-wide opt-out requires sub-class 3 governance.

**Controlled-use cross-field rules (S2-8; sub-class 6 ControlledUseAccessPolicy).** When `token_policy_config.enabled = true`, the configurator additionally enforces the following six rules at Stage 4. Failures are emitted together with the CF-01..CF-07 rules and surface in the partner-readable validation report per §4.7.

**Rule CF-CU-01 — `commit_version` binding.** If `token_policy_config.enabled = true`, then `commit_version` MUST equal `0x0303` (per S2-1 §2.8.6 controlled-use profile additions). Conversely, if `commit_version != 0x0303`, then `token_policy_config.enabled` MUST be `false`. Validation code: `CF-CU-01_COMMIT_VERSION_MISMATCH`. The configurator REJECTS any PDA whose `commit_version` and `token_policy_config.enabled` disagree.

**Rule CF-CU-02 — controlled-use × SD forbid (F-9).** If `token_policy_config.enabled = true`, then `sd_election` MUST equal `DISABLED`. The configurator REJECTS any PDA whose `token_policy_config.enabled = true` AND `sd_election != DISABLED`. Validation code: `CF-CU-02_SD_FORBIDDEN_UNDER_CONTROLLED_USE`. This honors Stage-0 Q-0-7's mandatory-SD election as deferred to the App. C `/design` fork "A21-SD-integration" — until the fork is authored and a coordinated S2-7 amendment lands, controlled-use × SD is forbidden at PDA validation time.

**Rule CF-CU-03 — `stream2_cosign_gate` vendor-family consistency (H-4).** If `token_policy_config.audit_policy.stream2_cosign_gate ∈ {G3_DCIPHER, G3_DRAND}`, then the chosen gate-family MUST match `g3_choice`. Specifically: `stream2_cosign_gate = G3_DCIPHER` requires `g3_choice = dcipher`; `stream2_cosign_gate = G3_DRAND` requires `g3_choice = drand`. When `stream2_cosign_gate = G2_LIT`, no vendor-family-consistency rule against `g3_choice` applies (G2 Lit V3 is a separate vendor family from G3 per S2-3 §3 + §5 cross-vendor disjoint mandate). Validation code: `CF-CU-03_COSIGN_GATE_VENDOR_FAMILY_MISMATCH`.

**Rule CF-CU-04 — emergency-elevation requires subject visibility.** If `token_policy_config.emergency_elevation_policy.enabled = true`, then `token_policy_config.audit_policy.subject_checkpoint_mode` MUST be `OPT_IN` or `MANDATORY` (never `DISABLED`). Validation code: `CF-CU-04_EMERGENCY_ELEVATION_REQUIRES_SUBJECT_CHECKPOINT`. Emergency elevations are always subject-witnessable per H-3 accountability discipline; a deployment that fires emergency-elevation tokens but hides them from subjects is rejected at PDA validation time. The configurator additionally requires `emergency_elevation_policy.authority` to be a non-empty list when `emergency_elevation_policy.enabled = true` (S2-8 §3.2.8); empty authority list is `CF-CU-04_EMERGENCY_AUTHORITY_LIST_EMPTY`.

**Rule CF-CU-05 — DeadManSwitch × PresentedTokenCondition forbid (H-6).** If `token_policy_config.enabled = true` AND any reveal-side condition module includes both `DeadManSwitchModule` AND `PresentedTokenConditionModule` (per S2-2 §4.11.5), the composition is FORBIDDEN at PDA validation time. PresentedTokenCondition requires σ_holder (proof of life); DeadManSwitch fires on holder absence (proof of death). Logically self-canceling per design-capture A24. Validation code: `CF-CU-05_DEADMANSWITCH_PRESENTEDTOKEN_FORBIDDEN`. Partners needing "trustee acts on behalf of incapacitated subject" use `SubjectInitiatedModule(trustee_passkey)` + `ConsentGateModule` instead. The configurator REJECTS the composition; this is enforced before deployment, not at runtime.

**Rule CF-CU-06 — web-profile write coupling (H-8).** If `token_policy_config.web_profile_write_allowed = true`, then `token_policy_config.recommended_client_profile` MUST be `WEB_ONESHOT`. Writes-from-web are normative only under the one-shot profile per H-8 (the 100ms wipe + cache constraints in S2-8 §7.1 hold under WEB_ONESHOT and do not hold under NATIVE_SESSION or NATIVE_HEADLESS); a deployment electing `web_profile_write_allowed = true` under a native profile is rejected at PDA validation time. Validation code: `CF-CU-06_WEB_WRITE_REQUIRES_WEB_ONESHOT_PROFILE`. Partners using a native profile and wanting writes use the native write path; partners using web and wanting writes accept the one-shot profile.

The challenge-window guardrail is enforced through CF-01 and CF-06 plus Stage 3 archetype floors. Tier A with non-zero relevant-axis window is rejected; Tier B/C below floor is rejected.

### §4.6 Stage 5 — simulation plus human review

Stage 5 runs deterministic analysis:

- FSM reachability: every state reachable from initial; every terminal firing state reachable from at least one valid path.
- Axis separation: reveal and shred terminal states separated.
- Gas budget: worst-case `advanceFSM` and predicate paths within PDA budget.
- Schema compatibility: every Claim path type-checks against OracleSchemaRegistry examples.
- Canonical examples: each Claim passes registered valid examples and fails registered invalid examples.
- Challenge windows: zero-window and non-zero-window lifecycle paths replay correctly.
- Registry overlay: deprecated-before-authorization and deprecated-after-authorization paths replay according to §10.
- SD isolation: escrow succeeds when SD fails; non-`escrow_only` fields appear in audit diff.
- Recipient policy: conditional-recipient threshold and per-recipient delivery mode replay.
- Universal tripwire negative test: no delivery path fires before on-chain condition and gate eligibility.

After automated simulation, a human Cealis operator reviews:

- partner intent translation summary;
- decoded PDA;
- validation results;
- simulation digest;
- risk acknowledgments;
- partner-readable inspection preview.

Human review is halt-or-correct, not authority to waive validation. A reviewer cannot approve a Stage 1-4 failure.

### §4.7 Stage-indexed validation messages

The implementation MUST preserve both internal and partner-facing forms. Example:

Internal:

```
S2_4_STAGE_4.cealis_class_wide_halt_opt_out.LEGAL_EFFECT_FORBIDDEN
surface=cealis_class_wide_halt_opt_out
category=(b)
failed_rule=CF-02
value_class=boolean_true
source=WP §F Art.22 guardrail; S2-1 §3.3.4; S2-2 App.A PdaRootFields
remediation=set false or reclassify PDA as non-legal-effect with counsel-approved basis
```

Partner-facing:

```
This deployment expects legal effects, so it cannot opt out of Cealis's class-wide halt safety path. Set halt opt-out to false, or run a separate non-legal-effect deployment.
```

## §5 — Per-Surface Class Table (NORMATIVE)

> **See S2-8 (controlled-use spec) §3 for the new `token_policy_config` PDA field family and the ControlledUseAccessPolicy PDA+ governance sub-classification that this table extends with when a partner elects the controlled-use profile.**

### §5.1 Schema

The table below is the canonical placement registry. The row ids are stable. Implementations may store these rows in structured data, but the semantics here are normative.

Rows with integer ids are root surface families. Decomposed child ids use `<root>.<child>` suffixes and are the executable rows for that family. CI MUST count physical executable rows and also verify that integer root ids remain reserved and contiguous.

### §5.2 Canonical placement registry

| ID | surface_name | test_exited_on | category | governance_sub_class | default_table_index | cross_ref_to_pda_root_field | rationale |
|---|---|---:|---|---|---|---|---|
| 1 | `commit_version_0x0302` | 1 | (d) | N/A | none | `commit_AAD.commit_version` | A1+Shamir changes commit semantics; configurator cannot vary it per partner. |
| 2 | `sigma_as_authorization` | 1 | (d) | N/A | none | S2-1 §6.3 / §14 | σ authorizes share admission; treating σ as key material breaks realizability and doctrine. |
| 3 | `fixed_gate_set_lit_g3_g4` | 1 | (d) | N/A | none | `commit_AAD` gate refs | New partner-ready commits require Lit, G3, and G4 fixed shares. |
| 4 | `shamir_fixed_threshold_base_3` | 1 | (d) | N/A | none | S2-1 §6.3 | The base threshold equals the three fixed custody gates and is not a PDA knob. |
| 5 | `shamir_conditional_threshold_k` | 3 | (c) | N/A | archetype | `commit_AAD.conditional_recipients_policy_digest` | `k_conditional` varies by PDA but must satisfy PDA+ bounds. |
| 6 | `conditional_recipients_policy_bounds` | 2 | (a) | 4 | archetype | `conditional_recipients_updatable`, AAD policy digest | Bounds on `n`, `k`, role tags, and modes preserve reveal correctness across PDAs. |
| 7 | `mode_3_reserved` | 1 | (d) | N/A | none | S2-2 §11 / S2-1 Mode 3 | Mode 3 is architected but not active; no PDA can enable it at V2 launch. |
| 8 | `sd_failure_does_not_block_escrow` | 1 | (d) | N/A | none | `sdMerkleRoot` / S2-7 §12 | SD is parallel; escrow commit cannot depend on SD success. |
| 9 | `sd_schema_availability` | 2 | (a) | 1/2 | archetype | S2-7 §12.2 | PDA+ decides which schema families may emit SD outputs. |
| 10 | `sd_field_policy` | 3 | (b) | N/A | none | S2-7 §12.1 / `sdMerkleRoot` | Partner picks `cleartext`, `zkp`, or `escrow_only` per field from PDA+ policy. |
| 11 | `schema_library` | 2 | (a) | 1/2 | archetype | `schema_digest` via `h_commit` | Templates are convenience starts, not a closed catalog; PDA+ governs library membership. |
| 12 | `schema_selection` | 3 | (b) | N/A | archetype | `schema_digest` via `h_commit` | PDA picks or derives a schema from the library; digest binds actual schema. |
| 13 | `art_9_basis_taxonomy` | 2 | (a) | 4 | archetype | `art_9_basis_id` | PDA+ owns the closed Art. 9(2) basis taxonomy; this row is not the per-PDA selected value. |
| 14 | `art_9_scoped_flag` | 3 | (b) | N/A | archetype | `art_9_scoped` | PDA declares whether special-category processing applies; guardrail requires basis when true. |
| 14.1 | `art_9_basis_id_pick` | 3 | (b) | N/A | archetype | `art_9_basis_id` | Required when `art_9_scoped = true`; PDA selects one taxonomy value from PDA+ and zeros the field when out of scope. |
| 15 | `legal_effect_classification_rule` | 2 | (a) | 4 | archetype | `legal_effect_expected` | PDA+ owns the rule that derives legal-effect posture and mandatory guardrails; partners cannot self-label around it. |
| 15.1 | `legal_effect_expected_value` | 3 | (b) | N/A | archetype | `legal_effect_expected` | Frozen per-PDA value set or derived by Cealis operator under the classification rule; partner inspection only, not partner-free-form. |
| 16 | `subject_authenticator_class_allowlist` | 2 | (a) | 4 | archetype | `subject_authenticator_class` | PDA+ maps legal-effect posture to allowed authenticator classes. |
| 17 | `subject_authenticator_class_pick` | 3 | (b) | N/A | archetype | `subject_authenticator_class` | PDA chooses platform authenticator, QTSP QES, or synced passkey where allowed. |
| 18 | `qes_subject_required` | 3 | (b) | N/A | archetype | `qtsp_provider_ref` zero/non-zero | Partner elects §371a/QTSP posture; default remains §286 unless selected. |
| 19 | `qtsp_registry` | 2 | (a) | 1/2 | none | `qtsp_provider_ref` | QTSP membership is uniform registry governance, not per-partner free text. |
| 20 | `refusal_reason_encrypted_default` | 2 | (a) | 4 | none | off-chain PDA JSON / G4 policy | Fundamental-rights refusal codes default encrypted across PDAs. |
| 21 | `cealis_class_wide_halt_opt_out` | 3 | (b) | N/A | archetype | `cealis_class_wide_halt_opt_out` | Non-legal-effect PDAs may elect opt-out; legal-effect guardrail rejects it. |
| 22 | `mandatory_shred_guardrail` | 1.5 | (a) | 5 | none | `shred_condition_spec_hash` | Derived from universal tripwire; every shred condition must include `NOT post_challenge_reveal_in_progress`. |
| 23 | `shred_authority_allowed_modes` | 2 | (a) | 4 | archetype | `shred_authority_id` via `h_commit` | PDA+ defines which of Subject, Joint, Operator, Timelock, Disabled are allowed per type. |
| 24 | `shred_authority_pick` | 3 | (b) | N/A | archetype | `shred_authority_id` via `h_commit` | PDA chooses one allowed authority mode. |
| 25 | `shred_condition_template_library` | 2 | (a) | 1/2 | archetype | `shred_condition_spec_hash`, `template_id` | PDA+ controls available shred templates and deprecates bad ones. |
| 26 | `shred_condition_pick` | 3 | (b) | N/A | archetype | `shred_condition_mode`, `shred_condition_spec_hash` | PDA picks Mode P/F template and parameters inside PDA+ guardrails. |
| 27 | `minimum_shred_latency_floor` | 2 | (a) | 4 | archetype | `minimum_shred_latency` | PDA+ floors preserve legal and emergency response windows. |
| 28 | `minimum_shred_latency_value` | 3 | (c) | N/A | archetype | `minimum_shred_latency` | PDA can lengthen inside min/max; cannot undercut floor. |
| 29 | `reveal_challenge_window_floor` | 2 | (a) | 4 | archetype | `reveal_challenge_window` via `h_commit` | Tier A requires zero; Tier B/C requires archetype floor. |
| 30 | `reveal_challenge_window_value` | 3 | (c) | N/A | archetype | `reveal_challenge_window` via `h_commit` | PDA supplies duration inside tier/archetype bounds. |
| 31 | `shred_challenge_window_floor` | 2 | (a) | 4 | archetype | `shred_challenge_window` via `h_commit` | Same tier logic applies independently to shred axis. |
| 32 | `shred_challenge_window_value` | 3 | (c) | N/A | archetype | `shred_challenge_window` via `h_commit` | PDA supplies shred window inside PDA+ bounds. |
| 33 | `ceremony_resolver_type_allowlist` | 2 | (a) | 4 | archetype | `ceremony_resolver_id` | Legal-effect Tier B/C PDAs require active human/judicial endpoint class. |
| 34 | `ceremony_resolver_pick` | 3 | (b) | N/A | archetype | `ceremony_resolver_id` | PDA chooses resolver address/type from allowed classes. |
| 35 | `eligible_challenger_roles_allowlist` | 2 | (a) | 4 | archetype | challenger roots | PDA+ defines eligible role set shape. |
| 36 | `eligible_challengers_reveal` | 3 | (b) | N/A | archetype | `eligible_challengers_reveal_root` | PDA chooses roles and named observers; root binds result. |
| 37 | `eligible_challengers_shred` | 3 | (b) | N/A | archetype | `eligible_challengers_shred_root` | Same for shred axis. |
| 38 | `ingestion_mode_availability` | 2 | (a) | 1/2 | archetype | off-chain PDA JSON; affects TEE/device path | PDA+ enables Mode A/B availability; Mode B rules are uniform. |
| 39 | `ingestion_mode_pick` | 3 | (b) | N/A | archetype | off-chain PDA JSON; commit evidence | PDA chooses Mode A or Mode B where enabled. |
| 40 | `g3_default_table` | 2 | (a) | 4 | both | `g3_choice` via `commit_AAD` | PDA+ supplies use-case and archetype defaults for dcipher/drand. |
| 41 | `g3_choice` | 3 | (b) | N/A | use-case | `commit_AAD.g3_choice` | PDA chooses dcipher or drand; both are first-class. |
| 42 | `g4_phase_guardrail` | 2 | (a) | 4 | archetype | `commit_AAD.phase` | Partner-ready and legal-effect PDAs require Phase 2. |
| 43 | `g4_phase_pick` | 3 | (b) | N/A | archetype | `commit_AAD.phase` | PDA can represent Phase 1 only for dev-scaffold/historical cases. |
| 44 | `cross_vendor_tee_rule` | 2 | (a) | 5 | none | S2-3 §2.4 | Vendor-family normalization is a platform validator, checked again at reveal. |
| 45 | `gate_recipient_pubkey_lifecycle` | 1 | (d) | N/A | none | S2-3 §2.5 / S2-2 §9.10A | Gate kind fixes ephemeral vs long-lived pubkey model; PDA cannot change it. |
| 46 | `oracle_registry` | 2 | (a) | 1/2 | none | `oracle_references_root` | Oracle admission and deprecation are cross-PDA platform governance. |
| 47 | `oracle_reference_pick` | 3 | (b) | N/A | archetype | `oracle_references_root` | PDA picks oracle refs from registry. |
| 48 | `oracle_schema_registry` | 2 | (a) | 1/2 | none | S2-2 §9 / schema refs | Claim replay examples and schema hashes must be platform-governed. |
| 49 | `dsl_version_registry` | 2 | (a) | 1/2 | none | `dsl_version` | DSL versions are platform interpreter surfaces. |
| 50 | `dsl_version_pick` | 3 | (b) | N/A | archetype | `dsl_version` | PDA binds one enabled DSL version. |
| 51 | `wasm_predicate_whitelist` | 2 | (a) | 1/2/5 | none | `wasm_predicate_hashes_root` | WASM predicates require platform audit and enablement. |
| 52 | `wasm_predicate_pick` | 3 | (b) | N/A | archetype | `wasm_predicate_hashes_root` | PDA may reference enabled predicate hashes only. |
| 53 | `fsm_template_library` | 2 | (a) | 1/2 | archetype | `template_id`, condition spec hashes | Templates are content-addressed PDA+ artifacts. |
| 54 | `template_id_pick` | 3 | (b) | N/A | archetype | `template_id` | PDA picks one content-addressed template. |
| 55 | `condition_parameter_values` | 3 | (c) | N/A | archetype | condition spec hashes | Timing, amount, threshold, and grace values are PDA parameters. |
| 56.1 | `payment_obligation_template_pick` | 3 | (b) | N/A | use-case | reveal condition spec / template_id | PDA picks an active content-addressed PaymentObligation template from the PDA+ allow-list. |
| 56.2 | `payment_obligation_parameter_values` | 3 | (c) | N/A | use-case | reveal condition spec | Amount, deadline, grace, dispute, and obligation scalars are PDA parameters inside PDA+ bounds. |
| 57 | `timelock_target_timestamp` | 3 | (c) | N/A | use-case | reveal condition spec hash | TimeLock target varies per PDA; zero disallowed except test fixtures. |
| 58 | `subject_initiated_axis` | 3 | (b) | N/A | archetype | reveal/shred condition spec hash | PDA decides subject-initiated reveal or shred patterns where allowed. |
| 59 | `heartbeat_missed_cadence` | 3 | (c) | N/A | use-case | condition spec hash | Heartbeat interval/grace is non-KYC composition surface. |
| 60.1 | `oracle_attestation_reference_pick` | 3 | (b) | N/A | archetype | oracle root, DSL version, spec hash | PDA picks oracle ref, schema, DSL version, and claim template from active PDA+ registries. |
| 60.2 | `oracle_attestation_claim_parameters` | 3 | (c) | N/A | archetype | condition spec hash | Thresholds, expiry, replay, confidence, freshness, and claim scalar values stay inside PDA+ bounds. |
| 61 | `multiparty_signal_threshold` | 3 | (c) | N/A | archetype | condition spec hash | M&A and irreversible use cases set k-of-n thresholds within bounds. |
| 62.1 | `dead_man_switch_evidence_template_pick` | 3 | (b) | N/A | use-case | condition spec hash | PDA picks a liveness, evidence, notification, and beneficiary template from PDA+ allowed templates. |
| 62.2 | `dead_man_switch_evidence_parameters` | 3 | (c) | N/A | use-case | condition spec hash | Grace window, notification delay, beneficiary count, evidence expiry, and cadence-adjacent scalars stay inside bounds. |
| 63.1 | `consent_gate_authority_set_pick` | 3 | (b) | N/A | archetype | condition spec hash | PDA picks authority roles, addresses, or set root from allowed authority classes. |
| 63.2 | `consent_gate_threshold_value` | 3 | (c) | N/A | archetype | condition spec hash | PDA sets k-of-n threshold, quorum, and cardinality inside bounds; ConsentGate cannot alter reveal content. |
| 64.1 | `composed_module_child_picks` | 3 | (b) | N/A | archetype | condition spec hash | PDA picks child modules and operators from PDA+ allow-lists. |
| 64.2 | `composed_module_tree_parameters` | 3 | (c) | N/A | archetype | condition spec hash | PDA sets depth, child count, arity, thresholds, and ordering caps inside PDA+ bounds. |
| 65 | `retention_window_bounds` | 2 | (a) | 4 | archetype | `h_commit.retention_window` | Platform min/max protect legal and crypto-aging invariants. |
| 66 | `retention_window_value` | 3 | (c) | N/A | archetype | `h_commit.retention_window` | PDA supplies retention duration inside bounds. |
| 67 | `evidence_retention_bounds` | 2 | (a) | 4 | use-case | retention + shred condition | Evidence PDAs require bounded retention and cannot silently loosen shred. |
| 68 | `archival_permanent_shred_disabled` | 3 | (b) | N/A | use-case | `shred_authority_id`, condition hash | Permanent archival may choose Disabled authority where template permits. |
| 69.1 | `testament_flow_template_pick` | 3 | (b) | N/A | use-case | conditional policy + condition hash | PDA picks testament, vital-record, dead-man path, and role-tag template from PDA+ allowed templates. |
| 69.2 | `testament_flow_parameters` | 3 | (c) | N/A | use-case | conditional policy + condition hash | PDA sets vital-record k-of-n, recipient count, TTL, update windows, and long-retention scalars inside bounds. |
| 70 | `ma_multi_party_signal_defaults` | 2 | (a) | 4 | archetype | condition spec defaults | M&A templates require board/counsel/acquirer threshold defaults as platform metadata. |
| 71 | `trust_tier_taxonomy` | 2 | (a) | 4 | none | off-chain PDA JSON; artifact field | Tier A/B/C semantics are platform-defined. |
| 72 | `trust_tier_declaration` | 3 | (b) | N/A | archetype | condition spec / artifact | PDA declares tier, then CF-06 verifies oracle consistency. |
| 73 | `pause_authority_allowed_modes` | 2 | (a) | 4 | archetype | `pause_authority_id` | Platform bounds pause to Partner, Joint, or None only; this is not the shred-authority enum. |
| 74 | `pause_authority_pick` | 3 | (b) | N/A | archetype | `pause_authority_id` | PDA chooses one pause authority. |
| 75 | `issuer_mode` | 3 | (b) | N/A | use-case | subject commitment derivation | PDA picks external issuer, self-sovereign, or asset-not-person mode. |
| 76 | `attestation_requirements_per_field` | 3 | (b) | N/A | archetype | `p15_attestations_root` | PDA chooses self-declared vs externally attested per field. |
| 77.1 | `submitter_set_mode_pick` | 3 | (b) | N/A | archetype | `submitter_sets_root` | PDA picks oracle-self-only, relayer-set, or permitted submitter class from PDA+ allow-list. |
| 77.2 | `submitter_set_parameters` | 3 | (c) | N/A | archetype | `submitter_sets_root` | PDA sets submitter count, quorum, expiry, and per-set bounds inside PDA+ limits. |
| 78 | `applicable_jurisdiction_shape` | 2 | (a) | 4 | archetype | `applicable_jurisdiction` | Scalar vs set-valued jurisdiction is platform-gated by archetype. |
| 79.1 | `applicable_jurisdiction_code_pick` | 3 | (b) | N/A | archetype | `applicable_jurisdiction` | PDA picks scalar jurisdiction code or each set member from PDA+ jurisdiction taxonomy. |
| 79.2 | `applicable_jurisdiction_set_parameters` | 3 | (c) | N/A | archetype | `applicable_jurisdiction` | When set-valued shape is enabled, PDA sets max size, required coverage, and min-count bounds. |
| 80 | `pda_updatable_default` | 2 | (a) | 4 | archetype | `pda_updatable` | Long-TTL defaults to updatable to manage emergency bricking risk. |
| 81 | `pda_updatable_pick` | 3 | (b) | N/A | archetype | `pda_updatable` | PDA may choose immutability with required acknowledgment. |
| 82 | `conditional_recipients_updatable_pick` | 3 | (b) | N/A | archetype | `conditional_recipients_updatable` | Subject-recipient updateability is PDA choice within long-TTL guardrail. |
| 83 | `emergency_response_bricking_ack` | 3 | (b) | N/A | archetype | `emergency_response_bricking_acknowledgment` | PDA records subject acknowledgment when choosing long-TTL immutability. |
| 84 | `time_critical_pda_flag` | 3 | (b) | N/A | archetype | `time_critical_pda_flag` | PDA flags affirmative-harm deadline risk; validator forces updatability. |
| 85 | `default_table_use_case_index` | 2 | (a) | 4 | use-case | template metadata | Use-case defaults are platform metadata, not a fifth category. |
| 86 | `default_table_archetype_index` | 2 | (a) | 4 | archetype | template metadata | Archetype defaults are platform metadata and fallback when use-case absent. |
| 87.1 | `per_pda_pricing_tier_pick` | 3 | (b) | N/A | commercial | off-chain PDA JSON; billing system | Commercial view: PDA picks a billing catalog tier; price tier is not a cryptographic invariant. |
| 87.2 | `per_pda_pricing_amounts` | 3 | (c) | N/A | commercial | off-chain PDA JSON; billing system | Commercial view: retainer, per-identity, per-obligation, per-reveal, percentage, cap, and floor values stay inside billing bounds. |
| 88 | `per_pda_usage_quota` | 3 | (c) | N/A | commercial | off-chain PDA JSON; S2-5 rate limits | Commercial view: quota bounds API/ops load but cannot alter reveal correctness. |
| 89 | `partner_onboarding_archetype` | 3 | (b) | N/A | partner-fit | off-chain PDA JSON | Partner-fit view: archetype drives defaults and review path. |
| 90.1 | `partner_legal_entity_jurisdiction_pick` | 3 | (b) | N/A | partner-fit | off-chain PDA JSON / legal packet | Partner-fit/legal view: PDA picks incorporation or regulatory jurisdiction code from legal taxonomy. |
| 90.2 | `partner_legal_entity_jurisdiction_set_parameters` | 3 | (c) | N/A | partner-fit | off-chain PDA JSON / legal packet | When legal packet allows multi-jurisdiction context, PDA sets set size, effective-date, and review-window bounds. |
| 91 | `partner_readable_inspection_surface` | 2 | (a) | 4 | none | S2-5 forward ref | Platform must expose decoded PDA for partner review; partners cannot edit it. |
| 92 | `token_policy_config.enabled` | 3 | (b) | 6 | use-case | `token_policy_config.enabled` (controlled-use; S2-8 §3.2) | PDA elects controlled-use profile; gates `commit_version = 0x0303` per S2-1 §2.8.6. Forbids `sd_election != DISABLED` per S2-8 §3.2.10 / F-9. |
| 93 | `token_policy_config.master_token_classes` | 3 | (b) | 6 | archetype | off-chain PDA JSON; class set per S2-8 §2.2 | PDA selects subset of nine token classes the deployment activates from PDA+ ControlledUseAccessPolicy allow-list. |
| 94 | `token_policy_config.sub_token_lifetime_default_seconds` | 3 | (c) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2 | Default sub-token TTL (u64, default 300 s per H-7). |
| 95 | `token_policy_config.recommended_sub_token_max_ttl_seconds` | 3 | (c) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2 / H-7 | Maximum allowable sub-token TTL per H-7 time-of-check / time-of-use boundary. |
| 96 | `token_policy_config.scope_field_grammar.allowed_forms` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §1.5 | PDA picks allowed scope-grammar forms `{SINGLE_SLICE, MULTI_SLICE_SUBSET, MASTER_WILDCARD}` from PDA+ enum. |
| 97 | `token_policy_config.scope_field_grammar.slice_atomicity_allowed` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §1.5 / F-15 | Whether a master token may satisfy a multi-slice PresentedTokenCondition op atomically (per F-15). |
| 98.1 | `token_policy_config.slice_layout.slices_template` | 2 | (a) | 6 | archetype | `pda_slice_layout_anchor` (S2-2 §9.16B; controlled-use) | Slice-layout schemas + write/read authority matrices authored Cealis-internal under ControlledUseAccessPolicy review; partners cannot author raw. |
| 98.2 | `token_policy_config.slice_layout.slices_pick` | 3 | (b) | 6 | archetype | `pda_slice_layout_anchor` (S2-2 §9.16B; controlled-use) | PDA instantiates slice declarations (slice_id, schema_hash, write_authority_matrix, read_authority_matrix, slice_dek_policy) from PDA+ allowed templates per S2-8 §3.2.2. |
| 99 | `token_policy_config.slice_layout.evolution_policy` | 3 | (b) | 6 | archetype | off-chain PDA JSON; F-10 | Enum `{FROZEN_SCOPE, REISSUE_REQUIRED}` (default `FROZEN_SCOPE`); slice topology evolution semantics per §10 + S2-8 §5.7. |
| 100 | `token_policy_config.cache_policy` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2 / H-8 | Enum `{NONE, EPHEMERAL_ONLY, ENCRYPTED_CACHE_OPT_IN}` (default `EPHEMERAL_ONLY`); web profile constraint per H-8. |
| 101 | `token_policy_config.recommended_client_profile` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §7 / F-13 | Cealis-internal recommendation `{WEB_ONESHOT, NATIVE_SESSION, NATIVE_HEADLESS}` per archetype. |
| 102 | `token_policy_config.partner_may_strengthen_profile` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.4 / F-13 | Boolean (default `true`); partner may force a stronger-wipe profile, never weaker. |
| 103 | `token_policy_config.web_profile_write_allowed` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.5 / H-8 | Boolean (default `true` for `WEB_ONESHOT`); requires `recommended_client_profile = WEB_ONESHOT` (cross-field rule CF-CU-06). |
| 104 | `token_policy_config.first_presentation_gas_attribution` | 3 | (b) | 6 | use-case | off-chain PDA JSON; S2-8 §3.2.9 / F-12 | Enum `{HOLDER, PARTNER_META_TX, SUBJECT, NONE_CHAIN_SUBSIDIZED}` (default `PARTNER_META_TX`) — who pays the first-presentation anchor SSTORE. |
| 105.1 | `token_policy_config.audit_policy.stream1_retention_class` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.6 / F-19 | Enum `{PDA_DEFAULT, ART17_SHREDDABLE, DEEPER_ERASURE_OPT_IN}` (default `ART17_SHREDDABLE`); Stream 1 retention. |
| 105.2 | `token_policy_config.audit_policy.stream2_retention_class` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.6 / F-19 | Enum `{ART5_ACCOUNTABILITY, DEEPER_ERASURE_OPT_IN}` (default `ART5_ACCOUNTABILITY`); `DEEPER_ERASURE_OPT_IN` DEFAULT-FORBIDDEN at configurator review per F-19 — counsel sign-off gate required. |
| 105.3 | `token_policy_config.audit_policy.stream2_cosign_gate` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-2 §11.5 / S2-1 §1.9 (S2-8 §1.9) / H-4 | Enum `{G2_LIT, G3_DCIPHER, G3_DRAND}`; vendor-family-consistency with `g3_choice` enforced by cross-field rule CF-CU-03. |
| 105.4 | `token_policy_config.audit_policy.stream2_pepper_root` | 3 | (c) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.6 / F-14 | `bytes32`; deployment-scoped audit-pepper-epoch-0 root commitment (H-3 + F-14). The pepper itself is partner-held off-chain; the on-chain root commits to `pepper_epoch_number` per S2-8 §3.2.6; partners rotate epochs to limit blast radius of a single-epoch leak. |
| 105.5 | `token_policy_config.audit_policy.stream2_content_shape_digest_enabled` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.6 / H-3 | Boolean (DEFAULT-ON for regulator-audit-subject partners; PDA-configurable OFF for max-subject-privacy). |
| 105.6 | `token_policy_config.audit_policy.subject_checkpoint_mode` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.6 / Alt-D | Enum `{DISABLED, OPT_IN, MANDATORY}`; required `!= DISABLED` when `emergency_elevation_policy.enabled = true` (CF-CU-04). |
| 105.7 | `token_policy_config.audit_policy.regulator_anchor_mode` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.6 / Alt-E | Enum `{DISABLED, OPT_IN, MANDATORY}`; Stream 2 anchor co-publication to regulator mirror. |
| 106 | `token_policy_config.revocation_mode` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-2 §9.16C/D / S2-8 §3.2.7 | Enum `{MASTER_ONLY, MASTER_AND_SUB_CRL}` (default `MASTER_ONLY`); opt-in per-sub-token CRL (TokenRevocationRegistry deployed iff at least one PDA elects MASTER_AND_SUB_CRL). |
| 107.1 | `token_policy_config.emergency_elevation_policy.enabled` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.8 / F-COS-6 | Boolean (default `false`); HL7 BTG-aligned emergency-elevation token authority. |
| 107.2 | `token_policy_config.emergency_elevation_policy.authority` | 3 | (c) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.8 | List of EVM addresses authorized to issue emergency-elevation tokens; required non-empty if `enabled = true`. |
| 107.3 | `token_policy_config.emergency_elevation_policy.audit_class` | 3 | (b) | 6 | archetype | off-chain PDA JSON; S2-8 §3.2.8 | Enum forced to `STREAM2_ALWAYS_LOGGED` when `enabled = true` (every emergency-elevation presentation produces a Stream 2 entry regardless of `stream1_retention_class`). |

No executable row has a mixed category. Former hybrid source objects are decomposed into child rows with stable suffix ids; each child row maps to exactly one Stage 3 validation mode.

Rows 92 through 107.3 form the controlled-use `token_policy_config` field family per S2-8 §3.2. The full family is class PDA+ ControlledUseAccessPolicy at the governance layer (sub-class 6, defined in §6.5A); the per-field placement above maps each value-bearing surface to its Stage 3 / Stage 4 validation mode under that PDA+ sub-class. All controlled-use rows are gated by `token_policy_config.enabled = true` (row 92); when disabled, rows 93 through 107.3 are inert and absent from the PDA's normative surface.

### §5.3 Required additions from ground-check

The table includes non-KYC composition surfaces: `heartbeat_missed_cadence`, `dead_man_switch_evidence_template_pick`, `dead_man_switch_evidence_parameters`, `multiparty_signal_threshold`, `evidence_retention_bounds`, `archival_permanent_shred_disabled`, `testament_flow_template_pick`, `testament_flow_parameters`, and `ma_multi_party_signal_defaults`.

The table includes Commercial-view surfaces: `per_pda_pricing_tier_pick`, `per_pda_pricing_amounts`, and `per_pda_usage_quota`.

The table includes Partner-fit surfaces: `partner_onboarding_archetype`, `partner_legal_entity_jurisdiction_pick`, and `partner_legal_entity_jurisdiction_set_parameters`.

The table includes the explicit trust-tier row pair: `trust_tier_taxonomy` and `trust_tier_declaration`.

### §5.4 CI-style consistency check

An implementation MUST expose an internal consistency check over the table:

- physical executable row count is 103 for the pre-controlled-use surface; 128 when controlled-use rows 92-107.3 are active (rows 98, 105, 107 decompose into child suffixes, adding 25 controlled-use rows total);
- integer root ids are contiguous from 1 through 107 (rows 92-107 are the controlled-use extension, sub-class 6 ControlledUseAccessPolicy per S2-8 §3.2);
- child ids are unique, suffixed under an existing integer root, and contiguous within that root;
- `surface_name` values are unique;
- every row has exactly one `test_exited_on`;
- every category (a) row has a governance sub-class or composition;
- every category (b)/(c) row has a PDA+ allow-list or bound;
- every `cross_ref_to_pda_root_field` either maps to S2-1 §3.3 / §4, S2-2, S2-7, or is explicitly off-chain PDA JSON;
- no duplicate "issuer mode" row exists;
- every row id referenced by the coverage sidecar exists;
- all 9 condition modules appear at least once in the coverage sidecar (10 condition modules when controlled-use is active and PresentedTokenCondition per S2-2 §4.11.5 is included);
- all 7 views appear at least once in the coverage sidecar;
- when any PDA elects `token_policy_config.enabled = true`, every controlled-use row 92-107.3 has a value, and the cross-field rules CF-CU-01..CF-CU-06 (§4.5) all PASS.

### §5.4A Coverage sidecar for CI

The table's rationale prose is audit context, not the source for machine coverage checks. Implementations MUST materialize the sidecar below as structured data keyed by row id.

View coverage:

| View | Required row ids |
|---|---|
| Enforcement | `3`, `22`, `56.1`, `56.2`, `61`, `70` |
| Tamper-proof / integrity | `67`, `68`, `91` |
| Selective Disclosure | `8`, `9`, `10`, `76` |
| Commercial | `87.1`, `87.2`, `88` |
| Legal | `13`, `14`, `14.1`, `15`, `15.1`, `18`, `19`, `33`, `34` |
| Use-case flex | `53`, `54`, `55`, `57`, `58`, `59`, `60.1`, `60.2`, `61`, `62.1`, `62.2`, `63.1`, `63.2`, `64.1`, `64.2`, `69.1`, `69.2` |
| Partner-fit | `89`, `90.1`, `90.2`, `91` |

Condition-module coverage:

| Condition module | Required row ids |
|---|---|
| PaymentObligation | `56.1`, `56.2` |
| TimeLock | `57` |
| SubjectInitiated | `58` |
| HeartbeatMissed | `59`, `62.1`, `62.2` |
| OracleAttestation | `60.1`, `60.2` |
| MultiPartySignal | `61`, `70`, `69.2` |
| DeadManSwitch | `62.1`, `62.2`, `69.1` |
| ConsentGate | `63.1`, `63.2` |
| Composed | `64.1`, `64.2` |

### §5.5 Rationale column requirement

The `rationale` column is mandatory. A table exported to code without the rationale is non-conformant for audit. The rationale does not need long prose, but it must state which test fired and why the surface cannot be placed elsewhere.

### §5.6 Cross-reference to S2-1 and S2-2

S2-1 §3.3 has the canonical 29-field `pda_root` field set. S2-2 App. A `PdaRootFields` mirrors it. S2-4 class-table entries that map to those fields are author-locked against both specs. A future S2-4 field requiring a new `pda_root` anchor is not a local change; it is a BP-N candidate.

S2-2 `registerPDA` accepts `authorizationId`, `hCommit`, `pdaRoot`, `partnerId`, condition refs, and conditional-recipient mode data sufficient to reject Mode 3 on-chain. S2-4's richer PDA JSON must compile down to those refs plus off-chain IPFS artifacts and contract-visible roots. If a guardrail must be contract-enforced, S2-4 cannot rely only on off-chain JSON.

## §6 — PDA+ Governance: Six Sub-Classifications

> **See S2-8 (controlled-use spec) §3.3 for ControlledUseAccessPolicy (sub-class 6), the governance sub-classification that owns the `token_policy_config` field family (rows 92-107.3 of §5.2). Authority discipline: TimelockController-gated PDA+ governance edits; Cealis-internal configurator review required; every edit emits an on-chain configurator event for transparency; cross-field rules CF-CU-01..CF-CU-06 (§4.5) enforce internal consistency.**

### §6.1 Sub-class 1: TimelockController-7d additions

Sub-class 1 is for adding new platform data that expands the allowed set without altering existing entries:

- new schema template;
- new FSM template id;
- new oracle entry;
- new OracleSchemaRegistry entry;
- new DSL version entry;
- new QTSP entry;
- new plugin hash entry;
- new G4 authority entry;
- new approved WASM predicate binary.

The default mechanism is TimelockController with 7-day delay. The 7-day observation window lets partners, recipients, auditors, and watchdogs inspect incoming platform capacity before it becomes usable.

### §6.2 Sub-class 2: CealisSecurityMultisig deprecations

Sub-class 2 is for deprecating an existing entry when the safe move is removal or refusal. It uses CealisSecurityMultisig and the `DeprecationFlag` discipline:

- non-canonical entry: immediate deprecation;
- canonical-in-use entry: 24h expedited delay;
- disclosure required within 72h or auto-clear;
- re-deprecation cooldown 30 days after auto-clear;
- clearing requires TimelockController.

Examples: compromised oracle, vulnerable plugin, stale DSL interpreter, expired QTSP registration, outdated FSM template.

### §6.3 Sub-class 3: CealisSecurityMultisig with circuit breaker

Sub-class 3 is for platform-wide emergency authority where the Security Multisig itself may be compromised or where a class-wide halt surface is being exercised. It composes CealisSecurityMultisig with EmergencyGovernance circuit breaker.

Examples:

- class-wide `DeprecationFlag` emergency response;
- G4AuthorityRegistry rotation after suspected key compromise;
- temporary suspension of Security Multisig deprecation power;
- opt-out transparency handling for non-legal-effect PDAs.

### §6.4 Sub-class 4: PDA+ conditional-rule constraint adjustment

Sub-class 4 is for adjusting parameters inside an existing cross-field rule without changing the rule's code shape.

Examples:

- changing Tier B challenge-window floor from 14 days to 21 days;
- changing long-TTL threshold from 5 years to 3 years;
- changing minimum shred latency for evidence;
- updating Art. 9 explicit-consent ceremony text hash;
- updating the list of human resolver types if the enum already exists.

Mechanism: TimelockController-7d. These are data-only adjustments to existing validator predicates.

### §6.5 Sub-class 5: PDA+ conditional-rule addition

Sub-class 5 is for adding a new cross-field validator. This is codepath-bound. It requires:

- design note naming the invariant or platform reason;
- implementation change in shared validator;
- test coverage in CLI/API/UI paths;
- simulation vectors;
- partner inspection rendering update;
- S2-6 ceremony entry for rollout;
- author-lock review for S2-1/S2-2 impact.

It does not automatically require a `commit_version` bump. A bump is required only if the new rule changes S2-1 byte layouts, commit semantics, cryptographic construction, or historical verification.

Example: a future "DeadManSwitch heartbeat interval must be less than retention window" rule.

### §6.5A Sub-class 6: ControlledUseAccessPolicy (controlled-use deployments only)

Sub-class 6 is the 6th PDA+ governance sub-classification, introduced by S2-8 controlled-use access sessions (`commit_version = 0x0303`). It owns the `token_policy_config` field family enumerated in §5.2 rows 92-107.3.

**Authority discipline.** TimelockController-gated PDA+ governance edits, mirroring sub-class 1 (additions) and sub-class 4 (constraint adjustments). No partner self-serve mutations; the Apr 13 platform-pivot operationalization (§2.4) admits no exception under controlled-use. All ControlledUseAccessPolicy edits route through Cealis-internal configurator review per §7.2.

**Required reviewer.** Every ControlledUseAccessPolicy instantiation or evolution requires Cealis-internal configurator review under the 5-stage layered verification gate (§4). Partners cannot author raw slice layouts, raw token-class catalogs, or raw audit-policy enums; the configurator review at §4.5 cross-field rules CF-CU-01..CF-CU-06 enforces internal consistency.

**Audit requirements.** Every ControlledUseAccessPolicy edit emits an on-chain configurator event for transparency. The event records: surface name (one of rows 92-107.3), prior value digest, new value digest, governance ceremony reference (`S2-6-CER-06`, new ceremony class added under §6.7), timelock block. Slice-layout evolutions additionally emit a `pda_slice_layout_anchor` Merkle root update event per S2-2 §9.16B.

**Cross-field gates.** The cross-field rules CF-CU-01..CF-CU-06 (§4.5) enforce ControlledUseAccessPolicy-internal consistency at PDA validation time. The rules cover: `commit_version` ↔ `token_policy_config.enabled` binding (CF-CU-01), SD-on forbid under controlled-use per F-9 (CF-CU-02), vendor-family consistency between `stream2_cosign_gate` and `g3_choice` (CF-CU-03), subject-checkpoint discipline under emergency-elevation (CF-CU-04), DeadManSwitch × PresentedTokenCondition forbid per H-6 (CF-CU-05), and web-profile write coupling per H-8 (CF-CU-06).

**S2-6 ceremony class.** ControlledUseAccessPolicy adds `S2-6-CER-06` (controlled-use additions / evolutions / revocations) to the §6.7 ceremony catalog. The ceremony shape follows sub-class 1 / sub-class 4 (TimelockController-7d) plus a mandatory configurator review step. Class-wide emergency response (e.g., slice-layout vulnerability requiring class-wide halt) routes through sub-class 3 with a controlled-use-specific carve-out documented at S2-6.

**Class-CATALOG vs class-CRYPTO interaction.** The `token_policy_config` field family is class-CATALOG at the PDA+ governance layer (Cealis-internal review required to instantiate; partner cannot author raw) per `v3-registry-class-discipline.md` (internal design note, not in this export). The four S2-2 §9.16A-D registries (CredentialAnchorRegistry, SliceLayoutRegistry, MasterTokenRevocationRegistry, TokenRevocationRegistry) are class-CRYPTO at the on-chain layer; the registry-key discipline (TAG-prefixed keys per S2-1 §2.3.5) does not bleed into the PDA+ field family classification.

### §6.6 Composition matrix

| Surface family | Addition | Deprecation | Emergency | Constraint adjustment | New rule |
|---|---|---|---|---|---|
| Schema library | 1 | 2 | 3 if class-wide safety | 4 for bounds | 5 if new validator |
| FSM template library | 1 as new content-addressed template | 2 old template | 3 if active exploit | 4 for parameter floors | 5 if new cross-field rule |
| OracleRegistry | 1 | 2 | 3 for compromise | 4 for vetting bounds | 5 if validator changes |
| DSLVersionRegistry | 1 | 2 | 3 for interpreter bug | 4 for cap-set values | 5 if new semantic rule |
| WASM predicate whitelist | 1 | 2 | 3 for exploit | 4 for gas/time caps | 5 if new predicate class rule |
| QTSPRegistry | 1 | 2 | 3 for trust break | 4 for admissibility constraints | 5 if new QES rule |
| G4AuthorityRegistry | 1 | 2 | 3 for authority compromise | 4 for phase eligibility data | 5 if phase rule changes |
| Cross-field rules | N/A | N/A | 3 if emergency-disable path exists | 4 | 5 |
| Default tables | 1 for new default row | 2 deprecate unsafe default | 3 if immediate halt needed | 4 for changed value | 5 if default implies validator |
| ControlledUseAccessPolicy slice layouts (S2-8 §3.2.2) | 6 for new slice template; 1 for new slice schema in shared library | 6 for retiring a slice template; 2 for retiring a slice schema | 3 if class-wide controlled-use halt | 6 for adjusting slice authority matrices inside existing layout | 5 if new cross-field rule (e.g., a future CF-CU-07) |
| ControlledUseAccessPolicy audit policies (S2-8 §3.2.6) | 6 for new audit-policy variant | 6 for retiring a variant | 3 if pepper-epoch compromise class-wide | 6 for retention-class or cosign-gate constraint adjustment | 5 if new audit-policy validator |
| ControlledUseAccessPolicy token-class catalog (S2-8 §2.2) | 1 for new token class in shared catalog | 2 for retiring a token class | 3 if exploit on a class | 4 for class-specific bounds | 5 if new class-specific validator |

### §6.7 S2-6 ceremony types per sub-class

S2-6 must define six ceremony shapes:

1. Timelocked addition ceremony: proposal, queue, observation, execute, event, partner inspection update.
2. Deprecation ceremony: reason, disclosure hash, flag set, publish disclosure, auto-clear/cooldown.
3. Emergency circuit-breaker ceremony: trigger, suspension scope, max duration, restore.
4. Constraint-adjustment ceremony: parameter diff, compatibility check, queue, execute, default-table diff.
5. Rule-addition ceremony: design lock, code release, test evidence, rollout, activation block, partner inspection update.
6. ControlledUseAccessPolicy ceremony (S2-6-CER-06): controlled-use additions, evolutions, and revocations. Composes the addition / constraint-adjustment shapes with a mandatory configurator review step and an on-chain `pda_slice_layout_anchor` update event when slice layouts evolve.

S2-4 names the ceremony classes; S2-6 owns runbooks.

### §6.8 Governance metadata interface

S2-6 may refine the runbook details, but it MUST implement the interface shape below so the configurator, escalation report, and partner inspection surface render the same governance facts.

| Sub-class | authority_ref | threshold_ref | delay_seconds | max_duration_seconds | on_chain_event | inspection_visibility | s2_6_ceremony_ref |
|---|---|---|---:|---:|---|---|---|
| 1 | `TimelockController-7d` | `TIMELOCK_PROPOSER` plus `TIMELOCK_EXECUTOR` per S2-6 | 604800 | 0 | `PDAPlusAdditionQueued` / `PDAPlusAdditionExecuted` | Public queued diff before activation; partner inspection after activation. | `S2-6-CER-01` |
| 2 | `CealisSecurityMultisig` | `SECURITY_MULTISIG_THRESHOLD` per S2-6 | 0 for non-canonical entry; 86400 for canonical-in-use entry | 259200 disclosure deadline; 2592000 re-deprecation cooldown | `PDAPlusEntryDeprecated` / `PDAPlusDeprecationCleared` | Immediate warning on affected PDA summaries; disclosure hash shown when published. | `S2-6-CER-02` |
| 3 | `CealisSecurityMultisig` plus `EmergencyGovernance` | `SECURITY_MULTISIG_THRESHOLD` plus circuit-breaker confirmation per S2-6 | 0 | 7776000 unless S2-6 narrows the emergency surface | `PDAPlusEmergencyTriggered` / `PDAPlusEmergencyRestored` | Immediate public emergency banner, affected surface list, restore deadline, and final restoration notice. | `S2-6-CER-03` |
| 4 | `TimelockController-7d` | `TIMELOCK_PROPOSER` plus `TIMELOCK_EXECUTOR` per S2-6 | 604800 | 0 | `PDAPlusConstraintAdjustmentQueued` / `PDAPlusConstraintAdjustmentExecuted` | Queued parameter diff before activation; applied default-table diff after activation. | `S2-6-CER-04` |
| 5 | `RuleAdditionTimelockController` plus code-release author-lock | `RULE_ADDITION_APPROVER_THRESHOLD` per S2-6 | 604800 after code and test evidence publication | 0 | `PDAPlusRuleAdditionQueued` / `PDAPlusRuleActivated` | Design note, validator version, tests, activation block, and affected partner surfaces. | `S2-6-CER-05` |
| 6 | `TimelockController-7d` plus configurator-internal review author-lock | `TIMELOCK_PROPOSER` plus `TIMELOCK_EXECUTOR` plus `CONTROLLED_USE_REVIEWER_THRESHOLD` per S2-6 | 604800 after configurator review pass | 0 | `ControlledUseAccessPolicyQueued` / `ControlledUseAccessPolicyExecuted` (additionally `SliceLayoutAnchorUpdated` per S2-2 §9.16B when slice layout evolves) | Queued `token_policy_config` diff before activation; partner inspection after activation; on-chain anchor update visible on every slice-layout evolution. | `S2-6-CER-06` |

## §7 — Configurator Surface Duality

### §7.1 CLI/API at pilot and internal UI later

CLI/API and internal UI are both first-class surfaces over the shared model. Stage-0 Q-0-6 locks both. The CLI/API is expected to exist first because Stage-2 and Stage-3 engineering need scriptable output. The UI exists for internal BD, legal, policy, and operations authors and cannot emit a different PDA than the API for identical inputs.

Required shared backend operations:

- create draft PDA from partner intent;
- select template;
- apply defaults;
- validate through Stages 1-5;
- render partner-readable preview;
- pin canonical JSON;
- compute `pda_root`;
- register PDA handoff;
- supersede old PDA version.

### §7.2 Internal-only at all phases

No partner self-serve surface exists. Partner-facing controls are request, review, and inspect. Authoring remains Cealis-internal.

This remains true after UI launch. An internal UI is not a partner UI. If a future partner portal is built, it submits requests into Cealis review; it does not bypass validation or deploy directly.

### §7.3 Partner-readable post-deploy PDA inspection

S2-4 requires a partner-readable inspection surface. S2-5 defines HTTP details, but S2-4 fixes content:

- `partner_id`, `pda_id`, `pda_version`, `pda_root`;
- template id and template digest;
- schema digest and human-readable schema summary;
- reveal and shred condition summaries;
- trust tier and oracle refs;
- G3 choice and G4 phase;
- recipients summary and schema selectors;
- conditional-recipient policy summary;
- SD audit diff showing all non-`escrow_only` fields;
- retention and challenge windows;
- shred authority and shred condition;
- legal flags, Art. 9 basis, QES posture, jurisdiction;
- class-table classification per surface;
- defaults applied and whether partner overrode them;
- validation report digest;
- simulation report digest;
- IPFS CIDs and on-chain tx refs.

Endpoint forward reference: `/v1/pda/{partner_id}` or equivalent authenticated S2-5 endpoint. IPFS partner mirror stores the canonical JSON and a redacted partner summary.

### §7.4 Partner-review escalation flow

If a partner finds drift:

1. Partner cites inspection row or summary mismatch.
2. Cealis-internal operator opens a configurator drift review.
3. Operator compares partner intent digest, translated PDA JSON, validation report, and on-chain `pda_root`.
4. If the PDA was emitted incorrectly, Cealis emits a new PDA version with a new `pda_root`.
5. Future commits use the new root. Existing commits remain bound to the prior root unless a separate update/supersession ceremony applies.
6. Supersession discipline follows S2-1 `SupersededCommitRegistry` and S2-5/S2-6 ceremony boundaries.

Partners cannot directly patch deployed PDA JSON.

## §8 — Partner-Intent Translation Flow

> **See S2-8 (controlled-use spec) §3 for the controlled-use intent branch: "What is the access-control model for this data?" → "rare sealed reveal (default)" vs "controlled-use access tokens" → if controlled-use elected, the intent flow extends with token-class, scope-field, slice-topology, cache-policy, revocation-authority, and audit-retention questions.**

### §8.1 Stage 1: partner intent to internal translation

Partner intent arrives as conversation notes, partner technical requirements, legal posture, schema samples, jurisdiction constraints, recipient roles, reveal trigger description, shred expectations, and commercial/operational parameters.

Cealis translates intent into a structured draft form:

- use case;
- archetype;
- schema family;
- intended legal effect;
- trust tier target;
- reveal condition;
- shred condition;
- recipients;
- retention;
- challenge windows;
- SD outputs;
- ingestion mode;
- G3 preference;
- G4 phase eligibility;
- risk acknowledgments;
- **access-control model (initial branch; see §8.1A): "rare sealed reveal (default)" vs "controlled-use access tokens" — the latter triggers the §8.1A controlled-use sub-tree and enables `token_policy_config` in the structured draft form.**

The translation artifact is stored as a digest plus redacted summary in audit trail.

### §8.1A Stage 1 controlled-use intent branch (S2-8)

The very first intent question added by S2-8 controlled-use access sessions is the access-control model.

**Initial intent question:** *"What is the access-control model for this data?"*

- **Option A — "Rare sealed reveal (default)":** the existing §8.1 flow continues. The PDA proceeds to NE / TP / CR intent translation per the existing Stage 2 / Stage 3 pipeline. `token_policy_config.enabled = false` (the surface row 92 is omitted from the PDA's normative set).
- **Option B — "Controlled-use access tokens":** the configurator enters the controlled-use sub-tree below. `token_policy_config.enabled = true`; `commit_version = 0x0303`; `sd_election = DISABLED` per F-9 (CF-CU-02 enforces).

**Controlled-use sub-tree (Option B):** the configurator asks the following questions in order, mapping each answer to one or more `token_policy_config.*` fields per §5.2 rows 92-107.3.

1. *"Which token classes does the deployment need?"* → `master_token_classes` (row 93; multi-select subset of the nine-class catalog per S2-8 §2.2).
2. *"What is the schema for each slice the data divides into?"* → `slice_layout.slices[]` (row 98.2; Cealis-internal authoring of schemas + write/read authority matrices + `slice_dek_policy` per S2-8 §3.2.2; partners cannot author raw — row 98.1 governs the template library).
3. *"What is the default sub-token lifetime?"* → `sub_token_lifetime_default_seconds` (row 94; default 300 s per H-7) and *"what is the maximum allowable sub-token TTL?"* → `recommended_sub_token_max_ttl_seconds` (row 95).
4. *"What scope grammar does the deployment use?"* → `scope_field_grammar.allowed_forms` (row 96) and `scope_field_grammar.slice_atomicity_allowed` (row 97).
5. *"What slice-layout evolution policy?"* → `slice_layout.evolution_policy` (row 99; default `FROZEN_SCOPE` per F-10).
6. *"What cache policy on the client?"* → `cache_policy` (row 100; default `EPHEMERAL_ONLY`, with H-8 web-profile constraint).
7. *"Which client profile is recommended?"* → `recommended_client_profile` (row 101) and *"may the partner strengthen the profile?"* → `partner_may_strengthen_profile` (row 102; default `true`).
8. *"Are web one-shot writes needed?"* → `web_profile_write_allowed` (row 103; CF-CU-06 enforces coupling with `recommended_client_profile = WEB_ONESHOT`).
9. *"Who pays first-presentation gas?"* → `first_presentation_gas_attribution` (row 104; default `PARTNER_META_TX`).
10. *"What retention policy on data-events (Stream 1) vs metadata-events (Stream 2)?"* → `audit_policy.stream1_retention_class` (row 105.1) + `audit_policy.stream2_retention_class` (row 105.2; counsel sign-off gate required for `DEEPER_ERASURE_OPT_IN` on Stream 2 per F-19).
11. *"Which gate cosigns Stream 2 audit anchors?"* → `audit_policy.stream2_cosign_gate` (row 105.3; CF-CU-03 enforces vendor-family consistency with `g3_choice` per H-4).
12. *"Which audit-pepper-epoch-0 root commitment?"* → `audit_policy.stream2_pepper_root` (row 105.4); `pepper_epoch_number` per epoch is bound inside the root per S2-8 §3.2.6.
13. *"Do Stream 2 entries carry a content-shape digest?"* → `audit_policy.stream2_content_shape_digest_enabled` (row 105.5; DEFAULT-ON for regulator-audit-subject partners, PDA-configurable OFF for max-subject-privacy).
14. *"Do subjects receive checkpoints of their own access history?"* → `audit_policy.subject_checkpoint_mode` (row 105.6; CF-CU-04 enforces `!= DISABLED` when emergency-elevation is enabled).
15. *"Do regulators receive an anchor mirror?"* → `audit_policy.regulator_anchor_mode` (row 105.7).
16. *"Per-sub-token revocation needed (high-stakes deployments)?"* → `revocation_mode` (row 106; default `MASTER_ONLY`).
17. *"Is emergency-elevation (HL7 BTG-aligned) authority needed?"* → `emergency_elevation_policy.enabled` (row 107.1) and, if yes, `emergency_elevation_policy.authority` (row 107.2). `emergency_elevation_policy.audit_class` (row 107.3) is forced to `STREAM2_ALWAYS_LOGGED` per S2-8 §3.2.8.

Each answer feeds the structured draft form at §8.1 and gets translated to a `token_policy_config.*` field in Stage 3 parameterization (§8.3). The Cealis-internal review at Stage 5 (§4.6) verifies that the controlled-use sub-tree produces an internally-consistent PDA before commit.

### §8.2 Stage 2: template selection from PDA+ libraries

The configurator selects from:

- schema library;
- FSM template library;
- condition module templates;
- OracleRegistry and OracleSchemaRegistry;
- DSLVersionRegistry;
- WASM predicate whitelist;
- default tables;
- conditional-recipient role/mode library;
- SD claim library.

Template selection is not final until validation passes. A template id is content-addressed and immutable once admitted.

### §8.3 Stage 3: parameterization

The configurator fills category (b) picks and category (c) parameters:

- G3 choice;
- trust tier declaration;
- oracle refs;
- timing windows;
- retention window;
- thresholds;
- heartbeat intervals;
- recipient list;
- delivery modes;
- jurisdiction;
- Art. 9 basis;
- authenticator class;
- SD field policies;
- commercial quota metadata.

Default-table application occurs before manual override. Use-case-index defaults win when present; archetype-index defaults are fallback. Overrides are recorded in the partner-readable inspection surface.

### §8.4 Stage 4: verification gate

The five-stage verification gate in §4 runs. Stages 1-4 must pass before simulation. Human review cannot override failures.

### §8.5 Stage 5: FSM spec to canonical JSON and IPFS multi-pin

After validation, the FSM spec and PDA source JSON are canonicalized. The configurator computes:

- canonical PDA JSON digest;
- reveal condition spec hash;
- shred condition spec hash;
- oracle references root;
- submitter sets root;
- eligible challenger roots;
- SD plan root;
- conditional-recipient policy digest;
- template id refs.

The spec is pinned to IPFS:

- Cealis primary pin;
- partner mirror;
- optional Filecoin deal funded from PDA retainer.

### §8.6 Stage 6: `pda_root` computation and on-chain commit

The configurator constructs S2-1 §3.3 `PdaRootFields` in exact order and computes `pda_root`. It then hands the contract-visible refs to S2-2 `registerPDA` and related on-chain registration surfaces.

The configurator MUST compare:

- locally computed `pda_root`;
- contract helper `computePdaRoot` output where available;
- emitted `PDARegistered` `pdaRoot`.

Mismatch is a terminal emission failure.

### §8.7 Stage 7: frozen at commit

A commit references the `pda_root` active for that commit. Later PDA updates create new roots; they do not mutate old roots. The partner inspection surface must show which commits use which root.

### §8.8 Failure recovery and retry

Syntax and Stage 3 failures are draft-level failures. Partner intent may be revised and validation re-run.

Stage 2 failures require removal of impossible configuration. They are not governance-expandable unless a protocol version changes.

Stage 4 failures require field adjustment or PDA+ rule change. If the partner genuinely needs a new rule or bound, route through §6 governance.

Stage 5 simulation failures require template correction, new template id, or parameter adjustment. Do not patch existing template bytes.

Post-pin but pre-chain failures can retry if canonical JSON digest is unchanged. Post-chain mismatch requires supersession with a new PDA version.

## §9 — Three Extensibility Vectors

### §9.1 Vector 1: template composition

Template composition is the highest-priority path. It combines existing audited primitives into a new content-addressed template. It is data-shaped and operationally cheap. Governance: sub-class 1 addition, sub-class 2 deprecation for unsafe old templates.

Partners drive most new needs through template composition.

### §9.2 Vector 2: oracle onboarding

Oracle onboarding adds a new off-chain fact source:

- operator identity;
- signing pubkey;
- attestation schema;
- canonical valid and invalid examples;
- trust tier;
- operational history;
- legal basis;
- metadata hash.

Governance: 7-day timelocked addition, with vetting before queue. Deprecation uses sub-class 2/3 depending on severity.

### §9.3 Vector 3: DSL/WASM extension

DSL/WASM extension changes the expressive surface. It is the lowest-priority path because it can affect determinism, gas, verification, and auditability. Governance requires design review, interpreter or predicate registration, audit, S2-6 rollout ceremony, and author-lock check.

### §9.4 Priority and cadence rationale

Priority order is lowest friction first:

1. Template composition uses existing primitives.
2. Oracle onboarding introduces a new trust surface.
3. DSL/WASM extension introduces a new expressive surface.

Governance burden increases with trust and expressiveness. Commit-version coordination is normally only a risk for Vector 3, or for any vector that changes S2-1 byte layout.

## §10 — PDA Evolution Semantics (NORMATIVE)

> **See S2-8 (controlled-use spec) §5 for slice-layout evolution semantics under controlled-use: frozen-scope LEGACY-slice-only normative rule; slice-id collisions across evolutions FORBIDDEN; existing credentials point at slice-ids-at-issue-time forever.**

### §10.1 Frozen-at-commit

Each commit binds a specific `pda_root`. That root is the PDA snapshot for the commit. Existing commits do not silently inherit future PDA JSON changes, template defaults, registry additions, or parameter changes.

### §10.2 Updates produce new `pda_root`

A PDA update creates a new `pda_version` and new `pda_root`. The old root remains auditable and historically valid. The partner inspection surface must display the lineage.

### §10.3 Mid-flight commits

For reveal ceremonies, the canonical event block is the `RevealAuthorized` block. Gate clients and combiners use that authorization snapshot for in-flight semantics. Once gate signing is in progress, emergency deprecation and shred do not race the ceremony.

### §10.4 Two-layer evaluation

S2-4 uses two-layer evaluation:

1. **Frozen PDA layer.** The commit references the `pda_root` at its commit/version block.
2. **Registry deprecation overlay.** Registry deprecation state is checked at the authorization block according to S2-2/S2-3 historical lookup and emergency-response semantics.

This closes the stale-root problem. A PDA root from block N does not hide a registry deprecation that landed before `RevealAuthorized`. G4 and combiner check deprecation state at the authorization block.

### §10.5 Long-TTL handling

Long-TTL PDAs, including testament, archival, and dead-man's-switch deployments, use the same two-layer model. They do not receive a separate evolution regime.

The root remains frozen. Registry overlay applies at authorization. If a long-TTL PDA references an entry deprecated decades later, reveal may halt unless the PDA has migrated through an allowed update path or the deprecation cleared. This is why `pda_updatable` and `conditional_recipients_updatable` default true for long-TTL modules and why immutable long-TTL choices require bricking acknowledgment.

### §10.6 Supersession discipline

Supersession follows S2-1 `SupersededCommitRegistry` and downstream S2-5/S2-6 ceremonies. S2-4 may emit a new PDA root, but it cannot reinterpret an old commit's AAD. Re-key, migration, and supersession are explicit ceremonies.

### §10.7 Slice-layout evolution (controlled-use; S2-8 §5.7 / F-10)

Slice-layout evolution applies only to controlled-use PDAs (`token_policy_config.enabled = true`). It evolves the slice topology of an existing PDA while preserving — or invalidating, per partner election — the credentials issued under the prior topology. The evolution policy is declared at PDA election time (row 99 `token_policy_config.slice_layout.evolution_policy`) and is normative.

**`evolution_policy = FROZEN_SCOPE` (default).** Legacy slice-ids remain valid; existing credentials cover the legacy slice forever; slice-id collisions across evolutions are FORBIDDEN by `slice_topology_evolution_authority` (Cealis-internal-only). Legacy credentials effectively become read-only-historical as new writes go to the successor slice; the legacy slice remains valid for read-against-frozen-content. This preserves read-continuity for existing credentials.

**`evolution_policy = REISSUE_REQUIRED`.** Legacy credentials become inert at slice-layout evolution; partners accept the operational burden of re-issuance. Holders must request new credentials under the new slice layout. Partners electing this policy explicitly trade read-continuity for write-continuity across slice topology evolutions.

**Cross-field gate.** Slice topology evolution updates the `pda_slice_layout_anchor` Merkle root recorded in S2-2 §9.16B `SliceLayoutRegistry`. The anchor update is timelock-gated under PDA+ sub-class 6 governance (§6.5A), routed through the `S2-6-CER-06` ceremony, and emits an on-chain `SliceLayoutAnchorUpdated` event. Partners CANNOT evolve slice layouts unilaterally or instantaneously; the timelock window allows holders and downstream consumers to observe the evolution before it activates.

**Frozen-at-commit composition.** Slice-layout evolution interacts with the §10.1 frozen-at-commit rule: existing commits remain bound to the `pda_root` active at their commit/version block, including the slice-layout state captured at that block. A `pda_slice_layout_anchor` update produces a new `pda_root` (per §10.2), so historical commits continue to bind their original slice topology. This composes cleanly with the S2-8 §5.3 supersession-invariant slice-latest-sealed-envelope-ref rule: SliceLayoutRegistry entries are supersession-invariant across re-key, and slice topology evolution is a separate ceremony from re-key.

**Banned operation.** Slice-id collision across evolutions (re-using a retired slice-id under a different schema) is FORBIDDEN at PDA validation time. The configurator REJECTS any proposed slice-layout evolution that re-uses a retired slice-id. This forecloses an attack where a partner retires a slice and then re-creates a "different" slice with the same slice-id to silently expand credential coverage.

## §11 — Trust-Tier Taxonomy (NORMATIVE)

### §11.1 Tier A / Tier B / Tier C

Tier A is chain-native facts: TimeLock, SubjectInitiated, OnchainState reads against audited contracts. The chain is the oracle. No off-chain oracle-honesty trust point exists.

Tier B is commodity oracle: established oracle operators or data sources with public operational history, such as Chainlink Automation, vital-records providers, or court-docket aggregators.

Tier C is bespoke oracle: partner-operated or single-purpose sources. It is most permissive and carries the narrowest trust basis.

### §11.2 Per-PDA declaration

Trust tier is declared per PDA and per relevant axis where needed. A composed condition with any Tier B/C child triggers the relevant-axis Tier B/C safeguards.

The declaration is category (b). The taxonomy and consistency rule are category (a).

### §11.3 Sixth cross-field rule

CF-06 enforces trust-tier-to-oracle-tier consistency:

- Tier A PDA: only chain-native modules and oracle refs classified as chain-native.
- Tier B PDA: Tier A or Tier B refs only.
- Tier C PDA: Tier A/B/C refs permitted with explicit acknowledgment.

This rule is not optional. It is the configurator-side enforcement of the tier claim carried in the artifact.

### §11.4 Tier carried in RevealArtifactBundle

The tier must appear in the RevealArtifactBundle through S2-5/S2-1 artifact construction. S2-4's role is to ensure the declared tier matches the configured condition and that the partner-readable inspection surface shows the tier.

### §11.5 Shamir threshold split

The Shamir threshold split is:

- fixed base: `3` = Lit V3 + G3 + G4, category (d);
- variable conditional-recipient threshold: `k_conditional`, category (c), from `conditional_recipients_policy`;
- PDA+ bounds: `1 <= k <= n`, long-TTL redundancy, role/mode constraints, category (a).

The configurator must not classify the full formula as PDA+. Only the bounds and validators are PDA+; the base fixed gates are architectural; the conditional-recipient threshold is PDA-specific.

## §12 — Multi-Oracle k-of-n MultiPartySignal

### §12.1 Archetype defaults

Irreversible or high-consequence archetypes default to k-of-n MultiPartySignal with `k >= 2` across independent oracles:

- testament;
- evidence;
- archival where an external event can authorize access;
- M&A multi-party release;
- dead-man's-switch with external liveness source.

This is PDA+ default metadata, not a new category.

### §12.2 Configurator enforcement

CF-07 enforces the default unless the partner explicitly opts out where the archetype permits opt-out. The validator checks:

- independent oracle operators;
- threshold `k <= n`;
- no duplicate signer identities;
- all oracle refs match declared trust tier;
- signal digest binding across all signers.

### §12.3 Opt-out governance

Opt-out from k-of-n default on irreversible archetypes requires sub-class 3 governance if the opt-out is class-wide. A per-PDA opt-out, where allowed by template, requires explicit partner acknowledgment and appears in the inspection surface. The primary failure code is `CF-07_MULTIPARTY_SIGNAL_DEFAULT`.

### §12.4 Conditional-recipient cross-reference

`conditional-recipient.md` defines recipient k-of-n for custody share admission. MultiPartySignal defines oracle/signer k-of-n for condition firing. They are separate thresholds:

- MultiPartySignal threshold decides whether the on-chain condition fires.
- Conditional-recipient threshold decides how many recipient shares are needed after fixed gates authorize.

Both may appear in one PDA.

## §13 — PDA Template Defaults (NORMATIVE)

### §13.1 Default table as metadata

Default tables are metadata on category (b) and category (c) surfaces. They are not a fifth category. Applying a default produces the same PDA field as an explicit partner choice; the inspection surface marks whether the value was defaulted or overridden.

### §13.2 Use-case-index defaults

Use-case-index defaults include:

- KYC, M&A, regulated-EU, and evidence: dcipher default for G3 where available.
- Testament, time-lock, archival, dead-man's-switch, and long-retention: drand default for G3.
- Long-TTL condition modules: `pda_updatable = true` and `conditional_recipients_updatable = true`.
- Irreversible external-trigger archetypes: k-of-n oracle default.

### §13.3 Archetype-index defaults

Archetype defaults include trust tier, challenge windows, shred authority, shred condition, resolver type, eligible challengers, minimum shred latency, SD default, and authenticator class.

Examples:

- KYC-lending chain-native: Tier A, zero reveal/shred challenge window, enforcement shred condition.
- KYC-lending oracle-attested: Tier B/C, 14-day challenge windows with bond.
- Evidence: Tier B/C, 7-day challenge windows, observer-capable challenge set.
- Testament: Tier B/C vital-records k-of-n, zero challenge windows, conditional recipients.
- Archival: zero windows, retention-window or joint-attest shred, Disabled authority for permanent archives where chosen.

### §13.4 Precedence rule

Use-case-index wins when present. Archetype-index is fallback. Specific-over-general is the rule.

If both indexes produce values for the same field, the use-case-index value is applied and the inspection surface records the archetype fallback that was superseded. A partner override can still choose another allowed value, and the override is recorded.

### §13.5 Content-addressed template immutability

Templates are immutable. `template_id` is a content-addressed digest of the canonical template spec. A patch creates a new `template_id`. The old template may be deprecated through CealisSecurityMultisig, but existing PDAs using the old `template_id` continue to bind their frozen `fsm_hash` and historical semantics unless the registry deprecation overlay halts future authorization.

No implementation may mutate canonical bytes under an existing `template_id`.

### §13.6 Default change semantics

Changing a default affects future PDA emissions only. Existing PDAs do not re-anchor because a default table changed. A default is metadata applied at configuration time, not a live pointer inside historical commits.

## §14 — Out-of-Bounds Handling

### §14.1 Stage 3 allow-list failures

When a category (b) pick is outside the PDA+ allow-list, the configurator returns a Stage 3 failure. Examples:

- drand selected where the PDA+ state marks drand unavailable for the selected template;
- subject shred authority selected for an archetype that forbids it;
- oracle id not in OracleRegistry;
- schema family not SD-enabled;
- delivery mode not enabled for role tag;

Partner remediation is to choose an allowed value or request PDA+ expansion.

### §14.2 Stage 4 cross-field failures

Cross-field failures are emitted together. Example: a legal-effect Tier B PDA with zero challenge window, bot resolver, subject missing from challenger set, halt opt-out true, and Phase 1 selected returns all relational failures in one Stage 4 report. Stage 3 may note that Phase 1 is only allow-listed for dev-scaffold or historical PDAs, but CF-05 owns the primary legal-effect/partner-ready rejection.

The implementation must not force iterative one-error-at-a-time correction for cross-field rules.

### §14.3 PDA+ governance escalation

If partner intent cannot fit the existing PDA+ range, Cealis routes it:

- new template request: sub-class 1;
- new oracle: sub-class 1 plus vetting;
- unsafe old entry: sub-class 2/3;
- changed bound: sub-class 4;
- new validation predicate: sub-class 5;
- cryptographic byte layout change: BP-N / S2-1 author-lock path.

### §14.4 Partner-facing validation messages

Partner-facing validation copy must say which intent failed, not expose internal taxonomy alone. It must not overclaim. Use outcome-language:

- "This configuration would allow a shred after gate signing starts; Cealis rejects that because shred cannot race an authorized reveal."
- "This deployment uses a third-party oracle, so it needs a challenge window."
- "This recipient mode is reserved in V2 and cannot be selected."

## §15 — Cross-References

### §15.1 S2-1 imports

S2-4 imports:

- S2-1 §3.3 `pda_root` 29-field fixed-width preimage;
- S2-1 §4 `commit_AAD`, including `sdMerkleRoot`;
- S2-1 §6.3 Shamir reconstruction and `3 + k_conditional`;
- S2-1 §17 author-locks and S2-4 consumption obligations.

S2-1 §3.3 is the canonical 29-field layout. S2-4 follows §3.3 and S2-2 App. A `PdaRootFields`.

### §15.2 S2-2 imports

S2-4 imports:

- S2-2 §4 ConditionEngine and the 9 modules;
- S2-2 §9 V3 registries, `GateRecipientPubkeyRegistry`, `DisclosureRegistry`, and `DeprecationFlag`;
- S2-2 §11 Mode 3 contract rejection;
- S2-2 §12 `RevealAuthorized`;
- S2-2 App. A `PdaRootFields`, `HCommitFields`, `DeprecationFlag`, and `registerPDA`.

### §15.3 S2-3 imports

S2-4 imports:

- G3/G4 selection and Phase 2 partner posture;
- cross-vendor TEE vendor-family normalization;
- gate-recipient pubkey lifecycle;
- Mode A commit-time G4 ingestion TEE boundary;
- combiner pre-verification and Shamir-share admission rules.

### §15.4 S2-7 imports

S2-4 imports S2-7 §12:

- `SdFieldPolicy`;
- per-field `cleartext`, `zkp`, `escrow_only`;
- schema-level SD availability;
- Mode B rejection for TEE-side SD;
- default `escrow_only`;
- audit diff for all non-`escrow_only` fields.

### §15.5 Forward references

S2-5 consumes partner-readable PDA inspection, `/v1/pda/{partner_id}` or equivalent, ingestion/delivery idempotency, IPFS partner mirror, webhook and vault handling.

S2-6 consumes the five governance ceremony shapes, oracle onboarding runbooks, registry deprecation operations, Phase 1-to-Phase 2 operational transition, Mode 3 future activation, and cross-vendor classification records.

### §15.6 Design references

Binding design record: `configurator-pda.md` (internal design note, not in this export).

Pattern analogy: `v3-registry-class-discipline.md` (internal design note, not in this export).

Conditional-recipient k-of-n and role/mode rules: `conditional-recipient.md` (internal design note, not in this export).

Emergency response and in-flight protection: `emergency-response.md` (internal design note, not in this export).

DEK lifecycle and Shamir threshold: `dek-lifecycle.md` (internal design note, not in this export).

### §15.7 WP §F citations

WP §F is the conceptual source for PDA+/PDA two-level configurability, Cealis-internal configurator discipline, challenge-window guardrail, Art. 22 guardrail, subject authenticator guardrail, Art. 9 guardrail, trust tiers, oracle discipline, challenge resolution, AI composition, out-of-bounds handling, template defaults, and schema polymorphism.

This document does not propose WP §F edits. A short WP §F reference paragraph pointing to S2-4 as the normative class table may be useful, but requires Simon confirmation under Rule 33 because WP voice-pass discipline applies.

## §16 — Threat Model

### §16.1 Configurator compromise

Threat: Cealis-internal configurator server or operator is compromised and emits malicious PDA JSON.

Controls:

- Stage 2 invariants reject impossible surfaces;
- S2-2 contract rejects legal-effect Phase 1, halt opt-out, missing shred guardrail, and Mode 3;
- subject-side verifier displays conditional recipients before σ_subject;
- `pda_root` and `commit_AAD` bind emitted values;
- partner inspection surface exposes decoded PDA;
- human review identity digest and simulation digest are auditable.

Residual risk: a compromised internal process can attempt to mis-translate partner intent inside allowed bounds. Partner inspection and audit trail mitigate; they do not eliminate the need for operational review.

### §16.2 Partner-intent misinterpretation

Threat: Cealis translates partner prose into the wrong template or parameters.

Controls:

- structured intent form;
- partner-readable preview;
- defaults and overrides visible;
- post-deploy inspection;
- supersession path for future commits.

Historical commits remain bound to the emitted PDA; misinterpretation cannot be silently edited away.

### §16.3 Mid-flight PDA update race

Threat: PDA updates or registry deprecations occur between commit and reveal.

Controls:

- commit binds `pda_root`;
- updates produce new roots;
- registry deprecation overlay checked at authorization block;
- in-flight after `RevealAuthorized` completes under authorization-block snapshot;
- shred and emergency deprecation do not race gate-signing.

### §16.4 Emergency-response halt during PDA config

Threat: registry deprecation lands during two-phase ingestion or PDA emission.

Controls:

- Stage 3 reads registry effective/tombstone/deprecation state;
- G4 two-phase ingestion precheck re-verifies before plaintext acceptance;
- post-pin/pre-chain failures retry only if canonical digest unchanged;
- new ingestion refused when referenced entry deprecated.

### §16.5 Test 1 audit-skip risk

Threat: a new surface is added as PDA+ or PDA without recognizing a cryptographic invariant.

Controls:

- mandatory §5 row before implementation;
- Stage 2 invariant catalog;
- author-lock review;
- CI-style table check;
- sub-class 5 process for new validators.

### §16.6 Hybrid surface decomposition compromise

Threat: implementation treats a hybrid surface as one field and misses subfield classification.

Examples: condition template + parameters + oracle refs; SD plan + claim ids + cleartext opening mode; conditional-recipient policy + delivery modes + threshold.

Controls:

- §3.6 requires decomposition;
- §5 decomposes former hybrid surfaces into single-category child rows;
- validator runs subfield checks;
- template ids are content-addressed and immutable.

## §17 — Author-Locks

### §17.1 What S2-4 binds

S2-4 binds:

- boundary-decision cascade;
- Stage 2 invariant catalog;
- Stage 4 cross-field rule set;
- class-table placement;
- default-table precedence;
- PDA+ governance sub-class taxonomy;
- partner-intent emission flow;
- two-layer PDA evolution;
- partner-readable inspection content;
- out-of-bounds routing.

Downstream specs cannot redefine these.

### §17.2 Cross-spec author-lock surfaces

| Surface | Locked against | Update discipline |
|---|---|---|
| `pda_root` field mapping | S2-1 §3.3 + S2-2 App. A | Coordinated S2-1/S2-2/S2-4 update; BP-N if new field. |
| `commit_AAD.sdMerkleRoot` | S2-1 §4 + S2-7 §12 | S2-4 cannot omit SD root binding. |
| Mode 3 rejection | S2-1 + S2-2 §11 + S2-3 combiner | Activation requires S2-6 ceremony and author-lock review. |
| Legal-effect guardrails | WP §F + S2-1 pda_root + S2-2 validators | S2-4 cannot weaken Phase 2, halt opt-out, or authenticator constraints. |
| Irreversible MultiPartySignal default | configurator-pda design §11 + S2-2 condition modules + S2-6 ceremonies | S2-4 owns CF-07; class-wide opt-out requires sub-class 3 governance and partner inspection update. |
| Shamir threshold | S2-1 §6.3 + dek-lifecycle design | S2-4 only sets `k_conditional` within bounds. |
| Gate-recipient pubkey lifecycle | S2-3 §2.5 + S2-2 registry | S2-4 cannot make drand ephemeral or Lit/G4 long-lived by config. |
| Trust tier | WP §F + S2-2 modules + S2-5 artifact | S2-4 declares and validates; artifact carries. |
| SD mapping | S2-7 §12 | S2-4 owns mapping UI/API; S2-7 owns proof semantics. |

### §17.3 Rule 30 §K cross-check

This document avoids WP §K banned phrasings:

- It does not claim Mode A makes it mathematically impossible for Cealis to see data.
- It does not describe Cealis as decentralized or without control.
- It does not say "GDPR-compliant" as a blanket claim.
- It does not say §371a admissibility is default.
- It treats G4 as attestation/refusal, not custody.
- It states emergency halt as halt-only and bounded.
- It treats Mode 3 EIP-1271 as reserved and contract-trust, not cryptographic consent.
- It does not claim reveal delivery is private.

### §17.4 BP-N back-propagation queue

No new BP-N is required by this S2-4 draft. The class table maps required cryptographic anchors to existing S2-1 §3.3, S2-1 §4, S2-2 App. A, or off-chain PDA JSON.

Editorial check: S2-4 treats S2-1 §3.3 and S2-2 App. A as the canonical 29-field `pda_root` authorities. This is not a new BP-N because S2-4 already follows that layout; any support-text mismatch elsewhere belongs to the relevant spec's editorial pass.

## App. A — Pilot Instance PDAs

The examples below are parameterized template instances, not named partner deployments. They demonstrate how the class table applies to concrete archetypes.

### App. A.1 KYC-lending enforcement PDA

Template: `kyc_lending_payment_default_v2`.

Defaults:

- use-case: KYC-lending;
- archetype: enforcement;
- G3: dcipher default;
- trust tier: Tier A if partner contract state is chain-native; Tier B/C if oracle-attested;
- reveal condition: PaymentObligationModule terminal default;
- shred condition: enforcement shred predicate plus mandatory guardrail;
- challenge windows: zero for Tier A, 14 days for Tier B/C;
- G4 phase: Phase 2;
- `legal_effect_expected = true`;
- `cealis_class_wide_halt_opt_out = false`;
- SD: optional per-field, default `escrow_only`.

Classifications: G3 choice category (b); challenge windows category (c) bounded by PDA+; legal-effect classification rule category (a) plus `legal_effect_expected_value` category (b); universal tripwire category (d); PaymentObligation template pick category (b) plus parameter values category (c).

### App. A.2 Testament PDA

Template: `testament_vital_records_k_of_n_v2`.

Defaults:

- use-case: testament;
- archetype: irreversible personal reveal;
- G3: drand default;
- trust tier: Tier B/C vital-records oracle k-of-n;
- condition: MultiPartySignal over independent vital-records attestations, optionally DeadManSwitch heartbeat-grace path;
- conditional recipients: role_tag HEIR or BENEFICIARY, `k >= 1`;
- `conditional_recipients_updatable = true` by default;
- challenge windows: zero by archetype;
- shred authority: Subject or Disabled depending on testament posture;
- long-TTL bricking acknowledgment required if immutability selected.

Classifications: testament flow template pick category (b) plus testament flow parameters category (c); k-of-n MultiPartySignal category (c) inside CF-07 default; long-TTL updatability default category (a) metadata; `k_conditional` category (c); base threshold 3 category (d).

### App. A.3 Evidence archival PDA

Template: `evidence_provenance_retention_v2`.

Defaults:

- use-case: evidence;
- archetype: tamper-proof / retention;
- G3: dcipher for regulated evidence, drand for long archival evidence where time-based retention dominates;
- trust tier: Tier B/C if custody oracle or evidence custodian attestation used;
- condition: EvidenceProvenance plus OracleAttestation or TimeLock;
- retention: bounded by evidence retention floors and max;
- challenge windows: 7 days where external oracle/custodian attestation drives legal effect;
- shred authority: Disabled for permanent archive or Joint for release-window archive;
- SD: metadata proofs possible, default `escrow_only`.

Classifications: evidence retention bounds category (a); retention value category (c); custodian oracle pick category (b); evidence schema SD availability category (a); SD field mapping category (b).

### App. A.4 M&A deal PDA

Template: `ma_deal_multiparty_closing_v2`.

Defaults:

- use-case: M&A;
- archetype: multi-party commercial escrow;
- G3: dcipher default for regulated/commercial-EU posture;
- trust tier: Tier A if closing event on partner contract, Tier B/C if counsel/court/oracle attested;
- condition: MultiPartySignal threshold among acquirer counsel, seller counsel, board representative, or registered oracle;
- conditional recipients: ACQUIRER_COUNSEL optional;
- challenge windows: zero for Tier A, 14 days for Tier B/C;
- jurisdiction: scalar or set-valued only if joint-escrow archetype opts in;
- QES: optional if §371a posture required.

Classifications: MultiPartySignal threshold category (c); jurisdiction shape category (a), jurisdiction code pick category (b), jurisdiction set parameters category (c) when enabled; QES pick category (b); QTSPRegistry category (a); commercial pricing tier pick category (b), pricing amounts category (c), and quota category (c).

### App. A.5 Dead-man's-switch PDA

Template: `dead_man_switch_heartbeat_release_v2`.

Defaults:

- use-case: dead-man's-switch;
- archetype: conditional reveal / liveness;
- G3: drand default for time/long-retention;
- condition: DeadManSwitchModule with heartbeat interval, grace window, optional notification delay, optional subject liveness oracle;
- recipients: BENEFICIARY or SUBJECT_ALTERNATE;
- conditional recipients: optional but default for high-consequence release;
- `pda_updatable = true` for long TTL;
- challenge windows: zero unless external Tier B/C oracle dispute surface is meaningful;
- shred authority: Subject or Timelock depending on intent.

Classifications: heartbeat cadence category (c); DeadManSwitch evidence template pick category (b) plus evidence parameters category (c); long-TTL updatability category (a default plus b pick); conditional-recipient threshold category (c); trust tier declaration category (b) with CF-06 enforcement.

### App. A.6 Example inspection summary fields

Every example produces a partner-readable summary with:

- applied defaults and overrides;
- class-table row ids;
- validation stages passed;
- simulation digest;
- `pda_root`;
- IPFS CIDs;
- on-chain registration tx;
- unresolved governance requests, if any.

No example grants a partner the ability to self-edit PDA JSON after deployment.

This summary applies equally to the controlled-use archetypes (A.7-A.10) introduced below; the controlled-use rows 92-107.3 of §5.2 appear in the class-table row ids list when `token_policy_config.enabled = true`.

### App. A.7 Pharmacy / prescription one-shot controlled-use PDA

Template: `pharmacy_prescription_one_shot_v3` (PDA+ ControlledUseAccessPolicy sub-class 6; see §6.5A).

Deployment shape: patient holds a health-record PDA; doctor writes a prescription slice; patient grants a one-shot consumption sub-token to a specific pharmacy for the prescription slice; pharmacy reads the prescription, appends a dispense-state-transition entry, and the sub-token is consumed.

Defaults:

- use-case: pharmacy / prescription (controlled-use);
- archetype: enforcement (one-shot consumption);
- `commit_version = 0x0303` (per CF-CU-01);
- `g3_choice = dcipher` (KYC / regulated-EU per Stage-0);
- `sd_election = DISABLED` (per CF-CU-02 / F-9);
- `token_policy_config.enabled = true`;
- `token_policy_config.master_token_classes = {Master, One-shot consumption, Scoped-slice}`;
- `token_policy_config.sub_token_lifetime_default_seconds = 86400` (24h pharmacy dispense window);
- `token_policy_config.scope_field_grammar = { allowed_forms: [SINGLE_SLICE], slice_atomicity_allowed: false }`;
- `token_policy_config.slice_layout = { slices: [prescription], evolution_policy: FROZEN_SCOPE }` with `prescription` slice carrying `write_authority_matrix = [(Doctor-master, WRITE), (Pharmacy-one-shot, WRITE_DISPENSE_TRANSITION)]`, `read_authority_matrix = [(Pharmacy-one-shot, READ)]`, `slice_dek_policy = PER_SLICE_DEK`;
- `token_policy_config.cache_policy = EPHEMERAL_ONLY`;
- `token_policy_config.recommended_client_profile = WEB_ONESHOT`;
- `token_policy_config.partner_may_strengthen_profile = true`;
- `token_policy_config.web_profile_write_allowed = true` (pharmacy dispense-transition; CF-CU-06 satisfied because profile is WEB_ONESHOT);
- `token_policy_config.audit_policy.stream1_retention_class = ART17_SHREDDABLE`;
- `token_policy_config.audit_policy.stream2_retention_class = ART5_ACCOUNTABILITY`;
- `token_policy_config.audit_policy.stream2_cosign_gate = G3_DCIPHER` (CF-CU-03 satisfied — matches `g3_choice = dcipher`);
- `token_policy_config.audit_policy.stream2_content_shape_digest_enabled = true` (BfArM prescription tracking is regulator-audit-subject);
- `token_policy_config.audit_policy.subject_checkpoint_mode = OPT_IN` (patient sees their pharmacy access trail);
- `token_policy_config.audit_policy.regulator_anchor_mode = OPT_IN` (BfArM verification mirror);
- `token_policy_config.revocation_mode = MASTER_ONLY`;
- `token_policy_config.emergency_elevation_policy.enabled = false`;
- `token_policy_config.first_presentation_gas_attribution = PARTNER_META_TX` (pharmacy partner sponsors);
- Stage 4 cross-field rules: CF-CU-01, CF-CU-02, CF-CU-03, CF-CU-06 all PASS; CF-CU-04, CF-CU-05 inapplicable (emergency-elevation disabled; DeadManSwitch not composed).

Classifications: PDA+ ControlledUseAccessPolicy (sub-class 6); class-table rows 92, 93, 94, 96, 97, 98.2, 99, 100, 101, 102, 103, 104, 105.1, 105.2, 105.3, 105.5, 105.6, 105.7, 106, 107.1 all present.

Simulation digest, `pda_root`, IPFS CIDs, on-chain registration tx: produced per §8.6 / §8.5.

### App. A.8 Doctor / health-record long-form controlled-use PDA

Template: `doctor_health_record_long_form_v3`.

Deployment shape: patient holds a health-record PDA with multiple slices (diagnosis, prescription, history, lab-results); doctor holds a master credential authorizing read across slices + write to diagnosis + prescription; consultation session lasts ~30-60 minutes with multiple cross-slice ops.

Defaults:

- use-case: doctor / health-record long-form (controlled-use);
- archetype: enforcement (session-bound);
- `commit_version = 0x0303`;
- `g3_choice = dcipher`;
- `sd_election = DISABLED`;
- `token_policy_config.enabled = true`;
- `token_policy_config.master_token_classes = {Master, Scoped-slice, Append-only writer, Emergency-elevation}`;
- `token_policy_config.sub_token_lifetime_default_seconds = 1800` (30-minute session);
- `token_policy_config.scope_field_grammar = { allowed_forms: [MULTI_SLICE_SUBSET, MASTER_WILDCARD], slice_atomicity_allowed: true }` (consultation = note + prescription + lab-order atomically);
- `token_policy_config.slice_layout = { slices: [diagnosis, prescription, history, lab-results], evolution_policy: FROZEN_SCOPE }` (per-slice DEK, with `history` immutable);
- `token_policy_config.cache_policy = ENCRYPTED_CACHE_OPT_IN` (consultation may cache briefly);
- `token_policy_config.recommended_client_profile = NATIVE_SESSION`;
- `token_policy_config.partner_may_strengthen_profile = true`;
- `token_policy_config.web_profile_write_allowed = false` (CF-CU-06 satisfied — native profile, web writes disabled);
- `token_policy_config.audit_policy.stream1_retention_class = ART17_SHREDDABLE`;
- `token_policy_config.audit_policy.stream2_retention_class = ART5_ACCOUNTABILITY`;
- `token_policy_config.audit_policy.stream2_cosign_gate = G3_DCIPHER`;
- `token_policy_config.audit_policy.stream2_content_shape_digest_enabled = true`;
- `token_policy_config.audit_policy.subject_checkpoint_mode = MANDATORY` (patient sees all access; required because `emergency_elevation_policy.enabled = true` per CF-CU-04);
- `token_policy_config.audit_policy.regulator_anchor_mode = OPT_IN`;
- `token_policy_config.revocation_mode = MASTER_ONLY`;
- `token_policy_config.emergency_elevation_policy.enabled = true` with `authority = [hospital_emergency_admin_address, attending_physician_role_address]` and `audit_class = STREAM2_ALWAYS_LOGGED`;
- `token_policy_config.first_presentation_gas_attribution = PARTNER_META_TX` (hospital partner sponsors);
- Stage 4 cross-field rules: CF-CU-01, CF-CU-02, CF-CU-03, CF-CU-04 (subject_checkpoint MANDATORY ↔ emergency_elevation enabled), CF-CU-06 all PASS; CF-CU-05 inapplicable (DeadManSwitch not composed — forbidden under controlled-use per H-6).

Classifications: PDA+ ControlledUseAccessPolicy (sub-class 6); class-table rows 92-107.3 with `emergency_elevation_policy` (rows 107.1-107.3) actively populated.

### App. A.9 Sealed team codebase / headless controlled-use PDA

Template: `sealed_team_codebase_headless_v3`.

Deployment shape: team of developers working on a high-sensitivity codebase stored as a per-slice envelope chain (each top-level directory is a slice); developer master credentials grant read across all code slices + append-only write to code slices; CI infrastructure uses team-member tokens for headless build operations.

Defaults:

- use-case: sealed team codebase / headless (controlled-use);
- archetype: enforcement (developer / CI);
- `commit_version = 0x0303`;
- `g3_choice = dcipher`;
- `sd_election = DISABLED`;
- `token_policy_config.enabled = true`;
- `token_policy_config.master_token_classes = {Master, Team-member, Hardware-bound, Append-only writer}`;
- `token_policy_config.sub_token_lifetime_default_seconds = 28800` (8-hour developer workday);
- `token_policy_config.scope_field_grammar = { allowed_forms: [MULTI_SLICE_SUBSET, MASTER_WILDCARD], slice_atomicity_allowed: true }` (commit = multiple-slice atomic);
- `token_policy_config.slice_layout = { slices: [src/main, src/tests, docs], evolution_policy: REISSUE_REQUIRED }` (team rotates credentials at slice topology evolution; CF-CU-06 satisfied — native profile);
- `token_policy_config.cache_policy = ENCRYPTED_CACHE_OPT_IN` (IDE workflows);
- `token_policy_config.recommended_client_profile = NATIVE_HEADLESS` (CI workflows; developers may use NATIVE_SESSION via `partner_may_strengthen_profile`);
- `token_policy_config.partner_may_strengthen_profile = true`;
- `token_policy_config.web_profile_write_allowed = false`;
- `token_policy_config.audit_policy.stream1_retention_class = ART17_SHREDDABLE` (typically retained for codebase integrity by partner choice);
- `token_policy_config.audit_policy.stream2_retention_class = ART5_ACCOUNTABILITY`;
- `token_policy_config.audit_policy.stream2_cosign_gate = G3_DCIPHER`;
- `token_policy_config.audit_policy.stream2_content_shape_digest_enabled = true`;
- `token_policy_config.audit_policy.subject_checkpoint_mode = DISABLED` (codebase is not subject-data; CF-CU-04 inapplicable because `emergency_elevation_policy.enabled = false`);
- `token_policy_config.audit_policy.regulator_anchor_mode = DISABLED`;
- `token_policy_config.revocation_mode = MASTER_AND_SUB_CRL` (CI tokens may need immediate revocation on team-member exit);
- `token_policy_config.emergency_elevation_policy.enabled = false`;
- `token_policy_config.first_presentation_gas_attribution = PARTNER_META_TX` (team partner sponsors);
- Stage 4 cross-field rules: CF-CU-01, CF-CU-02, CF-CU-03, CF-CU-06 all PASS; CF-CU-04 vacuously satisfied; CF-CU-05 inapplicable.

Classifications: PDA+ ControlledUseAccessPolicy (sub-class 6); class-table row 106 active under `MASTER_AND_SUB_CRL` (triggers `TokenRevocationRegistry` deploy per S2-2 §9.16D).

### App. A.10 M&A diligence room controlled-use PDA

Template: `ma_diligence_room_controlled_use_v3`.

Deployment shape: acquirer and target's M&A diligence; sealed diligence room with multiple document slices; acquirer's deal team holds master credentials authorizing read across slices; target's deal team holds master credentials authorizing append (data-room updates); closing event activates one-shot consumption tokens converting authority.

Defaults:

- use-case: M&A diligence room (controlled-use);
- archetype: multi-party commercial escrow with controlled-use access;
- `commit_version = 0x0303`;
- `g3_choice = dcipher` (regulated-EU per M&A jurisdiction);
- `sd_election = DISABLED`;
- `token_policy_config.enabled = true`;
- `token_policy_config.master_token_classes = {Master, Scoped-slice, Hardware-bound, One-shot consumption}`;
- `token_policy_config.sub_token_lifetime_default_seconds = 3600` (1-hour session);
- `token_policy_config.scope_field_grammar = { allowed_forms: [SINGLE_SLICE, MULTI_SLICE_SUBSET], slice_atomicity_allowed: false }` (diligence is non-atomic by slice);
- `token_policy_config.slice_layout = { slices: [financial-records, legal-documents, ip-documents], evolution_policy: FROZEN_SCOPE }` (closing event freezes layout);
- `token_policy_config.cache_policy = EPHEMERAL_ONLY` (no persistent caching for diligence);
- `token_policy_config.recommended_client_profile = NATIVE_SESSION`;
- `token_policy_config.partner_may_strengthen_profile = true`;
- `token_policy_config.web_profile_write_allowed = false`;
- `token_policy_config.audit_policy.stream1_retention_class = ART17_SHREDDABLE` (post-deal cleanup);
- `token_policy_config.audit_policy.stream2_retention_class = ART5_ACCOUNTABILITY`;
- `token_policy_config.audit_policy.stream2_cosign_gate = G3_DCIPHER`;
- `token_policy_config.audit_policy.stream2_content_shape_digest_enabled = true`;
- `token_policy_config.audit_policy.subject_checkpoint_mode = DISABLED` (diligence is non-subject-data; CF-CU-04 inapplicable);
- `token_policy_config.audit_policy.regulator_anchor_mode = OPT_IN` (M&A regulator audit; BaFin, FCA, etc.);
- `token_policy_config.revocation_mode = MASTER_AND_SUB_CRL` (immediate revocation at deal-close or break);
- `token_policy_config.emergency_elevation_policy.enabled = false`;
- `token_policy_config.first_presentation_gas_attribution = PARTNER_META_TX` (deal-room partner sponsors);
- Stage 4 cross-field rules: CF-CU-01, CF-CU-02, CF-CU-03, CF-CU-06 all PASS; CF-CU-04 vacuously satisfied; CF-CU-05 inapplicable.

Classifications: PDA+ ControlledUseAccessPolicy (sub-class 6); class-table row 106 active under `MASTER_AND_SUB_CRL`; row 105.7 `regulator_anchor_mode = OPT_IN` for M&A regulator visibility.
