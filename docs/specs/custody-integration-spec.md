# Cealis V2 System, V3 Custody - Custody Integration Specification (S2-3)

## §0 - Front Matter

### §0.1 Document identity

**Title:** Cealis V2 System, V3 Custody - Custody Integration Specification (S2-3)

**Stage:** Stage-2 mandatory specification. S2-3 is the normative SDK, vendor, attestation, transport, reliability, and integration-surface specification for the V2 system with V3 custody architecture. It consumes S2-1 (`docs/specs/cryptography-spec.md`) and S2-2 (`docs/specs/smart-contracts-spec.md`) and fixes how Cealis actually calls, verifies, retries, monitors, and pins the rented custody substrates: G2 Lit V3, G3 dcipher or drand, and G4 Phase 1 or Phase 2.

**Output artifact:** this document only. S2-3 does not write SDK code, adapters, runtime services, CLI tools, or Solidity contracts. Stage 3 implements this specification and proves it against real vendor SDK calls, mocked fault injection, attestation vectors, and multi-gate integration tests.

**Normative posture:** S2-3 is an adapter and verification specification, not a convenience wrapper. If a vendor SDK makes an operation easy but does not expose the evidence S2-1/S2-2 require, the SDK path is incomplete. Cealis must either use a lower-level API that exposes the evidence, obtain the missing evidence through a documented vendor channel, or block production enablement for that gate path. "The vendor said it verified" is not sufficient for any gate whose signature authorizes Shamir-share admission.

**Dependency relationship:** S2-3 consumes S2-1 byte layouts and S2-2 contract names. S2-3 is canonical for off-chain custody integration behavior: SDK versions, transport policy, failure taxonomy, gate request construction, quote verification selection, monitoring signals, and caller recovery boundaries. Downstream S2-5 ingestion/delivery and S2-6 operational ceremonies consume S2-3 rather than re-specifying gate integration.

### §0.2 Audience and reading order

**Cealis-internal integration engineer.** Read §1 conventions, §2 topology, §3 through §7 per-gate adapters, §9 combiner SDK, §11 version pins, §13 errors, and §14 tests. The implementation question is: can a Stage 3 engineer build adapters and a combiner client without asking how to call a gate or how to handle a failed attestation?

**External substrate auditor.** Read §0.6 source ordering, §0.7 discipline anchors, §2 topology, §3.4 and App. A DCAP verification, §7 G4, §9 combiner, §10 trust/failure matrix, and §11 version pins. The audit question is: do the SDK and attestation choices support the substrate claims without silently downgrading the 4-gate composition?

**Future Cealis engineers.** Read §11, §12, §13, and §15 first. These sections state how version churn is absorbed, where monitoring detects drift, and what future changes must not silently alter.

**Partners doing deep integration verification.** Read §2 topology, §3 Lit V3, §6 G3 choice, §7 G4, §10 trust assumptions, and §12 monitoring. Partner-facing copy must still obey WP §K; this document is a technical verification artifact, not marketing material.

### §0.3 Terminology discipline

**V2 vs V3.** V2 is the system version. V3 is the custody/key-holding subsystem inside V2. This document says "V2 system, V3 custody" or "V3 custody." It does not use bare "V3" as a system version. `_V3` suffixes on constants are imported from S2-1 and refer to the custody subsystem version.

**Gate names.** G1 is the Base on-chain ConditionEngine and `RevealAuthorized` event surface. G2 is Lit V3. G3 is dcipher or drand, chosen per PDA and frozen at commit. G4 is the Cealis verification component, with Phase 1 sealed-code server support for pre-funding dev-scaffold commitments and Phase 2 rented TEE support for partner-ready commitments.

**σ-as-authorization.** σ values are conventional authorization signatures over the reveal context. They are not HKDF input keying material and not DEK material. S2-3 uses the same doctrine as S2-1 §0.3 and §14: σ_Lit, σ_G3, σ_G4, σ_subject, and σ_conditional must verify before the corresponding wrapped Shamir share is admitted into the combiner. The drand path remains public-by-design for σ_G3 availability; strict composition remains load-bearing because the combiner needs threshold shares, not because σ bytes are secret.

**Phase 1 / Phase 2 G4.** Both phases are represented at the lookup and historical-verification layer. Phase 1 is pre-funding dev scaffold only. Partner-ready and legal-effect PDAs must commit under Phase 2. Phase 1 commitments remain verifiable after cutover through `G4AuthorityRegistry.getEntryAt(...)` and S2-1 §9.6 phase-swap discipline.

### §0.4 What this spec does not cover

S2-3 does not define cryptographic byte layouts for σ values, `h_commit`, `commit_AAD`, TAG constants, Shamir reconstruction, AEAD, stanza MACs, or endpoint attestation digests. Those are S2-1.

S2-3 does not define Solidity contracts, registry storage, access control, `RevealAuthorized`, `G4RefusalRegistry`, `LitV3Assignment`, `GateRecipientPubkeyRegistry`, `ShredRegistry`, or historical lookup semantics. Those are S2-2.

S2-3 does not define the PDA configurator fields or UI/CLI behavior for choosing dcipher vs drand, Phase 1 vs Phase 2, or legal-effect constraints. Those are S2-4.

S2-3 does not define ingestion/delivery REST endpoints, webhooks, vault object APIs, artifact JSON, or plaintext delivery. Those are S2-5.

S2-3 does not define operational ceremonies for G4 key rotation, plugin binary release, TimelockController execution, external advisor seating, vendor contract renewal, or emergency-response runbooks. Those are S2-6 and S3-1.

S2-3 does not define SD circuits or Selective Disclosure runtime. SD remains parallel and is S2-7.

### §0.5 Status of this document

This is the first S2-3 canonical draft. It is implementation-grade for Stage 3 except where this document explicitly marks a vendor-confirmation gate. A vendor-confirmation gate is not a design placeholder; it is a release-blocking integration assertion that must be proven against vendor SDK documentation, test vectors, or contract addresses before any production or partner-ready deployment.

Vendor-confirmation gates are tracked differently from architectural open questions. An architectural open question would require design escalation to the maintainer. A vendor-confirmation gate is an engineering proof obligation: identify the exact package, API, ciphersuite, address, release tag, or test vector and then update §11/App. B without changing the V2 system design. Stage 3 may close vendor-confirmation gates mechanically; it may not reinterpret gate composition or substitute substrates while doing so.

### §0.6 Source-of-truth ordering

For cryptographic constructions and byte-exact verification inputs, S2-1 is canonical.

For on-chain contract names, event fields, registry shapes, role names, and historical lookup semantics, S2-2 is canonical.

For full-engine scope, the internal Stage-0 decisions record (not included in this export) is canonical: both G3 paths are first-class; all gates are in the full system; pilot/partner commitments use Phase 2 G4; Phase 1 is dev-scaffold.

For project-level trust framing and banned public phrasings, WP §K is canonical. S2-3 inherits its caution against overclaiming "mathematically impossible" in Mode A, "decentralized," or "G4 is custody."

For V3 custody field names and historical reason-code context, `docs/designs/flows-spec-final.md` is a cross-check target, superseded by S2-1 and S2-2 where the Stage-2 specs deliberately updated it.

### §0.7 Document discipline anchors

**Rule 12 production-grade.** Every normative integration surface must be implementable. No adapter may treat a missing gate as a successful gate. No caller may replace a failing gate with another gate without a new PDA commit that binds the new choice.

**Rule 26 seven-view check.** The integration surface was checked across Enforcement, Tamper-proof, Selective Disclosure isolation, Commercial, Legal, Use-case flexibility, and Partner-fit. Concrete consequences: no Web3-lending-only gate path, no public σ logs as "proof," no Phase 1 legal-effect path, no automatic dcipher-to-drand fallback, and no partner-visible self-service use-case creation.

**Rule 29 naming.** V2 is the system; V3 custody is the custody subsystem.

**Rule 31 full engine.** Both dcipher and drand are in scope. Both G4 phases are represented. Historical 3-gate compatibility is represented only to preserve older/minimum-viable commit verification and migration semantics; it is not the normative partner launch scope.

**Universal tripwire.** No release path exists that bypasses the on-chain-verified predefined condition. S2-3 enforces this by requiring `RevealAuthorized` finality before gate requests, `canGatesSign(authorizationId) == true` before G4 signing, registry state at the authorization block, and a combiner that aborts unless all required σ values verify before Shamir-share admission.

**TAG import.** S2-3 imports TAG names from S2-1 §2 by name and section anchor only. S2-3 does not introduce new TAG constants. If an SDK-level construction appears to require a new domain separator, that is a BP-N candidate back to S2-1.

**Cross-vendor TEE.** For Phase 2 G4, the Lit V3 serving TEE vendor and G4 TEE vendor must be disjoint for the same commit/op. This document treats the disjoint check as normative at both commit-time validation and reveal-time recomputation.

### §0.8 Cross-reference index

**S2-1 imports:** §1 conventions; §2 TAG registry; §4 `commit_AAD`; §6 envelope and AEAD; §7 σ_Lit; §8 σ_G3; §9 σ_G4; §11 endpoint attestation; §12 registry verification; §14 combiner; §16 abort discipline; §17/App. C library pin deferrals.

**S2-2 imports:** §2 contract registry; §5 AttestationGate read surfaces; §9 five V3 registries plus `LitV3Assignment`, `GateRecipientPubkeyRegistry`, and `DisclosureRegistry`; §10 ShredRegistry state read; §11 Mode 3 reserved rejection; §12 `RevealAuthorized`; §14 refusal enum; §16 role matrix; §21 S2-3 consumption surface.

**Downstream consumers:** S2-4 consumes G3/G4 eligibility rules and SDK-readable validation errors. S2-5 consumes per-gate request/response semantics, idempotency keys, and σ delivery constraints. S2-6 consumes version-pin review cadence, plugin distribution references, G4 phase cutover surfaces, and vendor ceremony obligations. S3-1 consumes monitoring and alerting expectations.

### §0.9 PII content statement

S2-3 integration metadata is PII-minimized. SDK calls and logs may contain `authorizationId`, `h_commit`, `pda_root`, registry refs, block numbers, vendor identifiers, attestation measurements, and opaque error codes. They must not contain plaintext, subject identifiers, σ bytes, partial σ bytes, passkey public keys where avoidable, partial `commit_AAD`, or sensitive refusal plaintext. Refusal codes `0x02` and `0x03` inherit encrypted-reason handling.

## §1 - Conventions

### §1.1 Language and runtime conventions

The default off-chain implementation target is TypeScript on Node.js 20 LTS or newer for Cealis services and recipient plugin support, with Go used where vendor libraries are Go-native (`filippo.io/age`, `drand/kyber`, Automata Go DCAP tooling). Rust is permitted for TEE enclave code and DCAP quote parsing where the vendor SDK is Rust-first. Cross-language implementations must pass the same S2-1 byte-vector tests before they can be considered equivalent.

All adapters expose a typed interface shaped around:

- `prepareCommitBinding(...)`: construct or validate commit-time gate identity material.
- `requestSigma(...)`: request or fetch the reveal-time σ material after `RevealAuthorized` finality and challenge-window closure.
- `verifySigma(...)`: verify the returned σ and all companion attestation data before admitting it into the combiner.
- `healthProbe(...)`: report readiness, staleness, vendor version, registry agreement, and known deprecation state.

### §1.2 Confidential delivery convention

σ delivery and share-decap channels must provide authenticated encryption. Minimum acceptable transport is TLS 1.3 with certificate pinning or mTLS for service-to-service flows. Noise or TEE-native secure channels are acceptable if the implementation proves endpoint identity and forward secrecy. Plain HTTP, unauthenticated WebSocket, debug proxy forwarding, and queue-based σ/share persistence are forbidden.

σ values and recovered Shamir shares may be held only in process memory inside the gate adapter and combiner boundary. If a transient retry queue is needed, it stores only request metadata and opaque gate request ids, never σ bytes or share bytes. Any persisted diagnostic artifact stores hashes of non-secret public data only. Crash dumps that may contain σ material, shares, DEK, or plaintext must be disabled for combiner and gate adapter processes.

**Evidence without σ or shares.** Auditors still need to verify that the adapter did the right work. The evidence record therefore stores verification transcripts, not secrets: request id, authorization tuple, registry entry ids, quote digest, public-key digest, ciphersuite id, verifier contract address where applicable, SDK version, and pass/fail code. If a future auditor cannot replay why a gate was accepted without seeing σ bytes or share bytes, the adapter evidence shape is wrong. The evidence record must be sufficient to prove "this σ authorized this stanza decap under the canonical registry and ciphersuite" while remaining insufficient to reconstruct `file_key`.

### §1.3 Error model

S2-3 defines operational error codes distinct from S2-1 cryptographic `ERR_*` codes. Operational errors begin with `CUSTODY_ERR_`. When an S2-1 cryptographic check fails, the adapter surfaces the S2-1 code as the forensic sub-code and wraps it in a `CUSTODY_ERR_*` caller-facing class.

Every error is fail-closed. Caller recovery is operational only: retry the same gate request, re-fetch a registry entry, wait for finality, or re-run verification. Caller recovery never means "derive with fewer σ values" or "switch G3 path."

### §1.4 Logging discipline

Logs must be useful for operations and useless for decryption. A log entry may include:

- correlation id
- adapter name
- `authorizationId`
- `h_commit`
- `pda_root`
- chain id
- authorization block number and block hash
- gate name
- vendor id
- registry entry id
- error code
- latency bucket

A log entry must not include σ bytes, partial σ bytes, plaintext, ciphertext bytes, WebAuthn assertion bytes, wallet signature bytes, DCAP quote bytes, raw `commit_AAD`, raw ACC source if it contains partner-sensitive condition text, or encrypted-refusal plaintext. For DCAP, logs may include measurement digest and quote version only.

### §1.5 Retry and idempotency conventions

The canonical reveal workflow idempotency key is `(authorizationId, h_commit, authorizationBlock)` from S2-2 §12.3. Gate-specific retry keys extend it:

- G2 Lit V3: `(authorizationId, h_commit, authorizationBlock, assigned_tee_id)`
- G3 dcipher: `(authorizationId, h_commit, authorizationBlock, committee_epoch)`
- G3 drand: `(authorizationId, h_commit, target_round, chain_hash)`
- G4: `(authorizationId, h_commit, authorizationBlock, g4_authority_ref, phase)`

Retries must be bounded, jittered, and classified by failure type. Network timeout, rate limit, or vendor unavailable may retry. Signature verification failure, quote user_data mismatch, cross-vendor violation, registry tombstone before authorization, Mode 3 reserved, and G4 refusal do not retry automatically.

### §1.6 Failure mode taxonomy

S2-3 classifies custody failures as:

- **Network error:** endpoint unreachable, timeout, DNS failure, TLS failure, rate limit.
- **Attestation fail:** DCAP quote invalid, stale TCB, unrecognized vendor root, user_data mismatch.
- **Quote replay:** valid quote but bound to different `(authorizationId, h_commit, block_hash)`.
- **Assignment mismatch:** serving TEE does not match `LitV3Assignment`.
- **Vendor outage:** Lit, dcipher, drand, Automata, or G4 TEE provider cannot serve.
- **Governance rotation:** registry entry changed, tombstoned, or deprecated.
- **Cross-vendor mismatch:** Lit and G4 Phase 2 report same TEE vendor for the op.
- **Refusal:** G4 emits refusal code and does not provide σ_G4.
- **Gate-recipient KEM pubkey failure:** gate-recipient KEM pubkey cannot be fetched, does not match registry/attestation, or rotates mid-flight.
- **Shred state block:** ShredRegistry reports a non-signable state before gate signing.
- **Share admission failure:** σ verifies false, stanza decap fails, or Shamir threshold cannot be met.
- **Combiner hardening failure:** binary hash mismatch, sandbox unavailable, crash dump enabled, debug output active.

## §2 - Integration topology

### §2.1 Four-gate runtime composition

Runtime reveal proceeds in this order:

1. G1 emits `RevealAuthorized` through ConditionEngine or its authorized emitter.
2. Off-chain workers wait for Base finality and challenge-window satisfaction.
3. Gate adapters request or fetch σ_Lit, σ_G3, and σ_G4 from their respective substrates.
4. The recipient-side combiner verifies all gate signatures, attestations, registries, gate-recipient KEM pubkeys, and envelope bindings.
5. The combiner unwraps the authorized stanzas, recovers Shamir shares, reconstructs `file_key` via S2-1 §6.3, and decrypts via S2-1 §6.4.

G1 is event-visible rather than a σ input. G2, G3, and G4 produce σ authorizations. Conditional recipients produce σ_conditional where the PDA requires them. Missing any required σ or any threshold-required Shamir share produces no file key.

The adapter must treat G1 as more than "an event appeared in a log." It must bind every off-chain request to the event's contract address, chain id, `authorizationId`, `hCommit`, `authorizationBlock`, `authorizationTimestamp`, `challengeWindow`, `conditionRef`, and final block hash. If an indexer supplies the event, the adapter still verifies the event against an RPC source or proof service before gate requests. Indexer trust is operational convenience only; it is not a custody gate.

All gate requests are made against the authorization snapshot. "Current head" reads are used only to discover that more finality is needed or that a rotation occurred. Acceptance decisions use the block that S2-2 makes canonical for the reveal. This matters when a registry entry rotates between authorization and delivery: current-state convenience must not erase historical truth, and historical truth must not authorize a gate that was already tombstoned before authorization.

### §2.2 Per-PDA gate selection

The following fields are frozen into commit metadata:

- `g3_choice = 0`: dcipher
- `g3_choice = 1`: drand
- `phase = 1`: G4 Phase 1 dev-scaffold path
- `phase = 2`: G4 Phase 2 partner-ready path

G2 Lit V3 is mandatory for all current full-engine commits. G3 choice is per-PDA, selected by use-case default or explicit partner choice in the configurator. G4 phase is constrained by PDA type; legal-effect and partner-ready PDAs require Phase 2.

The adapter must read `g3_choice` and `phase` from the same `commit_AAD`/chain anchor the combiner verifies. Adapter configuration cannot override those fields at reveal.

### §2.3 Phase lookup matrix

The `phase` field is commit-bound trust posture. Commit-time validation and reveal/admission validation are separate checks, and both must agree with the frozen `phase`.

| G4 phase | Commit validation | Reveal/admission validation |
|---|---|---|
| Phase 1 | `phase = 1`; sealed-code server metadata only; PDA must be eligible for dev-scaffold commitments | accept only Ed25519 σ_G4 plus Phase 1 binary metadata; historical verification only; reject DCAP/Phase 2 artifacts |
| Phase 2 | `phase = 2`; rented-TEE endpoint attestation and serving-key binding required; partner-ready/legal-effect path | accept only DCAP quote σ_G4; require `phase == 2`; run cross-vendor check; run refusal/signability checks |

Reverse substitution is forbidden in both directions. A Phase 2 commit cannot accept a Phase 1 σ_G4. A Phase 1 commit cannot accept a Phase 2 DCAP σ_G4 as an upgrade. Any artifact/commit phase mismatch fails `CUSTODY_ERR_G4_PHASE_MISMATCH`; PDA-type ineligibility remains `CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE`. Re-commit under Phase 2 is required if a former Phase 1 flow needs partner-ready trust posture.

### §2.4 Cross-vendor TEE disjoint constraint

For every Phase 2 G4 reveal, the adapter must recover:

- Lit V3 TEE vendor from the Lit per-op DCAP quote and assignment metadata.
- G4 TEE vendor from the G4 Phase 2 quote and registry entry.

If both vendors are the same, verification fails with `CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION` wrapping S2-1 `ERR_SIGMA_G4_PHASE2_CROSS_VENDOR_VIOLATION`. This is mandatory even when both quotes otherwise verify. Configurator-time validation is not enough because Lit assignment is per-op and can differ at reveal time.

The disjointness check compares normalized vendor family, not marketing product name. Intel SGX and Intel TDX are the same vendor family for this constraint. AWS Nitro is its own vendor family even when the host CPU is Intel or AMD, provided the attestation root and isolation claim are Nitro's. AMD SEV-SNP is the AMD vendor family. If a vendor path is ambiguous, the adapter fails closed until S2-6 records an explicit classification.

### §2.5 Gate-recipient KEM pubkey lifecycle

Every stanza that wraps a Shamir share names a **gate-recipient KEM pubkey at commit** from S2-2 `GateRecipientPubkeyRegistry` or an equivalent attested source bound into that registry. The adapter fetches the pubkey at the commit block, verifies the registry or attestation proof for that snapshot, and rejects current-head substitution.

S2-3 uses a split-key model for every share-bearing gate:

- `gate_recipient_kem_pubkey_at_commit` is the ML-KEM-768 + X25519 or tlock recipient key used only to wrap and decapsulate the typed Shamir share for that stanza generation.
- `gate_sigma_verification_pubkey_at_authorization` is the signing, threshold-signing, passkey, wallet, or attestation verification key used only to verify σ authorization evidence at the `RevealAuthorized` block.

These keys are never interchangeable. A reveal-time assignment key cannot replace a commit-time KEM recipient key. A commit-time KEM recipient key cannot verify σ. No BLS-to-X25519, Ed25519-to-X25519, P-256-to-X25519, secp256k1-to-X25519, or attestation-root-to-KEM conversion is defined or permitted.

The universal block rule is strict: commit-block state verifies stanza wrapping, KEM pubkey identity, and share-domain binding; authorization-block state verifies σ authority, assignment, tombstone/deprecation status, G4 phase/refusal state, and signability. A combiner may admit a share only when both snapshots verify and the gate proves continuity between the authorization-time σ authority and the commit-bound KEM decap authority.

Lit V3, G4, and conditional recipients prefer per-commit or per-generation KEM pubkeys. dcipher may use a committee-epoch or PDA-scoped KEM pubkey. drand uses a long-lived committee tlock/KEM key because the drand path does not provide a private per-commit recipient primitive. This is structurally weaker than Lit/G4/Conditional, so the drand adapter must document the active committee key, governance timelock entry, and share-only leak mitigation: a compromised drand unwrap exposes at most `TopShare(G3)` and cannot reconstruct the DEK without the other mandatory branches.

IB-2 composition is imported here. Lit, G3, and G4 wrap mandatory top-level shares. Conditional-recipient stanzas are absent for `FIXED_ONLY`, wrap `TopShare(RECIPIENT)` for `RECIPIENT_1_OF_1`, and wrap `NestedShare(RECIPIENT_BRANCH, recipient_index)` for `RECIPIENT_K_OF_N`. Conditional-recipient surplus can satisfy only the recipient branch; it can never replace Lit, G3, or G4.

Mode B device-encrypt commitments must fetch gate-recipient KEM pubkeys on the subject device at commit time. The partner specifies the fetch endpoint and registry proof shape; the device verifies registry/attestation binding before wrapping shares. Failures are terminal for that commit attempt: `CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL`, `CUSTODY_ERR_GATE_PUBKEY_MISMATCH`, or `CUSTODY_ERR_GATE_PUBKEY_ROTATION_MID_FLIGHT`.

## §3 - G2 Lit V3 integration

> **See S2-8 (controlled-use spec) §4 for the cross-vendor cosign extension: a controlled-use PDA may select G2 Lit V3 as the cosign-gate for Stream 2 audit-event signing alongside G4.**

### §3.1 SDK selection and version pin

The Lit integration uses Lit Chipotle through Lit's Core/REST SDK surface and JS packages:

- `@lit-protocol/lit-node-client` pinned to `7.3.0` for Stage 3 baseline.
- `@lit-protocol/contracts-sdk` pinned to `7.4.0` where contract reads are SDK-mediated.
- Lit Chipotle REST/Core API version pinned by base URL plus documented API version in deployment config.

The version pin is not a claim that later Lit releases are unsafe. It is the baseline that Stage 3 test vectors verify. Upgrading requires S2-3 §11 re-review and replay of σ_Lit, ACC, assignment, and DCAP tests.

The Lit adapter must not hide behind a high-level decrypt or access helper that returns plaintext or an opaque "allowed" flag. Cealis needs the gate signature material and the attestation evidence separately so the recipient combiner can pre-verify under S2-1. Any Lit SDK path that combines access evaluation, signature production, and decryption inside a single opaque call is unsuitable unless it exposes the same σ_Lit bytes and quote evidence defined here.

### §3.2 Commit-time ACC construction

The Lit Access Control Conditions (ACC) bind the reveal to the on-chain condition and the specific commit. The ACC must require:

- Base chain id.
- ConditionEngine/AttestationGate contract address.
- `authorizationId`.
- `h_commit`.
- finalized `RevealAuthorized` block hash.
- `canGatesSign(authorizationId) == true`.
- no current shred state for `h_commit`.

ACC source bytes are treated as protocol-canonical bytes for `Lit_ACC_spec` in S2-1. The adapter must canonicalize ACC JSON deterministically before hashing or submission: stable key ordering, no insignificant whitespace dependency, explicit chain id, explicit contract address, and explicit function signature. A different ACC parser result for semantically equivalent JSON is a deployment blocker because it changes the identity surface Lit signs against.

### §3.2.1 Lit gate-recipient KEM pubkey at commit

During Mode A commit, before plaintext leaves the G4 ingestion TEE, the sealing context resolves `lit_gate_recipient_kem_pubkey_at_commit` from `GateRecipientPubkeyRegistry` or a Lit-attested equivalent reflected into that registry at the commit snapshot. The record must name the X25519 public key, ML-KEM-768 public key, ciphersuite ids, key generation, registry/source id, effective block, and `lit_kem_pubkey_digest`.

The Lit stanza wraps exactly `TopShare(LIT)` under `lit_gate_recipient_kem_pubkey_at_commit`. Its wrap AAD must bind `stanza_index = 0`, `share_domain = TOP_LEVEL`, `share_role = LIT`, logical top-level index, `access_structure_profile`, `commit_context_digest`, `plugin_version_digest`, and `lit_kem_pubkey_digest`. Later Lit KEM rotation cannot replace this pubkey for the existing envelope. Re-key may append a new wrap generation around the same logical `TopShare(LIT)`; ordinary reveal verifies the selected generation against its own commit-generation snapshot.

`assignedTeePubkey` from `LitV3Assignment` is not the Lit stanza recipient key. It is the reveal-time σ verification key. The only way a reveal-time Lit TEE can release the commit-wrapped Lit share is by proving decap authority over the commit-bound KEM key without replacing that key.

### §3.3 LitV3Assignment fetch and verification

Before accepting σ_Lit, the adapter reads `LitV3Assignment.getAssignment(authorizationId)` from the S2-2 mirror contract at the authorization block. This record provides `lit_sigma_verification_pubkey_at_authorization`, not the stanza KEM recipient key. The record must provide:

- `authorizationId`
- `assignedTeeId`
- `assignmentBlock`
- `assignedTeePubkey`
- `sourceGovernanceDigest`

Verification steps:

1. Query at `authorizationBlock`, not current head.
2. Confirm the assignment exists and `assignmentBlock <= authorizationBlock`.
3. Confirm `assignedTeeId` matches the TEE id derived from the DCAP quote.
4. Confirm `assignedTeePubkey` verifies σ_Lit under the S2-1 §7 signing input.
5. Confirm `sourceGovernanceDigest` matches the Lit governance bridge event the mirror claims to represent.

If the mirror is missing or stale, the reveal does not proceed. Cealis governance cannot synthesize a Lit assignment.

The adapter records the mirror read as an evidence edge: `authorizationId -> LitV3Assignment entry -> quote tee id -> σ_Lit verification key`. This edge is what lets an external auditor distinguish "Lit signed" from "the assigned Lit TEE for this reveal signed." A signature under an otherwise valid Lit key that is not the assigned key for the authorization id is rejected.

Before admitting `TopShare(LIT)`, the adapter must also verify a Lit KEM-to-assignment binding proof. The proof binds `(authorizationId, h_commit, block_hash, lit_kem_pubkey_digest, assignedTeeId, assignedTeePubkey, assignmentBlock, access_structure_profile, stanza_index = 0, share_domain = TOP_LEVEL, share_role = LIT)` and is signed by the same `assignedTeePubkey` that verifies σ_Lit or carried inside the per-op DCAP evidence as an equivalent TEE-local statement. A valid σ_Lit without this binding proof authorizes nothing at the share layer.

### §3.4 Per-op DCAP quote verification

Lit V3 per-op DCAP verification checks:

- quote signature chain to the hardware vendor root
- TCB status accepted under the current allowlist at authorization time
- enclave measurement matches Lit's assigned serving TEE
- `user_data` first 32 bytes equal `keccak256(authorizationId || h_commit || block_hash)[:32]`
- remaining 32 `user_data` bytes are zero
- quote freshness is within the configured window

S2-1 contains a deliberate asymmetry: Lit's BLS signing input/user_data digest is the raw `authorizationId ‖ h_commit ‖ block_hash` digest, while G4 Phase 2 uses `TAG_G4_ATTESTATION_V3` in the user_data digest. S2-3 adopts the S2-1 §7/§11 discipline: Lit user_data verification uses the Lit raw tuple digest plus zero padding and never imports `TAG_G4_ATTESTATION_V3` into the Lit path.

Vendor support is Intel SGX, AMD SEV-SNP, or AWS Nitro where Lit exposes such heterogeneity. If Lit's production API exposes only a subset, deployment config must state the subset and the cross-vendor rule must be evaluated against the actual vendor returned.

### §3.5 σ_Lit reception and redaction discipline

σ_Lit is accepted only from the assigned Lit TEE response channel. It is written directly into combiner memory or a bounded in-process handoff object. The adapter stores only:

- received timestamp
- assignment id
- quote digest
- verification result
- error code if failed

It must not store σ_Lit, quote bytes, or partial signature bytes in logs or persistent queues. The combiner zeroizes σ_Lit after authorization verification and zeroizes the recovered Lit share after Shamir reconstruction.

### §3.6 Failure modes

| Failure | Error | Recovery |
|---|---|---|
| Lit API unavailable | `CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE` | retry with jitter; alert after SLO breach |
| assignment missing | `CUSTODY_ERR_LIT_ASSIGNMENT_MISSING` | no automatic retry past bridge lag window |
| assigned TEE mismatch | `CUSTODY_ERR_LIT_ASSIGNMENT_MISMATCH` | abort; possible vendor/security incident |
| DCAP invalid | `CUSTODY_ERR_LIT_DCAP_INVALID` | abort; no retry unless fresh quote requested |
| user_data mismatch | `CUSTODY_ERR_LIT_QUOTE_REPLAY` | abort; security incident |
| BLS signature invalid | `CUSTODY_ERR_LIT_SIG_INVALID` | abort |
| ACC rejected | `CUSTODY_ERR_LIT_ACC_REJECTED` | caller may re-read chain state; no fallback |

### §3.7 Reliability and monitoring

Lit monitoring tracks assignment bridge lag, quote verification latency, API error rate, TEE vendor distribution, cross-vendor pair availability, ACC parser failures, and rate-limit events. Any spike in assignment mismatch or quote replay is severity critical because it attacks the A06/A14 substrate.

### §3.8 Stream 2 cosign extension (controlled-use, commit_version = 0x0303)

Lit V3 is a candidate cosign-gate for the controlled-use Stream 2 audit-anchoring chain per S2-8 §4.4 and synthesis H-4. The cosign role is additive to the read-path σ_Lit role established in §3.1–§3.7; it does not replace, weaken, or substitute the read-path responsibilities of the Lit V3 SDK in §3.

**Selection.** A controlled-use PDA selects Lit V3 as the cosign-gate by setting `audit_policy.stream2_cosign_gate = G2_LIT` (S2-8 §3.2.6, propagated to PDA at S2-4 amendment). Selection is per-PDA at commit and is not switchable mid-deployment. Non-controlled-use deployments do not exercise this path.

**Signing authority and domain separation.** The cosign uses the same Lit V3 signing authority that produces σ_Lit on the read path (the LitV3Assignment-resolved assigned TEE — §3.3). The Lit BLS signing key is reused; what differs is the input domain. The cosign input is domain-separated under `TAG_CU_AUDIT_STREAM2_V3` (S2-1 §2.3.5, introduced under `commit_version = 0x0303`), so a Stream 2 cosign signature can never collide with, replay against, or substitute for a read-path σ_Lit signature even though both share Lit V3 hardware authority.

**Cosign input form (per S2-8 §4.4):**

```
stream2_cosign_input = keccak256(
    TAG_CU_AUDIT_STREAM2_V3 ||
    stream2_merkle_root ||
    pepper_epoch_number ||
    block_hash
)
```

`stream2_merkle_root` is the root of the Stream 2 audit-event Merkle batch flushed at the configured cadence (S2-8 §6.1 step 10). `pepper_epoch_number` is the deployment-scoped audit-pepper epoch covering the batch (S2-8 §10). `block_hash` is the chain block hash the cosign is anchored to.

**Reception flow.** A Stream 2 anchor batch is assembled by G4 (per §7.X Write-validation TEE scope extension); G4 computes `stream2_merkle_root`, signs the audit-stream2 signature under `K_G4_audit_stream2`, then the adapter requests a Lit V3 cosign for the same root via the existing Lit V3 per-op signing pattern (§3.4 per-op DCAP quote + Lit BLS production). The Lit cosign signature is bundled with the G4 audit-stream2 signature into the on-chain anchor transaction. Both signatures land in the same Stream 2 anchor transaction; the anchor cannot land with only one of the two.

**DCAP discipline.** A Stream 2 cosign request reuses the §3.4 per-op DCAP quote machinery (assigned TEE id, quote-signature chain, TCB acceptance, measurement match, freshness window). The cosign quote's `user_data` first 32 bytes equal `keccak256(stream2_merkle_root || pepper_epoch_number || block_hash)[:32]` — distinct from the read-path `user_data` digest. Remaining 32 `user_data` bytes are zero. Reusing the read-path DCAP user_data digest as cosign user_data is forbidden and the adapter must reject such a payload as cross-domain replay.

**Vendor-family consistency.** Cross-vendor disjoint mandate from §2.4 extends to the Stream 2 cosign-gate selection: at the deployment layer, the {G2 Lit V3, G3 dcipher, G3 drand} cosign choice must not collapse the cross-vendor diversity claim that the read path requires from σ_Lit + σ_G3 + σ_G4. Vendor-family normalization rules from §2.4 apply identically; vendor-family ambiguity at cosign selection fails closed.

**Failure mode.** Cosign absence at Stream 2 anchor validation time produces `CU_ERR_STREAM2_COSIGN_MISSING` (§13.1). The Stream 2 anchor transaction must not land on-chain without both the G4 audit-stream2 signature and the Lit cosign signature; partial submission is rejected at the chain-level check.

**Substrate alignment with the Lit V3 Chipotle pivot.** Per the recorded Lit V3 Chipotle substrate-pivot decision, Lit V3 ships at first pilot on the single-TEE Phala TDX + on-chain KMS substrate. The Stream 2 cosign protocol rides the same substrate as the read-path σ_Lit signing; it does not introduce a second Lit signing surface. Substrate-specific byte-level details (Phala TDX quote semantics, on-chain KMS interaction for cosign-time key release) defer to the Lit V3 Chipotle SDK version pin in §11.

**Redaction.** Stream 2 cosign signatures from Lit V3 are subject to the same §3.5 reception-and-redaction discipline as read-path σ_Lit: never logged, never persisted in clear, accepted only from the assigned channel, zeroized after admission into the anchor transaction.

## §4 - G3 dcipher integration

### §4.1 SDK selection and version pin

dcipher is a first-class G3 path. The Randamu dcipher SDK version pin is vendor-gated because the public SDK and exact BLS variant were not confirmed in the S2-3 source corpus. Stage 3 may not ship the dcipher adapter until it pins:

- SDK package name and release version or immutable git commit
- BLS12-381 variant, signature length, and pubkey length
- committee registry endpoint
- epoch and tombstone data shape
- test vector for σ_G3 over `authorizationId ‖ h_commit ‖ block_hash`

Until those are proven, dcipher PDAs remain spec-complete but implementation-blocked. This is not permission to auto-fallback to drand.

The dcipher release gate is intentionally strict because dcipher carries the regulated-EU and governed-threshold posture in the G3 design. A hand-rolled BLS adapter against an undocumented endpoint is forbidden. If Randamu exposes multiple networks, committees, or environments, Stage 3 must pin the exact network and distinguish testnet vectors from production vectors. A production PDA may not rely on a testnet committee, even if the signature format is byte-identical.

### §4.2 Commit-time dcipher gate-recipient KEM pubkey

For `g3_choice = 0`, the sealing context resolves `dcipher_gate_recipient_kem_pubkey_at_commit` from the dcipher registry path configured by the PDA at the commit snapshot. The KEM key may be committee-epoch scoped or PDA-scoped; the chosen scope must be explicit in registry evidence. New partner-ready commits prefer PDA-scoped KEM keys when Randamu exposes them. Committee-epoch KEM keys remain valid only when the registry certificate names the committee, epoch, ciphersuite ids, and pubkey digests.

The dcipher G3 stanza wraps exactly `TopShare(G3)` under the commit-bound dcipher KEM tuple. The wrap context must bind `g3_choice = 0`, dcipher network/environment id, committee id, KEM epoch, KEM scope, `pda_root` or digest, `authorizationId`, `commit_context_digest`, `stanza_index = 1`, `share_domain = TOP_LEVEL`, `share_role = G3`, X25519 pubkey digest, ML-KEM-768 pubkey digest, and KEM ciphersuite ids.

A later dcipher KEM rotation cannot replace the commit-bound KEM pubkey at reveal. If the KEM key needs replacement, the path is re-key or supersession; it is not caller recovery and not current-head substitution.

### §4.3 Authorization-time committee pubkey fetch and σ verification

For `g3_choice = 0`, the adapter resolves the dcipher committee pubkey at the authorization block/epoch:

1. Read `g3_choice` from `commit_AAD`.
2. Resolve the Randamu Threshold Association committee epoch covering `authorizationBlock`.
3. Fetch committee pubkey and membership metadata from the vendor registry.
4. Confirm the registry entry is effective and not tombstoned at the authorization block.
5. Verify σ_G3 under the resolved committee pubkey over S2-1 §8.2.3 input.

If Randamu exposes an on-chain registry on a non-Base chain, the adapter must carry chain id, block/epoch reference, finality proof, and source digest in the artifact. If a mirror contract is introduced later, that is an S2-2/S2-6 coordination item.

The authorization-time dcipher committee pubkey is `dcipher_sigma_verification_pubkey_at_authorization`. It verifies σ_G3 only. It cannot be substituted as the stanza KEM recipient key. Before admitting `TopShare(G3)`, the adapter must prove continuity between `dcipher_sigma_verification_pubkey_at_authorization` and `dcipher_gate_recipient_kem_pubkey_at_commit`: either the same committee registry entry controls both, or a registry-signed delegation/rotation record links the authorization committee to the commit-bound KEM key without replacing the committed KEM key. If continuity is absent, the G3 branch is absent even if σ_G3 verifies.

### §4.4 σ_G3 threshold BLS verification

dcipher σ_G3 verification uses the SDK's published BLS/threshold-IBE verification function and must be cross-checked with `@noble/curves` BLS verification where possible. The S2-1 wire format treats the dcipher signature as `Bytes`; S2-3 requires the implementation to reject any length that does not match the pinned SDK variant.

### §4.5 Epoch rotation handling

dcipher epoch rotation is historical, not current-state. The adapter must accept a committee that was valid at the authorization block even if a later committee is current. Rotation events after `RevealAuthorized` do not invalidate in-flight ceremonies. Rotation events before authorization block and not reflected in the adapter cache invalidate the cache and require fresh fetch.

### §4.6 Governance rotation and tombstone semantics

A tombstone at or before the authorization block fails verification. A tombstone after the authorization block does not fail the historical reveal. A deprecation active at authorization block triggers G4 refusal and combiner abort unless the PDA legally permits opt-out; legal-effect PDAs cannot opt out.

The dcipher adapter must surface tombstone/deprecation state to the artifact layer without free-form vendor prose. Use reason codes, entry ids, block/epoch numbers, and disclosure CIDs.

### §4.7 Failure modes

| Failure | Error | Recovery |
|---|---|---|
| SDK unavailable in build | `CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED` | release blocker |
| committee registry unavailable | `CUSTODY_ERR_DCIPHER_REGISTRY_UNAVAILABLE` | retry; alert |
| committee epoch mismatch | `CUSTODY_ERR_DCIPHER_EPOCH_MISMATCH` | abort after fresh fetch |
| threshold not met | `CUSTODY_ERR_DCIPHER_THRESHOLD_NOT_MET` | wait/retry if ceremony still open |
| signature invalid | `CUSTODY_ERR_DCIPHER_SIG_INVALID` | abort |
| tombstoned before authorization | `CUSTODY_ERR_DCIPHER_TOMBSTONED` | abort |

### §4.8 Stream 2 cosign extension (controlled-use, commit_version = 0x0303)

dcipher is a candidate cosign-gate for the controlled-use Stream 2 audit-anchoring chain per S2-8 §4.4 and synthesis H-4. The cosign role is additive to the read-path σ_G3 role established in §4.1–§4.7.

**Selection.** A controlled-use PDA selects dcipher as the cosign-gate by setting `audit_policy.stream2_cosign_gate = G3_DCIPHER` (S2-8 §3.2.6). Selection is per-PDA at commit. Until the dcipher SDK vendor confirmation gate clears (§4.1), this selection remains spec-complete but implementation-blocked, matching the same release gate that holds read-path σ_G3.

**Signing authority and domain separation.** The cosign uses the same dcipher Threshold Association committee BLS aggregate that produces σ_G3 on the read path (§4.3 authorization-time committee pubkey). The input is domain-separated under `TAG_CU_AUDIT_STREAM2_V3` (S2-1 §2.3.5) so a Stream 2 cosign signature can never collide with or substitute for a read-path σ_G3 signature.

**Cosign input form (per S2-8 §4.4):**

```
stream2_cosign_input = keccak256(
    TAG_CU_AUDIT_STREAM2_V3 ||
    stream2_merkle_root ||
    pepper_epoch_number ||
    block_hash
)
```

`stream2_merkle_root`, `pepper_epoch_number`, and `block_hash` carry the same meanings as in §3.8.

**Reception flow.** G4 computes `stream2_merkle_root` and signs under `K_G4_audit_stream2`; the adapter then requests a dcipher threshold cosign for the same input via the same Randamu Threshold Association committee surface that produces read-path σ_G3 (§4.3). Both signatures bundle into the on-chain Stream 2 anchor transaction. The anchor cannot land with only one of the two.

**Committee continuity.** The cosign verification key for Stream 2 is the dcipher committee pubkey covering the anchor block (resolved analogously to §4.3 step 2). A rotation tombstone or deprecation effective at or before the anchor block fails the cosign and forces an alternate anchor cadence boundary per S2-8 §4.6 escalation rules.

**Vendor-family consistency.** Same cross-vendor disjoint discipline as §3.8 applies. If the PDA reserves σ_G3 for the dcipher read path AND selects `G3_DCIPHER` as the Stream 2 cosign-gate, the cross-vendor diversity claim is preserved only when the cosign committee instance and the read-path committee instance are operated under separate vendor-family attestations; vendor-family normalization rules from §2.4 govern this evaluation. Vendor-family ambiguity fails closed.

**BLS variant.** The Stream 2 cosign signature length and BLS12-381 variant match the read-path σ_G3 pin established in §4.1. A length mismatch is rejected.

**Failure mode.** Cosign absence at Stream 2 anchor validation time produces `CU_ERR_STREAM2_COSIGN_MISSING` (§13.1).

**Redaction.** Stream 2 cosign signatures from dcipher are subject to the same §4-wide redaction discipline (no logs, no persistence in clear, drift detection on registry state).

## §5 - G3 drand integration

### §5.1 SDK selection and version pin

drand integration uses:

- `github.com/drand/kyber` pinned to `v1.3.2` for Go verification.
- `drand-client` pinned to `1.4.2` for JavaScript client-side fetch where browser/Node use is required.
- `@noble/curves` pinned per §11 for independent BLS12-381 verification.

drand uses the minimum-pubkey-size BLS12-381 variant per S2-1: G1 public key, 48 bytes; G2 signature, 96 bytes.

The drand path is public randomness, not a private committee signature service. Its value in V3 custody is time/availability composition, not secrecy of σ_G3. The adapter therefore applies the same redaction and no-logs discipline to drand's public signature inside common σ-handling code paths for uniform hardening, while the security argument acknowledges that anyone can fetch the same round signature once available. This prevents accidental special-case leaks in the combiner without pretending drand is secret.

### §5.2 drand round targeting at commit

For `g3_choice = 1`, the G3 stanza contains a target drand round. The target round must be derived from PDA policy and frozen at commit. The adapter must not choose a later round at reveal to recover from an unavailable target round. If a target round is unavailable, the reveal waits or fails according to PDA policy; it does not silently move to another round.

The round calculation must account for the drand chain period, genesis time, and chain hash. The chain hash and public key are part of the configuration profile. A chain hash mismatch fails verification.

The drand share-wrap layer treats the committed tlock/committee public key as `drand_gate_recipient_kem_pubkey_at_commit`. It is usually long-lived committee material rather than per-PDA key material, but it is still resolved at the commit snapshot and role-tagged as the share-wrap key. The reveal-time drand threshold-signature verification key is `drand_sigma_verification_pubkey_at_authorization`. These roles remain distinct even if the same drand chain public key bytes participate in both the tlock construction and BLS signature verification.

### §5.3 drand tlock share-decap construction

The drand adapter treats the published round signature as σ_G3. For `g3_choice = 1`, every drand G3 stanza is tlock-wrapped so the combiner has explicit share-decapsulation material in addition to the public authorization signature. The combiner's required authorization artifact remains the verified BLS round signature bytes; the tlock wrapper only recovers the committed G3 Shamir share and must not introduce a separate release path.

Commit-time wrapping binds `TopShare(G3)` to `(chain_hash, target_round, drand_gate_recipient_kem_pubkey_digest, h_commit, stanza_index, g3_choice, tlock_ciphersuite_id, share_domain = TOP_LEVEL, share_role = G3)` as stanza context/AAD. `target_round` is derived from PDA policy, frozen at commit, present in stanza metadata, and present in the tlock identity. The `chain_hash` and public-key digest must match the committed drand configuration profile.

Reveal-time decap material is exactly: verified drand BLS round signature bytes for `(chain_hash, target_round)`, the tlock ciphertext, the committed stanza context/AAD, and the pinned tlock ciphersuite id. Endpoint response bodies, timestamps, and URLs are evidence only; they are not trusted decap authority. If the returned randomness has a different round, chain hash, public key, or signature bytes than the committed stanza target, the adapter rejects with `CUSTODY_ERR_DRAND_ROUND_MISMATCH` or `CUSTODY_ERR_DRAND_CHAIN_MISMATCH` and must not try adjacent or later rounds.

After successful decap, the recovered 32-byte share enters the same deterministic G3 share slot as dcipher. Ordering is by committed stanza index and policy order, never endpoint arrival order or fetch order. Duplicate or mismatched G3 share indexes are rejected before threshold evaluation.

Verification steps:

1. Fetch randomness for `target_round` from at least two independent drand endpoints when available.
2. Confirm chain hash and round number.
3. Verify the BLS signature under the League of Entropy public key.
4. Confirm signature bytes equal the stanza-selected round.
5. Admit exactly those bytes as σ_G3.

### §5.4 Finality semantics

drand rounds are final once signed by the threshold network and verified under the public key. The adapter may cache verified rounds because the signature is public and immutable. The cache key is `(chain_hash, round)`. Cache entries store signature bytes encrypted at rest if stored, even though the source is public, to keep adapter code paths uniform; logs still do not print the bytes.

### §5.5 Failure modes

| Failure | Error | Recovery |
|---|---|---|
| target round not yet available | `CUSTODY_ERR_DRAND_ROUND_PENDING` | wait and retry |
| endpoint unavailable | `CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE` | try another configured endpoint |
| chain hash mismatch | `CUSTODY_ERR_DRAND_CHAIN_MISMATCH` | abort |
| signature invalid | `CUSTODY_ERR_DRAND_SIG_INVALID` | abort |
| wrong round returned | `CUSTODY_ERR_DRAND_ROUND_MISMATCH` | abort after alternate endpoint check |

### §5.6 Stream 2 cosign extension (controlled-use, commit_version = 0x0303)

drand is a candidate cosign-gate for the controlled-use Stream 2 audit-anchoring chain per S2-8 §4.4 and synthesis H-4. The cosign role is additive to the read-path σ_G3 role established in §5.1–§5.5.

**Selection.** A controlled-use PDA selects drand as the cosign-gate by setting `audit_policy.stream2_cosign_gate = G3_DRAND` (S2-8 §3.2.6). Selection is per-PDA at commit.

**Signing authority and domain separation.** The cosign uses the same drand League of Entropy BLS12-381 threshold-signed round signature that produces read-path σ_G3 (§5.2–§5.3). Because drand round signatures are deterministic over `(chain_hash, target_round)`, the cosign cannot literally re-sign over a different input; instead, the cosign is the drand round signature for a target round derived from the Stream 2 anchor batch's pepper_epoch_number + flush cadence. The domain separation is enforced by binding the round number derivation under `TAG_CU_AUDIT_STREAM2_V3` (S2-1 §2.3.5).

**Cosign input form (per S2-8 §4.4, drand-adapted).** Because drand cannot sign arbitrary inputs, the cosign-bind digest is reconstructed deterministically at verification time:

```
stream2_cosign_bind = keccak256(
    TAG_CU_AUDIT_STREAM2_V3 ||
    stream2_merkle_root ||
    pepper_epoch_number ||
    block_hash
)
target_round = derive_round_for_anchor(pepper_epoch_number, flush_cadence)
σ_cosign = drand_round_signature(chain_hash, target_round)
```

The chain-side validation checks that (a) the anchor transaction carries `σ_cosign` matching the drand round signature for `(chain_hash, target_round)` derived from the anchor's `pepper_epoch_number`, AND (b) `target_round` satisfies the deterministic mapping rule above. A drand round signature that does not match the derived `target_round` for the anchor batch is rejected as `CUSTODY_ERR_DRAND_ROUND_MISMATCH` (existing §5.5 code).

**Reception flow.** G4 computes `stream2_merkle_root` and signs under `K_G4_audit_stream2`. The adapter resolves `target_round` per the deterministic mapping, fetches the drand round signature from at least two independent endpoints (§5.3 verification steps), verifies the BLS signature under the League of Entropy public key, and bundles the resulting `σ_cosign` with the G4 audit-stream2 signature into the on-chain anchor transaction.

**Round availability.** Because anchor flush cadence and drand round period are independent, the deterministic mapping may resolve to a round not yet available (`CUSTODY_ERR_DRAND_ROUND_PENDING`). In that case the anchor batch waits for round availability before landing on-chain. Partners select drand for Stream 2 cosign accept this latency floor.

**Vendor-family consistency.** Same cross-vendor disjoint discipline as §3.8 applies. drand and dcipher both nominally operate on BLS12-381 but under different operator sets (League of Entropy vs Randamu Threshold Association); selecting `G3_DRAND` as the Stream 2 cosign-gate when σ_G3 is dcipher (or vice versa) is permitted because the operator-set diversity preserves the cross-vendor claim. Selecting the same G3 path for both σ_G3 and Stream 2 cosign collapses vendor-family disjointness and is rejected at PDA validation.

**Failure mode.** Cosign absence at Stream 2 anchor validation time produces `CU_ERR_STREAM2_COSIGN_MISSING` (§13.1). Round-mismatch produces `CUSTODY_ERR_DRAND_ROUND_MISMATCH`; chain-mismatch produces `CUSTODY_ERR_DRAND_CHAIN_MISMATCH`.

**Redaction.** drand round signatures are public; the §5.1 uniform-hardening discipline (no logs of bytes even though source is public) extends to the Stream 2 cosign path.

## §6 - G3 choice semantics

### §6.1 Per-PDA choice

`g3_choice` is a commit-bound field. S2-3 adapters read it; they do not decide it. S2-4 configurator decides the default and exposes override. S2-1/S2-2 bind it into `commit_AAD`, `pda_root`, and `h_commit`. The selected path determines stanza[1], σ_G3 verification, failure semantics, and monitoring.

### §6.2 Failure fallback policy

Automatic fallback is forbidden. If a PDA commits with dcipher and dcipher is unavailable, the adapter returns dcipher unavailable. It does not fetch drand. If a PDA commits with drand and drand target round is unavailable, the adapter waits or fails. It does not ask dcipher to sign the tuple.

Changing G3 path requires a new commit under a PDA or a re-key/supersession ceremony defined by S2-1/S2-6. The old commit remains bound to its original path.

### §6.3 Use-case defaults

Stage-0 defaults:

- dcipher: KYC, M&A, regulated-EU, evidence, and any use case where legal-coercion resistance and committee governance are load-bearing.
- drand: time-locked, testament, archival, dead-man's-switch, journalism, long-retention, and public-good availability cases.

These are defaults, not hard-coded protocol categories. Partner-fit can override at PDA configuration time if the risk analysis is documented and legal guardrails permit it.

Override records must state why the selected G3 path matches the PDA's reveal condition and retention horizon. Examples: a regulated enforcement PDA selecting dcipher because committee governance and jurisdictional posture matter; a long-retention testament PDA selecting drand because public future availability is the primary primitive; an evidence PDA selecting dcipher because the reveal should remain institutionally mediated rather than purely time-triggered. These examples are not product tiers. They are configuration rationales for the same V2 system, V3 custody substrate.

### §6.4 Conditional-recipient key lifecycle

Conditional-recipient stanzas use the same split-key model as gate stanzas. `recipient_wrap_kem_pubkeys_at_commit_generation` are the explicit X25519 + ML-KEM-768 pubkeys used to wrap the recipient share in a specific envelope generation. `recipient_authorization_key_at_authorization_block` is the passkey, EOA, or future EIP-1271 control key used to verify σ_conditional at reveal. These roles must not be conflated; a passkey, wallet address, or contract signature verifier is not a KEM recipient key.

For `PASSKEY_ACCOUNT`, the commit-generation stanza binds the recipient account's explicit X25519 + ML-KEM wrap pubkeys from the `PasskeyRotationLog` entry selected for that generation. At reveal, the combiner walks the log from `rotation_log_anchor` to the authorization block and verifies the WebAuthn assertion under the resolved P-256 passkey. The P-256 key authorizes share admission only. The stanza is decapsulated with the private keys matching the generation-bound X25519 + ML-KEM pubkeys. If the recipient rotated and discarded old wrap secrets, original-generation decap fails; recovery requires an explicit re-key generation that re-wraps the same logical share to later pubkeys.

For `WALLET_EOA`, the commit-generation stanza binds explicit recipient-provided `delivery_x25519_pubkey` and `delivery_mlkem_pubkey`. At reveal, the combiner verifies the EIP-712 σ_conditional by recovering the secp256k1 address and requiring equality with the stanza-pinned `wallet_address`. Replacing the wallet address is recipient-policy supersession. Replacing only KEM pubkeys requires an explicit re-key/re-wrap ceremony authorized by the same wallet; it is never reveal-time substitution.

For `WALLET_EIP1271`, V2 launch behavior is rejection. The configurator, subject-side verifier, and combiner reject the reserved mode before share admission. When enabled post-V2, the same split applies: explicit KEM pubkeys wrap the share, while `isValidSignature` at the authorization block authorizes admission. Contract-code drift rules may constrain the authorization key; they do not convert the contract into a KEM recipient.

Conditional-recipient access-structure semantics are IB-2 typed hierarchical Shamir. `FIXED_ONLY` has no conditional-recipient stanzas. `RECIPIENT_1_OF_1` admits one `TopShare(RECIPIENT)` after σ_conditional and KEM decap both verify. `RECIPIENT_K_OF_N` admits `NestedShare(RECIPIENT_BRANCH, recipient_index)` values, reconstructs the recipient aggregate from `k` valid nested shares, then combines that aggregate with Lit, G3, and G4 at the top level. Flat `3 + k_conditional` reconstruction is forbidden.

## §7 - G4 Cealis verification component integration

> **See S2-8 (controlled-use spec) §4 for the G4 Phase 2 TEE scope extension to write-validation (schema / scope / history-immutability / policy-allow / token-authorizes-this-exact-write) plus Stream 2 audit-event signing under `K_G4_audit_stream2`, with on-chain policy-hash replay as the defense-in-depth check.**

### §7.0 G4 pre-signing and pre-admission checklist

Before G4 produces σ_G4, and before the adapter admits σ_G4 into the combiner, the G4 service and adapter must verify the same signability transcript:

1. `RevealAuthorized(authorizationId, h_commit, authorizationBlock, block_hash)` is finalized at the chain finality depth required by S2-2.
2. The PDA challenge window is closed for the canonical authorization block.
3. `AttestationGate.canGatesSign(authorizationId) == true` at the authorization-block boundary.
4. `ShredRegistry.currentShredState(hCommit)` is signable and not finalized/shredded at the current-state safety read immediately before signing/admission.
5. G4 refusal state has no active blocking code `0x01` through `0x09`; authorization-block refusal history and current-state refusal safety read are both recorded.

The evidence transcript must name which reads are authorization-block historical reads and which are current-state safety reads. A passing channel identity, Ed25519 signature, or DCAP quote cannot substitute for this checklist.

G4 uses two key surfaces. `g4_gate_recipient_kem_pubkey_at_commit` is the explicit X25519 + ML-KEM-768 recipient key tuple used to wrap `TopShare(G4)` in `stanza[2]`. `g4_sigma_verification_pubkey_at_authorization` is the Phase 1 Ed25519 authority key or Phase 2 attestation-bound signing/verification key used to verify σ_G4. These keys may be bound by the same G4 authority entry, but they are not the same field and are never derived from each other.

### §7.1 Phase 1 sealed-code server integration

Phase 1 produces an Ed25519 σ_G4 from a Cealis sealed-code daemon. The adapter verifies:

- `phase == 1` in commit metadata.
- §7.0 G4 pre-signing and pre-admission checklist passed.
- binary hash from `endpoint_attestation_digest`.
- `G4AuthorityRegistry` entry effective at `authorizationBlock`.
- Ed25519 signature over S2-1 §9.2.3 input.
- Phase 1 allowed for the PDA type.

Phase 1 is dev-scaffold only. Any partner-ready or legal-effect PDA with Phase 1 fails `CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE`, even if the Ed25519 signature verifies.

For Phase 1 commits, `g4_gate_recipient_kem_pubkey_at_commit` is published through the sealed-code dev-scaffold authority record at the commit snapshot. The corresponding KEM secret is held only by the sealed-code daemon for that authority entry. At reveal, the Ed25519 σ_G4 verifies authorization, while the daemon must separately prove it can decap the commit-bound G4 KEM stanza. A valid Ed25519 σ_G4 without matching KEM decap authority does not admit `TopShare(G4)`.

### §7.2 Phase 2 rented TEE integration

Phase 2 produces a DCAP quote used as σ_G4. The adapter verifies:

- `phase == 2` in commit metadata.
- §7.0 G4 pre-signing and pre-admission checklist passed.
- quote signature against vendor root
- TCB acceptance
- measurement in `G4AuthorityRegistry` at authorization block
- `user_data_digest = keccak256(TAG_G4_ATTESTATION_V3 ‖ authorizationId ‖ h_commit ‖ block_hash)[:32]`
- remaining `user_data` bytes zero-padded according to S2-1
- cross-vendor disjointness with Lit V3 TEE
- no active G4 refusal code `0x01` through `0x09`

Automata DCAP Attestation is the baseline EVM verification path. S2-3 pins the contract deployment by release channel, chain id, verifier contract address, verifier type, quote version support, and zkVM program identifier if using SNARK verification. A deployment config without those fields is invalid.

The G4 Phase 2 adapter stores two related but separate facts: the hardware attestation result and the Cealis authority eligibility result. A quote can be hardware-valid but authority-invalid if the measurement is not listed in `G4AuthorityRegistry` at the authorization block. A registry entry can be current but quote-invalid if collateral, TCB, report data, or vendor root verification fails. Both must pass; neither substitutes for the other.

For Phase 2 commits, `g4_gate_recipient_kem_pubkey_at_commit` is generated inside, or explicitly sealed to, the rented G4 TEE and published with commit-time endpoint-attestation evidence. That evidence must bind the KEM pubkey tuple to the TEE measurement, `g4_authority_ref`, `phase = 2`, and the commit-generation attestation context. At reveal, σ_G4 verifies through the Phase 2 attestation path, and the reveal-time TEE must prove it owns or can unwrap the commit-bound KEM secret for `TopShare(G4)`. Phase 2 DCAP evidence cannot substitute a new reveal-time KEM key for the committed stanza key.

### §7.3 On-chain zkDCAP verification

The adapter supports two verification modes:

- **On-chain verification:** submit or call Automata's DCAP Attestation contract to verify the quote directly.
- **SNARK-backed verification:** generate proof via Automata's supported zkVM path and verify through the release-pinned verifier contract.

Stage 3 must pick one default per environment. The default for production should minimize trust and operational latency while staying inside Base gas budgets. Regardless of mode, the adapter must persist the verifier contract address, release id, and proof/quote digest in the artifact metadata.

Verifier choice is an operational parameter with audit impact. If the same quote is verified off-chain for latency and on-chain for audit, the artifact must mark which result was admission-authoritative for the reveal. Admission-authoritative verification is the check the adapter used before accepting σ_G4 into the combiner. Additional verification may strengthen audit evidence, but it cannot repair an admission failure after plaintext has been released.

### §7.4 Channel semantics

G4 request channels are mTLS minimum. G4 responses must be bound to the request id and to `(authorizationId, h_commit, block_hash)`. A G4 service may refuse; it must not return a partial σ or a "pending but signed" placeholder. The adapter treats "refused" as terminal for that attempt.

Authenticated channel identity is tied to registry identity. The TLS/mTLS certificate or TEE channel public key must map to the `G4AuthorityRegistry` entry or to an entry-authorized serving key. A correct Ed25519/DCAP artifact delivered over an unauthenticated or mismatched channel is rejected before σ admission, because otherwise an attacker could replay a valid artifact from a different operational context into the reveal workflow.

### §7.5 Phase swap discipline

Phase swap is registry and deployment configuration, not byte-layout mutation. Phase 1 and Phase 2 entries coexist in `G4AuthorityRegistry`. Historical lookups use authorization block. New partner commits after Phase 2 cutover must reject Phase 1. Dev-scaffold Phase 1 commits remain verifiable but cannot be converted into legal-effect Phase 2 commits without re-commit and σ_subject re-signing.

### §7.6 σ_G4 reception and redaction discipline

σ_G4 is never logged, never emitted on-chain, and never cached. For Phase 2, the DCAP quote bytes are also redacted from logs and public delivery paths because they accompany a σ context even though measurements are non-PII. Artifact bundles may carry quote bytes encrypted to the recipient/auditor path; public references carry only quote digest and verifier result.

### §7.7 Refusal semantics

G4 may refuse with codes:

- `0x01` legal compel
- `0x02` GDPR Art. 17
- `0x03` GDPR Art. 18
- `0x04` integrity fail
- `0x05` chain mismatch
- `0x06` plugin deprecated
- `0x07` authority deprecated
- `0x08` DSL deprecated
- `0x09` oracle deprecated
- `0x0A` opt-out active informational signal

Codes `0x01` through `0x09` mean σ_G4 is absent and the combiner cannot admit the G4 Shamir share. Code `0x0A` means G4 signs and records the opt-out fact for non-legal-effect PDAs. Codes `0x02` and `0x03` default to encrypted-reason mode; the adapter logs only `RefusalSignal` and encrypted blob hash.

### §7.8 Reliability and monitoring

G4 monitoring tracks TEE quote success rate, verifier gas/latency, vendor distribution, measurement registry agreement, refusal rate by code, Phase 1 usage count, Phase 2 cross-vendor failures, and `G4AuthorityRegistry` drift. Any Phase 1 use outside development is severity critical.

### §7.9 Commit-time G4 ingestion TEE boundary

Under Mode A, the commit-time G4 ingestion TEE generates `DEK_commit` from TEE-internal randomness, encrypts the payload once, Shamir-splits the DEK under S2-1 §6.3, and wraps each typed share to the commit-bound gate-recipient KEM pubkey set before plaintext leaves the TEE boundary. The TEE performs this before plaintext destruction; no service outside the TEE receives plaintext, DEK, Shamir polynomial coefficients, or unwrapped shares.

The SD pipeline may read the same in-TEE DEK context only for S2-7 §1.5 `sd_master_salt` derivation and related commit-time SD outputs. SD failure is isolated under §13.3 and does not unwind the escrow commit once the envelope is sealed.

After envelope sealing, the TEE zeroizes plaintext, DEK, polynomial coefficients, unwrapped shares, SD salts, and transient parser buffers. Evidence records store only digests, attestation refs, pubkey refs, and success/failure codes. Mode B performs the same Shamir split and per-stanza wrapping on the subject device; G4 verifies the resulting commit metadata but never receives plaintext.

### §7.10 Write-validation TEE scope (controlled-use, commit_version = 0x0303)

The G4 Phase 2 TEE scope established in §7.2 + §7.9 extends to controlled-use write-validation per S2-8 §4. This sub-section and §7.11–§7.16 enumerate the controlled-use additions to G4. Non-controlled-use deployments do not exercise these paths; the §7.2 + §7.9 read-path scope remains the only G4 surface they invoke.

#### §7.10.1 G4 Phase 2 TEE scope (write-validation)

The G4 Phase 2 TEE (rented commodity TEE per §7.2, attested via DCAP per App. A) is the only enforcement boundary for controlled-use write validation. At every controlled-use write operation, the TEE-resident write-validation gate runs five normative checks before producing the write-validation attestation:

1. **Schema conformance.** The proposed write payload, in canonical form, conforms to the slice's `schema_hash` (per S2-8 §1.6). The TEE decrypts the proposed payload inside its boundary and verifies schema conformance against the registered `schema_hash`. Failure produces `CU_ERR_SCHEMA_VIOLATION` (§13.1) and refusal code `0x04` integrity fail (§7.7).

2. **Scope conformance.** The presented sub-token's `scope` (S2-8 §2.7) includes the target slice; the sub-token's class is admitted by the slice's `write_authority_matrix` for the proposed `op_kind`. Failure produces `CU_ERR_SCOPE_OUT_OF_TOKEN` and refusal `0x04`.

3. **History immutability.** The proposed write does not modify any existing sealed envelope. The new envelope's `slice_preceding_envelope_ref` is set to the slice's latest sealed envelope ref AT WRITE-VALIDATION TIME (per S2-8 §5.3 supersession-invariance: the ref is the original `h_commit`; supersession is walked forward via `SupersededCommitRegistry` per S2-1 §15.3 — never modifying the registry entry). Failure produces `CU_ERR_HISTORY_REWRITE_ATTEMPT` and refusal `0x04`.

4. **Policy-allow check.** The PDA's policy admits the proposed write under the slice's `write_authority_matrix`, the sub-token's class, AND the current time (TTL not expired). Failure produces `CU_ERR_POLICY_DENIES_WRITE` and refusal `0x04`.

5. **Token-authorizes-this-exact-write check.** The σ_holder signature over the canonical presentation digest (S2-8 §2.8) binds to the specific write being proposed: `slice_id`, `op_kind`, and `content_ref` are all bound under σ_holder. A σ_holder authorizing a read or a different slice/op cannot be presented as authorization for this write. Failure produces `CU_ERR_HOLDER_SIGNATURE_NOT_BOUND_TO_WRITE` and refusal `0x04`.

On all five checks PASSING, the TEE produces the write-validation attestation signed under `K_G4_write_attest`:

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

`TAG_CU_WRITE_ATTEST_V3` is the controlled-use write-attestation domain-separator introduced in S2-1 §2.3.5 under `commit_version = 0x0303`. `policy_hash` is the keccak hash of the slice's authority-matrix + schema_hash + current PDA state digest, published to the PDA-side artifact registry per §7.11.

The TEE never sees the write payload in plaintext outside its boundary. The G4 write-validation ingest path accepts the encrypted commit ciphertext + commit AAD; the TEE decrypts inside its boundary, validates, re-encrypts under the slice DEK if needed, and seals the new envelope. **G4 sees the write commit ciphertext + AAD plus, briefly inside the TEE boundary, the plaintext payload during schema validation — never plaintext outside the boundary.** This is the σ-as-authorization-doctrine-consistent path; the §7.6 σ_G4 reception-and-redaction discipline applies to `write_attest` byte handling.

The five checks run sequentially per the order above so the cheapest checks (scope, policy, token-binding) short-circuit before the more expensive schema-conformance + history-immutability checks. Implementations may optimize the order internally but the conformance contract is that ALL five checks pass before `write_attest` is signed; partial-passing attestation is forbidden.

### §7.11 On-chain policy-hash replay verification

After the TEE produces `write_attest`, the chain-side write transaction re-verifies `policy_hash` against the PDA-side artifact independently of the TEE. The chain reads the PDA's current authority-matrix + schema_hash + state digest, recomputes `policy_hash`, and compares against the attested value. Mismatch produces `CU_ERR_POLICY_HASH_REPLAY_FAIL` (§13.1) and the chain rejects the write.

This is the **G4 TEE attestation + on-chain policy-hash replay** pattern (renamed from the synthesis predecessor "hybrid attestation" per S2-8 F-COS-2; do not reuse the predecessor term). The two-source verification chain is the defense-in-depth claim: a malicious or compromised G4 TEE cannot land an attestation against an out-of-date or fabricated policy without the chain catching the mismatch at the policy-hash replay step.

The PDA-side artifact carrying `policy_hash` is resolved at the chain layer per S2-2 amendment (the artifact lives either in a standalone `PDARegistry` or in a PDA-bound artifact reference inside the existing `pda_root` resolution path; the binding contract is the same either way and does not affect S2-3 adapter behavior). The S2-3 adapter does not author this resolution; it consumes the chain-side replay result as part of the §7.0 pre-signing checklist for controlled-use write paths.

### §7.12 Refusal model (controlled-use extension)

The §7.7 closed 5-reason-code enum (`0x01` legal compel, `0x02` Art. 17, `0x03` Art. 18, `0x04` integrity fail, `0x05` chain mismatch) extends to controlled-use write operations per S2-8 §4.3. The enum is closed; controlled-use does not add new reason codes. The interpretation per code in the write-validation context is:

- `0x01` legal compel — refuse the write because the partner is under legal compulsion that prohibits accepting writes to this slice (e.g., court-ordered freeze covering the slice).
- `0x02` Art. 17 — refuse the write because the subject has an Art. 17 erasure request pending against the PDA; writes against pending-erasure PDAs are refused.
- `0x03` Art. 18 — refuse the write because of an Art. 18 reveal freeze covering the slice.
- `0x04` integrity fail — any one of the five §7.10.1 checks fails (schema, scope, history, policy-allow, token-binding).
- `0x05` chain mismatch — the chain state seen by G4 does not match the chain state at the proposed write block (e.g., a re-org affected the slice's latest sealed envelope ref between G4's read and the proposed write).

Refusal is crypto-enforced via σ_G4 absence: G4 does not sign `write_attest` and does not contribute σ_G4 to the read-path 4-gate AND for the corresponding `WriteAuthorized` event; the gate composition fails, blocking the write at the gate-composition layer. This is the σ-as-authorization-doctrine-consistent halt mechanism, identical in shape to the §7.7 read-path refusal mechanism.

Codes `0x06`–`0x09` (plugin/authority/DSL/oracle deprecated) are inherited from §7.7 and apply identically to write paths if the slice's controlled-use stack includes deprecated artifacts; in those cases refusal precedes the §7.10.1 checks.

Encrypted-reason mode for codes `0x02` and `0x03` (per §7.7) applies identically to write paths.

### §7.13 Two distinct G4 ingest paths

The G4 Phase 2 TEE has two distinct ingest paths under controlled-use; the spec keeps both explicit per S2-8 §4.5 + H-5:

1. **Write-validation ingest path (§7.10).** G4 receives encrypted commit ciphertext + commit AAD. The TEE decrypts inside its boundary, runs the five-check validation, produces `write_attest`, signs the Stream 2 entry under `K_G4_audit_stream2`, and posts the new envelope into the slice DEK lifecycle. **G4 sees ciphertext + AAD + (briefly, inside boundary) plaintext.**

2. **Read-event ingest path (§7.14).** G4 receives a read-event tuple from the controlled-use client SDK (S2-8 §7). The tuple carries `actor_token_digest`, `slice_id`, `op_kind = READ`, `timestamp`, and `content_shape_digest`, signed by σ_holder. The TEE validates σ_holder against the credential anchor + revocation registries (S2-2 §9.16A / §9.16C / §9.16D), counter-signs the tuple's digest with `K_G4_audit_stream2`, and includes the entry in the next Merkle batch. **G4 sees only event-shape + actor metadata, NEVER plaintext content for read events.**

The asymmetric ingest scope is a normative design discipline. Writes pass through the TEE because the partner needs the schema/history-enforcement assurance; reads do not pass through the TEE because the recipient combiner (§9) holds the plaintext per the σ-as-authorization doctrine. G4's role at read time is audit signing, not content mediation. The asymmetry mirrors the §9 combiner trust model: gates authorize release; recipients hold bytes.

### §7.14 Read-event ingest API contract sketch (client SDK ↔ G4)

The G4 read-event ingest endpoint accepts a fixed-shape tuple from the controlled-use client SDK (S2-8 §7). The contract sketch:

**Request body (JSON, canonicalized per §1.2):**

```
{
    "actor_token_digest":        bytes32,    // S2-8 §1.7 envelope-hash family
    "slice_id":                  bytes32,
    "op_kind":                   u8,         // READ = 0x01 (S2-8 §6.1)
    "timestamp":                 u64,        // Unix seconds, BE
    "content_shape_digest":      bytes32,    // S2-8 §3.2.6 audit-pepper-keyed HMAC
    "sigma_holder":              bytes,      // σ_holder over canonical presentation digest (S2-8 §2.8)
    "pda_root":                  bytes32,
    "block_number_at_read":      u64
}
```

**Validation (TEE-side):**

1. Resolve `pda_root` against on-chain PDA state at `block_number_at_read`.
2. Resolve the credential anchor in `CredentialAnchorRegistry` (S2-2 §9.16A) for the actor token's master credential digest.
3. Verify revocation absence in `MasterTokenRevocationRegistry` (S2-2 §9.16C); if `revocation_mode = MASTER_AND_SUB_CRL`, additionally verify in `TokenRevocationRegistry` (S2-2 §9.16D).
4. Verify σ_holder against the holder-binding pubkey recorded in the credential anchor, over the canonical presentation digest reconstructed from `(actor_token_digest, slice_id, op_kind, timestamp, content_shape_digest, pda_root, block_number_at_read)`.
5. On PASS, sign the tuple digest under `K_G4_audit_stream2`.

**Response:**

```
{
    "audit_stream2_signature":   bytes,      // σ over keccak256 of the tuple per S2-8 §1.8
    "batch_id":                  u64,        // batch this entry is queued into
    "ingest_timestamp":          u64
}
```

**Failure responses** carry standardized error codes from the controlled-use enumeration (§13.1) — `CU_ERR_ANCHOR_NOT_FOUND`, `CU_ERR_REVOKED_MASTER`, `CU_ERR_INVALID_HOLDER_SIGNATURE`, `CU_ERR_TTL_EXPIRED`, etc.

The tuple is batched into the next Stream 2 Merkle root anchor transaction (flush cadence per PDA `audit_policy`). Batching reduces on-chain gas costs; the batch root is co-signed by the PDA-selected cosign-gate (§3.8 / §4.8 / §5.6) and G4's `K_G4_audit_stream2` before landing on-chain.

**Authoritative HTTP API contract authoring** (TLS pin, mTLS client cert resolution, header fields, rate limiting, retry semantics, idempotency keys) defers to S2-5 (ingestion-delivery API spec) amendment per the same controlled-use propagation cycle. This sub-section establishes the cryptographic + validation contract; S2-5 owns the transport layer.

### §7.15 G4AuthorityRegistry extension (per S2-8 §4.6)

The existing `G4AuthorityRegistry` (per S2-1 §10 + S2-2 §9; class-CRYPTO) records the G4 authority public keys per deployment. The controlled-use profile adds two new key entries per deployment:

- `K_G4_write_attest_pubkey` — the public verification key for `write_attest` signatures produced under §7.10.1.
- `K_G4_audit_stream2_pubkey` — the public verification key for Stream 2 audit-stream signing produced under §7.13 + §7.14.

Both are anchored in the same `G4AuthorityRegistry` (no new registry per S2-8 §4.6; the S2-2 propagation table at S2-2 §9.16A–D does not add a new G4-authority registry surface). The two new entries are scoped per deployment: a controlled-use deployment registers both alongside the existing G4 sigma verification pubkey. Non-controlled-use deployments do not register these keys.

Key rotation discipline inherits from S2-6 operational ceremonies. Controlled-use does not introduce new rotation semantics; rotation of `K_G4_write_attest` and `K_G4_audit_stream2` follows the same registry-update ceremony pattern as the existing G4 sigma key. App. A per-vendor DCAP coverage for the two new keys is documented at §A.5.

### §7.16 Stream 2 cross-vendor cosign protocol coordination

Per synthesis H-4 and the §3.8 / §4.8 / §5.6 cosign-gate sub-sections, every Stream 2 anchor batch carries TWO signatures: the G4 `K_G4_audit_stream2` signature and the PDA-selected cosign-gate signature (one of {G2 Lit V3, G3 dcipher, G3 drand}). The S2-3 adapter coordinates the protocol sequence:

1. **G4 batch assembly.** G4 accumulates Stream 2 entries (from §7.13 ingest paths — both write-validation and read-event) until the configured flush cadence boundary.
2. **G4 stream2 root signing.** At batch close, G4 computes `stream2_merkle_root` over the batched entries, then signs `keccak256(TAG_CU_AUDIT_STREAM2_V3 || stream2_merkle_root || pepper_epoch_number || block_hash)` under `K_G4_audit_stream2`.
3. **Cosign-gate selection.** The adapter resolves `audit_policy.stream2_cosign_gate` from the PDA at `block_hash`.
4. **Cosign request.** Per §3.8 / §4.8 / §5.6, the adapter requests the cosign signature from the resolved gate over the same input form (drand uses the deterministic-round adaptation per §5.6).
5. **Anchor transaction assembly.** The S2-3 adapter assembles the on-chain anchor transaction with BOTH signatures plus `stream2_merkle_root`, `pepper_epoch_number`, and `block_hash`.
6. **Chain-side validation.** The chain verifies both signatures against the keys registered in `G4AuthorityRegistry` (for `K_G4_audit_stream2_pubkey`) and the cosign-gate's authorization-time signing key (per §3.4 / §4.3 / §5.3). Failure on either signature rejects the anchor; the batch must be re-anchored.

The two-signature scheme means a single G4 TEE key compromise can no longer forge Stream 2 log roots: the attacker would need to compromise both `K_G4_audit_stream2` and the cosign-gate's signing infrastructure within the same flush window. This restores the cross-vendor disjoint security envelope for Stream 2 to parity with the read/write σ ensemble.

Failure modes for this protocol are enumerated at §13.1 — primary new code is `CU_ERR_STREAM2_COSIGN_MISSING` for cosign-gate signature absence; primary inherited codes are `CUSTODY_ERR_LIT_*` / `CUSTODY_ERR_DCIPHER_*` / `CUSTODY_ERR_DRAND_*` if the cosign-gate signing fails through its native path.

## §8 - Historical 3-gate compatibility and 4-gate full-engine target

### §8.1 SCALE tuple support

S2-1 states the age plugin's SCALE tuple can represent different signature counts for historical compatibility. S2-3 treats the full-engine tuple as σ_Lit, σ_G3, σ_G4, plus zero or more σ_conditional. A historical 3-gate tuple is valid only if its commit version and `commit_AAD` prove it was created under a version/profile that did not bind the missing gate. New partner-ready V2 system commitments must not omit G3.

### §8.2 Verification after expansion

When verifying a historical 3-gate commit after full 4-gate expansion, the combiner must:

1. read `commit_version`
2. read gate-count/profile fields from the envelope/commit metadata
3. verify exactly the gates that profile required
4. reject any attempt to use a 3-gate profile for a 4-gate commit

This preserves historical verifiability without reopening a reduced-gate launch scope.

### §8.3 Migration semantics

A partner moving from a historical 3-gate profile to the full 4-gate profile creates new commits or a governance-authorized supersession lineage. Existing commits remain under their original profile. The migration cannot be represented as "add σ_G3 at reveal" because `h_commit`, stanza set, and `commit_AAD` would not bind the new gate.

### §8.4 Plugin distribution reference

The plugin signed-binary distribution channel is S2-6. S2-3 requires only that every plugin binary exposes:

- supported commit profile list
- supported gate tuple layouts
- build hash used for `plugin_version_digest`
- disabled profile list for deprecated gate layouts

The disabled profile list is security-sensitive. It must be part of the signed binary metadata, not a remote feature flag. Remote disablement may add a block, but remote enablement must never revive a deprecated profile without a new signed binary and `PluginHashRegistry` entry. This prevents an operations console from silently weakening historical profile enforcement.

## §9 - Combiner SDK

### §9.1 Architecture

The combiner is recipient-side, sealed-binary, in-process, and non-Cealis-operated per S2-1 §14. S2-3 specifies the SDK contract around that binary:

```ts
combineAndDecrypt(input: {
  authorizationId: Bytes32;
  hCommit: Bytes32;
  authorizationBlock: bigint;
  blockHash: Bytes32;
  commitAAD: Uint8Array;
  ageEnvelope: Uint8Array;
  sigmas: SigmaEvidenceBundle;
  registrySnapshots: {
    commitSnapshot: CommitRegistrySnapshot;
    authorizationSnapshot: AuthorizationRegistrySnapshot;
  };
}): DecryptResult
```

`SigmaEvidenceBundle` contains σ values or opaque handles to in-memory σ values plus the stanza-decapsulation material needed to recover Shamir shares. Adapter-side `verifySigma(...)` is only a pre-screen. The combiner treats `SigmaEvidenceBundle` as untrusted input and independently verifies every σ value, binding, and share-decap transcript before share admission. It is not serializable to JSON. The former name `VerifiedSigmaBundle` is deprecated because it implied the combiner could skip verification.

The combiner SDK is deliberately narrow. It does not fetch gates, query vendors, resolve legal disputes, or decide whether a PDA should reveal. By the time `combineAndDecrypt` is called, all policy and substrate checks must already be expressed as verified inputs and registry snapshots. This boundary keeps the combiner auditable: it either proves that a fixed authorization set recovers enough Shamir shares under S2-1, or it refuses.

### §9.2 σ authorization set and share ordering

Ordering is fixed:

1. σ_Lit
2. σ_G3
3. σ_G4
4. σ_conditional vector in the ordered policy sequence

The SDK must reject duplicate gates, missing required gates, extra gates not bound by the commit profile, σ_conditional out of policy order, and recovered shares whose stanza index does not match the commit's ordered policy.

### §9.3 Pre-verification

Before Shamir reconstruction:

- verify plugin binary hash against `PluginHashRegistry`
- verify `age_envelope` digest against `ciphertext_digest`
- verify `commit_AAD` round-trip and `h_commit`
- verify stanza MACs before parsing payload
- verify endpoint attestations and registry snapshot
- verify gate-recipient KEM pubkeys at the commit block
- verify σ_Lit, σ_G3, σ_G4, and σ_conditional
- reject Mode 3 conditional recipient at V2 launch
- verify `ShredRegistry.currentShredState(hCommit)` is signable and not finalized/shredded
- verify supersession lineage where relevant

Mode 3 rejection is defense-in-depth with S2-2 §11 and S2-1 §10. The combiner must retain the reveal-time rejection even though the configurator and contracts also reject Mode 3.

### §9.4 Shamir-share reconstruction

Shamir reconstruction is imported from S2-1 §6.3. S2-3 adds only implementation rules:

- separate registry snapshots before any unwrap: commit-block state verifies stanza/wrap binding, while authorization-block state verifies σ authority, assignment, tombstone status, deprecation status, G4 phase, refusal state, and signability checks
- unwrap each verified stanza to a 32-byte share only after the matching σ verifies against authorization-block state and the stanza/wrap binding verifies against commit-block state
- admit shares in deterministic stanza order and reject duplicate share indexes
- reconstruct by `access_structure_profile`: `FIXED_ONLY` combines Lit, G3, and G4 at `3-of-3`; `RECIPIENT_1_OF_1` combines Lit, G3, G4, and one recipient top-level share at `4-of-4`; `RECIPIENT_K_OF_N` first reconstructs the recipient aggregate from `k_conditional` valid nested recipient shares, then combines Lit, G3, G4, and that aggregate at `4-of-4`
- zeroize recovered shares immediately after `file_key` reconstruction
- abort on any library exception

### §9.5 file_key derivation and AEAD decryption

`file_key` is a 32-byte in-memory value. It is passed directly to ChaCha20-Poly1305 AEAD and zeroized after decryption. AEAD tag failure returns S2-1 `ERR_AEAD_TAG_VERIFY_FAIL` wrapped as `CUSTODY_ERR_AEAD_FAIL`. No partial plaintext is returned.

### §9.6 Plugin integrity

Before any σ handling, the plugin computes its own canonical binary hash and verifies `plugin_version_digest` against `PluginHashRegistry.getEntryAt(...)`. If the binary is deprecated before authorization block, abort. If deprecated after authorization block, historical in-flight rules apply; the artifact records the snapshot.

### §9.7 Recipient-side hardening

The combiner runtime must disable:

- crash dumps
- debug logging
- network egress during combine/decrypt
- IPC export of σ values
- long-lived worker memory reuse containing unzeroized buffers

For regulated recipients, combiner execution should be inside a recipient-controlled TEE/HSM or equivalent sandbox. Consumer recipients may run audited process memory with an explicit risk statement inherited by S2-5 UX.

The combiner returns plaintext only to the recipient delivery boundary defined by S2-5. It never writes plaintext to temporary files by default. If a recipient integration requires a file output, the caller supplies an encrypted destination or an OS secure-file handle; the SDK does not invent a filesystem path. This is part of the same discipline as σ handling: reveal is allowed only after the condition, but post-reveal handling still must not create unnecessary copies.

## §10 - Cross-gate trust assumptions and failure-mode matrix

### §10.1 Single gate down

| Gate down | Result | Security posture |
|---|---|---|
| G1 chain unavailable | no final event; gates refuse | no release |
| G2 Lit unavailable | σ_Lit absent | no file_key |
| G3 dcipher/drand unavailable | σ_G3 absent | no file_key |
| G4 unavailable/refuses | σ_G4 absent | no file_key |
| conditional recipient unavailable | required σ_conditional absent | no file_key for that policy |

Liveness failure is not a safety failure. The system may delay reveals; it must not derive with fewer gates.

### §10.2 One gate key compromise

A single compromised gate can produce its σ early or incorrectly, but cannot reconstruct file_key alone because it controls at most one Shamir share. The combiner still requires the other gates, the chain event, registry checks, and conditional-recipient authorizations. Compromise may become a deprecation event under G4 refusal codes `0x06` through `0x09`.

If a compromised gate signs before `RevealAuthorized`, the combiner still rejects because it binds σ verification to the authorization block hash and condition snapshot. If a compromised gate signs after `RevealAuthorized` but under a tombstoned key, registry verification rejects. If a compromised gate signs correctly after authorization, the remaining gates and G4 refusal surface still define whether the release is complete. S2-3 therefore treats gate compromise as serious but non-terminal unless it combines with additional failures.

### §10.3 Cross-organization legal compulsion

Cealis can be compelled at G4 and can refuse. Lit and G3 are independent organizations; compulsion against one does not produce the full tuple. The strongest coercion defense for regulated-EU use cases is dcipher as G3 because its governance and jurisdictional posture fit legal-resistance needs better than drand's public-good beacon.

The failure matrix does not claim Cealis can resist every legal order. It claims no single organization receives enough material to release alone. G4 is explicitly refusal-capable and controller-conceded where the legal design requires it; Lit and G3 remain external substrates; the chain condition remains public and predefined. This is the integration-level expression of the WP's "data locked by condition, not by a party" claim, without turning it into an absolute non-custody slogan.

### §10.4 Cross-vendor TEE compromise

The Lit/G4 cross-vendor rule exists because Lit and Phase 2 G4 both rely on TEE attestation. A single vendor PKI break must not compromise both TEE-backed gates for the same op. If vendor diversity cannot be achieved for a commit, Phase 2 verification fails rather than downgrading.

### §10.5 SD isolation

Selective Disclosure does not consume custody σ values. S2-3 adapters must not expose σ values to SD code paths. SD delivery failures do not block escrow. Escrow reveal failures do not authorize post-onboarding SD generation.

## §11 - Version pins per dependency

### §11.1 Pinning philosophy

The pin is the version Stage 3 must test. It is not a floating recommendation. Exact versions are captured in lockfiles, deployment manifests, and auditor traceability packets. Minor upgrades require re-running the relevant vector suite and updating this section or its S2-6 change log.

Every production deployment records both declared version and resolved artifact identity. For npm this means package name, semver, integrity hash, lockfile entry, and resolved tarball URL. For Go this means module path, version or pseudo-version, sumdb hash, and vendored checksum. For deployed contracts this means chain id, address, bytecode hash, release tag, and governance owner. For SDKs downloaded outside public registries this means immutable commit, vendor signature, and archived source bundle hash.

### §11.2 Baseline pins

| Dependency | Baseline pin | Role | Notes |
|---|---:|---|---|
| Lit Chipotle Core/REST API | `VENDOR_CONFIRMATION_LIT_CORE_API` | G2 request/ACC/assignment | deployment API version and base URL pinned in env manifest |
| `@lit-protocol/lit-node-client` | `7.3.0` | Lit node client | npm package baseline |
| `@lit-protocol/contracts-sdk` | `7.4.0` | Lit contract reads | npm/jsDelivr package baseline; Stage 3 may replace with direct contract reads if assignment evidence is clearer |
| Randamu dcipher SDK | `VENDOR_CONFIRMATION_DCIPHER_SDK` | G3 dcipher | release-blocking until public SDK/test vector |
| `github.com/drand/kyber` | `v1.3.2` | drand BLS verification | Go path |
| `drand-client` | `1.4.2` | JS drand fetch | secondary to Go verification |
| `@noble/curves` | `2.0.0` | BLS/P-256/Ed25519/X25519 | ESM-only implications reviewed |
| `@noble/hashes` | `2.0.0` | keccak/SHA and non-DEK hash helpers | ESM-only; strict Uint8Array inputs |
| `@noble/ciphers` | `2.0.0` | ChaCha20-Poly1305 | ESM-only |
| `@polkadot/util` | `13.5.6` | SCALE primitives | verify canonical SCALE behavior |
| `filippo.io/age` | `v1.3.1` | age format/plugin baseline | Go library and plugin support |
| `@simplewebauthn/server` | `13.1.2` production-soak baseline | WebAuthn verification | `13.2.1` observed as newer on 2026-05-04; adopt only after soak/review |
| Automata DCAP Attestation | `VENDOR_CONFIRMATION_AUTOMATA_DCAP_CONTRACTS` | DCAP verification | current baseline; `v1.0` accepted only as historical/audited fallback by S2-6 risk review |
| Automata Go DCAP SDK | `VENDOR_CONFIRMATION_AUTOMATA_GO_DCAP_SDK` | proof generation/callback | alpha packages not authority without review |

### §11.3 BLS variant status

drand is locked: minimum-pubkey-size variant, G1 pubkey 48 bytes, G2 signature 96 bytes.

Lit V3 is implemented under the S2-1 §7.4 assumption: G1 pubkey 48 bytes, G2 signature 96 bytes. `VENDOR_CONFIRMATION_LIT_BLS_VARIANT` must prove this against Lit Chipotle SDK test vectors. If Lit's SDK contradicts this shape, that is a BP-N candidate back to S2-1, not an S2-3 local change.

dcipher remains vendor-gated. The adapter rejects production enablement until `VENDOR_CONFIRMATION_DCIPHER_BLS_VARIANT` proves the variant and signature byte length.

### §11.4 Vendor-confirmation checklist

Each `VENDOR_CONFIRMATION_*` item is a release blocker, not an architectural open question.

| Checklist item | Owner | Blocking surface | Required artifact |
|---|---|---|---|
| `VENDOR_CONFIRMATION_LIT_CORE_API` | Stage 3 Lit adapter owner | G2 request, ACC evaluation, assignment reads | Lit Chipotle API version, base URL, API documentation digest, request/response fixture for ACC + assignment |
| `VENDOR_CONFIRMATION_LIT_BLS_VARIANT` | Stage 3 Lit adapter owner | σ_Lit verification and combiner admission | ciphersuite identifier, pubkey length, signature length, and σ_Lit vector against assigned TEE key |
| `VENDOR_CONFIRMATION_DCIPHER_SDK` | Stage 3 G3 adapter owner | dcipher adapter production enablement | SDK package/version or immutable commit, vendor signature/source archive, committee registry endpoint, epoch/tombstone schema, σ_G3 vector |
| `VENDOR_CONFIRMATION_DCIPHER_BLS_VARIANT` | Stage 3 G3 adapter owner | dcipher σ_G3 verification and share admission | threshold-BLS ciphersuite identifier, committee pubkey length, signature length, threshold-not-met fixture, tombstoned-entry fixture |
| `VENDOR_CONFIRMATION_AUTOMATA_DCAP_CONTRACTS` | Stage 3 G4 adapter owner with S2-6 release owner | Phase 2 G4 on-chain or SNARK-backed DCAP verification | chain id, verifier contract address, bytecode hash, release tag, verifier type, quote-version support, zkVM program id if used, governance owner |
| `VENDOR_CONFIRMATION_AUTOMATA_GO_DCAP_SDK` | Stage 3 G4 attestation owner | Phase 2 G4 off-chain proof generation/callback path | Go module path, immutable version or commit, sumdb/vendored checksum, supported quote types, callback/proof fixture |

### §11.5 Re-review cadence

Re-review dependencies:

- before first partner pilot
- before mainnet deployment
- quarterly post-launch
- immediately on CVE, vendor deprecation, TCB status change, major npm/Go module release, Lit network version sunset, dcipher governance change, drand chain change, Automata verifier redeploy, or Base hard fork affecting verifier gas/precompile assumptions

## §12 - Reliability and monitoring

### §12.1 Per-gate health probes

Every gate adapter exposes a health probe returning status, version pin, endpoint latency, registry head, last successful vector verification, and last refusal/deprecation signal. Health is not a gate signature and cannot be used as a release condition.

### §12.2 Staleness detection

Staleness thresholds:

- Lit assignment bridge lag over configured blocks
- dcipher committee epoch cache older than current epoch
- drand endpoint lag behind expected round
- G4AuthorityRegistry local cache not matching chain
- Automata verifier deployment config not matching registry ref

Staleness blocks new attempts when it can affect correctness. It does not alter historical verification; adapters fetch historical state at authorization block.

Caches are optimization only. Each cache entry carries source, block/epoch/round, fetched-at timestamp, expiry, and digest. A cache hit must be indistinguishable from a fresh fetch for verification purposes; if the cache cannot prove its source block or epoch, it is bypassed. Negative caches are especially constrained: a temporary "assignment missing" or "round pending" result must expire quickly and cannot outlive the configured bridge/round lag window.

### §12.3 Rotation event detection

Adapters subscribe to:

- `EntryAdded`, tombstone, and deprecation events on five V3 registries
- `LitAssignment` mirror writes/corrections
- G4 refusal events
- drand chain info changes
- dcipher epoch/committee updates
- Automata verifier release/deployment announcements consumed by S2-6

### §12.4 Refusal signal detection

G4 refusal events are monitored by `authorizationId` and by class-wide grouped proof tuple. Code `0x0A` is not an error by itself; it is a trust-basis warning that downstream artifacts and partner dashboards must surface.

### §12.5 SLO expectations

SLOs are operational targets, not cryptographic relaxations:

- G2 σ request p95 under 30 seconds after gates can sign
- G3 dcipher p95 under 60 seconds after committee reachable
- G3 drand fetch p95 under 5 seconds after target round exists
- G4 Phase 2 quote/proof p95 under 120 seconds
- combiner pre-verify p95 under 10 seconds excluding DCAP proof generation

If SLOs fail, reveal is delayed. It is not downgraded.

Monitoring must separate liveness incidents from safety incidents. Liveness incidents include vendor outage, slow proof generation, and rate limits. Safety incidents include quote replay, cross-vendor violation, registry mismatch, signature invalidity, unredacted σ in logs, and combiner binary mismatch. Safety incidents page security/leadership immediately and block affected adapters until triage. Liveness incidents follow operational escalation and partner communication runbooks in S3-1.

## §13 - Error model and caller recovery

### §13.1 Per-gate error enumeration

Core operational errors:

- `CUSTODY_ERR_FINALITY_PENDING`
- `CUSTODY_ERR_CHALLENGE_WINDOW_OPEN`
- `CUSTODY_ERR_GATES_CANNOT_SIGN`
- `CUSTODY_ERR_LIT_NETWORK_UNAVAILABLE`
- `CUSTODY_ERR_LIT_ASSIGNMENT_MISSING`
- `CUSTODY_ERR_LIT_ASSIGNMENT_MISMATCH`
- `CUSTODY_ERR_LIT_ACC_REJECTED`
- `CUSTODY_ERR_LIT_DCAP_INVALID`
- `CUSTODY_ERR_LIT_QUOTE_REPLAY`
- `CUSTODY_ERR_LIT_SIG_INVALID`
- `CUSTODY_ERR_DCIPHER_SDK_NOT_PINNED`
- `CUSTODY_ERR_DCIPHER_REGISTRY_UNAVAILABLE`
- `CUSTODY_ERR_DCIPHER_EPOCH_MISMATCH`
- `CUSTODY_ERR_DCIPHER_THRESHOLD_NOT_MET`
- `CUSTODY_ERR_DCIPHER_TOMBSTONED`
- `CUSTODY_ERR_DCIPHER_SIG_INVALID`
- `CUSTODY_ERR_DRAND_ROUND_PENDING`
- `CUSTODY_ERR_DRAND_ENDPOINT_UNAVAILABLE`
- `CUSTODY_ERR_DRAND_CHAIN_MISMATCH`
- `CUSTODY_ERR_DRAND_ROUND_MISMATCH`
- `CUSTODY_ERR_DRAND_SIG_INVALID`
- `CUSTODY_ERR_G4_PHASE_NOT_ELIGIBLE`
- `CUSTODY_ERR_G4_PHASE_MISMATCH`
- `CUSTODY_ERR_G4_DCAP_INVALID`
- `CUSTODY_ERR_G4_REFUSED`
- `CUSTODY_ERR_CROSS_VENDOR_TEE_VIOLATION`
- `CUSTODY_ERR_GATE_PUBKEY_FETCH_FAIL`
- `CUSTODY_ERR_GATE_PUBKEY_MISMATCH`
- `CUSTODY_ERR_GATE_PUBKEY_ROTATION_MID_FLIGHT`
- `CUSTODY_ERR_SHRED_STATE_BLOCKED`
- `CUSTODY_ERR_SHAMIR_THRESHOLD_NOT_MET`
- `CUSTODY_ERR_AEAD_FAIL`
- `CUSTODY_ERR_SD_ONBOARDING_PARTIAL_FAILURE`
- `CUSTODY_ERR_COMBINER_BINARY_MISMATCH`
- `CUSTODY_ERR_SIGMA_REDACTION_BREACH`
- `CUSTODY_ERR_SIGMA_CONFIDENTIALITY_BREACH` (deprecated compatibility alias; new SDKs emit `CUSTODY_ERR_SIGMA_REDACTION_BREACH`)
- `CUSTODY_ERR_MODE3_RESERVED`

Controlled-use errors (commit_version = 0x0303 only; emitted by §7.10–§7.16 paths):

- `CU_ERR_SCHEMA_VIOLATION` — write-validation TEE schema-conformance check fails: the proposed payload, in canonical form, does not conform to the slice's registered `schema_hash`.
- `CU_ERR_SCOPE_OUT_OF_TOKEN` — write-validation TEE scope-conformance check fails: the presented sub-token's `scope` does not include the target slice, or the sub-token's class is not in the slice's `write_authority_matrix` for the proposed `op_kind`.
- `CU_ERR_HISTORY_REWRITE_ATTEMPT` — write-validation TEE history-immutability check fails: the proposed write attempts to modify an existing sealed envelope rather than appending a new one, or its `slice_preceding_envelope_ref` does not match the slice's latest sealed envelope ref at write-validation time.
- `CU_ERR_POLICY_DENIES_WRITE` — write-validation TEE policy-allow check fails: the PDA's policy does not admit the proposed write under the combination of authority matrix, sub-token class, and current time (TTL).
- `CU_ERR_HOLDER_SIGNATURE_NOT_BOUND_TO_WRITE` — write-validation TEE token-authorizes-this-exact-write check fails: σ_holder is valid in shape but does not bind to the specific `slice_id`, `op_kind`, and `content_ref` of the proposed write.
- `CU_ERR_POLICY_HASH_REPLAY_FAIL` — on-chain policy-hash replay verification fails: chain-side recomputation of `policy_hash` does not match the value attested in `write_attest`, indicating a malicious or stale G4 attestation.
- `CU_ERR_STREAM2_COSIGN_MISSING` — Stream 2 anchor transaction is missing the cosign-gate signature alongside the G4 `K_G4_audit_stream2` signature; the anchor cannot land without both signatures present.
- `CU_ERR_INVALID_HOLDER_SIGNATURE` — σ_holder verification fails against the holder-binding pubkey recorded in the credential anchor.
- `CU_ERR_REVOKED_MASTER` — the master credential digest is recorded in `MasterTokenRevocationRegistry` with non-zero revocation timestamp; presentation is refused.
- `CU_ERR_ANCHOR_NOT_FOUND` — the credential anchor is absent in `CredentialAnchorRegistry` on a non-first-presentation attempt.
- `CU_ERR_TTL_EXPIRED` — the sub-token's TTL declared at derivation has elapsed at presentation time.

### §13.2 Composite errors

Composite errors carry one top-level operational class and one or more forensic sub-codes. Example: `CUSTODY_ERR_G4_REFUSED` with sub-code `0x08 dsl_deprecated`, registry entry id, deprecation block, and disclosure CID. Composite errors still must not include plaintext, σ bytes, raw quotes, or partial AAD.

### §13.3 Caller recovery boundary

Caller may:

- wait for finality
- wait for challenge window close
- retry network calls
- fetch a fresh quote
- fetch registry state at the same authorization block
- ask recipient to re-run local σ_conditional ceremony
- surface G4 refusal to human/legal workflow
- retry SD-side output generation only within S2-7's caller boundary when escrow sealing has not been made dependent on it

Caller may not:

- switch G3 path
- ignore cross-vendor failure
- accept current registry state instead of authorization-block state
- reconstruct with fewer Shamir shares than the commit threshold
- use Phase 1 σ for Phase 2 commit
- use Phase 2 DCAP σ for Phase 1 commit
- log σ values for debugging
- log recovered shares, Shamir coefficients, DEK, or plaintext for debugging
- propagate `CUSTODY_ERR_SD_ONBOARDING_PARTIAL_FAILURE` into escrow commit failure once escrow envelope sealing has completed

`ERR_SD_ONBOARDING_PARTIAL_FAILURE` from S2-7 §1.5 is SD-side only. SD pipeline failure MUST NOT block escrow at commit-time. The escrow commit completes independently once plaintext has been encrypted, Shamir-split, wrapped, and sealed; S2-7 handles SD retry/degradation without changing custody state.

If caller recovery would require changing a commit-bound field, it is outside S2-3 recovery and becomes a new ceremony. That includes G3 path change, G4 phase change, plugin profile change, recipient policy change, conditional-recipient mode change, gate-recipient KEM pubkey replacement after commit, and post-authorization shred override. S2-3 adapters expose these as hard errors so S2-5 and S2-6 can route the user/operator to the correct ceremony instead of retrying a structurally impossible reveal.

## §14 - Test obligations

### §14.1 Unit tests

Each adapter must test canonical request construction, idempotency key derivation, parsing, successful verification, every failure mode, redaction, and zeroization. Tests include explicit "no σ appears in logs" assertions.

Redaction tests must be adversarial. Test inputs include σ-like byte sequences in error messages, vendor response bodies, exception stack traces, JSON stringification paths, and debug-level logs. A test passes only if the emitted logs contain neither the raw bytes nor stable reversible encodings such as base64, hex, decimal arrays, or protobuf dumps. Hashes of σ values are also forbidden unless S2-1 explicitly authorizes a public digest; S2-3 does not.

### §14.2 Integration tests

Integration tests cover:

- Lit assignment + quote + σ_Lit happy path
- Lit quote replay rejection
- dcipher happy path once SDK ships
- dcipher epoch rotation historical lookup
- drand round fetch and wrong-round rejection
- G4 Phase 1 historical dev commit verification
- G4 Phase 2 DCAP quote verification
- cross-vendor mismatch rejection
- registry deprecation before and after authorization block
- G4 refusal codes and encrypted-reason mode

### §14.3 Combiner tests

Combiner tests must cover Mode 3 rejection, missing σ, extra σ, σ order swap, stale plugin hash, stanza MAC failure, AEAD tag failure, no partial plaintext, no σ persistence, crash-dump disabled, and decryption success with all required gates.

### §14.4 Test vector references

S2-1 App. B owns crypto vectors. S2-3 adds integration vectors:

- Lit Chipotle σ_Lit and DCAP vector
- dcipher σ_G3 vector after SDK confirmation
- drand round vector for fixed chain hash/round
- G4 Phase 1 Ed25519 vector
- G4 Phase 2 DCAP vector
- cross-vendor rejection vector
- 3-gate historical profile vector
- full 4-gate profile vector

## §15 - Cross-references

### §15.1 S2-1 sections imported

S2-3 imports S2-1 §1 conventions, §2 TAGs, §4 `commit_AAD`, §6 envelope/AEAD, §7 σ_Lit, §8 σ_G3, §9 σ_G4, §11 endpoint attestation, §12 registry verification, §14 combiner, §16 abort discipline, §17/App. C version pin deferrals.

### §15.2 S2-2 sections imported

S2-3 imports S2-2 §2 contract registry, §5 AttestationGate views, §9 registries plus `LitV3Assignment`, `GateRecipientPubkeyRegistry`, and `DisclosureRegistry`, §10 ShredRegistry state read, §11 Mode 3 rejection, §12 `RevealAuthorized`, §14 refusal enum, §16 roles, and §21 S2-3 consumption surface.

### §15.3 Downstream consumers

S2-4 consumes G3/G4 eligibility, G3 default table, Phase 2 enforcement for legal-effect PDAs, and Mode 3 rejection. S2-5 consumes adapter request/response shapes, idempotency keys, artifact metadata, encrypted quote/refusal handling, and caller recovery. S2-6 consumes version-review cadence, binary distribution references, vendor coordination points, and G4 phase cutover. S3-1 consumes health probes, SLOs, alert classes, and incident response triggers.

### §15.4 Stage-3 forward references

Stage 3 must produce:

- lockfiles proving §11 pins
- SDK compatibility matrix
- vendor test vectors
- attestation proof fixtures
- Base Sepolia registry deployment addresses
- reproducible combiner binary hash
- log-redaction evidence
- failure-injection report

Note on the live deployment: the Base Sepolia deployment referenced here is testnet-only, and deployed bytecode may lag or diverge from this source; see `deployments/README.md`.

## App. A - Per-vendor DCAP quote verification protocols

### A.1 Common DCAP checks

Every DCAP quote path verifies quote signature, collateral freshness, TCB status, enclave measurement, report/user_data binding, quote freshness, and vendor root. The adapter records vendor, quote version, measurement digest, collateral digest, verifier address, and verification mode.

### A.2 Intel SGX / TDX

Intel path enforces the 64-byte report-data limit. S2-3 uses S2-1's keccak-compressed 32-byte digest plus zero padding. TCB statuses accepted for production must be explicitly allowlisted; "out of date" or equivalent warning statuses require S2-6 risk review before acceptance.

### A.3 AMD SEV-SNP

AMD path verifies report signature chain, chip endorsement material, policy flags, measurement, and report data. If AMD report-data semantics differ from Intel's byte placement, the adapter maps the S2-1 32-byte digest into the vendor-supported report-data field and test vectors prove exact extraction.

### A.4 AWS Nitro

Nitro path verifies attestation document signature, PCR set, module id, public key/user_data binding, timestamp freshness, and AWS root. The G4 Phase 2 deployment must document which PCRs bind the G4 binary and runtime config. A Nitro path cannot be treated as DCAP-equivalent unless the artifact makes the root, PCR, and user_data verification explicit.

### A.5 Controlled-use G4 key coverage (commit_version = 0x0303)

The two controlled-use G4 keys introduced at §7.15 — `K_G4_write_attest_pubkey` and `K_G4_audit_stream2_pubkey` — are covered by the existing G4 Phase 2 DCAP attestation chain. No new vendor-specific quote semantics are added for controlled-use; the two new keys ride the same DCAP-bound key publication path as the existing G4 sigma verification pubkey.

**Report-data binding.** When the G4 Phase 2 TEE publishes either `K_G4_write_attest_pubkey` or `K_G4_audit_stream2_pubkey` (at registry commit time or at key rotation), the DCAP quote's `user_data` (Intel SGX/TDX) or report-data (AMD SEV-SNP) or PCR-bound public key field (AWS Nitro) carries the keccak digest of the published key alongside the existing G4 authority context. The byte positions are the same as those described in §A.2 / §A.3 / §A.4 for the existing G4 sigma key; the digest occupies the canonical 32-byte slot, with zero-padding to fill the vendor-supported report-data field.

**Distinct user_data digests at use.** At runtime (when the TEE produces `write_attest` or signs Stream 2), the DCAP `user_data` digest binds the specific signing operation:

- For `write_attest` signing: `user_data[0:32] = keccak256(TAG_CU_WRITE_ATTEST_V3 || h_envelope_proposed || slice_id || actor_token_digest || block_hash || policy_hash)[:32]` (per §7.10.1 + S2-8 §4.1).
- For Stream 2 signing: `user_data[0:32] = keccak256(TAG_CU_AUDIT_STREAM2_V3 || stream2_merkle_root || pepper_epoch_number || block_hash)[:32]` (per §7.16 + S2-8 §4.4).

These digests are deliberately distinct from the read-path σ_G4 `user_data` digest (which uses `TAG_G4_ATTESTATION_V3` per §A.2 + S2-1 §9.2.3). Reusing the read-path σ_G4 user_data digest as a write-attest or Stream 2 user_data is forbidden and the adapter must reject such a payload as cross-domain replay.

**Per-vendor.** The vendor-specific byte-position handling per §A.2 / §A.3 / §A.4 applies identically: the controlled-use additions do not change the vendor mapping, only the input digest the user_data slot carries. A.4 AWS Nitro deployments must document which PCRs bind the controlled-use G4 binary (which may differ from the non-controlled-use G4 binary if controlled-use ships as a separate enclave image).

**Authority registry binding.** The DCAP quote at publication time binds both new keys to the same G4 authority entry that holds the existing G4 sigma key. A `G4AuthorityRegistry` entry under controlled-use carries three pubkey slots (sigma verification, write-attest, audit-stream2); a non-controlled-use entry carries one. Both shapes coexist; the entry version field distinguishes them.

## App. B - Test vector placeholders

Stage 3 fills this appendix with links or embedded hashes for:

- TAG digest table inherited from S2-1
- `commit_AAD` SCALE fixture
- Lit ACC canonicalization fixture
- Lit assignment/DCAP/σ fixture
- dcipher committee/σ fixture
- drand round/σ fixture
- G4 Phase 1 fixture
- G4 Phase 2 fixture
- cross-vendor mismatch fixture
- combiner full decrypt fixture
- refusal/encrypted-reason fixture

The placeholder categories are normative. Missing a category blocks production readiness. Vendor-bound fixtures close the matching §11.4 checklist items: Lit assignment/DCAP/σ fixtures close `VENDOR_CONFIRMATION_LIT_CORE_API` and `VENDOR_CONFIRMATION_LIT_BLS_VARIANT`; dcipher committee/σ fixtures close `VENDOR_CONFIRMATION_DCIPHER_SDK` and `VENDOR_CONFIRMATION_DCIPHER_BLS_VARIANT`; G4 Phase 2 fixtures close `VENDOR_CONFIRMATION_AUTOMATA_DCAP_CONTRACTS` and `VENDOR_CONFIRMATION_AUTOMATA_GO_DCAP_SDK`.

## App. C - Scope-out enumeration

S2-3 deliberately excludes:

- cryptographic byte layouts owned by S2-1
- Solidity contract interfaces owned by S2-2
- configurator UI/CLI and PDA authoring owned by S2-4
- REST ingestion/delivery and artifact JSON owned by S2-5
- operational ceremonies, vendor renewal, external-advisor seating, and plugin OTA distribution owned by S2-6
- monitoring runbooks and incident playbooks owned by S3-1
- SD pipeline runtime owned by S2-7
- production activation of dcipher until a Randamu SDK release/commit and test vector are pinned
- production activation of any Lit or G4 ciphersuite that contradicts S2-1 without a BP-N back-propagation

None of these exclusions authorizes a degraded release path. They identify the owning spec or release gate.
