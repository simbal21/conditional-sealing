# Cealis V2 System, V3 Custody - Smart Contracts Specification (S2-2)

## §0 - Front Matter

### §0.1 Document identity

**Title:** Cealis V2 System, V3 Custody - Smart Contracts Specification (S2-2)

**Stage:** Stage-2 mandatory specification. S2-2 is the normative on-chain contract-surface specification for the V2 system with V3 custody architecture. It consumes S2-1 (`docs/specs/cryptography-spec.md`) and fixes the Solidity-facing shape of ConditionEngine, condition modules, AttestationGate, FSMInterpreter, Claim DSL, oracle registries, custody registries, ShredRegistry, PasskeyRotationLog, SupersededCommitRegistry, RevealAuthorized emission, pause/halt mechanics, access control, deploy order, upgrade strategy, gas-budget expectations, and contract-level test obligations.

**Output artifact:** this document only. No Solidity source files are authored by S2-2. Stage 3 implements these interfaces and proves them through Foundry build, unit, fuzz, invariant, and gas-snapshot tests.

**Version field semantics:** this document's own version is `1.0-draft`. The protocol version it consumes is S2-1 `commit_version = 0x0302`. A future contract-surface change that alters byte layouts consumed by S2-1 requires the S2-1 §2.8 tag/version discipline plus coordinated Stage-2 spec updates.

### §0.2 Audience and reading order

**Cealis-internal Solidity engineer.** Read §1 conventions first, then §2 contract registry, §4 ConditionEngine modules, §5 AttestationGate, §9 registries, §10 ShredRegistry, §12 RevealAuthorized, §16 access control, §17 deploy order, §18 upgrade strategy, and App. A interfaces. App. A is the implementation checklist: every interface, event, error, and role declared there must be either implemented directly or explicitly wrapped by a contract with identical externally observable behavior.

**External contract auditor.** Read §0.6 source ordering, §0.7 discipline anchors, §1 fail-closed conventions, §3 composite identifiers, §4 release-path logic, §5 no-σ-on-chain boundary, §9 registry governance, §10 shred guardrail, §11 Mode 3 rejection, §14 halt mechanics, §16 role matrix, §18 upgrade strategy, §19 gas-budget assumptions, §20 tests, and App. C scope-outs. The audit-critical question is narrow: can any contract path emit `RevealAuthorized` or permit gate-signing to proceed without the predefined on-chain condition, registry state, challenge-window rules, shred guardrails, and halt/refusal checks required here?

**Future Cealis engineers.** Read §21 cross-references after §0 and §1. §21 states what later Stage-2 docs consume from S2-2 and where future changes must propagate. Storage layouts are append-only and role surfaces are timelocked; future versions extend rather than replace unless a protocol-version bump explicitly says otherwise.

### §0.3 Terminology discipline

**V2 vs V3.** V2 is the system version. V3 is the custody/key-holding subsystem inside V2. This document says "V2 system, V3 custody" or "V3 custody" when naming the four-gate custody substrate. It does not use bare "V3" as a system version.

**G1/G2/G3/G4.** G1 is the on-chain ConditionEngine surface. G2 is Lit V3. G3 is dcipher or drand, selected per PDA. G4 is the Cealis verification component with Phase 1 sealed-code server path and Phase 2 rented TEE path. S2-2 implements G1 and the on-chain registries that G2/G3/G4 and the combiner read.

**σ-as-authorization.** S2-1 §0.3 and §14 are binding: σ values are authorization signatures over the reveal context, not HKDF input keying material and not DEK material. On-chain contracts in S2-2 never store, emit, or require σ_Lit, σ_G3, σ_G4, or σ_conditional in calldata. Where this document says "gate binding", it means an on-chain binding to commitment metadata, registered authority state, assignment records, gate-recipient pubkeys, refusal state, or event-visible condition state. It never means publication of σ bytes.

**AttestationGate name discipline.** In WP §B P4, AttestationGate is the condition primitive: it verifies signed oracle attestations or chain-state predicates against the frozen PDA Claim expression. It is not a custody-combiner contract. Custody σ verification remains off-chain in the recipient combiner per S2-1 §14. S2-2 specifies the on-chain binding and registry surfaces that make that off-chain verification auditable.

**Phase 1 / Phase 2 G4.** Contracts support both Phase 1 and Phase 2 G4 entries at the registry level. Partner-ready and legal-effect PDAs must commit under Phase 2, enforced by configurator and contract validation surfaces. Phase 1 commitments remain historically verifiable after Phase 2 cutover via G4AuthorityRegistry historical lookup.

### §0.4 What this spec does not cover

This document does not duplicate S2-1 cryptographic byte layouts. It imports them by section anchor. S2-1 §2 `TAG_*_V3` preimages, SCALE schemas, σ construction, Shamir-share reconstruction, AEAD, stanza wrapping, endpoint attestation byte layouts, and combiner pre-verification remain S2-1.

This document does not specify commodity-network SDK integration. Lit V3 SDK, Randamu dcipher SDK, drand client, Automata zkDCAP, BLS variant assignments, TEE vendor SDKs, and library version pins live in S2-3.

This document does not specify the full PDA configurator UI/API. It specifies the on-chain validation and registry surfaces the configurator must call. Shared PDA data model, CLI/API, internal UI, validation copy, template library, and partner-review flows live in S2-4.

This document does not specify ingestion/delivery REST APIs, webhooks, recipient artifact JSON, plaintext delivery, or vault deletion implementation. These live in S2-5.

This document does not specify operational ceremonies beyond their on-chain hooks. Key rotation runbooks, plugin distribution, deprecation disclosures, external-advisor seating, G4 Phase 1 to Phase 2 cutover ceremonies, and Mode 3 activation ceremony live in S2-6.

This document does not specify SD circuits or DisclosureRegistry details beyond the on-chain shape S2-7 consumes. Selective Disclosure remains parallel to escrow and lives in S2-7.

### §0.5 Status of this document

S2-2 is authored as a single-volume specification. It is implementation-grade but still pre-Stage-3: storage-slot packing, precise gas measurements, and bytecode-level OpenZeppelin integration are verified during Stage 3. This document is normative about externally observable behavior, role structure, events, errors, storage-field ordering, and upgrade invariants.

### §0.6 Source-of-truth ordering

For cryptographic byte-exact constructions, S2-1 is canonical. S2-2 imports S2-1 §1 conventions, §2 `TAG_*_V3` registry, §3 composite identifiers, §4 `commit_AAD`, §10 Mode 3 RESERVED discipline, §11 endpoint attestation, §12 registries, §13 PasskeyRotationLog, §14 combiner, §16 error model, §17 cross-references, and App. C scope-outs.

For full-engine scope decisions, the internal Stage-0 decisions record (not included in this export) is canonical: all nine condition modules ship, both G3 paths are first-class, both G4 phases are represented, full DSL plus reserved WASM custom predicate surface exists, both CLI/API and UI configurator consume this contract layer, and SD is mandatory as S2-7.

For project framing and PDA guardrails, WP §B, §C, §F, §K, and §P are canonical within the provided corpus. For V3 field names and the G4 refusal reason enum, `flows-spec-final.md` is the cross-check target, superseded where S2-1 explicitly back-propagated newer byte layouts.

Within the Stage-2 stack, S2-2 is canonical for the contract surfaces it defines. Downstream specs consume S2-2; they do not silently replace it.

### §0.7 Document discipline anchors

**Production-grade surface.** Every normative contract surface below must be implementable directly. No placeholder exists inside normative scope. App. B is a test-vector category placeholder by design; the vectors themselves are produced by Stage 3 reference implementation.

**Seven-view check.** The contract surface was checked against Enforcement, Tamper-proof, Selective Disclosure isolation, Commercial configurability, Legal guardrails, Use-case flexibility, and Partner-fit. Concrete consequence: S2-2 does not collapse to a lending-only obligation registry, does not publish σ values as proof objects, does not let legal-effect PDAs opt out of emergency halt, and does not hard-code one use-case template into ConditionEngine.

**Full engine.** All nine condition modules are in scope. Full DSL v1 with 12 operators is in scope. WASM custom predicate is reserved but surfaced. Mode B implications are represented at commitment and registry surfaces even though Mode A is current default. Mode 3 conditional recipient is architected but rejected at V2 launch by contract-level validation.

**Universal tripwire.** No release path exists that bypasses the on-chain-verified predefined condition. In S2-2 terms: only ConditionEngine may emit `RevealAuthorized`; every module path routes through either Mode F terminal state or Mode P predicate evaluation; challenge windows, shred state, pause state, registry deprecation, G4 refusal, and Mode 3 rejection cannot be bypassed by alternate emitters.

**TAG import.** S2-2 imports `TAG_*_V3` names from S2-1 §2 only. It does not define new tags. BP-13 is rejected (`dsl_version_ref` remains raw catalog ref), BP-14 is accepted (`TAG_ORACLE_REGISTRY_V3` active), and BP-15 is rejected (`qtsp_provider_ref` remains raw catalog ref) per `v3-registry-class-discipline.md` (internal design note, not in this export).

**Custom errors only.** Solidity implementations must use custom errors for all revert paths. No string reverts. Interface examples in App. A declare canonical errors.

**UUPS discipline.** Every upgradeable Cealis contract inherits `Initializable` and `UUPSUpgradeable`. `_authorizeUpgrade(address)` is `internal override onlyRole(UPGRADER_ROLE)`. `UPGRADER_ROLE` is held exclusively by TimelockController after deployment. Storage layout is append-only; field reordering is forbidden.

### §0.8 Cross-reference index

S2-1 imports used by S2-2:

| S2-1 anchor | S2-2 consumption |
|---|---|
| §1 conventions | hash, SCALE, endian, fail-closed, PII discipline |
| §2 `TAG_*_V3` registry | contract helpers that re-compute identifiers and registry refs |
| §3 composite identifiers | `subject_commitment_v3`, `authorizationId`, `pda_root`, `h_commit` helper signatures |
| §4 `commit_AAD` | registry refs, deprecation snapshot, plugin/G4/DSL/oracle/QTSP bindings |
| §10 Mode 3 | contract-level rejection and defense-in-depth |
| §11 endpoint attestation | LitV3Assignment, G4AuthorityRegistry, at-commit-block reading |
| §12 registry verification | five V3 registries, DeprecationFlag, 72h auto-clear, 30-day cooldown |
| §13 PasskeyRotationLog | ABI surface and walk-from-anchor support |
| §14 combiner | ShredRegistry, SupersededCommitRegistry, registry and event surfaces consumed by off-chain combiner |
| §16 error model | custom error naming and fail-closed semantics |
| §17 and App. C | S2-2 ownership boundaries and author-lock surfaces |

Downstream consumption:

| Downstream spec | S2-2 surface consumed |
|---|---|
| S2-3 | registry names, gate assignment, attestation contract addresses, on-chain DCAP verifier hooks |
| S2-4 | PDA registration, module config, Mode 3 rejection, legal-effect constraints, challenge/shred guardrails |
| S2-5 | `RevealAuthorized`, `ShredAuthorized`, refusal and challenge events, idempotent event keys |
| S2-6 | timelock governance, deprecation disclosure, upgrade, registry rotation, emergency governance hooks |
| S2-7 | DisclosureRegistry shape and SD isolation constraints |

### §0.9 PII content statement

S2-2 contracts store and emit zero plaintext PII. Permitted on-chain objects are commitment hashes, digest refs, public keys, contract addresses, opaque IDs, enum values, timestamps, block numbers, registry metadata, and challenge/refusal state. Subject data, plaintext payloads, σ values, and vault ciphertext contents remain off-chain. Sensitive G4 refusal reasons for codes `0x02` and `0x03` default to encrypted-reason mode.

## §1 - Conventions

### §1.1 Solidity version, EVM target, and library set

All Cealis V2 system contracts target Solidity `^0.8.20`, compiled with `0.8.28`, EVM Cancun. OpenZeppelin v5.x is the baseline for `AccessControlUpgradeable`, `PausableUpgradeable`, `UUPSUpgradeable`, `Initializable`, `TimelockController`, `ECDSA`, `EIP712`, and cryptographic utility libraries available in OZ. Non-OZ verification libraries such as Automata zkDCAP are referenced through explicit interfaces and pinned in S2-3.

Contracts must not depend on chain-specific predeploys except standard EVM functionality available on Base Mainnet. Base Sepolia may be used for Stage 3 verification, but the deployment target is Base Mainnet.

Note: the Base Sepolia deployment that accompanies this repository is testnet-only, and the deployed bytecode may lag or diverge from this source; see `deployments/README.md`.

### §1.2 Storage layout discipline

Every Cealis upgradeable contract uses one of two storage patterns:

1. OZ v5 namespaced storage when the contract naturally fits ERC-7201 namespacing.
2. Explicit append-only storage structs with a `uint256[N] __gap` when namespacing is not used.

The invariant is the same: initial field ordering is frozen at deployment; future versions append new fields only. Mappings and arrays are never repurposed. Enum discriminants are never reordered; new enum values append at the end. A storage-layout diff is a required Stage 3 and future-upgrade artifact.

### §1.3 Custom error discipline

All revert paths use custom errors. Error names are contract-scoped by prefix where ambiguity would hurt auditing, for example `ConditionUnknownAuthorization`, `RegistryEntryNotEffective`, `ShredRevealInProgress`, `Mode3Reserved`, `UUPSUnauthorizedUpgrade`. Error arguments must be typed enough for forensics but must not include PII, σ bytes, plaintext bytes, partial AAD bytes, or oracle attestation plaintext. Hashes and IDs are acceptable.

### §1.4 Event discipline

Events are SDK-readable and privacy-minimized. `authorizationId`, `hCommit`, `pdaRoot`, registry refs, entry IDs, and module IDs may be indexed. Events must not emit plaintext, σ values, oracle attestation plaintext, or sensitive refusal text. Events that anchor off-chain evidence emit digest refs, CIDs, or encrypted blobs.

The canonical reveal event is:

```solidity
event RevealAuthorized(
    bytes32 indexed authorizationId,
    bytes32 indexed hCommit,
    bytes32 indexed pdaRoot,
    uint64 authorizationBlock,
    uint64 authorizationTimestamp,
    uint32 challengeWindow,
    bytes32 conditionRef
);
```

The `authorizationBlock` is the block containing the event. Off-chain consumers use the finalized block hash for S2-1 reveal-challenge and DCAP `block_hash` bindings. Contracts cannot know the current block hash during event emission.

### §1.5 Access-control role naming

Role identifiers are `bytes32` constants named in uppercase. Core roles:

| Role | Meaning |
|---|---|
| `DEFAULT_ADMIN_ROLE` | Held by TimelockController after deploy and admin renounce |
| `UPGRADER_ROLE` | Held only by TimelockController |
| `PAUSER_ROLE` | Bounded pause/unpause on specific contracts |
| `OPERATOR_ROLE` | Operational actions that do not alter policy or release data |
| `ORCHESTRATOR_ROLE` | Backend-triggered lifecycle actions such as registering commit refs after validation |
| `ISSUER_ROLE` | External attestation issuer role where on-chain source authorizes records |
| `MODULE_ADMIN_ROLE` | Adds or deprecates condition modules under timelock |
| `REGISTRY_ADMIN_ROLE` | Adds registry entries under timelock |
| `SECURITY_COUNCIL_ROLE` | CealisSecurityMultisig instant or expedited deprecation path |
| `EMERGENCY_GOVERNANCE_ROLE` | Circuit breaker that can suspend security council deprecation authority |
| `CHALLENGE_RESOLVER_ROLE` | PDA-bound resolver actions during challenge windows |
| `REKEY_GOVERNANCE_ROLE` | SupersededCommitRegistry writes after timelock |
| `ORACLE_SUBMITTER_ROLE` | Oracle attestation submission when a module requires an authorized submitter |
| `LIT_GOVERNANCE_BRIDGE_ROLE` | Writes LitV3Assignment mirrored from Lit governance |
| `GATE_PUBKEY_PUBLISHER_ROLE` | Writes per-commit gate-recipient pubkey entries for Lit, G4, and conditional-recipient paths |
| `SD_OPERATOR_ROLE` | Submits SD proof-verification records to DisclosureRegistry |
| `REVOCATION_ADMIN_ROLE` | Global Cealis-controlled revocation authority on `DisclosureRevocationRegistry` (Art. 17 erasure, legal compel, integrity incidents). Coexists with per-disclosure `authorizedRevoker` partner delegation. |

Any role granted to an EOA at deployment must be temporary unless explicitly named as an operational key in S2-6. Post-deploy scripts must transfer admin authority to TimelockController and renounce deployer admin.

### §1.6 EIP-712 domain naming

S2-2 contracts use these EIP-712 domains when an on-chain contract verifies a typed-data signature:

| Domain | Contract / use | Version |
|---|---|---|
| `CealisRevealManager` | Existing reveal/challenge typed messages where retained for compatibility | `1` |
| `CealisConditionalRecipient` | Mode 2 conditional-recipient EOA recovery, imported from S2-1 §10 | `1` |
| `CealisSubjectInitiated` | SubjectInitiated module release request | `1` |
| `CealisConsentGate` | ConsentGate co-signature request | `1` |
| `CealisMultiPartySignal` | MultiPartySignal signer attestation | `1` |
| `CealisPasskeyRotationLog` | Rotation authorization if mirrored through EIP-712 helper for non-WebAuthn tooling | `1` |

WebAuthn itself is not EIP-712. PasskeyRotationLog WebAuthn assertions verify through WebAuthn semantics and S2-1 §13 digests.

### §1.7 `TAG_*_V3` import convention

Every `TAG_*_V3` name in S2-2 imports S2-1 §2. S2-2 may define Solidity `bytes32 constant` values derived from S2-1 labels, but the label and preimage meaning remain S2-1's responsibility. Contract helpers that compute `authorizationId`, `pda_root`, `h_commit`, `plugin_version_digest`, `g4_authority_ref`, `rotation_log_anchor`, `rotation_authorization_digest`, and `superseded_commit_lookup` must cite the S2-1 anchor in NatSpec.

S2-2 does not introduce `TAG_DSL_VERSION_V3` or `TAG_QTSP_PROVIDER_V3`; BP-13 and BP-15 are rejected and those refs remain raw catalog keys. BP-14 is accepted in S2-1, so OracleRegistry helpers use `TAG_ORACLE_REGISTRY_V3` for `oracle_id` recomputation where they expose an oracle-id helper.

### §1.8 Gas-budget conventions

Gas targets in §19 are order-of-magnitude design budgets, not measured numbers. Stage 3 produces measured Foundry gas snapshots. Any Stage 3 implementation exceeding these budgets must either optimize or document why the budget was structurally wrong.

Bounded-gas rules:

- `advanceFSM` must be bounded by PDA-configured max transitions per call.
- Claim DSL evaluation must be bounded by max AST nodes, max path depth, max `IN` set size, and max nested boolean depth.
- Oracle attestation verification must verify digest and signature over a bounded schema ref, not parse unbounded plaintext payloads on-chain.
- `Composed` conditions must cap child count and short-circuit deterministically.
- Registry reads must be O(1) by key, except historical pagination helpers that are explicitly view-only.

### §1.9 Fail-closed discipline on-chain

Every contract method that can affect reveal, shred, challenge, registry validity, pause state, or module activation must fail closed. Unknown IDs revert. Expired windows revert. Deprecated-before-authorization registry entries block. Shredded commitments block. Paused PDAs block FSM advancement but do not erase historical state. Mode 3 selection reverts at V2 launch. Legal-effect PDAs with Phase 1 G4 or halt-opt-out revert. No contract silently returns false when a state transition was requested and failed.

### §1.10 ABI naming and type discipline

External ABI names use Solidity camelCase. Cryptographic field names in prose preserve S2-1 snake_case where that avoids ambiguity (`authorizationId` is already camelCase in contract ABI; `pda_root` and `h_commit` remain prose names). Struct fields exposed in Solidity should be idiomatic camelCase but NatSpec must map them to S2-1 names. Example: `hCommit` maps to S2-1 `h_commit`; `pdaRoot` maps to `pda_root`; `g4AuthorityRef` maps to `g4_authority_ref`.

Enums must have explicit discriminants in implementation tests even if Solidity source does not assign values manually. The contract ABI cannot rely on source-order memory alone for audit confidence. Stage 3 tests should assert:

- `ConditionMode.ModeF == 1` and `ConditionMode.ModeP == 2` if `None == 0`.
- `G3Choice.Dcipher == 0` and `G3Choice.Drand == 1`.
- `G4Phase.Phase1 == 1` and `G4Phase.Phase2 == 2`.
- shred authority values match S2-1 §3.4.4 left-padded `bytes32(uint256(enum_value))` form.

ABI functions that accept byte arrays must document maximum length. Unbounded `bytes` is allowed only where the underlying primitive is variable length and Stage 3 caps calldata length in code.

## §2 - Contract Registry: Full V2 Contract List

### §2.1 Core condition platform

**ConditionEngine.** Entry point for reveal and shred condition evaluation. Owns PDA condition references, module dispatch, challenge-window opening, `RevealAuthorized` and `ShredAuthorized` emission, and the canonical `post_challenge_reveal_in_progress` state read consumed by ShredRegistry. UUPS upgradeable. Depends on FSMInterpreter, DSL interpreter, AttestationGate, ShredRegistry, ChallengeRegistry, OracleRegistry, OracleSchemaRegistry, DSLVersionRegistry, and TimelockController.

**PaymentObligationModule.** Evaluates obligations and defaults for enforcement/KYC-lending PDAs. Supports chain-native partner contract reads and oracle-attested payment status. Module state includes obligation lifecycle, cure window, default evidence digest, and trust tier.

**TimeLockModule.** Evaluates time conditions against block timestamp or a registered time oracle. Pure chain-native mode is Tier A; oracle-backed time is Tier B/C. State includes target timestamp, earliest fire time, optional latest fire time, and clock source.

**SubjectInitiatedModule.** Evaluates subject-signed release or shred intent. Uses EIP-712 or WebAuthn-backed subject assent depending on PDA configuration. It is used for subject-initiated reveal, consumer shred, and self-archival cases.

**HeartbeatMissedModule.** Maintains heartbeat deadlines and rolling liveness windows. Fires when the subject or required actor misses the configured heartbeat by `gracePeriod`. Used by dead-man's-switch and testament patterns.

**OracleAttestationModule.** Verifies a registered oracle's signed attestation digest against OracleRegistry and OracleSchemaRegistry, then evaluates the PDA's Claim expression against the typed payload hash and schema ref. On-chain does not store attestation plaintext.

**MultiPartySignalModule.** Tracks a configured set or Merkle-rooted set of signers and a threshold. Fires when k-of-n parties submit valid signatures or oracle attestations for the same signal digest.

**DeadManSwitchModule.** Composes HeartbeatMissed with recipient/beneficiary constraints. It provides a dedicated module because operational defaults, challenge behavior, and artifact semantics differ from generic `Composed(HeartbeatMissed, ...)`.

**ConsentGateModule.** Requires a named authority, resolver, court address, medical proxy, or other PDA-bound authority to co-sign the condition. This is a condition gate, not custody σ_conditional.

**ComposedModule.** Deterministic AND/OR/NOT composition over child module results. It cannot call arbitrary external code. Child count, nesting depth, and evaluation budget are capped.

### §2.2 Shared condition infrastructure

**AttestationGate.** Verifies signed condition attestations from OracleRegistry entries against OracleSchemaRegistry schemas and Claim DSL predicates. For custody gates it verifies only on-chain binding metadata and registry/refusal state; it never accepts σ bytes.

**FSMInterpreter.** Stores compact state for Mode F conditions: current state, FSM spec hash, cursor data, terminal flags, submitter constraints, and advance budget. It checks that submitted transition evidence matches the frozen FSM hash and module expectations before it advances.

**ClaimDSL and DSLVersionRegistry.** ClaimDSL evaluates Claim AST v1 with 12 operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `AND`, `OR`, `NOT`, `IN`, `path_access`, and `within_time_window`. `custom_predicate(wasm_hash, input_binding)` is reserved and registry-pinned. DSLVersionRegistry registers interpreter versions with DeprecationFlag governance.

**OracleRegistry and OracleSchemaRegistry.** OracleRegistry registers oracle pubkeys, addresses, type, schema refs, effective/tombstone blocks, and deprecation state. OracleSchemaRegistry stores schema hashes and canonical example hashes for verification-gate replay and on-chain schema identity.

**ChallengeRegistry.** Manages reveal and shred challenges for Tier B/C PDAs with non-zero windows. It records eligible challengers, challenge reason enum, counter-attestation refs, bonds, resolver actions, extension counts, and challenge status.

### §2.3 V3 custody registries and lifecycle contracts

**PluginHashRegistry.** Registers canonical `age-plugin-cealis-v3` binary digests. Consumed by recipient combiner and G4 ingestion precheck. Additions are 7-day timelocked; deprecations use DeprecationFlag.

**G4AuthorityRegistry.** Registers Phase 1 sealed-code binary hash entries and Phase 2 TEE measurement/authority entries. Supports simultaneous Phase 1 and Phase 2 historical lookup. Phase 1 entries remain valid for Phase 1 commits after Phase 2 cutover.

**LitV3Assignment.** Read-only mirror of Lit governance assignment records keyed by `authorizationId`. Writes are accepted only from an authorized Lit governance bridge. Cealis governance cannot invent assignments outside that bridge.

**ShredRegistry.** Records shred authorization, challenge, finalization, and permanent shredded state for each `hCommit`. Enforces authority axis and condition axis plus mandatory `NOT post_challenge_reveal_in_progress` guardrail.

**SupersededCommitRegistry.** Records re-key supersession lineage. Writes are timelocked and require RekeyGovernance authorization. It lets combiners walk generation lineage without treating a re-key as a new release path.

**QTSPRegistry.** Registers EU QTSP roots and metadata for QES-grade σ_subject path. It follows the same governance shape as the five V3 registries.

**PasskeyRotationLog.** ABI-standard append-only rotation log for Mode 1 PASSKEY_ACCOUNT recipients. Cealis provides a canonical deployment, but verifiers may use any ABI-compatible deployment because contract address is bound into rotation digests.

**G4RefusalRegistry.** Records blocking G4 refusals and separate advisory G4 signals, with encrypted or public reason metadata where applicable. It is a halt/refusal registry, not a custody key registry. Sensitive blocking codes `0x02` and `0x03` default to encrypted reason; advisory `0x0A opt_out_active` is never blocking.

**RevealAuthorizedEmitter.** Optional split contract. The default architecture keeps reveal emission inside ConditionEngine; if split for upgrade isolation, the emitter is role-gated so only ConditionEngine can call it.

**TimelockController.** Standard OZ TimelockController. Holds `DEFAULT_ADMIN_ROLE` and `UPGRADER_ROLE` across upgradeable contracts post-deploy. Enforces 7-day normal governance and 24h expedited delay where registry deprecation of canonical-in-use entries requires it.

**CealisSecurityMultisig and EmergencyGovernance.** On-chain governance contracts or role-bearing multisigs used for DeprecationFlag and emergency circuit-breaker flows. Governance Phase 1 may be Cealis-held, but contract surfaces must already support Phase 2 external advisor seats.

### §2.4 Storage layout registry

This subsection gives the storage fields an implementation team should expect before Stage 3 packing. Field names are normative for meaning, not for literal private variable names. Implementations may pack or namespace storage differently as long as getters and events expose the same semantics and storage-layout evolution stays append-only.

| Contract | Hot storage | Cold storage | Historical lookup requirement |
|---|---|---|---|
| ConditionEngine | lifecycle state by `authorizationId`, hCommit, pdaRoot, challenge deadlines, post-challenge reveal flag | PDA refs, module refs, registry refs, partner id, legal flags | yes, event history plus state snapshots |
| PaymentObligationModule | obligation status, due timestamp, cure deadline | obligation config digest, partner contract ref, oracle refs, evidence refs | yes, status at authorization |
| TimeLockModule | target timestamp, clock source, fired flag | optional time oracle config, drift rules | yes, timestamp source |
| SubjectInitiatedModule | consumed nonce/high-water mark, last action digest | subject authenticator policy refs | yes, action digest |
| HeartbeatMissedModule | last heartbeat, deadline, missed flag | actor config, grace policy | yes, heartbeat history |
| OracleAttestationModule | accepted attestation digest, consumed flag | oracle/schema/claim refs | yes, oracle/schema at authorization |
| MultiPartySignalModule | signer count, signer bitmap/root accumulator | signer set root, threshold, signal digest | yes, signer set |
| DeadManSwitchModule | heartbeat/deadline status, triggered flag | beneficiary policy digest, notification config | yes, trigger path |
| ConsentGateModule | consent count/digest, consumed flag | authority root, role type, threshold | yes, authority set |
| ComposedModule | child result cache, terminal result | composition tree root, child refs | yes, child module refs |
| FSMInterpreter | current state, terminal state, last advanced at, deadline, fsm hash, cursor data | transition roots, submitter roots, max budget | yes, state path |
| ClaimDSL | no per-PDA mutable state | version caps, interpreter metadata | no, via DSLVersionRegistry |
| OracleRegistry | entry mapping, canonical id | entry metadata, deprecation flags | yes, `getAt` |
| OracleSchemaRegistry | schema hash mapping | example hashes, metadata | yes, schema version |
| PluginHashRegistry | entry mapping, canonical id | source digest, disclosure records | yes, `getAt` |
| G4AuthorityRegistry | entry mapping by `g4_authority_ref` | phase metadata, DCAP verifier refs | yes, `getAt` |
| DSLVersionRegistry | entry mapping | cap set hash, custom predicate flag | yes, `getAt` |
| QTSPRegistry | entry mapping | jurisdiction and eIDAS refs | yes, `getAt` |
| LitV3Assignment | assignment by `authorizationId` | bridge source digest, correction records | yes, by assignment block |
| ShredRegistry | shred status by `hCommit` | authority evidence, proof_shred, latency timestamps | yes, shredded state |
| SupersededCommitRegistry | successor by old hCommit | governance refs and generation | yes, lineage walk |
| PasskeyRotationLog | head index by account | entries by account/index | yes, walk from anchor |
| G4RefusalRegistry | refusal state by `authorizationId` | public proof ref or encrypted blob hash | yes, refusal at authorization |
| ChallengeRegistry | active challenge by authorization+axis | bonds, resolver actions, counter-attestation refs | yes, challenge history |

### §2.5 External-call policy

ConditionEngine modules must not make unbounded external calls. Allowed external calls are:

1. Calls to Cealis registries and Cealis modules declared in §2.
2. Static calls to partner contracts explicitly bound in the PDA for Tier A chain-native reads.
3. Static calls to verifier contracts whose address is pinned in a registry entry.
4. Token transfer calls inside ChallengeRegistry bond escrow, limited to PDA+ approved tokens.

No module may call arbitrary recipient addresses, arbitrary oracle addresses outside OracleRegistry, or contracts whose address is supplied only in calldata. Every external target must be either bound in PDA state, registered in a registry, or hardcoded by timelocked governance. This is the contract-level version of the universal tripwire: a caller cannot route condition evaluation to a new authority by passing a different address at reveal time.

### §2.6 Read freshness

Every state-changing function that emits a ceremony event must re-read all live preconditions in the same transaction:

- lifecycle state has not advanced to shredded or reveal-in-progress conflict state.
- PDA pause is not active.
- registry entries required for the condition are effective at the relevant block and not tombstoned before authorization.
- challenge-window guardrail still matches module trust tier.
- `post_challenge_reveal_in_progress` is false for shred.
- blocking G4 refusal state has not already blocked the authorization; advisory G4 signal state is audit-only.

S2-2 inherits Cealis Rule 25: snapshot-once multi-step flows are a known failure mode. Implementations must not validate preconditions in a preparatory transaction and then emit `RevealAuthorized` later without re-validation.

## §3 - Composite Identifiers On-Chain

### §3.1 Helper-contract principle

S2-2 implements helpers for identifier recomputation so Solidity tests, indexers, and downstream contracts can verify the same commitments as off-chain clients. Helpers must be pure or view. They must mirror S2-1 §3 and §4; they do not redefine the byte layouts.

These helpers are allowed to accept digest inputs and scalar fields. They are not allowed to accept plaintext payloads or σ values. They may accept `bytes` only for public-key material, oracle signatures, schema refs, and SCALE-encoded structures whose contents are contract-level metadata.

### §3.2 `subject_commitment_v3`

On-chain helper:

```solidity
function computeSubjectCommitmentV3(
    bytes32 personKey,
    bytes32 partnerNamespace,
    bytes32 registrationNonce
) external pure returns (bytes32 subjectCommitmentV3);
```

The helper imports S2-1 §3.1 and `TAG_SUBJECT_V3` from S2-1 §2.3.1. It accepts only already-derived `personKey`; derivation of provider IDs, wallet addresses, and depositor content hashes remains off-chain/configurator-side. This avoids putting subject pseudo-identifiers into unnecessary contract calldata.

### §3.3 `authorizationId`

On-chain helper:

```solidity
function computeAuthorizationId(
    bytes32 subjectCommitmentV3,
    bytes32 pdaId,
    uint64 pdaVersion,
    uint64 epoch,
    bytes32 nonce
) external pure returns (bytes32 authorizationId);
```

The helper imports S2-1 §3.2 and `TAG_AUTHID_V3` from S2-1 §2.3.1. `authorizationId` is the primary indexed lifecycle key for commit, reveal, challenge, refusal, assignment, and shred events.

### §3.4 `pda_root`

On-chain helper:

```solidity
function computePdaRoot(PdaRootFields calldata fields)
    external
    pure
    returns (bytes32 pdaRoot);
```

`PdaRootFields` mirrors S2-1 §3.3's 29 fields. The Solidity struct must preserve the S2-1 field order. It uses fixed-width types: `bytes32`, `uint64`, `uint8`, and booleans encoded as `uint8` in the preimage. The helper imports `TAG_PDA_ROOT_V3` from S2-1 §2.3.1.

Contract validation must enforce these S2-1/WP §F constraints before a PDA can become active. Hash-only PDA registration is non-conformant: the registering call must provide the concrete fields from which `pda_root` and `h_commit` are recomputed, plus the axis, registry, legal, pause, challenge, G3/G4, shred, and conditional-recipient fields the contracts need for on-chain guardrails.

- `reveal_condition_mode` and `shred_condition_mode` are Mode F or Mode P only.
- `cealis_class_wide_halt_opt_out == false` when `legal_effect_expected == true`.
- `phase == 2` when legal-effect PDA template requires Phase 2 G4.
- `subject_authenticator_class != synced_passkey` when `legal_effect_expected == true`.
- `qtsp_provider_ref != 0` when QES is required; zero otherwise.
- Art. 9 scoped PDAs carry non-zero `art_9_basis_id`.
- challenge windows respect Tier-A-zero / Tier-B-C-required guardrail.
- every shred condition spec hash references a compiled guardrail that AND-composes `NOT post_challenge_reveal_in_progress`.
- Mode 3 conditional recipient is rejected by PDA registration at V2 launch.

`registerPDA(PDARegistration calldata reg)` recomputes `pdaRoot = computePdaRoot(reg.pdaRootFields)` and `hCommit = computeHCommit(reg.hCommitFields)`, requires `reg.hCommitFields.pdaRoot == pdaRoot`, validates the guardrails above, and stores the concrete fields ConditionEngine, ChallengeRegistry, ShredRegistry, G4RefusalRegistry, and G4 authority reads consume. A contract implementation that accepts only caller-supplied `pdaRoot`/`hCommit` hashes cannot prove the hidden fields were valid and does not conform to S2-2.

### §3.5 `h_commit`

On-chain helper:

```solidity
function computeHCommit(HCommitFields calldata fields)
    external
    pure
    returns (bytes32 hCommit);
```

`HCommitFields` mirrors S2-1 §3.4's 15 inputs with split reveal and shred challenge windows. The helper imports `TAG_COMMIT_V3` from S2-1 §2.3.1. `phase` accepts `1` and `2`; contract validators reject Phase 1 for partner/legal-effect PDAs but keep the helper capable of historical verification.

`hCommit` is the chain anchor. No contract stores full commit_AAD. Contracts store the minimal fields necessary to route condition evaluation and registry lookup: `authorizationId`, `hCommit`, `pdaRoot`, validated axis configs, challenge windows, phase, G3 choice, G4 authority ref, registry refs, legal flags, pause-authority mode, conditional-recipient modes, and lifecycle status.

### §3.6 Registry-ref helpers

S2-2 helpers compute registry refs only where S2-1 has locked the TAG-prefixed form:

- `computePluginVersionDigest(bytes32 canonicalBinaryHash)` imports `TAG_PLUGIN_VERSION_V3` from S2-1 §2.3.4.
- `computeG4AuthorityRef(bytes calldata authorityPubkey)` imports `TAG_G4_ATTESTATION_AUTHORITY_V3` from S2-1 §2.3.3.
- `computeRotationLogAnchor(...)` imports `TAG_ROTATION_LOG_ANCHOR_V3` from S2-1 §2.3.4 and §13.4.
- `computeRotationAuthorizationDigest(...)` imports `TAG_ROTATION_AUTHORIZATION_V3` from S2-1 §2.3.4 and §13.3.
- `computeSupersededCommitLookup(bytes32 supersededCommitRef, uint16 commitGeneration)` imports `TAG_SUPERSEDED_COMMIT_REGISTRY_V3` from S2-1 §2.3.4 and §15.6.3.

S2-2 does not compute TAG forms for DSL or QTSP refs because BP-13 and BP-15 are rejected; those remain raw 32-byte catalog refs. Oracle helper implementations may compute `oracle_id` with `TAG_ORACLE_REGISTRY_V3` because BP-14 is accepted in S2-1.

### §3.7 PII and calldata minimization for helpers

Identifier helpers are safe to expose because they operate on digest-layer fields. Even so, implementation should not encourage frontends to submit raw subject identifiers to helper contracts. The public helper for `subject_commitment_v3` accepts `personKey`, not a wallet address, provider id, national id, KYC id, or content descriptor. The public helper for `pda_root` accepts only hashes and enum/scalar fields. Any frontend or SDK that derives `personKey` should do so locally or inside the ingestion boundary, then discard source material according to S2-5.

The same principle applies to test tooling. Foundry tests may include dummy values that look like addresses or IDs, but production logs and fixtures should label them as random digests to avoid accidental drift into real identifiers. S2-2 contract helpers are not a data-ingestion API.

### §3.8 Hash helper failure semantics

Pure helper functions should not silently normalize invalid enum values. If a helper is intended to be byte-exact for historical reconstruction, it may compute over any byte value. If a helper is intended for PDA registration, it must validate enum ranges and legal guardrails. Stage 3 should split these surfaces:

- `compute...` pure helpers: byte-exact, minimal validation, used for audit reconstruction.
- `validateAndCompute...` helpers: full contract validation, used by configurator and registration.

This prevents a future auditor from being unable to reproduce a historical invalid preimage while still preventing new invalid PDAs from registering.

## §4 - ConditionEngine and Nine Condition Modules

> **See S2-8 (controlled-use spec) §6 for the tenth ConditionEngine module (PresentedTokenCondition) and the H-6 composition-compatibility matrix (including DeadManSwitch × PresentedTokenCondition FORBIDDEN). See S2-8 §5–§8 for the three new on-chain registries (`CredentialAnchorRegistry`, `SliceLayoutRegistry`, `MasterTokenRevocationRegistry`) plus opt-in `TokenRevocationRegistry`.**

### §4.1 ConditionEngine lifecycle

ConditionEngine owns the condition lifecycle for both reveal and shred axes. A PDA registration binds validated concrete fields, not only opaque hashes:

- `authorizationId`
- `hCommit`
- `pdaRoot`
- reveal axis: mode, module config ref, challenge window, eligible challenger root, resolver
- shred axis: mode, module config ref, challenge window, eligible challenger root, resolver
- G3 choice and G4 phase
- G4 authority ref and registry refs needed for at-commit-block verification
- legal-effect, Art. 9, QES, halt-opt-out, pause-authority, and conditional-recipient mode flags
- current lifecycle state

The ConditionEngine state machine is:

1. `Registered`: commit exists but no reveal or shred authorization has fired.
2. `RevealConditionMet`: reveal condition evaluated true and `RevealAuthorized` emitted.
3. `RevealChallengeOpen`: non-zero reveal challenge window active.
4. `PostChallengeRevealInProgress`: challenge window closed or zero-window path reached; gates may sign.
5. `RevealCompleted`: delivery side reports completion digest, if PDA tracks completion.
6. `ShredConditionMet`: shred condition evaluated true and `ShredAuthorized` emitted.
7. `ShredChallengeOpen`: non-zero shred challenge window active.
8. `Shredded`: permanent shred finalized.
9. `Paused`: overlay state that blocks advancement but does not erase base state.

`RevealAuthorized` opens an authorization; it does not decrypt. Gates sign only after finality plus challenge discipline. That distinction is central to the shred guardrail.

### §4.2 Mode F vs Mode P

**Mode F** uses FSMInterpreter through ConditionEngine. External actors call the ConditionEngine dispatcher. ConditionEngine re-reads pause, shred, challenge, registry, legal, and refusal preconditions, then calls FSMInterpreter as the only state-changing caller. FSMInterpreter receives the original actor explicitly, verifies submitter authorization, FSM hash, transition guard, attestation gate result, gas budget, and terminal state, and returns a result. When a terminal firing state is reached, ConditionEngine emits `RevealAuthorized` or `ShredAuthorized` in the same transaction.

**Mode P** evaluates a stateless Claim expression at ceremony attempt time. `evaluatePredicate(authorizationId, axis, contextRef)` calls the DSL interpreter and required module readers. If true, ConditionEngine emits the ceremony event directly.

Both modes share pause, challenge, registry, and shred checks. A module cannot bypass ConditionEngine emission.

### §4.3 PaymentObligationModule

**Trigger condition.** Payment obligation default, non-payment after grace period, cure-window expiry, or partner contract state declaring default.

**On-chain state.** `obligationId`, debtor/subject commitment ref, partner contract ref, principal/amount digest, due timestamp, cure window, status enum, trust tier, default evidence digest, oracle refs if not chain-native.

**Advance functions.**

- `registerObligation(authorizationId, obligationRef, configDigest)` by orchestrator/configurator.
- `markPaymentObserved(obligationRef, paymentDigest)` from chain-native contract or authorized oracle.
- `markDefaultObserved(obligationRef, defaultDigest)` from chain-native contract or authorized oracle.
- `advancePaymentObligation(authorizationId, evidenceRef)` called by ConditionEngine or authorized relayer.

**Terminal semantics.** Fires when default is observed and any configured cure/challenge precondition has elapsed. It must re-read obligation active/default state at fire time, not rely on an earlier snapshot.

### §4.4 TimeLockModule

**Trigger condition.** Current block timestamp or registered time-oracle timestamp reaches target.

**On-chain state.** `targetTimestamp`, optional `notBefore`, optional `notAfter`, clock source enum, grace policy, trust tier.

**Advance functions.**

- `configureTimeLock(authorizationId, configDigest, targetTimestamp, clockSource)`.
- `evaluateTimeLock(authorizationId)` view.
- `advanceTimeLock(authorizationId)` state-changing path for Mode F.

**Terminal semantics.** Fires when timestamp condition is true. Chain-native block timestamp is Tier A when no off-chain clock is referenced. Time-oracle mode is Tier B/C and inherits challenge-window guardrails.

### §4.5 SubjectInitiatedModule

**Trigger condition.** Subject initiates reveal or shred through an authenticated action bound to `authorizationId`, `hCommit`, axis, nonce, and expiration.

**On-chain state.** subject commitment ref, authenticator class, replay nonce bitmap or monotonically increasing nonce, optional allowed recipient/axis constraints.

**Advance functions.**

- `submitSubjectInitiated(authorizationId, axis, digest, signatureEnvelopeRef)`.
- `consumeSubjectNonce(authorizationId, nonce)`.

**Terminal semantics.** Fires when the subject action verifies and has not expired or been replayed. For WebAuthn-heavy paths, on-chain may verify a digest attestation/ref while full WebAuthn verification remains off-chain; the PDA must commit which path is active.

### §4.6 HeartbeatMissedModule

**Trigger condition.** Required actor fails to refresh heartbeat before deadline plus grace period.

**On-chain state.** heartbeat actor, last heartbeat timestamp/block, interval, grace period, escalation policy, optional relayer set.

**Advance functions.**

- `recordHeartbeat(authorizationId, heartbeatDigest, signatureEnvelopeRef)`.
- `advanceHeartbeatMissed(authorizationId)`.

**Terminal semantics.** Fires when `block.timestamp > lastHeartbeat + interval + grace`. Heartbeat submission after terminal fire is ignored unless the PDA explicitly defines a re-lock window before terminal state.

### §4.7 OracleAttestationModule

**Trigger condition.** Registered oracle signs an attestation whose schema and Claim evaluation satisfy the PDA condition.

**On-chain state.** oracle refs root, schema refs, accepted attestation digest, Claim AST root, trust tier, attestation freshness window.

**Advance functions.**

- `submitOracleAttestation(authorizationId, oracleId, schemaId, attestationDigest, signature, proofRefs)`.
- `advanceOracleAttestation(authorizationId, attestationDigest)`.

**Terminal semantics.** Fires only if OracleRegistry entry was effective at commit/authorization block, not tombstoned, not deprecated before authorization, `OracleSchemaRegistry.getSchemaAt(schemaId, authorizationBlock)` returns the schema bound by the oracle entry, signature verifies, and Claim DSL evaluates true.

### §4.8 MultiPartySignalModule

**Trigger condition.** k-of-n configured parties submit signatures or oracle attestations for the same signal digest.

**On-chain state.** signer set root, threshold, collected signer bitmap or Merkle leaf set, signal digest, replay nonce, expiration.

**Advance functions.**

- `submitSignal(authorizationId, signer, signalDigest, signatureEnvelopeRef, proof)`.
- `advanceMultiPartySignal(authorizationId, signalDigest)`.

**Terminal semantics.** Fires when threshold is met by distinct eligible signers before expiration. Duplicate signatures do not increment threshold. Signer eligibility is read from commit-bound root.

### §4.9 DeadManSwitchModule

**Trigger condition.** A heartbeat or re-lock cadence is missed and optional beneficiary/recipient constraints are satisfied.

**On-chain state.** heartbeat config, beneficiary/recipient policy digest, grace window, optional subject liveness oracle refs, optional notification delay.

**Advance functions.**

- `recordDeadManHeartbeat(authorizationId, heartbeatDigest, signatureEnvelopeRef)`.
- `advanceDeadManSwitch(authorizationId)`.

**Terminal semantics.** Fires after missed heartbeat plus grace. If configured with conditional recipients, it must verify the PDA requires their later σ_conditional cooperation off-chain; the module itself does not collect σ_conditional.

### §4.10 ConsentGateModule

**Trigger condition.** A named authority co-signs release or shred under a PDA-bound domain.

**On-chain state.** authority set root, threshold, consent digest, nonce/expiration, role type, trust tier.

**Advance functions.**

- `submitConsent(authorizationId, authority, consentDigest, signatureEnvelopeRef, proof)`.
- `advanceConsentGate(authorizationId, consentDigest)`.

**Terminal semantics.** Fires when required authority or threshold consents verify. Consent is halt-or-allow; it cannot modify reveal content.

### §4.11 ComposedModule

**Trigger condition.** Boolean composition of child module results.

**On-chain state.** child module refs, operator tree, max depth, max child count, cached child result refs where Mode F requires persistence.

**Advance functions.**

- `configureComposed(authorizationId, compositionRoot)`.
- `advanceComposed(authorizationId, childEvidenceRefs)`.
- `evaluateComposed(authorizationId)` view.

**Terminal semantics.** Fires when the deterministic boolean tree evaluates true. Child modules cannot have side effects during a view evaluation. State-changing child advances must happen before `advanceComposed`.

### §4.11.5 PresentedTokenConditionModule (controlled-use; commit_version = 0x0303 only)

PresentedTokenConditionModule is the tenth ConditionEngine module, added by the controlled-use access sessions configuration profile per S2-8 §6. The module is the chain-verifiable predicate "valid policy-scoped access token presented by a holder," consuming on-chain credential anchor state (§9.16A CredentialAnchorRegistry) plus revocation state (§9.16C MasterTokenRevocationRegistry and the opt-in §9.16D TokenRevocationRegistry where elected), and emitting `RevealAuthorized` (for read operations) or `WriteAuthorized` (for write operations) on PASS. The module is active only when a PDA elects the controlled-use profile (`token_policy_config.enabled = true`, `commit_version = 0x0303`). PDAs running NE / TP / CR without controlled-use never invoke this module. Naming discipline: the synthesis predecessor used "TokenPresented"; S2-8 §0.3 renames to "PresentedTokenCondition" to align with the §4.3-§4.11 condition-module naming convention and to avoid OAuth/OIDC "token presentation" overload.

**Trigger condition.** A holder presents a credential (master or sub-token) bound to a specific operation tuple (slice, op_kind, optional content_ref) under σ_holder over the canonical presentation digest defined in S2-1 §10.11 + S2-8 §2.8. The module verifies anchor presence, revocation absence, σ_holder validity, scope conformance, token-class permission, and TTL, and on PASS emits the appropriate authorization event.

**On-chain state.** A reference to the PDA's `token_policy_config` (slice layout anchor, schema bindings, write/read authority matrices, holder-binding key resolution), plus cached per-(authorizationId) evaluation results where Mode F requires persistence. The module does not duplicate registry state; it reads from CredentialAnchorRegistry, MasterTokenRevocationRegistry, SliceLayoutRegistry, and the opt-in TokenRevocationRegistry at evaluation time.

**Module ABI (sketch — full Solidity authoring deferred to BP-CU-1).**

```solidity
interface IPresentedTokenConditionModule is IConditionModule {
    function evaluate(
        bytes32 authorizationId,
        bytes32 credentialDigest,
        bytes32 subTokenDigest,            // bytes32(0) if presentation is of the master credential
        bytes32 sliceId,
        uint8 opKind,                      // READ=0x01, WRITE=0x02, COMPOSED_READ=0x03, COMPOSED_WRITE=0x04
        bytes calldata sigmaHolder,        // σ_holder over canonical presentation digest per S2-1 §10.11 + S2-8 §2.8
        bytes32 presentationDigest         // canonical presentation digest
    ) external returns (bool passes);

    function isFirstPresentation(bytes32 credentialDigest) external view returns (bool);
}
```

**Evaluation sequence (per S2-8 §6.1 ten-step normative flow; this module enforces steps 1-5; the 4-gate AND substrate covers steps 6+).**

1. **Anchor presence check.** SLOAD `CredentialAnchorRegistry[credentialDigest]`. If this is a first-presentation, proceed to step 2 (revocation check is enforced BEFORE σ verification AND BEFORE anchor SSTORE per the A22 transaction-atomic discipline at S2-8 §2.6); anchor SSTORE happens at step 4. If this is a subsequent presentation and the anchor is absent, REVERT with `AnchorNotFound`.
2. **Revocation check (BEFORE σ verification AND BEFORE anchor SSTORE per A22).** For master credentials: SLOAD `MasterTokenRevocationRegistry[credentialDigest]`; if `revokedAt != 0`, REVERT with `RevokedMaster`. For sub-tokens: SLOAD `MasterTokenRevocationRegistry[masterCredentialDigest]`; if revoked, REVERT. Additionally, if the PDA elects `revocation_mode = MASTER_AND_SUB_CRL`, SLOAD `TokenRevocationRegistry[subTokenDigest]`; if revoked, REVERT with `RevokedSubToken`.
3. **σ_holder verification.** Verify `sigmaHolder` against the holder-binding pubkey resolved from the credential's anchor entry for subsequent presentations, or from the in-tx-presented pubkey for first-presentations (the first-presentation pubkey is recorded into the anchor at step 4). Failure: REVERT with `InvalidHolderSignature`. First-presentations that do not carry an in-tx pubkey REVERT with `FirstPresentationRequiresInTxPubkey`.
4. **Anchor SSTORE (first-presentation only).** SSTORE `CredentialAnchorRegistry[credentialDigest] = (block.number, block.timestamp, holderBindingPubkeyRef)` via `CredentialAnchorRegistry.writeAnchor(...)`. Skipped for subsequent presentations.
5. **Composition + scope + class + TTL checks.** Scope conformance (for sub-tokens, sub.scope ⊆ master.scope; scope covers `sliceId`); token-class in the slice's `write_authority_matrix` for `opKind ∈ {WRITE, COMPOSED_WRITE}` or `read_authority_matrix` for `opKind ∈ {READ, COMPOSED_READ}`; TTL not expired (for sub-tokens); composition with other condition modules per the H-6 matrix below.

On all five passing, the module returns `true`; the ConditionEngine emits `RevealAuthorized` (for read axes) or `WriteAuthorized` (for write axes). The 4-gate AND substrate's σ ensemble collection continues per S2-3 §3, with σ_G4 attesting at the audit-signing scope for reads (per S2-8 §4.5) and at the write-validation scope for writes (per S2-8 §4.1). PresentedTokenCondition is an ADDITIONAL gate condition on top of the 4-gate AND substrate, not a substitute; the controlled-use reveal/write flow still requires σ_Lit + σ_G3 + σ_G4 + PresentedTokenCondition PASS. This is the σ-as-authorization-doctrine-consistent path.

**Composition-compatibility matrix (H-6; normative).**

| Other module | Composition status | Binding rule |
|---|---|---|
| PaymentObligationModule (§4.3) | composes-cleanly | `block.timestamp` snapshot at PresentedTokenCondition evaluation start |
| TimeLockModule (§4.4) | composes-cleanly | same as PaymentObligationModule |
| SubjectInitiatedModule (§4.5) | composes-cleanly | σ_subject required alongside σ_holder |
| HeartbeatMissedModule (§4.6) | requires-additional-binding | `block.timestamp` AND `HeartbeatMissed.lastBeat` locked at PresentedTokenCondition evaluation start; subsequent beats in the same tx do not retroactively validate |
| OracleAttestationModule (§4.7) | requires-additional-binding | oracle reading consumed at evaluation start; mid-tx oracle update ignored |
| MultiPartySignalModule (§4.8) | composes-cleanly | all required signals captured at evaluation start |
| DeadManSwitchModule (§4.9) | **FORBIDDEN** | PresentedTokenCondition requires σ_holder (proof of life); DeadManSwitch fires on holder absence (proof of death). Logically self-canceling per internal design ledger entry A24 (not in this export). The PDA configurator MUST reject any PDA whose declared composition includes both `DeadManSwitchModule` and `PresentedTokenConditionModule` at S2-4 §6 PDA+ governance validation time. For "trustee acts on behalf of incapacitated subject" use cases, use `SubjectInitiatedModule(trusteePasskey) + ConsentGateModule` instead. |
| ConsentGateModule (§4.10) | composes-cleanly | consent token snapshotted at evaluation start; revocation mid-tx aborts pending writes but does not unread completed reads (per S2-8 §H-7 time-of-check / time-of-use boundary) |
| ComposedModule (§4.11) | composes-cleanly (recursive) | tree-walk evaluation; one PresentedTokenCondition per leaf; cross-slice atomic operations use Composed with multiple sub-tokens per S2-8 §3.2 |

The composition matrix is enforced at PDA validation time by the configurator (S2-4) AND at evaluation time by ConditionEngine. PDA-side enforcement is the primary check; on-chain ComposedModule evaluation is the defense-in-depth check.

**Advance functions.**

- `configurePresentedTokenCondition(authorizationId, tokenPolicyConfigRef)`.
- `advancePresentedTokenCondition(authorizationId, presentationEvidenceRef)`.
- `evaluatePresentedTokenCondition(authorizationId)` view.

**Terminal semantics.** Fires when all five evaluation-sequence checks return PASS. The module is permissionless from the caller perspective (any address may submit a presentation) but bound to σ_holder + anchor + revocation state; coerced or invalid presentations fail at step 2 / step 3.

**Errors and reverts** (cross-ref §15 access control + the new custom errors in App. A):
- `AnchorNotFound(bytes32 credentialDigest)`
- `RevokedMaster(bytes32 credentialDigest, uint256 revokedAt)`
- `RevokedSubToken(bytes32 subTokenDigest, uint256 revokedAt)`
- `InvalidHolderSignature(bytes32 presentationDigest)`
- `ScopeOutOfToken(bytes32 sliceId, bytes32 tokenScope)`
- `TokenClassNotPermitted(uint8 tokenClass, uint8 opKind)`
- `TtlExpired(uint256 ttlExpiry, uint256 currentTime)`
- `ForbiddenCompositionDeadManSwitch()`
- `FirstPresentationRequiresInTxPubkey()`

**Composition axis.** PresentedTokenCondition is selectable on both reveal and shred axes under controlled-use, but axis separation (§4.15) still applies: separate config refs, separate eligible challenger roots, separate challenge windows, separate terminal states. The module's evaluation semantics are axis-agnostic; the emitted event differs (`RevealAuthorized` for reveal axis, `WriteAuthorized` for write axis, with the shred axis using the existing `ShredAuthorized` if the PDA composes controlled-use × shred-with-presentation).

**Module registration.** Registered via `MODULE_ADMIN_ROLE` under TimelockController; deployment is at the `commit_version = 0x0303` rollout per S2-1 §2.8.6. Non-controlled-use PDAs MUST NOT reference this module (PDA validation rejects the reference); controlled-use PDAs MUST reference this module exactly once in their reveal-axis condition tree.

**PII statement.** PresentedTokenCondition processes `credentialDigest` (32-byte one-way digest, pseudonymous under Breyer C-582/14 when correlated with off-chain issuance records held by the partner) and `subTokenDigest` (same class). The module itself never touches plaintext content; the σ_holder signature binds the holder's holder-binding key (passkey public key, hardware-token public key, EOA address, or app-session identifier) to the operation tuple, and the canonical presentation digest is one-way over `TAG_CU_CREDENTIAL_V3` plus per-presentation block + nonce material. Cross-ref §10.2 controllership analysis and S2-8 §10 layered controllership.

### §4.12 Challenge-window integration

Condition modules only determine whether a ceremony may be authorized. ChallengeRegistry determines whether gate signing may proceed after authorization. For zero-window Tier A conditions, ConditionEngine enters `PostChallengeRevealInProgress` in the same transaction as `RevealAuthorized`. For non-zero Tier B/C conditions, it opens a challenge window. Gate clients must wait until `canGatesSign(authorizationId) == true`.

### §4.13 Per-module invariants

Each module has local invariants in addition to global ConditionEngine invariants.

**PaymentObligationModule invariants.**

- A default cannot be marked while obligation status is inactive, cancelled, or already cured.
- A cure after default but before cure deadline must clear terminal default state unless the PDA explicitly configured "default irreversible after observation".
- Payment and default evidence refs must bind to the same obligation id.
- A chain-native partner contract read must be re-read at fire time.
- Oracle-attested default inherits Tier B/C challenge-window requirements.

**TimeLockModule invariants.**

- A target timestamp of zero is invalid unless the template explicitly uses zero as "already elapsed" in a test fixture; production PDAs reject it.
- `notAfter` must be zero or greater than `targetTimestamp`.
- A chain-native timestamp path must not call a time oracle.
- A time-oracle path must bind the oracle id in `oracle_references_root`.

**SubjectInitiatedModule invariants.**

- Nonces are consumed once.
- Signature domain includes axis, so reveal consent cannot replay as shred consent.
- Subject action expires if the PDA configured an expiry.
- SubjectInitiated cannot fire after final shred.

**HeartbeatMissedModule invariants.**

- Heartbeat interval and grace period are non-zero unless a template explicitly marks the module disabled.
- A heartbeat after terminal fire cannot un-fire the condition.
- Heartbeat signer must match the PDA-bound actor.
- Rolling deadlines update monotonically.

**OracleAttestationModule invariants.**

- Oracle id must be in the commit-bound oracle root.
- Schema id must match OracleRegistry entry.
- Attestation digest must be fresh under PDA freshness window.
- Claim AST must evaluate under the DSL version bound in pda_root.
- Attestation plaintext is never stored.

**MultiPartySignalModule invariants.**

- Signer identities are distinct.
- Threshold cannot exceed signer count.
- Signatures bind the same signal digest.
- A signer removed in a future registry rotation remains valid for historical commitments only if present in the commit-bound signer set.

**DeadManSwitchModule invariants.**

- DeadManSwitch cannot fire before heartbeat grace elapses.
- If beneficiary/recipient policy requires conditional recipients, the module may authorize only the chain gate; recipient σ_conditional remains required off-chain.
- Notification delays cannot exceed the PDA retention window.

**ConsentGateModule invariants.**

- Consent signer must be eligible for the configured role.
- Consent digest binds `authorizationId`, `hCommit`, axis, nonce, and expiration.
- Consent cannot modify recipients or schema selectors.

**ComposedModule invariants.**

- Child modules are evaluated against the same `authorizationId`.
- NOT nodes have one child only.
- AND/OR nodes have at least two children unless generated by a degenerate template explicitly allowed by PDA+.
- Recursion depth and child count caps are enforced before evaluation.

### §4.14 Module events

Each module emits module-specific events in addition to `ModuleAdvanced`. Event payloads carry digest refs only:

- `PaymentDefaultObserved(authorizationId, obligationRef, evidenceDigest)`
- `TimeLockReached(authorizationId, targetTimestamp, clockSource)`
- `SubjectActionAccepted(authorizationId, axis, actionDigest, nonce)`
- `HeartbeatRecorded(authorizationId, actorRef, nextDeadline)`
- `HeartbeatMissed(authorizationId, actorRef, missedAt)`
- `OracleConditionAccepted(authorizationId, oracleId, schemaId, attestationDigest)`
- `MultiPartySignalThresholdMet(authorizationId, signalDigest, count, threshold)`
- `DeadManSwitchTriggered(authorizationId, missedHeartbeatRef)`
- `ConsentAccepted(authorizationId, authorityRef, consentDigest)`
- `ComposedConditionMet(authorizationId, compositionRoot)`

No module event carries oracle attestation plaintext, subject plaintext, σ values, or decoded PDA content.

### §4.15 Axis separation

Reveal and shred axes may use the same module type but must use separate config refs, separate eligible challenger roots, separate challenge windows, and separate terminal states. A module may share read-only facts across axes, but it cannot let a reveal-axis terminal state imply shred-axis terminal state or the reverse. This prevents "condition aliasing" where a broad shred predicate accidentally authorizes reveal.

### §4.16 Module registration governance

New module implementations are added through TimelockController under `MODULE_ADMIN_ROLE`. Registration records:

- module address.
- module type id.
- supported axes.
- max gas estimate.
- DSL/operator dependencies.
- trust-tier classifications.
- source commit digest.
- audit digest.
- effective block.
- tombstone block.

Tombstoning a module prevents new PDA configs from using it. Existing PDAs keep historical semantics unless the module is deprecated before authorization under the DeprecationFlag emergency path. A module implementation upgrade that changes evaluation semantics requires a new module id; it cannot silently replace the old id.

Controlled-use deployments register one additional module via `MODULE_ADMIN_ROLE` under TimelockController at the `commit_version = 0x0303` rollout boundary (per S2-1 §2.8.6): `PresentedTokenConditionModule` (§4.11.5). The module is module-axis-eligible at both the `RevealAuthorized` axis and the `WriteAuthorized` axis. PDAs declaring controlled-use (`token_policy_config.enabled = true`) MUST include this module in their reveal-axis (and, where applicable, write-axis) composition; non-controlled-use PDAs MUST NOT include this module. Registration metadata for `PresentedTokenConditionModule` records the same fields as the nine pre-existing modules (address, type id, supported axes, max gas estimate, DSL/operator dependencies, trust-tier classifications, source commit digest, audit digest, effective block, tombstone block), with the added invariant that `effective block` is at or after the `commit_version = 0x0303` rollout block declared in S2-1 §2.8.6.

## §5 - AttestationGate and On-Chain Binding Verification

### §5.1 Scope

AttestationGate is the on-chain condition-attestation verifier. It checks oracle signatures, schema refs, typed payload digests, freshness, and Claim DSL results. It also exposes view helpers for gate-binding metadata consumed by G4 and the combiner. It does not verify or publish custody σ values.

### §5.2 Oracle attestation verification

`verifyOracleAttestation` accepts:

- `authorizationId`
- `oracleId`
- `schemaId`
- `attestationDigest`
- oracle signature bytes
- optional Merkle proof proving `oracleId` is in the PDA `oracle_references_root`

It verifies OracleRegistry entry, `OracleSchemaRegistry.getSchemaAt(schemaId, authorizationBlock)`, signature, freshness, and Claim DSL evaluation over digest-bound typed fields. The oracle entry's `schemaId` must match the schema supplied to AttestationGate at that historical block. On success it returns a boolean and may store `attestationDigest` as consumed evidence for Mode F.

### §5.3 Custody gate binding metadata

For G2/G3/G4/conditional recipient verification, on-chain contracts expose these binding sources:

- `RevealAuthorized` event and finalized block hash for G1.
- LitV3Assignment record for G2 assignment identity.
- G3 choice and authority/committee ref bound in PDA/commit metadata.
- G4AuthorityRegistry entry and G4RefusalRegistry state for G4.
- PasskeyRotationLog and conditional recipient mode validation for Mode 1/2 recipient cooperation.

All actual σ verification remains off-chain in S2-1 §14 combiner and S2-3 custody integration libraries.

### §5.4 Phase 1 and Phase 2 G4 paths

G4AuthorityRegistry stores both:

- Phase 1: authority pubkey, binary hash, effective block, tombstone block, deprecation flag.
- Phase 2: authority pubkey or TEE measurement ref, DCAP verifier ref, effective block, tombstone block, deprecation flag.

AttestationGate and G4AuthorityRegistry view functions must let clients query the entry that was valid at an authorization block. Phase 1 entries cannot be used for legal-effect partner PDAs, but they remain queryable for historical commits.

### §5.5 Fail-closed paths

AttestationGate reverts on unknown oracle, schema mismatch, invalid signature, stale attestation, registry entry not effective, tombstoned entry, deprecation before authorization, malformed Claim AST, unsupported DSL version, unsupported WASM predicate, and gas-budget exhaustion. It returns false only in view functions explicitly named `tryEvaluate...`.

### §5.6 On-chain/off-chain boundary matrix

| Evidence type | On-chain handling | Off-chain handling | Reason |
|---|---|---|---|
| Oracle signature over condition attestation | may be calldata and verified | stored in artifact bundle | condition evidence, not custody key material |
| Oracle attestation plaintext | no plaintext storage; digest only | held in artifact bundle / oracle records | avoids on-chain PII and unbounded parsing |
| Lit V3 σ_Lit | never calldata/storage/event | combiner verifies as authorization before admitting Lit's wrapped Shamir share | σ-as-authorization |
| G3 σ_G3 | never calldata/storage/event | combiner verifies as authorization before admitting G3's wrapped Shamir share | σ-as-authorization |
| G4 σ_G4 | never calldata/storage/event | combiner verifies as authorization before admitting G4's wrapped Shamir share | σ-as-authorization |
| σ_conditional | never calldata/storage/event | recipient plugin produces; combiner verifies before admitting the conditional-recipient share | σ-as-authorization and recipient privacy |
| DCAP quote bytes | only verifier refs/digests unless dedicated verifier adapter requires calldata | S2-3 verifies full quote | quote size and SDK dependency |
| G4 refusal reason | public code or encrypted blob | sensitive details decrypted by authorized recipients | Art. 17/18 minimization |
| proof_shred | stored/emitted | auditor reads | public lifecycle proof, not key material |

The practical rule is: condition evidence can be on-chain when bounded and non-PII; custody signatures and Shamir shares never are. This allows ConditionEngine to remain auditable without turning the chain into a decryption substrate.

### §5.7 `tryEvaluate` naming discipline

View functions that return `(bool ok, bytes32 reasonRef)` rather than reverting must be named `tryEvaluate...` or `preview...`. State-changing functions must revert on failure. This prevents callers from accidentally treating a false return from a state-changing path as a successful no-op. Auditor expectation: every state transition function either changes state and emits the expected event or reverts with a custom error.

### §5.8 G4-readable views

G4 needs deterministic read surfaces before signing or refusing. S2-2 contracts must expose:

- `ConditionEngine.canGatesSign(authorizationId)`.
- `ConditionEngine.lifecycleState(authorizationId)`.
- `ConditionEngine.postChallengeRevealInProgress(authorizationId)`.
- `ShredRegistry.isShredded(hCommit)`.
- `ShredRegistry.currentShredState(hCommit)`.
- `G4RefusalRegistry.refusalState(authorizationId)`.
- per-registry `getEntryAt(ref, authorizationBlock)`.
- `LitV3Assignment.getAssignment(authorizationId)`.
- `GateRecipientPubkeyRegistry.getPubkeyAt(authorizationId, gateKind, authorizationBlock)`.

None of these views can have caller-dependent behavior. The same chain state read by G4, recipient combiner, partner API, and auditor must produce the same result.

## §6 - FSMInterpreter

### §6.1 Storage target

FSMInterpreter stores a compact per-authorization state target near 64 bytes for hot-path fields:

```solidity
struct FSMState {
    uint32 currentState;
    uint32 terminalState;
    uint64 lastAdvancedAt;
    uint64 deadline;
    bytes32 fsmHash;
    bytes32 cursorData;
}
```

This is 112 bytes in raw Solidity layout before packing decisions. Stage 3 may split hot fields and cold fields to hit the ~64-byte target for hot storage while preserving the external struct semantics. Concretely, the hot-vs-cold split is: hot = `currentState (uint32) + terminalState (uint32) + lastAdvancedAt (uint64) + deadline (uint64)` = 24 bytes (single SLOAD on advance); cold = `fsmHash (bytes32) + cursorData (bytes32)` = 64 bytes (two additional SLOADs only when needed). The ~64-byte target from the internal stage-2 audit refers to the hot path, not the full struct; total raw is 112 bytes and that is acceptable as long as the hot-path SLOAD count is bounded.

### §6.2 `advanceFSM`

Canonical external dispatcher on ConditionEngine:

```solidity
function advanceFSM(
    bytes32 authorizationId,
    CeremonyAxis axis,
    bytes32 transitionId,
    bytes32 attestationDigest,
    bytes calldata transitionProof
) external returns (FSMAdvanceResult memory result);
```

`transitionProof` must not contain plaintext PII. It contains Merkle proofs, oracle signatures, digest refs, and bounded metadata. Large typed payloads remain off-chain; the contract verifies their digest and schema.

FSMInterpreter exposes the same transition shape only to ConditionEngine, with one additional `actor` argument supplied by ConditionEngine from the original external caller. FSMInterpreter must not infer submitter authorization from `msg.sender`, because `msg.sender` is always ConditionEngine under the conforming pattern.

### §6.3 Semantics

ConditionEngine `advanceFSM`:

1. Loads PDA axis config.
2. Verifies `fsmHash` equals the hash committed in `pda_root`.
3. Verifies submitter is allowed for this transition.
4. Verifies transition is valid from `currentState`.
5. Calls FSMInterpreter, which calls AttestationGate/DSL/module verifier under ConditionEngine control.
6. FSMInterpreter updates `currentState` and `cursorData`.
7. FSMInterpreter emits `FSMAdvanced`.
8. If terminal firing state is reached, ConditionEngine updates lifecycle state and emits `RevealAuthorized` or `ShredAuthorized`.

The transition and terminal check happen in one transaction, so no external caller can observe terminal state and front-run an alternate emitter. FSMInterpreter never calls back into ConditionEngine; that avoids an external callback path and preserves the universal tripwire that only ConditionEngine can cause authorization events.

### §6.4 Bounded gas

Each FSM declares:

- max transitions per authorization
- max proof bytes
- max Claim AST nodes per transition
- max submitter proof depth
- max child module calls

If a transition exceeds budget, it reverts with `FSMGasBudgetExceeded`. The PDA configurator must dry-run all template FSMs under these bounds before deployment.

## §7 - Claim DSL v1

### §7.1 Operator set

Claim DSL v1 supports exactly 12 live operators:

| Operator | Type | Semantics |
|---|---|---|
| `==` | comparison | typed equality |
| `!=` | comparison | typed inequality |
| `<` | comparison | numeric or timestamp less-than |
| `<=` | comparison | numeric or timestamp less-than-or-equal |
| `>` | comparison | numeric or timestamp greater-than |
| `>=` | comparison | numeric or timestamp greater-than-or-equal |
| `AND` | boolean | all children true, short-circuit |
| `OR` | boolean | at least one child true, short-circuit |
| `NOT` | boolean | unary negation |
| `IN` | set | typed member in bounded set |
| `path_access` | accessor | schema-checked path read from attestation digest context |
| `within_time_window` | time | timestamp inside `[start, end]` or relative window |

### §7.2 Reserved custom predicate

`custom_predicate(wasm_hash, input_binding)` is a reserved operator. At V2 launch, on-chain DSL evaluation rejects execution unless the WASM hash is registered, audited, and enabled through DSLVersionRegistry and the operational ceremony defined in S2-6. The AST representation exists now so PDA roots can bind future-compatible specs without changing the AST envelope; using it in an active V2 PDA before enablement reverts.

### §7.3 AST format

The Solidity interpreter consumes a canonical node array:

```solidity
struct ClaimNode {
    uint8 op;
    uint16 left;
    uint16 right;
    bytes32 valueRef;
    uint32 aux;
}
```

`left` and `right` are child indexes for boolean/comparison nodes. `valueRef` points to schema-bound field refs, constants, or set roots. `aux` carries small scalar metadata such as type tag or time-window mode. Variable data is stored off-chain and referenced by digest or registry key.

### §7.4 Determinism and type checking

Every node is type-checked against OracleSchemaRegistry before activation. Runtime evaluation must be deterministic across clients and nodes. No locale-sensitive string comparison, floating point, unbounded regex, dynamic external calls, or wall-clock reads outside the declared timestamp source.

### §7.5 Bounded evaluation

DSLVersionRegistry entry declares global caps:

- `maxNodes`
- `maxDepth`
- `maxInSetSize`
- `maxPathDepth`
- `maxEvaluationGas`
- `customPredicateEnabled`

The interpreter rejects ASTs that exceed caps at registration and re-checks caps at evaluation.

### §7.6 Operator semantics detail

`==` and `!=` operate only on identical static types. Bytes32-to-uint comparison is invalid even if both are 32-byte ABI words. Address equality is allowed only where schema marks a field as address. String equality is not a live V2 operator; string-like values must be normalized off-chain and represented by digest or enum.

`<`, `<=`, `>`, and `>=` operate on unsigned integer, signed integer if explicitly schema-tagged, timestamp, and fixed-point decimal values represented as scaled integers. Floating point is forbidden. Decimal scale must be part of schema metadata and cannot be supplied by calldata.

`AND` and `OR` short-circuit left-to-right over child indexes as stored in the AST. Short-circuiting must not skip required side-effectful calls because DSL evaluation is side-effect free. Implementers may reorder for gas only if they prove equivalence and preserve deterministic error behavior; default is no reordering.

`NOT` applies to exactly one child. Double negation is allowed but configurator may simplify it before registration. The on-chain interpreter need not optimize.

`IN` checks membership in a bounded set root or inline bounded set. Inline sets are capped by DSLVersionRegistry. Large sets must be Merkle-rooted and proved through `valueRef`; the proof is part of bounded evaluation context.

`path_access` reads a typed field from a schema-bound attestation context. Paths are not strings at runtime; they are precompiled path ids from OracleSchemaRegistry. Unknown paths fail at registration, not at reveal.

`within_time_window` accepts a timestamp value and a window descriptor. The descriptor may be absolute (`start`, `end`) or relative to an authorization block timestamp if the PDA declares that source. It cannot read wall-clock time from off-chain systems.

`custom_predicate` is a reserved AST node with two fields: `wasm_hash` and `input_binding`. At V2 launch it is valid to store in a future-disabled template only if PDA+ marks the template inactive. Active PDAs reject it until the registry says enabled.

### §7.7 DSL version lifecycle

DSLVersionRegistry entries are immutable. A new interpreter or cap set creates a new `dsl_version_ref`. Existing PDAs continue to bind the old ref. If a DSL version is deprecated before authorization, G4 refuses and ConditionEngine blocks where registry checks are on-chain. If deprecated after `RevealAuthorized`, in-flight semantics follow §9.4.

### §7.8 Claim AST registration gate

Before a Claim AST can be bound to a PDA, the configurator or registration helper must verify:

- AST root has exactly one root node.
- every node is reachable from root.
- no cycles exist.
- all child indexes are in range.
- operator arity matches operator.
- schema path ids exist.
- constants match expected type.
- `IN` sets are sorted and deduplicated if inline.
- estimated gas is below PDA max.
- WASM predicate nodes are disabled or registry-enabled according to launch state.

The on-chain registration helper may verify a compact proof that this gate ran, or it may rerun the full validation for smaller ASTs. Either implementation must make the result auditable.

## §8 - Oracle Onboarding and Rotation

### §8.1 OracleRegistry entry

An oracle entry contains:

- `oracleId`
- `oraclePubkeyOrAddress`
- `oracleType`
- `schemaId`
- `canonicalExamplesHash`
- `metadataHash`
- `effectiveBlock`
- `tombstoneBlock`
- `DeprecationFlag`
- `isCanonical`

Oracle IDs use the BP-14 accepted form from S2-1: `oracle_id = keccak256(TAG_ORACLE_REGISTRY_V3 ‖ oracle_pubkey_or_addr)`. Registry entries still store the concrete oracle pubkey/address and schema metadata needed for auditing.

### §8.2 OracleSchemaRegistry entry

A schema entry contains:

- `schemaId`
- `schemaHash`
- `validExamplesHash`
- `invalidExamplesHash`
- `schemaVersion`
- `metadataHash`
- `effectiveBlock`
- `tombstoneBlock`

Claim ASTs must be replay-tested against canonical examples before activation. On-chain stores the hashes; off-chain configurator runs the full replay.

### §8.3 Onboarding

Oracle onboarding is a 7-day timelocked addition. The queued operation includes oracle entry, schema entry, examples hash, metadata hash, trust tier, and intended PDA template classes. When executed, the registry emits `OracleAdded` and `OracleSchemaAdded`. The entry is not effective before `effectiveBlock`.

### §8.4 Rotation and tombstone semantics

Rotation adds a new entry and tombstones the old entry for future commits. Old entries remain historically readable for commitments that referenced them before tombstone. A tombstone before authorization blocks use; a tombstone after authorization does not retroactively break an in-flight ceremony.

### §8.5 Canonical examples

Every oracle schema must publish canonical valid and invalid examples. OracleSchemaRegistry stores their hashes. The configurator and audit tooling use them to verify Claim expressions and LLM-generated conditions. The chain does not store example bodies.

### §8.6 Canonical launch oracle set

Stage-0 locks the day-one registered oracle set to Chainlink Automation for time and SubjectInitiated self-oracle. Contract surfaces must treat these as normal OracleRegistry entries rather than special cases, with two pragmatic exceptions:

1. Chain-native `block.timestamp` TimeLock does not need an oracle signature and can remain Tier A.
2. SubjectInitiated self-oracle may verify the subject action through the subject authenticator path rather than an external oracle pubkey.

The default set is minimal, not closed. Additional oracles land through the same 7-day onboarding path. No module should hardcode "Chainlink only" or "subject only" into the protocol surface.

### §8.7 Oracle type enum

The first OracleRegistry enum values are:

- `0x01 signed_feed`: off-chain signed payload verified by oracle pubkey.
- `0x02 chain_event_emitter`: on-chain contract event or state read verified by contract address.
- `0x03 time_automation`: Chainlink Automation/Gelato/Pyth/Cealis beacon style time trigger.
- `0x04 subject_self`: subject action as oracle input.
- `0x05 court_or_legal_attestation`: court docket, legal hold, or regulator attestation source.
- `0x06 vital_records`: death/birth/medical status source.
- `0x07 partner_contract`: partner-owned contract used for Tier A reads.

New enum values append only. Existing values cannot be repurposed. OracleSchemaRegistry must identify which oracle types a schema supports.

### §8.8 Oracle rotation examples

**Pubkey rotation.** Oracle operator rotates signing key. Timelock queues a new OracleRegistry entry with the same metadata hash and new pubkey. Old entry tombstoned for future commits at `tombstoneBlock`; historical commits read old entry at authorization block.

**Schema rotation.** Oracle changes payload schema. OracleSchemaRegistry adds a new schema id. OracleRegistry entry may point to the new schema for future commitments. Existing commitments keep old schema.

OracleSchemaRegistry is not one of the five Cealis-governed V3 custody/config registries in §9.1, but it must implement the same historical lookup semantics as §9.13. Schema verification reads `getSchemaAt(schemaId, authorizationBlock)` or the commit-block equivalent, never the mutable current schema view. Schema entries carry `effectiveBlock` and `tombstoneBlock`; a schema tombstoned after the queried block remains valid for commitments that bound it before tombstone.

**Operator deprecation.** Security council deprecates an oracle after compromise. Pending and pre-authorization reveals halt. In-flight after `RevealAuthorized` completes under snapshot unless G4 has an independent refusal reason. New ingestion refuses the oracle reference.

**Example mismatch.** If valid/invalid examples fail replay during configurator emission, no on-chain action occurs. This is an S2-4 validation failure, not an OracleRegistry failure.

## §9 - Five V3 Registries: Contract Surface and DeprecationFlag

### §9.1 Common shape

The five V3 registries are PluginHashRegistry, G4AuthorityRegistry, DSLVersionRegistry, OracleRegistry, and QTSPRegistry. All implement:

- `getEntry(bytes32 id)` current view.
- `getEntryAt(bytes32 id, uint64 blockNumber)` historical lookup.
- 7-day timelocked additions.
- tombstone semantics.
- DeprecationFlag with 72h auto-clear.
- 30-day cooldown after auto-clear.
- 24h expedited delay for canonical-in-use deprecation where applicable.

### §9.2 DeprecationFlag

```solidity
struct DeprecationFlag {
    bool deprecated;
    uint64 deprecationBlockTimestamp;
    uint8 deprecationReasonCode;
    bytes32 disclosureCid;
    bytes32 disclosureCommitHash;
    uint64 disclosureVerifiedBlock;
    uint64 autoClearTimestamp;
    bool isCanonicalAtSet;
}
```

Reason codes:

- `0x01`: active exploit
- `0x02`: disclosed but unexploited vulnerability
- `0x03`: compromised operator or authority
- `0x04`: governance retirement

### §9.3 Disclosure and auto-clear

Deprecation call sets `DeprecationFlag` and emits `DeprecationFlagSet`. Within 72h, any account may call `publishDisclosure(entryId, summaryContent)`. The registry verifies `keccak256(summaryContent) == disclosureCommitHash`, stores `disclosureVerifiedBlock`, and emits `DisclosurePublished`. `summaryContent` is capped at 4096 bytes.

If no disclosure lands in 72h, `triggerAutoClear(entryId)` clears the flag and starts a 30-day cooldown. Security multisig cannot re-deprecate the same entry during cooldown; TimelockController can queue a normal re-deprecation under 7-day delay.

### §9.4 Halt-scope table

| Commit state | Deprecation effect |
|---|---|
| Pending/no authorization | Blocks authorization or G4 signing |
| Pre-RevealAuthorized | Blocks |
| In-flight after RevealAuthorized | Completes under snapshot at authorization block |
| Post-all-gates-signed | Completes |
| New ingestion | Refused by 2-phase ingestion precheck |

`cealis_class_wide_halt_opt_out` may ignore class-wide deprecation only where PDA+ permits it. Legal-effect PDAs must set it false.

### §9.5 PluginHashRegistry

Key is `plugin_version_digest` from S2-1 §4.6.1 using `TAG_PLUGIN_VERSION_V3` from S2-1 §2.3.4. Entry stores canonical binary hash, semver digest, source commit digest, effective block, tombstone block, deprecation flag, and canonical flag. Combiner and G4 ingestion precheck read it at authorization/commit block.

### §9.6 G4AuthorityRegistry

Key is `g4_authority_ref` from S2-1 §12.3.1 using `TAG_G4_ATTESTATION_AUTHORITY_V3` from S2-1 §2.3.3. Entry stores phase, authority pubkey hash, binary hash or TEE measurement, DCAP verifier ref, effective block, tombstone block, deprecation flag, and canonical flag. Both Phase 1 and Phase 2 entries can coexist.

### §9.7 DSLVersionRegistry

Key is raw 32-byte `dsl_version_ref` per S2-1 §12.0 class-CATALOG (BP-13 REJECTED 2026-05-04 per `v3-registry-class-discipline.md` (internal design note, not in this export)). The ref is governance-assigned and consumed downstream inside `commit_AAD` under `TAG_AAD_V3` upstream wrap; no per-key TAG-prefix is required because the ref has no preimage role anywhere in V3. Entry stores interpreter contract address, AST version, cap set hash, custom predicate enablement, effective block, tombstone block, deprecation flag, and canonical flag.

### §9.8 OracleRegistry

Key is `oracle_id` per S2-1 §12.5.1 BP-14 LOCKED 2026-05-04 (`v3-registry-class-discipline.md` (internal design note, not in this export) — class-CRYPTO via Merkle-leaf preimage role). Per-leaf preimage form: `oracle_id = keccak256(TAG_ORACLE_REGISTRY_V3 ‖ oracle_pubkey_or_addr)` where `TAG_ORACLE_REGISTRY_V3` is from S2-1 §2.3.4. The `oracle_references_root` Merkle leaves are TAG-prefixed at construction time so cross-tree leaf substitution is foreclosed under S2-1 §2.2 collision resistance. Entry stores oracle pubkey/address, oracle type, schema id, canonical examples hash, trust tier, metadata hash, effective block, tombstone block, deprecation flag, and canonical flag.

### §9.9 QTSPRegistry

Key is raw 32-byte `qtsp_provider_ref` per S2-1 §12.0 class-CATALOG (BP-15 REJECTED 2026-05-04 per `v3-registry-class-discipline.md` (internal design note, not in this export)). The ref is governance-assigned and consumed downstream inside `pda_root` → `commit_AAD` under `TAG_AAD_V3` upstream wrap; eIDAS legal force lives at the entry-payload signed Trust List layer per S2-1 §5.5.3 (Article 22), not at lookup-key derivation. Entry stores QTSP root pubkey hash, jurisdiction, eIDAS status URL hash, metadata hash, effective block, tombstone block, deprecation flag, and canonical flag.

### §9.10 LitV3Assignment

LitV3Assignment is not one of the five Cealis-governed V3 registries. It mirrors Lit governance assignments:

```solidity
struct LitAssignment {
    bytes32 authorizationId;
    bytes32 assignedTeeId;
    uint64 assignmentBlock;
    bytes assignedTeePubkey;
    bytes32 sourceGovernanceDigest;
}
```

Writes require `LIT_GOVERNANCE_BRIDGE_ROLE`. The contract is append-only per `authorizationId`. Corrections require a tombstone/correction pair that preserves historical trace.

### §9.10A GateRecipientPubkeyRegistry

GateRecipientPubkeyRegistry publishes the KEM public keys that S2-1 §6.2/S2-3 use to wrap per-stanza Shamir shares. The registry is separate from LitV3Assignment and G4AuthorityRegistry to keep assignment identity, long-lived authority identity, and per-commit share-recipient material distinct.

```solidity
enum GateKind { LitV3, Dcipher, Drand, G4, ConditionalRecipient }

struct GateRecipientPubkeyEntry {
    bytes32 authorizationId;
    uint8 gateKind;
    uint16 conditionalRecipientIndex;
    bytes kemPubkey;
    bytes32 attestationRef;
    uint64 effectiveBlock;
    uint64 tombstoneBlock;
    bool perCommitEphemeral;
}
```

Lit V3, G4 Phase 2, and conditional-recipient entries are per-commit ephemeral entries keyed by `(authorizationId, gateKind, conditionalRecipientIndex)`. They are written by `GATE_PUBKEY_PUBLISHER_ROLE` during commit/attestation preparation and do **not** require the 7-day registry-addition timelock because they are operation-specific material, not governance policy. The entry still has historical lookup semantics and tombstone support so a combiner can verify the pubkey that was effective at the commit block.

The drand path uses a long-lived committee KEM entry because drand does not provide a per-commit ephemeral recipient primitive. Long-lived drand committee entries are governance-controlled, UUPS-managed, and subject to the same 7-day addition timelock as the five Cealis-governed registries. The security mitigation is S2-1's Shamir-share-only leak property: disclosure of one drand-wrapped share cannot reconstruct the DEK without the threshold set.

G4 Phase 1 may publish a server-controlled per-commit pubkey as an operational scaffold. Partner-ready Phase 2 entries must bind `kemPubkey` to the TEE quote / attestation reference consumed by S2-3. A mismatch between registry pubkey and attested pubkey is fail-closed for gate signing and combiner admission.

### §9.10B SupersededCommitRegistry carve-out

SupersededCommitRegistry is a governed lifecycle registry, not a selectable authority/config registry. It is intentionally not promoted into the five Cealis-governed V3 registries because supersession lineage is an append-only fact about a commit generation, not a dependency that can be deprecated, halted, auto-cleared, and resumed.

| §9 common control | Applies? | SupersededCommitRegistry rule |
|---|---:|---|
| Historical lookup | yes | `successorOfAt(oldHCommit, blockNumber)` and lineage checkpoints are mandatory. |
| 7-day timelocked writes | yes | `REKEY_GOVERNANCE_ROLE` writes only after TimelockController delay. |
| Tombstone/correction | limited | Corrections append a correction edge/event; they never overwrite or delete the rejected edge. |
| DeprecationFlag / disclosure / auto-clear | no | Supersession is lifecycle lineage, not a canonical dependency. |
| 30-day cooldown | no | Cooldown semantics are irrelevant without DeprecationFlag. |

Existing supersession edges are immutable. A combiner or auditor walking lineage must be able to reconstruct the edge set visible at a historical block, including any later correction record as a later fact rather than a rewrite.

### §9.11 Registry addition workflow

All five Cealis-governed registries follow the same addition workflow:

1. Governance prepares entry payload and metadata hash.
2. TimelockController queues `addEntry`.
3. During the 7-day observation window, recipients, partners, and auditors can inspect payload, source commit, audit digest, and metadata.
4. After delay, TimelockController executes the addition.
5. Registry emits `EntryAdded`.
6. Entry is active only from `effectiveBlock`.

Implementations must store the scheduled operation id or a queue digest if the registry itself needs to defend against duplicate queued entries. TimelockController remains the source of truth for queue execution; the registry should not implement a parallel timelock.

### §9.12 Deprecation workflow

Deprecation takes one of three paths:

**Non-canonical entry.** CealisSecurityMultisig can set DeprecationFlag immediately. This handles vulnerable but not-current plugin versions, retired oracle entries, stale DSL versions, or non-current G4 authorities.

**Canonical-in-use entry.** CealisSecurityMultisig plus expedited TimelockController delay of 24h. This preserves partner/recipient observation window before halting a currently active dependency.

**Cooldown re-deprecation.** If a flag auto-cleared due to missing disclosure, the same security multisig cannot immediately re-deprecate. Re-deprecation within 30 days requires normal TimelockController 7-day queue.

Every deprecation path must bind reason code, disclosure CID, and disclosure commit hash. The registry must not accept free-form plaintext reason as a required on-chain field.

### §9.13 Registry historical lookup implementation

Historical lookup can be implemented by append-only checkpoints:

```solidity
struct RegistryCheckpoint {
    uint64 effectiveBlock;
    uint64 tombstoneBlock;
    bytes32 entryDigest;
}
```

`getEntryAt(id, blockNumber)` binary-searches checkpoints or reads direct effective/tombstone fields if each id has only one lifecycle. `OracleSchemaRegistry.getSchemaAt(schemaId, blockNumber)` follows the same semantics even though OracleSchemaRegistry is a schema registry rather than one of the five Cealis-governed V3 registries. Stage 3 chooses exact data structure. The external semantics are fixed:

- if no entry effective at `blockNumber`, revert `RegistryEntryUnknown`.
- if entry effective after `blockNumber`, revert `RegistryEntryNotEffective`.
- if tombstone block is non-zero and <= `blockNumber`, revert `RegistryEntryTombstoned`.
- if deprecation was set before or at `blockNumber` and not cleared before `blockNumber`, return entry plus active flag; caller decides halt behavior by lifecycle state.

**Historical-lookup semantics (NORMATIVE; resolves §8.4 + §4.16 alignment).** The `blockNumber` argument is the block at which the historical state is being read — typically the commit's `RevealAuthorized` block per S2-1 §12.6 at-commit-block reading discipline. The four reverts above MUST be evaluated against the lifecycle state visible at that block, not at current state. Worked example: a commit registered at block N consumes oracle entry E whose tombstone was set at block M > N. A reveal-time `getEntryAt(E, N)` MUST return E as effective (tombstone block M > queried block N → tombstone-after, not tombstone-before). The `RegistryEntryTombstoned` revert fires only when the tombstone block is at or before the queried block. This preserves §8.4 ("a tombstone after authorization does not retroactively break an in-flight ceremony") + §4.16 ("Existing PDAs keep historical semantics") + S2-1 §12.6 historical-verifiability invariant. Stage 3 implementations MUST cover this case in test vectors.

### §9.14 Registry and G4 refusal integration

Registry deprecation does not itself emit `RefusalSignal`. G4 reads registries and decides whether to refuse σ_G4. Contracts must expose enough view state for G4 to make that decision deterministically:

- entry active at authorization block.
- deprecation active at authorization block.
- reason code.
- disclosure state.
- class-wide halt opt-out status from PDA.
- legal-effect flag from PDA.

If a non-legal-effect PDA has halt opt-out active, registry view still returns deprecation; G4 records `0x0A opt_out_active` through advisory signal state in the artifact path for transparency. `0x0A` does not set blocking refusal state and does not by itself prevent σ_G4. If legal-effect flag is true, opt-out is impossible because PDA registration would have reverted.

### §9.15 DisclosureRegistry expansion (verifier surface)

DisclosureRegistry is the on-chain SD verification surface S2-7 consumes. **Revocation is a separate contract — `DisclosureRevocationRegistry` per S2-7 §11.2.** Both contracts isolated from ConditionEngine: SD proof success cannot emit `RevealAuthorized`, and SD failure cannot block escrow commit or reveal authorization (Rule 6b SD-D9 asymmetric isolation).

The verifier registry exposes:

- `verifyDisclosureProof(...)` for S2-7 PLONK proof verification against `sdMerkleRoot`, verifier ref, proof bytes, and public inputs.
- `commitDisclosure(...)` for binding the verified PLONK output to the on-chain commitment record.
- `verifyAndCommitDisclosure(...)` atomic verify-then-commit, fail-closed on revocation lookup.
- `disclosureRevoked(...)` view — convenience pass-through to `DisclosureRevocationRegistry.isRevoked(disclosureId)`. Reverts with `RevocationRegistryUnavailable` if the revocation registry is paused or unset.

Verifier registration follows UUPS/timelock discipline. SD proof submission uses `SD_OPERATOR_ROLE`; revocation lives entirely on `DisclosureRevocationRegistry` per S2-7 §11.2. S2-7 §10 owns circuit/public-input semantics; S2-7 §11 owns revocation lifecycle + reason codes; S2-2 owns the ABI, roles, isolation, and upgrade posture for both contracts.

Storage layout discipline: UUPS contract MUST reserve `uint256[50] private __gap;` per §General L124.

### §9.15.1 Pause + cross-contract fail-closed normative

If `DisclosureRevocationRegistry` is paused, has zero address, or returns revert from `isRevoked(disclosureId)`, then `verifyAndCommitDisclosure` and `disclosureRevoked` MUST revert with `RevocationRegistryUnavailable`. This is fail-closed: SD verification cannot proceed when revocation state is unverifiable. This preserves dual-layer revocation guarantee (S2-7 §11.4) under operational pause.

`DisclosureRegistry` MUST hold a single immutable storage reference to `DisclosureRevocationRegistry` set at initialization. Updates require UPGRADER_ROLE timelock (7-day) — same governance posture as verifier upgrades.

### §9.16 QTSP special handling

QTSPRegistry deprecation does not have a dedicated `0x06`-`0x09` reason in S2-1. S2-2 exposes QTSP deprecation state exactly like other registries, but G4 refusal maps QTSP failure to `0x04 integrity_fail` unless S2-1 later extends the enum. This is not a Solidity design gap; it is an intentional S2-1 enum boundary.

### §9.16A CredentialAnchorRegistry (controlled-use; class-CRYPTO; commit_version = 0x0303 only)

CredentialAnchorRegistry is a controlled-use-only on-chain registry mapping `credential_digest → first-presentation anchor entry`. The anchor SSTORE is gated on a revocation check + σ_holder verification per the A22 transaction-atomic discipline (S2-8 §2.6 + S2-2 §4.11.5 step 4). Class-CRYPTO per `v3-registry-class-discipline.md` (internal design note, not in this export); lookup keys are TAG-prefixed via `TAG_CU_ANCHOR_V3` (S2-1 §2.3.5). The registry is deployed only for partner deployments that elect the controlled-use profile (`token_policy_config.enabled = true`).

```solidity
struct AnchorEntry {
    uint64 firstPresentationBlock;
    uint64 firstPresentationTimestamp;
    bytes32 holderBindingPubkeyRef;     // 32-byte ref to holder-binding pubkey (passkey / hardware / app-session / EOA-EIP-712)
    bytes32 masterCredentialAnchorRef;  // bytes32(0) for masters; the master's anchor digest for sub-tokens (lazy-anchored from master)
}

interface ICredentialAnchorRegistry {
    function getAnchor(bytes32 credentialDigest) external view returns (AnchorEntry memory);
    function isAnchored(bytes32 credentialDigest) external view returns (bool);

    // Writable only by ConditionEngine via PresentedTokenConditionModule (CONDITION_ENGINE_ROLE).
    // Partner contracts cannot call this directly; the module gates the call inside its evaluation.
    function writeAnchor(
        bytes32 credentialDigest,
        bytes32 holderBindingPubkeyRef,
        bytes32 masterCredentialAnchorRef
    ) external;
}
```

**Storage layout.** Mapping from `credentialDigest` to `AnchorEntry`. Append-only at the per-entry level: anchor SSTORE happens exactly once at first presentation; the entry is never overwritten. UUPS storage layout discipline per §1.2 + §18.3; full byte-exact storage-slot authoring deferred to BP-CU-1.

**Roles.**
- `CONDITION_ENGINE_ROLE` — write authority. The PresentedTokenConditionModule (§4.11.5) calls `writeAnchor` from inside its evaluation at step 4; the role gate enforces caller-is-module discipline so partner contracts cannot bypass the revocation check at step 2.
- `DEFAULT_ADMIN_ROLE` — TimelockController for governance.
- `UPGRADER_ROLE` — TimelockController for UUPS upgrades.
- `PAUSER_ROLE` — emergency pause; bounded duration per §14.

**Events.**
- `AnchorWritten(bytes32 indexed credentialDigest, uint64 blockNumber, uint64 timestamp, bytes32 holderBindingPubkeyRef)`

**Errors.**
- `AnchorAlreadyExists(bytes32 credentialDigest)` — write attempted on an already-anchored credential (the first-presentation invariant is violated).
- `WriteAuthorityNotModule(address caller)` — a non-module caller attempted `writeAnchor`.
- `RevokedMasterAtAnchorTime(bytes32 credentialDigest, uint256 revokedAt)` — anchor write attempted on a credential whose master is already revoked at the anchor block (defense-in-depth against an H-1-class race; the module itself enforces revocation-FIRST at step 2, but the registry re-checks at the write boundary so a coding bug in the module cannot bypass revocation).

**UUPS discipline.** UUPSUpgradeable + Initializable per §1.10 convention; storage layout is append-only. Upgrade authority is TimelockController only.

**Universal tripwire interaction.** Anchor write is gated on revocation check FIRST per A22; this is the chain-side enforcement of the lazy-anchor revocation-FIRST discipline. The registry's `RevokedMasterAtAnchorTime` revert is the second-line defense; the primary defense is PresentedTokenConditionModule step 2.

### §9.16B SliceLayoutRegistry (controlled-use; class-CRYPTO; commit_version = 0x0303 only)

SliceLayoutRegistry maps `(pda_root, slice_id) → (slice_latest_sealed_envelope_ref, slice_position_counter)` for controlled-use deployments. Class-CRYPTO per the V3 registry class discipline; lookup keys are TAG-prefixed via `TAG_CU_SLICE_LAYOUT_V3` (S2-1 §2.3.5).

**Supersession-invariance (H-2 normative, per S2-8 §5.3).** The entry stored at `(pda_root, slice_id)` is the ORIGINAL-generation `h_commit` of the slice's latest sealed envelope; re-key ceremonies write `h_commit_vN` into the existing `SupersededCommitRegistry` (§9.10B) but **NEVER touch SliceLayoutRegistry**. The slice latest sealed envelope ref is supersession-invariant. Downstream consumers (writer, reader, write-validation TEE, audit-stream signer) read the original ref from `SliceLayoutRegistry` and walk `SupersededCommitRegistry` forward to the current generation; σ binding is against the current generation while `slice_preceding_envelope_ref` in `commit_AAD` stays anchored to the original ref.

```solidity
struct SliceLayoutEntry {
    bytes32 sliceLatestSealedEnvelopeRef;  // ORIGINAL h_commit (supersession-invariant)
    uint64 slicePosition;                  // monotonically increasing position counter within the slice
    uint64 lastUpdateBlock;
}

interface ISliceLayoutRegistry {
    function getSliceLatestSealedEnvelopeRef(bytes32 pdaRoot, bytes32 sliceId)
        external view returns (bytes32);
    function getSlicePosition(bytes32 pdaRoot, bytes32 sliceId)
        external view returns (uint64);
    function getSliceLayoutEntry(bytes32 pdaRoot, bytes32 sliceId)
        external view returns (SliceLayoutEntry memory);

    // Writable only by ConditionEngine on WriteAuthorized emission.
    function updateSliceHead(
        bytes32 pdaRoot,
        bytes32 sliceId,
        bytes32 hCommit,            // the new envelope's h_commit (original generation; never a re-key supersession ref)
        uint64 slicePosition        // MUST be strictly greater than the prior slicePosition
    ) external;
}
```

**Storage layout.** Nested mapping `(pdaRoot => slice_id => SliceLayoutEntry)`. UUPS storage layout discipline per §1.2 + §18.3; byte-exact storage-slot authoring deferred to BP-CU-1.

**Roles.**
- `CONDITION_ENGINE_ROLE` — write authority. The registry is updated by ConditionEngine on `WriteAuthorized` emission for controlled-use writes; the call is gated to ConditionEngine so writers cannot directly mutate the slice latest sealed envelope ref outside the gate-signing flow.
- `DEFAULT_ADMIN_ROLE` — TimelockController.
- `UPGRADER_ROLE` — TimelockController.
- `PAUSER_ROLE` — emergency pause per §14.

**Events.**
- `SliceLayoutUpdated(bytes32 indexed pdaRoot, bytes32 indexed sliceId, bytes32 hCommit, uint64 slicePosition)`

**Errors.**
- `SliceNotInPdaLayout(bytes32 pdaRoot, bytes32 sliceId)` — attempted update for a slice not declared in the PDA's `token_policy_config.slice_layout.slices[]`.
- `SlicePositionMustIncrement(uint64 prior, uint64 proposed)` — the proposed `slicePosition` is not strictly greater than the prior value; the per-slice chain is monotonic and append-only.
- `WriteAuthorityNotConditionEngine(address caller)` — a non-ConditionEngine caller attempted `updateSliceHead`.

**UUPS discipline.** UUPSUpgradeable + Initializable per §1.10; storage layout is append-only by entry but per-entry writeable.

**Topology evolution.** Slice layout evolution (`token_policy_config.slice_layout.evolution_policy`) updates the per-PDA `pda_slice_layout_anchor` Merkle root recorded inside PDA registration metadata (S2-4 coordinated amendment); the registry itself does not store the topology anchor — only per-slice latest sealed envelope refs. Evolution is timelock-gated per PDA+ governance; the `pda_slice_layout_anchor` predecessor name `slice_topology_root` is retired per S2-8 §0.3 + S2-1 §2.3.5.

### §9.16C MasterTokenRevocationRegistry (controlled-use; class-CRYPTO; commit_version = 0x0303 only)

MasterTokenRevocationRegistry maps `master_credential_digest → (revokedAt, revokerAuthority)`. Revocation is irreversible at the crypto layer (matches `DisclosureRevocationRegistry` discipline from S2-7 §11.2 per BP-SD-3). Class-CRYPTO per the V3 registry class discipline.

```solidity
struct MasterRevocationEntry {
    uint64 revokedAt;                  // 0 sentinel for non-revoked
    address revokerAuthority;          // address that submitted the revocation tx; validated against the PDA's master_revocation_authority set
    bytes32 evidenceRef;               // optional 32-byte ref to off-chain evidence (subpoena, court order, partner ticket); bytes32(0) for routine revocations
}

interface IMasterTokenRevocationRegistry {
    function isRevoked(bytes32 masterCredentialDigest) external view returns (bool);
    function getRevocation(bytes32 masterCredentialDigest) external view returns (MasterRevocationEntry memory);

    function revokeMaster(
        bytes32 masterCredentialDigest,
        bytes32 evidenceRef
    ) external;
}
```

**Storage layout.** Mapping `masterCredentialDigest => MasterRevocationEntry`. Append-only: once `revokedAt != 0`, the entry cannot be cleared. UUPS storage discipline per §1.2 + §18.3.

**Roles.**
- `REVOCATION_ADMIN_ROLE` — global Cealis revocation authority for Art. 17 erasure, legal compel, and integrity incidents (mirrors `DisclosureRevocationRegistry` role discipline at §16.1). Coexists with per-PDA `master_revocation_authority` partner delegation; the registry's `revokeMaster` function validates the caller against either authority path before writing.
- `DEFAULT_ADMIN_ROLE` — TimelockController.
- `UPGRADER_ROLE` — TimelockController (revocation lifecycle iterates independently of PresentedTokenCondition ABI churn).
- `PAUSER_ROLE` — emergency pause per §14.

**Events.**
- `MasterRevoked(bytes32 indexed masterCredentialDigest, uint64 revokedAt, address indexed revokerAuthority, bytes32 evidenceRef)`

**Errors.**
- `RevocationAlreadyRecorded(bytes32 masterCredentialDigest, uint64 priorRevokedAt)` — revocation attempted on an already-revoked master (no overwrite path; the prior record stands).
- `UnauthorizedRevoker(address caller, bytes32 masterCredentialDigest)` — caller is neither in `REVOCATION_ADMIN_ROLE` nor in the PDA's `master_revocation_authority` set.

**UUPS discipline.** UUPSUpgradeable + Initializable per §1.10; per-entry append-only.

**Revocation latency.** Per S2-8 §8.5, master revocation propagation is bounded by chain-confirmation depth. PresentedTokenConditionModule reads at the PDA-configurable `revocation_confirmation_depth` (default 12 blocks on Base mainnet); below that depth the read is preliminary. The registry surfaces `getRevocation` synchronously; the depth-window discipline is applied by the module, not the registry.

### §9.16D TokenRevocationRegistry (controlled-use opt-in; class-CRYPTO; commit_version = 0x0303 only)

TokenRevocationRegistry is the **opt-in** per-sub-token revocation registry, activated by PDA election `revocation_mode = MASTER_AND_SUB_CRL` per S2-8 §8.4. Class-CRYPTO per the V3 registry class discipline. Deployed only for high-stakes deployments that need per-sub-token revocation (e.g., a clinician's appointment is canceled mid-consultation; revoke the consultation sub-token immediately rather than wait for TTL expiry).

The ABI shape mirrors §9.16C exactly, replacing `master_credential_digest` with `sub_token_digest` and `revokeMaster` with `revokeSubToken`. The role + event + error structure also mirrors §9.16C:

```solidity
interface ITokenRevocationRegistry {
    function isRevoked(bytes32 subTokenDigest) external view returns (bool);
    function getRevocation(bytes32 subTokenDigest) external view returns (MasterRevocationEntry memory);

    function revokeSubToken(
        bytes32 subTokenDigest,
        bytes32 evidenceRef
    ) external;
}
```

**Roles.** Same as §9.16C — `REVOCATION_ADMIN_ROLE`, `DEFAULT_ADMIN_ROLE`, `UPGRADER_ROLE`, `PAUSER_ROLE`; per-PDA `master_revocation_authority` delegation also applies.

**Events.**
- `SubTokenRevoked(bytes32 indexed subTokenDigest, uint64 revokedAt, address indexed revokerAuthority, bytes32 evidenceRef)`

**Errors.**
- `RevocationAlreadyRecorded(bytes32 subTokenDigest, uint64 priorRevokedAt)`
- `UnauthorizedRevoker(address caller, bytes32 subTokenDigest)`

**Opt-in discipline.** Non-`MASTER_AND_SUB_CRL` PDAs do NOT deploy this registry; PresentedTokenConditionModule step 2 reads only `MasterTokenRevocationRegistry` for those PDAs. For `MASTER_AND_SUB_CRL` PDAs, the module reads BOTH registries at step 2 (master revocation first, then sub-token revocation if the master is not revoked). The opt-in is locked at PDA registration time; toggling `revocation_mode` post-registration follows PDA evolution policy (S2-4 coordinated amendment).

**UUPS discipline.** UUPSUpgradeable + Initializable per §1.10; per-entry append-only.

### §9.17 Registry PII statement

Registry entries are operator-side metadata. They may include public keys, contract addresses, source commit digests, audit digests, metadata hashes, CIDs, jurisdiction codes, and URLs. They must not include subject names, KYC data, claim plaintext, or plaintext refusal reasons for sensitive codes. Metadata bodies live off-chain and must be screened by S2-6/S2-5 publication rules.

Controlled-use registries (§9.16A-§9.16D) process pseudonymous identifiers (`credential_digest`, `sub_token_digest`, `master_credential_digest`) at the chain layer; under Breyer C-582/14, these qualify as personal data when correlated with off-chain credential issuance records held by the partner. The `holderBindingPubkeyRef` field in `AnchorEntry` records a 32-byte reference to holder-binding material (passkey public key, hardware-key public key, EOA address, or app-session pubkey); under the same Breyer reasoning, this is personal data when partner-held correlation is feasible. The `revokerAuthority` EVM address in `MasterTokenRevocationRegistry` / `TokenRevocationRegistry` is pseudonymous on-chain; partner-held off-chain mapping makes it personal data. Partners are responsible for treating these identifiers as personal data under GDPR Art. 4(5) when retaining them beyond their operational lifecycle. Cross-ref S2-8 §10 layered controllership and the `actor_token_digest` / `content_shape_digest` PII analysis at S2-8 §1.10.

## §10 - ShredRegistry

### §10.1 Authority axis

Selectable shred authority modes:

- `0x01 Subject`
- `0x02 Joint`
- `0x03 Operator`
- `0x04 Timelock`
- `0x05 Disabled`

The Solidity enum reserves `None == 0` as an invalid sentinel for uninitialized storage and malformed calldata; it is not PDA-selectable. The selected mode is bound into `h_commit.shred_authority_id` per S2-1 §3.4.4. ShredRegistry validates caller authority against this mode before condition evaluation. Disabled mode always reverts for shred attempts.

### §10.2 Condition axis

Every PDA has a shred condition. Mode P evaluates a Claim predicate at shred attempt time. Mode F advances an FSM to terminal shred state. Both reuse ConditionEngine infrastructure. Every shred condition includes the mandatory PDA+ guardrail `NOT post_challenge_reveal_in_progress`.

### §10.3 Mandatory guardrail

ConditionEngine is the only emitter of `ShredAuthorized`. Before ConditionEngine emits `ShredAuthorized`, and before ShredRegistry finalizes shred, ShredRegistry/ConditionEngine re-read:

```solidity
function postChallengeRevealInProgress(bytes32 authorizationId)
    external
    view
    returns (bool);
```

If true, shred reverts with `ShredRevealInProgress`. This applies even when subject authority would otherwise be valid. The guardrail closes the destruction-axis tripwire mirror: shred cannot break enforcement after the reveal ceremony has passed challenge and gates may sign. ShredRegistry records request, authorization notice, challenge, finalization, and permanent shredded state, but it must not emit `ShredAuthorized`; it only accepts a ConditionEngine-authenticated authorization notice after ConditionEngine emits.

### §10.4 Triple block

Finalized shred has three effects:

1. G1: ConditionEngine refuses future `RevealAuthorized` for the `hCommit`.
2. G4: G4 reads ShredRegistry and refuses σ_G4.
3. Vault: S2-5 vault deletes ciphertext after on-chain confirmation.

Only the first two are on-chain S2-2 surfaces. Vault deletion is S2-5.

### §10.5 `proof_shred`

`proof_shred` is a public verification token that a shred event finalized. It is not a custody signature, Shamir share, or DEK material. It may be emitted and stored on-chain:

```solidity
proofShred = keccak256(abi.encodePacked(hCommit, shredFinalizedBlock, shredAuthorityMode, shredConditionRef));
```

This hash is an audit handle only. It does not derive, wrap, or reveal any DEK.

### §10.6 Shred lifecycle

The lifecycle is `Requested -> Authorized -> ChallengeOpen -> Finalized -> Shredded`, with zero-window PDAs skipping `ChallengeOpen`. App. A preserves enum discriminants by appending `ChallengeOpen` and `Shredded` after the previously declared values; lifecycle order is defined by this paragraph and `ShredStateChanged`, not by enum ordinal order. `Finalized` is the transition where on-chain proof material is computed and finality preconditions are checked. `Shredded` is the permanent state consumed by ConditionEngine, G4, and S2-5 vault deletion workflows. Implementations may move `Finalized -> Shredded` in the same transaction, but the ABI must expose both states so audits can distinguish proof computation from permanent blocked state. Minimum shred latency from `pda_root.minimum_shred_latency` must elapse before finalization where non-zero.

## §11 - Mode 3 σ_conditional RESERVED Enforcement

Mode 3 WALLET_EIP1271 is architected in S2-1 §10.4 but reserved at V2 launch. S2-2 enforces the contract-layer part of the three-layer defense.

### §11.1 Contract rejection path

Any function that registers, updates, or validates conditional-recipient policy for an active PDA must reject `deliveryMode == 0x03` with `Mode3Reserved`. This includes ConditionEngine PDA registration, PDA config registry validation, and any helper used by S2-4.

`registerPDA(...)` therefore accepts the conditional-recipient mode vector or an equivalent policy digest-expanded validation input. The contract does not need the full off-chain recipient metadata, but it must see enough mode data to reject Mode 3 on-chain instead of trusting the configurator's precheck.

### §11.2 Defense-in-depth

Layer 1: S2-2/S2-4 configurator entry rejects Mode 3.

Layer 2: subject-side verifier rejects a Mode 3 stanza before σ_subject signing. This is S2-3/S2-4 implementation detail but S2-2 preserves the rejection reason.

Layer 3: combiner rejects Mode 3 at reveal with `ERR_MODE_3_NOT_SHIPPED_AT_V2`. This is S2-1/S2-3/S2-5 surface.

S2-2 must not expose a governance toggle that silently activates Mode 3. Activation requires S2-6 ceremony, S2-1 update if byte layouts change, and configurator release.

### §11.5 Mode T (Token) cosign-gate enforcement (controlled-use; commit_version = 0x0303)

Mode T (Token) is the controlled-use access-token signing mode introduced at S2-1 §10.11; it is co-located here under §11 because Mode T composes with the σ_conditional layer at PDA registration and σ-ensemble validation surfaces. Mode T is RESERVED in the same byte-layout enum space as Mode 1-Mode 3 at S2-1 §10.11; this section enforces the contract-layer part of Mode T cosign-gate discipline.

**PDA-validation-time cosign-gate enum enforcement.** At PDA registration for controlled-use deployments, the configurator MUST set `token_policy_config.audit_policy.stream2_cosign_gate ∈ {G2_LIT, G3_DCIPHER, G3_DRAND}` (S2-8 §1.9). ConditionEngine PDA registration validation rejects any controlled-use PDA whose `stream2_cosign_gate` is missing, set to an out-of-enum value, or set to a value inconsistent with the PDA's `g3_choice` per the vendor-family consistency rule below. Rejection surfaces with `CosignGateInvalid`.

**Vendor-family consistency rule (extends cross-vendor disjoint mandate from S2-3 §3, S2-3 §5).** When the PDA elects `stream2_cosign_gate ∈ {G3_DCIPHER, G3_DRAND}`, the choice MUST match the PDA's `g3_choice` family selection — a PDA with `g3_choice = G3_dcipher` for the read path cannot select `stream2_cosign_gate = G3_DRAND` for audit cosign, and vice versa. The rule preserves the cross-vendor disjoint analysis: at any given controlled-use commit, the gate vendors involved in σ_Lit + σ_G3 + σ_G4 + cosign are pairwise disjoint across the {Lit, dcipher, drand, G4} vendor families. Mismatch is rejected at PDA validation with `CosignGateVendorFamilyMismatch`. The rule does NOT prohibit `stream2_cosign_gate = G2_LIT` for a PDA with `g3_choice = G3_dcipher` or `g3_choice = G3_drand` — `G2_LIT` is vendor-disjoint from both G3 families and is a valid cosign-gate selection for any controlled-use PDA.

**Cross-vendor disjoint mandate extension (H-4).** Per S2-8 §4.4 + §H-4, Stream 2 events are signed by `K_G4_audit_stream2` AND co-signed by the PDA-selected cosign-gate. The disjoint mandate at S2-3 §3 (σ_Lit + σ_G3 + σ_G4 vendor disjoint) extends to Stream 2 anchoring: G4's `K_G4_audit_stream2` plus the cosign-gate signing key are vendor-disjoint, so a single G4 TEE key compromise cannot forge Stream 2 log roots. The chain-side Stream 2 anchor verification (cosign-gate signature check at anchor landing) is the contract-layer enforcement of this property.

**Stream 2 anchor landing — chain-side cosign verification.** When a Stream 2 Merkle root anchor is landed on-chain (via an anchor-emission transaction whose specifics are owned by S2-2 + S2-5 coordinated amendment per BP-CU-1), the contract MUST verify both signatures: the G4 signature against `K_G4_audit_stream2_pubkey` from `G4AuthorityRegistry` (§9.6, extended per Edit 5 below), and the cosign-gate signature against the corresponding gate's signing key (resolved via `GateRecipientPubkeyRegistry` §9.10A for per-commit gates, or via the long-lived drand committee entry for `G3_DRAND`). Both signatures cover the canonical Stream 2 cosign input per S2-8 §4.4. Verification failure produces `CU_ERR_STREAM2_COSIGN_MISSING` (per S2-8 §15) and rejects the anchor landing.

**No silent governance toggle for Mode T.** S2-2 must not expose a governance path that silently activates Mode T for non-controlled-use PDAs. Activation requires the `commit_version = 0x0303` rollout (S2-1 §2.8.6), PresentedTokenConditionModule registration (§4.16), the four new registries deployed (§9.16A-§9.16D), and the configurator path enabling `token_policy_config.enabled = true` per S2-4 coordinated amendment. The discipline mirrors the Mode 3 defense-in-depth pattern at §11.1-§11.2: no single contract toggle activates the feature; activation crosses S2-1 / S2-2 / S2-3 / S2-4 simultaneously.

## §12 - RevealAuthorized Event Surface

### §12.1 Canonical event

`RevealAuthorized` is emitted only by ConditionEngine or by RevealAuthorizedEmitter called by ConditionEngine. No module, registry, or governance contract may emit it directly.

```solidity
event RevealAuthorized(
    bytes32 indexed authorizationId,
    bytes32 indexed hCommit,
    bytes32 indexed pdaRoot,
    uint64 authorizationBlock,
    uint64 authorizationTimestamp,
    uint32 challengeWindow,
    bytes32 conditionRef
);
```

`authorizationId`, `hCommit`, and `pdaRoot` are indexed because S2-3, S2-5, and auditors join all reveal artifacts on these fields. `conditionRef` identifies the module/FSM/predicate that fired. `authorizationBlock` and `authorizationTimestamp` are included for SDK convenience; off-chain consumers use the actual block header for block hash.

### §12.2 No σ in event payload

No event in S2-2 emits σ values, σ digests, gate partials, or DEK material. The RevealAuthorized event is intentionally opaque: it says the chain condition fired, not that decryption happened.

### §12.3 SDK idempotency

S2-5 treats `(authorizationId, hCommit, authorizationBlock)` as the idempotency key for delivery workflows. If a chain reorg removes the block, SDKs must discard the event and wait for finality.

### §12.4 Reveal event lifecycle examples

**Tier A zero-window reveal.** PaymentObligationModule reads a partner contract and observes a default. ConditionEngine re-reads shred state, pause state, module state, registry refs, and legal guardrails. It emits `RevealAuthorized` with `challengeWindow = 0`, then immediately marks `PostChallengeRevealInProgress`. Gates may sign after L1 finality.

**Tier B oracle-attested reveal.** OracleAttestationModule accepts a signed oracle digest and Claim DSL evaluates true. ConditionEngine emits `RevealAuthorized` with `challengeWindow = 14 days` for KYC-lending/M&A archetypes. ChallengeRegistry opens the window. Gates cannot sign until `canGatesSign` becomes true after timeout or resolver confirmation.

**Challenge halt.** During a non-zero window, an eligible challenger opens a challenge. Resolver invokes G4 refusal path with a refusal proof. ConditionEngine does not emit a second reveal event. G4RefusalRegistry records refusal; gates observe missing σ_G4 and combiner cannot derive file_key.

**Shred race defense.** After zero-window reveal enters `PostChallengeRevealInProgress`, subject attempts shred. ShredRegistry checks ConditionEngine and reverts `ShredRevealInProgress`. If the subject had requested shred before the reveal passed challenge, normal shred condition and challenge rules would apply.

### §12.5 Event ordering constraints

For any `authorizationId`, event order must satisfy:

1. `PDARegistered` before any ceremony event.
2. At most one live `RevealAuthorized` unless a future protocol explicitly models repeated reveals; V2 treats reveal authorization as one lifecycle event per commitment.
3. `ShredFinalized` after `ShredAuthorized`.
4. No `RevealAuthorized` after `ShredFinalized`.
5. No `ShredFinalized` after `PostChallengeRevealInProgress` unless the reveal completed and a new PDA-specific lifecycle explicitly permits post-reveal shred.
6. `RefusalSignal` can occur after `RevealAuthorized` but does not erase it; it is a halt artifact.

Indexers and S2-5 delivery workers may reject sequences that violate this ordering as contract bugs or reorg artifacts.

## §13 - PasskeyRotationLog ABI

### §13.1 Contract identity

PasskeyRotationLog is an ABI standard. Cealis's canonical deployment is UUPS upgradeable and timelocked, but recipients may use compatible deployments. `contract_address` is bound into S2-1 §13.3 and §13.4 digests, preventing cross-deployment replay.

### §13.2 Entry struct

```solidity
struct PasskeyRotationEntry {
    bytes prevPubkey;
    bytes newPubkey;
    uint64 timestamp;
    bytes webauthnAssertion;
    bytes prevMlkemPubkey;
    bytes newMlkemPubkey;
    uint32 entryIndex;
    address contractAddress;
}
```

Implementation should enforce exact byte lengths: P-256 pubkeys 65 bytes, ML-KEM-768 pubkeys 1184 bytes, `entryIndex` monotonic. Entry 0 uses zero previous keys and empty assertion.

### §13.3 Append semantics

`appendRotation(accountId, entry, authorizationDigest)` verifies:

- account exists or entry index is 0.
- entry index is previous index + 1.
- previous keys match prior entry.
- `contractAddress == address(this)`.
- WebAuthn assertion verifies against previous passkey for entries after 0.
- rotation authorization digest matches S2-1 §13.3 using `TAG_ROTATION_AUTHORIZATION_V3` from S2-1 §2.3.4.

### §13.4 Walk helpers

The contract exposes:

- `getEntry(accountId, index)`
- `getHead(accountId)`
- `getEntries(accountId, from, to)` view with bounded page size
- `computeRotationLogAnchor(...)` helper importing S2-1 §13.4 and `TAG_ROTATION_LOG_ANCHOR_V3` from S2-1 §2.3.4

The on-chain contract need not perform the full walk for every reveal. The combiner performs S2-1 §13.5 walk-from-anchor. S2-2 guarantees the append-only data needed for that walk.

## §14 - Pause and Halt Mechanics

### §14.1 Pausable surfaces

Each mutable contract exposes pause only where halt is meaningful:

- ConditionEngine: pause blocks FSM advancement and new authorization emissions.
- Modules: pause blocks module-specific state transitions.
- Registries: pause blocks additions/tombstones but does not block reads.
- ShredRegistry: pause blocks new shred requests but not already-finalized shredded state reads.
- ChallengeRegistry: pause blocks new challenges only if configured; resolving active legal-effect challenges requires care and must be governed by S2-6.

Pause never deletes state, never emits reveal, and never grants release.

### §14.1A Scoped pause ABI

Every pausable surface exposes the same scoped pause shape:

```solidity
function pause(bytes32 scope, uint64 until, bytes32 reasonRef) external;
function unpause(bytes32 scope) external;
function isPaused(bytes32 scope) external view returns (bool active, uint64 until, bytes32 reasonRef);
```

`scope` is either a contract-wide scope id, a PDA/authorization scope id, or a module/registry-entry scope id defined by that contract. `until` must be non-zero and no later than the applicable max duration. Pauses auto-expire for read and state-transition checks once `block.timestamp > until`, even if no `unpause` transaction was sent. `unpause(scope)` clears early and emits the same state transition.

Max durations:

| Pause class | Max duration |
|---|---:|
| Operational contract/module pause | 72 hours |
| Registry-addition/tombstone pause | 7 days |
| Emergency governance circuit-breaker pause | 7 days |
| ChallengeRegistry new-challenge pause | 72 hours unless S2-6 legal ceremony explicitly grants a stricter PDA-bound window |

Pause authority uses `PauseAuthorityMode`, not `ShredAuthorityMode`. The only pause-authority values are `Partner`, `Joint`, and `None`; shred authority values (`Subject`, `Operator`, `Timelock`, `Disabled`) must not be reused for pause authority.

### §14.2 G4 refusal reason enum

G4RefusalRegistry supports the five base reason codes from `flows-spec-final.md` §425:

- `0x01 legal_compel`
- `0x02 art_17_erasure`
- `0x03 art_18_restriction`
- `0x04 integrity_fail`
- `0x05 chain_mismatch`

S2-1 §12/§16 also references deprecation refusal codes `0x06` through `0x0A`. S2-2 supports an extensible enum range but separates blocking refusal state from advisory signal state. Codes `0x01`-`0x09` are blocking refusal reasons that can prevent σ_G4. Code `0x0A` is an advisory transparency signal only:

- `0x06 plugin_deprecated`
- `0x07 authority_deprecated`
- `0x08 dsl_deprecated`
- `0x09 oracle_deprecated`
- `0x0A opt_out_active` (advisory, non-blocking)

### §14.3 Encrypted reason mode

For reason codes `0x02` and `0x03`, default storage is encrypted reason:

```solidity
event RefusalSignal(bytes32 indexed authorizationId, bytes32 indexed hCommit, uint8 reasonCode, bool blocking);
event RefusalReasonEncrypted(bytes32 indexed authorizationId, bytes encryptedReasonBlobHash);
event AdvisorySignal(bytes32 indexed authorizationId, bytes32 indexed hCommit, uint8 reasonCode);
```

The plaintext reason is not emitted. Public-reason mode for these codes requires PDA-level opt-out with explicit subject acknowledgment and partner attestation; legal-effect PDAs should not use public-reason mode unless counsel has approved. The `RefusalSignal`/`refusalState` channel is blocking-only. Advisory-only `0x0A` uses `AdvisorySignal`/`signalState` and must not appear as `refused == true`.

### §14.4 Class-wide halt opt-out

`cealis_class_wide_halt_opt_out == true` is forbidden when `legal_effect_expected == true`. Contract validators enforce this at PDA registration. If a non-legal-effect PDA opts out, G4 may record `0x0A opt_out_active` through advisory signal state for downstream transparency, while `refusalState.refused` remains false unless an independent blocking reason `0x01`-`0x09` exists. The opt-out cannot grant a reveal. It only prevents a class-wide deprecation halt from applying.

## §15 - EIP-712 Domains

### §15.1 Domains

S2-2 owns contract-side domain declarations for:

- `CealisRevealManager`
- `CealisConditionalRecipient`
- `CealisSubjectInitiated`
- `CealisConsentGate`
- `CealisMultiPartySignal`

The `CealisConditionalRecipient` domain must match S2-1 §10.3 for Mode 2 `ECDSA.recover`. If the verifying contract is `address(0)` in off-chain combiner context, on-chain helpers must document that they are reproducing an off-chain digest and not acting as the verifying contract.

### §15.2 Chain ID

Base Mainnet chain ID is the production domain. Base Sepolia is testnet. Signatures must bind chain ID. Cross-chain replay is rejected.

## §16 - Access Control Role Matrix

### §16.1 Matrix

| Contract | Role | Holder after deploy | Grants/revokes |
|---|---|---|---|
| All UUPS contracts | `DEFAULT_ADMIN_ROLE` | TimelockController | TimelockController |
| All UUPS contracts | `UPGRADER_ROLE` | TimelockController only | TimelockController |
| ConditionEngine | `MODULE_ADMIN_ROLE` | TimelockController | TimelockController |
| ConditionEngine | `ORCHESTRATOR_ROLE` | Orchestrator service/multisig | TimelockController |
| ConditionEngine | `PAUSER_ROLE` | PDA pause authority or ops multisig | TimelockController / PDA config |
| Modules | `PAUSER_ROLE` | ops multisig or PDA pause authority where configured | TimelockController / PDA config |
| Modules | `ORACLE_SUBMITTER_ROLE` | registered oracle/relayer where needed | TimelockController / OracleRegistry |
| Modules / issuer adapters | `ISSUER_ROLE` | external attestation issuer contract or adapter where configured | TimelockController / PDA config |
| Registries | `REGISTRY_ADMIN_ROLE` | TimelockController | TimelockController |
| Registries | `SECURITY_COUNCIL_ROLE` | CealisSecurityMultisig | TimelockController |
| Registries | `EMERGENCY_GOVERNANCE_ROLE` | EmergencyGovernance | TimelockController |
| Registries | `PAUSER_ROLE` | ops multisig for addition/tombstone pause only | TimelockController |
| ChallengeRegistry | `CHALLENGE_RESOLVER_ROLE` | PDA-bound resolver | PDA config / TimelockController |
| ChallengeRegistry | `PAUSER_ROLE` | ops multisig or legal-ceremony authority for new-challenge pause | TimelockController / PDA config |
| ShredRegistry | `PAUSER_ROLE` | ops multisig or PDA pause authority | TimelockController / PDA config |
| SupersededCommitRegistry | `REKEY_GOVERNANCE_ROLE` | RekeyGovernance multisig | TimelockController |
| LitV3Assignment | `LIT_GOVERNANCE_BRIDGE_ROLE` | Lit bridge | TimelockController |
| GateRecipientPubkeyRegistry | `GATE_PUBKEY_PUBLISHER_ROLE` | G4/ingestion publisher service for per-commit entries | TimelockController / PDA config |
| GateRecipientPubkeyRegistry | `REGISTRY_ADMIN_ROLE` | TimelockController for long-lived drand committee entries | TimelockController |
| DisclosureRegistry | `SD_OPERATOR_ROLE` | SD service / verifier relayer | TimelockController |
| DisclosureRegistry | `UPGRADER_ROLE` | Verifier-version upgrades | TimelockController |
| DisclosureRevocationRegistry | `ORCHESTRATOR_ROLE` | Disclosure registration at SD pipeline ingestion | TimelockController |
| DisclosureRevocationRegistry | `REVOCATION_ADMIN_ROLE` | Global Cealis revocation (Art. 17, legal compel, integrity incidents). Coexists with per-disclosure `authorizedRevoker` partner delegation set at registration. | TimelockController |
| DisclosureRevocationRegistry | `UPGRADER_ROLE` | Independent of DisclosureRegistry — revocation lifecycle can iterate without verifier ABI churn | TimelockController |
| G4RefusalRegistry | `OPERATOR_ROLE` | G4 authority component | TimelockController |
| CredentialAnchorRegistry (controlled-use; §9.16A) | `CONDITION_ENGINE_ROLE` | ConditionEngine (PresentedTokenConditionModule §4.11.5 calls `writeAnchor` from inside its evaluation; partner contracts cannot call directly) | TimelockController |
| CredentialAnchorRegistry (controlled-use; §9.16A) | `DEFAULT_ADMIN_ROLE` / `UPGRADER_ROLE` / `PAUSER_ROLE` | TimelockController (admin + upgrades) / ops multisig (bounded pause per §14) | TimelockController |
| SliceLayoutRegistry (controlled-use; §9.16B) | `CONDITION_ENGINE_ROLE` | ConditionEngine (`updateSliceHead` on `WriteAuthorized` emission; writers cannot mutate slice head outside the gate-signing flow) | TimelockController |
| SliceLayoutRegistry (controlled-use; §9.16B) | `DEFAULT_ADMIN_ROLE` / `UPGRADER_ROLE` / `PAUSER_ROLE` | TimelockController / ops multisig | TimelockController |
| MasterTokenRevocationRegistry (controlled-use; §9.16C) | `REVOCATION_ADMIN_ROLE` | Global Cealis revocation authority (Art. 17, legal compel, integrity incidents); mirrors the DisclosureRevocationRegistry pattern; coexists with per-PDA `master_revocation_authority` partner delegation set at PDA registration time | TimelockController |
| MasterTokenRevocationRegistry (controlled-use; §9.16C) | `DEFAULT_ADMIN_ROLE` / `UPGRADER_ROLE` / `PAUSER_ROLE` | TimelockController / ops multisig | TimelockController |
| TokenRevocationRegistry (controlled-use opt-in; §9.16D) | `REVOCATION_ADMIN_ROLE` | Same role + delegation pattern as §9.16C; deployed only for `revocation_mode = MASTER_AND_SUB_CRL` PDAs | TimelockController |
| TokenRevocationRegistry (controlled-use opt-in; §9.16D) | `DEFAULT_ADMIN_ROLE` / `UPGRADER_ROLE` / `PAUSER_ROLE` | TimelockController / ops multisig | TimelockController |
| G4AuthorityRegistry (controlled-use extension; §9.6 + §4.6 of S2-8) | `REGISTRY_ADMIN_ROLE` | TimelockController records two new key entries per controlled-use deployment: `K_G4_write_attest_pubkey` (write-validation attestation verification key) and `K_G4_audit_stream2_pubkey` (Stream 2 audit-stream signing verification key). Key rotation discipline inherits from S2-6 operational ceremonies | TimelockController |

### §16.2 Per-function access-control annotations

App. A functions must implement at least this access-control surface:

| Function/surface | Gate |
|---|---|
| `IConditionEngine.registerPDA` | `ORCHESTRATOR_ROLE` after `PDARegistration` validation. |
| `IConditionEngine.authorizeReveal` / `authorizeShred` | Permissionless or relayed entry, but gated by PDA axis config, module/FSM result, pause, challenge, shred, registry, and refusal preconditions. |
| `IConditionEngine.advanceFSM` | Permissionless or relayed entry, but ConditionEngine validates the actor against PDA/FSM submitter rules before calling FSMInterpreter. |
| `IFSMInterpreter.advanceFSM` | callable only by ConditionEngine. |
| `IConditionModule.configure` | callable only by ConditionEngine or `MODULE_ADMIN_ROLE` during controlled module setup, as the module type requires. |
| `IConditionModule.advance` / `evaluate` | callable only through ConditionEngine or read-only helper paths explicitly marked safe. |
| `IBaseRegistry` add/tombstone/deprecation controls | `REGISTRY_ADMIN_ROLE`, `SECURITY_COUNCIL_ROLE`, or `EMERGENCY_GOVERNANCE_ROLE` as §9 defines. |
| `IGateRecipientPubkeyRegistry.publishPubkey` | `GATE_PUBKEY_PUBLISHER_ROLE` for per-commit entries; `REGISTRY_ADMIN_ROLE`/TimelockController for long-lived drand committee entries. |
| `IShredRegistry.requestShred` | PDA-bound `ShredAuthorityMode`; `None == 0` is invalid. |
| `IShredRegistry.recordShredAuthorized` | callable only by ConditionEngine. |
| `IShredRegistry.finalizeShred` | permissionless after authorized/challenge/latency/precondition checks. |
| `IG4RefusalRegistry.refusePublic` / `refuseEncrypted` / `recordSignal(blocking=true)` | `OPERATOR_ROLE`; rejects advisory-only `0x0A`. |
| `IG4RefusalRegistry.recordAdvisorySignal` / `recordSignal(blocking=false)` | `OPERATOR_ROLE`; accepts advisory-only `0x0A` unless S2-6 later adds other advisory codes. |
| `IPasskeyRotationLog.appendRotation` | prior-key WebAuthn / rotation authorization validation; no global role shortcut. |
| `ISupersededCommitRegistry.recordSupersession` / correction | `REKEY_GOVERNANCE_ROLE` after TimelockController delay. |
| `IChallengeRegistry.openChallenge` | eligible challenger proof plus required bond. |
| `IChallengeRegistry.confirmNoIntervention` / `haltCeremony` / `extendChallenge` | PDA-scoped `CHALLENGE_RESOLVER_ROLE`. |
| `IPausableSurface.pause` / `unpause` | `PAUSER_ROLE` plus PDA `PauseAuthorityMode` where the scope is PDA-bound. |

### §16.3 Admin renounce

Deploy scripts must execute an environment-gated irreversible admin renounce:

1. Deploy implementations/proxies.
2. Initialize with deployer as temporary admin.
3. Grant roles to TimelockController and operational multisigs.
4. Verify role graph.
5. Set `RENOUNCE_ADMIN=true` for final script step.
6. Deployer renounces all admin roles.

No deployer EOA remains with upgrade, registry-admin, or default-admin power.

### §16.4 Role-grant invariants

The following invariants are mandatory:

- `UPGRADER_ROLE` has exactly one holder: TimelockController.
- `DEFAULT_ADMIN_ROLE` has exactly one holder per upgradeable contract after deploy: TimelockController.
- `SECURITY_COUNCIL_ROLE` cannot grant itself registry-addition power.
- `EMERGENCY_GOVERNANCE_ROLE` can suspend security council deprecation authority only for the bounded circuit-breaker duration.
- `ORACLE_SUBMITTER_ROLE` cannot add or rotate oracle registry entries.
- `CHALLENGE_RESOLVER_ROLE` is PDA-scoped and cannot resolve challenges for unrelated PDAs.
- `REKEY_GOVERNANCE_ROLE` cannot upgrade SupersededCommitRegistry.
- `LIT_GOVERNANCE_BRIDGE_ROLE` can record Lit assignments but cannot alter G4AuthorityRegistry or ConditionEngine.

### §16.5 Revocation discipline

Role revocations are timelocked unless the role is an operational hot key with an emergency revocation path explicitly listed in S2-6. Revoking an oracle submitter does not tombstone OracleRegistry entries; it only stops future submissions from that submitter account. Revoking a PDA resolver does not rewrite historical PDA resolver id; resolver rotation applies only to future PDAs unless the PDA was explicitly configured as updatable and update ceremony has completed.

### §16.6 Phase 1 governance caveat

Governance Phase 1 may have all CealisSecurityMultisig seats held by Cealis. Contracts must still implement the Phase 2 role model from launch. Public or partner-facing claims must not describe the Phase 1 multisig as independent-domain security. The contract surface provides friction and visibility in Phase 1; independent-domain defense begins only when external advisor seats are active.

## §17 - Deploy Order and Post-Deploy Config

### §17.1 Dependency graph

Deploy order:

1. TimelockController.
2. CealisSecurityMultisig and EmergencyGovernance.
3. Registry implementations and proxies: PluginHashRegistry, G4AuthorityRegistry, DSLVersionRegistry, OracleRegistry, OracleSchemaRegistry, QTSPRegistry.
4. GateRecipientPubkeyRegistry.
5. LitV3Assignment.
6. DisclosureRegistry.
7. G4RefusalRegistry.
8. PasskeyRotationLog.
9. SupersededCommitRegistry.
10. ChallengeRegistry.
11. ClaimDSL interpreter.
12. FSMInterpreter.
13. **Controlled-use registries (controlled-use deployments only; `commit_version = 0x0303` rollout boundary):** CredentialAnchorRegistry (§9.16A), SliceLayoutRegistry (§9.16B), MasterTokenRevocationRegistry (§9.16C), TokenRevocationRegistry (§9.16D — opt-in, deployed only when at least one PDA elects `revocation_mode = MASTER_AND_SUB_CRL`). Deployed BEFORE the controlled-use condition module so the module can resolve registry addresses at initialization. Non-controlled-use deployments SKIP this step.
14. Condition modules. **For controlled-use deployments, this step also includes PresentedTokenConditionModule (§4.11.5).** Module registration via `MODULE_ADMIN_ROLE` under TimelockController references the registries deployed at step 13.
15. AttestationGate.
16. ShredRegistry.
17. ConditionEngine.
18. Optional RevealAuthorizedEmitter.

The two controlled-use-only steps (13 and the PresentedTokenConditionModule portion of 14) are conditional on the partner deployment electing the controlled-use profile (`token_policy_config.enabled = true` in at least one PDA at deploy time, or in a future PDA per the topology-evolution path). Non-controlled-use deployments deploy steps 1-12 plus the original step 13-17 (now renumbered to 14-18 above with `PresentedTokenConditionModule` omitted from step 14 and the controlled-use registries omitted from step 13). The conditional deploy is documented in S2-6 operational ceremonies; the on-chain assertion at §17.3 is extended below.

### §17.2 Post-deploy config

Post-deploy script:

- wires ConditionEngine to modules, FSMInterpreter, AttestationGate, ShredRegistry, ChallengeRegistry.
- registers initial DSL version.
- registers initial Chainlink Automation time oracle and SubjectInitiated self-oracle schemas.
- registers initial G4 Phase 1 dev-scaffold entry and Phase 2 partner-ready entry when available.
- configures GateRecipientPubkeyRegistry roles; no per-commit pubkey entry is preloaded.
- configures DisclosureRegistry verifier/revocation roles and initial PLONK verifier refs where S2-7 on-chain verification is enabled.
- registers canonical plugin hash.
- grants roles and transfers admin to TimelockController.
- verifies Mode 3 rejection.
- verifies legal-effect PDA guardrails.
- verifies no non-timelock holder has `UPGRADER_ROLE`.
- **(controlled-use deployments only):** wires PresentedTokenConditionModule (§4.11.5) to CredentialAnchorRegistry (§9.16A), MasterTokenRevocationRegistry (§9.16C), SliceLayoutRegistry (§9.16B), and the opt-in TokenRevocationRegistry (§9.16D) where deployed; grants `CONDITION_ENGINE_ROLE` on the new registries to the ConditionEngine address; registers the two new key entries `K_G4_write_attest_pubkey` and `K_G4_audit_stream2_pubkey` in G4AuthorityRegistry (§9.6, extended per §16.1A and S2-8 §4.6); verifies Mode T cosign-gate consistency rule enforcement at PDA registration (§11.5); verifies the PresentedTokenCondition × DeadManSwitch composition is rejected at PDA validation (§4.11.5, S2-4 coordinated amendment).

### §17.3 Deployment assertions

The deployment script must assert, on-chain, before printing success:

- every proxy implementation address is non-zero.
- every initializer has run exactly once.
- every registry has TimelockController as default admin.
- every registry has CealisSecurityMultisig assigned only the deprecation role, not addition or upgrade roles.
- every UUPS contract has TimelockController as sole upgrader.
- ConditionEngine knows all nine module addresses.
- every module recognizes ConditionEngine as its only state-changing dispatcher where applicable.
- ShredRegistry recognizes ConditionEngine for `postChallengeRevealInProgress` reads.
- ChallengeRegistry recognizes ConditionEngine for challenge-window opening.
- G4RefusalRegistry recognizes the current G4 authority or operator role.
- GateRecipientPubkeyRegistry recognizes only the configured publisher role for per-commit entries and TimelockController for long-lived drand committee entries.
- DisclosureRegistry recognizes `SD_OPERATOR_ROLE` and `REVOCATION_ADMIN_ROLE` only on intended operators/admins.
- LitV3Assignment recognizes the Lit governance bridge only.
- PasskeyRotationLog canonical deployment address is recorded in configurator metadata.
- initial DSL version is active and not deprecated.
- initial oracle schema entries exist for Chainlink Automation and SubjectInitiated.
- Phase 1 G4 entry, if deployed, is marked dev-scaffold in metadata.
- Phase 2 G4 entry, if available, is marked partner-ready.
- **(controlled-use deployments only):** PresentedTokenConditionModule is registered in ConditionEngine module catalog at `commit_version = 0x0303` rollout block or later; CredentialAnchorRegistry / SliceLayoutRegistry / MasterTokenRevocationRegistry recognize ConditionEngine for `CONDITION_ENGINE_ROLE` writes; TokenRevocationRegistry (opt-in) is deployed iff at least one PDA elects `revocation_mode = MASTER_AND_SUB_CRL`; G4AuthorityRegistry holds the two new key entries (`K_G4_write_attest_pubkey`, `K_G4_audit_stream2_pubkey`); the Mode T `stream2_cosign_gate` enum and the vendor-family consistency rule (§11.5) are enforced at PDA validation; the DeadManSwitch × PresentedTokenCondition forbidden composition (§4.11.5) is rejected at PDA validation.

If any assertion fails, the deploy script must stop before admin renounce. A partially deployed contract set is not a valid Cealis environment.

### §17.4 Upgrade dry-run requirements

Before any future upgrade is queued, the proposer must run:

- storage layout diff against current implementation.
- selector clash check.
- initializer/reinitializer check.
- role graph diff.
- event ABI diff.
- custom error ABI diff.
- invariant suite focused on the changed contract plus ConditionEngine/ShredRegistry integration.
- migration script dry-run on a fork at a recent Base block.

The timelock proposal metadata hash should include these artifacts. The chain cannot enforce artifact quality, but the governance process can make omission visible.

## §18 - UUPS Upgrade Strategy

### §18.1 Inheritance

Every Cealis upgradeable contract inherits `Initializable` and `UUPSUpgradeable`. Contracts that use access control inherit `AccessControlUpgradeable`. Contracts with pause inherit `PausableUpgradeable`. Initializers call all parent initializers exactly once.

### §18.2 Authorization

```solidity
function _authorizeUpgrade(address newImplementation)
    internal
    override
    onlyRole(UPGRADER_ROLE)
{}
```

`UPGRADER_ROLE` is TimelockController only. Emergency governance cannot upgrade directly; it may pause or suspend security deprecation authority only where the contract exposes that specific power.

### §18.3 Storage invariant

Per contract: storage reorder is forbidden. Enum reorder is forbidden. Mapping key meaning is forbidden to change. Future fields append. Stage 3 tests include storage layout snapshots. Future upgrades include diff review before queueing timelock operation.

### §18.4 Phase 1 to Phase 2 G4

Phase 1 to Phase 2 G4 transition is not a contract upgrade. It is a registry-state transition: G4AuthorityRegistry contains both phase entry types and PDAs bind phase at commit. Historical Phase 1 commits remain valid under historical lookup; new partner/legal-effect commits use Phase 2.

### §18.5 Upgrade blast-radius controls

S2-2 contracts should be split so upgrades have bounded blast radius:

- Registry implementation upgrades do not upgrade ConditionEngine.
- Module upgrades add new module ids rather than mutating old module semantics.
- ClaimDSL interpreter upgrades add new DSLVersionRegistry entries.
- PasskeyRotationLog upgrades preserve old entry decoding.
- ShredRegistry upgrades cannot reset `isShredded`.
- G4RefusalRegistry upgrades cannot delete refusal records.
- SupersededCommitRegistry upgrades cannot rewrite lineage.

This split is why S2-2 permits an optional RevealAuthorizedEmitter. If ConditionEngine becomes too large or needs module-dispatch upgrades, the event ABI can remain stable behind a narrow emitter controlled only by ConditionEngine.

### §18.6 Non-upgradeable decisions

Some values are intentionally not mutable by upgrade:

- already emitted `RevealAuthorized` events.
- finalized shred state.
- historical registry entries.
- PasskeyRotationLog prior entries.
- consumed subject/action nonces.
- challenge records after terminal status.
- supersession lineage once recorded.

An upgrade may add new views or new future-state behavior, but it cannot rewrite these historical facts without violating chain-of-custody.

## §19 - Gas-Budget Analysis

### §19.1 Targets

| Operation | Target order | Notes |
|---|---:|---|
| `computeAuthorizationId` / `computeHCommit` | < 50k | pure helper, mostly hashing |
| `advanceFSM` simple transition | 150k-350k | oracle signature + storage update |
| `advanceFSM` complex transition | 350k-800k | bounded AST + proofs |
| Mode P chain-native predicate | 100k-300k | no oracle signature |
| Oracle attestation submit | 250k-700k | signature + registry/schema reads |
| `Composed` worst-case 9 child modules | 900k-2.5M | bounded; should rarely execute as one tx |
| Registry add | 120k-300k | timelocked execution |
| Deprecation flag set | 80k-180k | no delay for non-canonical |
| `publishDisclosure` | 80k + calldata | summary capped at 4096 bytes |
| Shred request/authorize | 180k-600k | condition-dependent |
| RevealAuthorized emission path | 150k-900k | depends on module |

### §19.2 AttestationGate budget

On-chain oracle signature verification is the expensive path. Stage 3 should prefer digest verification and precompiled/ecrecover-compatible schemes where possible. BLS/DCAP custody σ verification remains off-chain or through dedicated verifier contracts consumed by S2-3; ConditionEngine must not try to verify every custody proof inside the reveal event transaction.

### §19.3 Gas failure semantics

Gas exhaustion is fail-closed. A condition that cannot be evaluated within its declared budget does not fire. Configurator dry-run simulation must catch templates whose worst-case path exceeds per-PDA max gas.

### §19.4 Storage cost expectations

The heaviest storage surfaces are PasskeyRotationLog entries, challenge records, and registry metadata. Condition hot paths should avoid copying these large records. Expected posture:

- PasskeyRotationLog stores large ML-KEM pubkeys because S2-1 Architecture A requires them. It is not in the reveal authorization hot path.
- ChallengeRegistry stores counter-attestation refs, not full counter-attestations.
- OracleSchemaRegistry stores example hashes, not examples.
- Registry disclosure summaries are events plus minimal verification state; full advisory body is off-chain.
- ConditionEngine stores refs to module configs, not full configs.

Where data is large and only auditors need it, prefer event emission of digest refs plus off-chain artifact. Where data is needed for future on-chain decisions, store the minimal digest or scalar that makes the decision deterministic.

### §19.5 Batching posture

Batch functions are permitted for operational efficiency only when each item has independent failure reporting or the entire batch is atomic. For registry additions and PDA registrations, atomic batch is acceptable because a partial config is dangerous. For oracle attestation submissions, partial success is dangerous unless each accepted attestation emits its own event and callers can recover deterministically. Stage 3 should start with no complex batching on ceremony-critical paths; add batching only after single-item invariants are stable.

### §19.6 EIP-170 bytecode-size gate

Every Stage 3 PR that changes Solidity must run `forge build --sizes` and include the relevant runtime-size delta in the verification notes. Runtime bytecode gates:

| Runtime size | Required action |
|---:|---|
| `> 22,000` bytes | warning; identify largest functions/libraries. |
| `> 23,500` bytes | mandatory extraction review before merge. |
| `> 24,000` bytes | block merge unless Simon explicitly accepts the deployment-risk tradeoff. |
| `>= 24,576` bytes | hard fail under EIP-170; contract cannot deploy. |

Extraction candidates are module dispatch, registry decoding, event-emitter wrappers, and pure helper libraries. Extraction must not create an alternate `RevealAuthorized` path; any emitter wrapper remains callable only by ConditionEngine.

## §20 - Test Coverage Expectations

### §20.1 Unit tests

Each contract gets unit tests for initialization, role grants, role denials, custom errors, events, pause behavior, upgrade authorization, and storage accessors. Helpers get fixed-vector tests against S2-1 vectors once Stage 3 produces them.

### §20.2 Fuzz tests

Fuzz targets:

- identifier helpers vs reference implementation.
- Claim DSL AST evaluation.
- FSM transitions and terminal-state reachability.
- ComposedModule boolean tree equivalence.
- challenge-window edge timestamps.
- ShredRegistry guardrail.
- registry effective/tombstone/deprecation at historical blocks.
- OracleSchemaRegistry `getSchemaAt` rotation: commit at block N binds schema S1; S1 tombstoned at M > N; `getSchemaAt(S1, N)` succeeds and `getSchemaAt(S1, M)` tombstones for future commitments.
- Mode 3 rejection.
- legal-effect PDA guardrails.

### §20.3 Invariant tests

Mandatory invariants:

- Only ConditionEngine can emit/cause `RevealAuthorized`.
- No `RevealAuthorized` after finalized shred.
- No shred finalization while `postChallengeRevealInProgress`.
- No legal-effect PDA with class-wide halt opt-out.
- No legal-effect PDA with Phase 1 G4.
- No Mode 3 active PDA at V2 launch.
- No upgrade without TimelockController.
- Deprecation auto-clear and cooldown cannot be bypassed.
- Registry historical lookup returns the entry valid at target block.
- Pausing never mutates commitment content.

### §20.4 Integration tests

Stage 3 integration tests simulate at least:

- KYC-lending PaymentObligation Tier A zero-window.
- KYC-lending oracle-attested Tier B 14-day challenge.
- Testament DeadManSwitch plus conditional recipient.
- Evidence OracleAttestation with 7-day challenge.
- SubjectInitiated consumer shred.
- Re-key supersession lineage.
- Phase 1 historical G4 and Phase 2 current G4 lookup.

### §20.5 Negative tests

Every implementation must include negative tests for:

- direct module call attempting to emit reveal without ConditionEngine.
- registry deprecation after authorization not halting an in-flight reveal through registry snapshot.
- registry deprecation before authorization halting.
- subject shred attempt during `PostChallengeRevealInProgress`.
- operator shred attempt without authority mode.
- Timelock shred attempt before timelock authority matures.
- Mode 3 recipient hidden in a mixed recipient set.
- synced passkey authenticator class on legal-effect PDA.
- class-wide halt opt-out on legal-effect PDA.
- Phase 1 G4 on legal-effect PDA.
- `custom_predicate` used while disabled.
- Claim DSL path access to unknown schema field.
- multi-party duplicate signer.
- heartbeat after terminal missed state.
- challenge with ineligible challenger.
- resolver extension beyond cap.
- disclosure publication with wrong hash.
- deprecation re-set during cooldown by security multisig.
- non-timelock caller attempting upgrade.

### §20.6 Differential tests

Stage 3 should maintain a TypeScript or Rust reference model for:

- identifier helpers.
- Claim DSL evaluation.
- FSM transition.
- registry historical lookup.
- challenge-window state.
- shred lifecycle.

Foundry tests fuzz inputs against the reference model. Differential tests matter because the spec has many boundary rules that are easy to implement with off-by-one block or timestamp errors.

### §20.7 Gas regression tests

Gas snapshots should be kept per operation class rather than only per function, because module behavior varies by PDA config. Suggested snapshots:

- TimeLock zero-window authorize.
- PaymentObligation chain-native authorize.
- PaymentObligation oracle-attested authorize.
- OracleAttestation Claim with 10 AST nodes.
- Claim with max allowed AST nodes.
- FSM simple transition.
- FSM terminal transition.
- Composed with 3 children.
- Composed with 9 children.
- Shred request zero-window.
- Shred request with challenge.
- Registry add.
- Registry deprecate.
- PasskeyRotationLog append entry 0.
- PasskeyRotationLog append rotation entry.

Gas regressions above 15% require explanation in PR/release notes.

Gas regression verification must include the `forge build --sizes` bytecode table for any changed contract. A gas improvement that pushes runtime bytecode across the §19.6 extraction thresholds is not merge-ready until size is addressed or explicitly accepted.

## §21 - Cross-References

### §21.1 S2-1 consumption table

| S2-1 section | S2-2 use |
|---|---|
| §0 | document identity, naming, σ-as-authorization, Phase 1/2 framing |
| §1 | hash/SCALE/endian/fail-closed conventions |
| §2 | all TAG imports; no new tags |
| §3 | composite identifier helpers and PDA/hCommit fields |
| §4 | commit_AAD refs and registry binding |
| §10 | Mode 3 rejection and `CealisConditionalRecipient` domain |
| §11 | endpoint attestation and LitV3Assignment/G4Authority surfaces |
| §12 | five registries and DeprecationFlag |
| §13 | PasskeyRotationLog ABI |
| §14 | combiner's on-chain read surfaces |
| §16 | error naming and no σ/PII error context |
| §17/App. C | S2-2 ownership and scope-out boundaries |

### §21.2 S2-3 consumption surface

S2-3 consumes registry addresses, LitV3Assignment, GateRecipientPubkeyRegistry, G4AuthorityRegistry phase entries, AttestationGate digest conventions, OracleRegistry formats, DCAP verifier refs, ShredRegistry current-state reads, and the no-σ-on-chain boundary. S2-3 pins libraries and implements custody σ verification plus Shamir-share reconstruction off-chain or through dedicated verifier adapters.

### §21.3 S2-4 consumption surface

S2-4 consumes PDA registration structs, module config structs, legal-effect guardrails, challenge-window rules, conditional-recipient Mode 3 rejection, G3 choice enum, G4 phase enum, shred authority enum, and pda_root helper behavior.

### §21.4 S2-5 consumption surface

S2-5 consumes lifecycle events: `RevealAuthorized`, `ShredAuthorized`, `ShredFinalized`, blocking `RefusalSignal`, advisory `AdvisorySignal`, `ChallengeOpened`, `ChallengeResolved`, and registry deprecation events. Delivery idempotency keys are defined from these event fields.

### §21.5 S2-6 consumption surface

S2-6 consumes TimelockController operations, registry addition/deprecation, disclosure publication, external advisor seating, emergency governance, upgrade ceremonies, Phase 1 to Phase 2 G4 registry transition, Mode 3 activation gates, and **ChallengeRegistry pause governance** (per §14.1: pause blocks new challenges only when configured; resolving active legal-effect challenges requires care and is governed by S2-6 ceremony spec).

### §21.6 S2-7 consumption surface

S2-7 consumes DisclosureRegistry isolation, PLONK proof-verifier and revocation surfaces, SD tag namespace separation, and the rule that escrow contracts do not parse SD plaintext/proofs except through S2-7-defined verifier surfaces.

### §21.7 Cross-spec author-lock disciplines

Author-locked surfaces:

- S2-1 §2 `TAG_*_V3` imports.
- S2-1 pda_root and h_commit field order.
- Mode 3 reserved defense-in-depth.
- G4 Phase 1/Phase 2 historical lookup.
- DeprecationFlag governance shape.
- PasskeyRotationLog digest formulas.
- SupersededCommitRegistry lookup hash.
- no σ values on-chain.

### §21.8 Open architectural questions

1. BP-13/BP-14/BP-15 disposition is closed by `v3-registry-class-discipline.md` (internal design note, not in this export): BP-13 rejected, BP-14 accepted, BP-15 rejected.
2. `flows-spec-final.md` line references for state-read DSL operands point to the module catalog in the current file; no separate operand list exists in the source corpus. S2-2 therefore uses the 12-operator list from Stage-0 and WP §B/§F.

### §21.9 S2-2 internal conformance checklist

An implementation conforms to S2-2 only if all of these statements are true:

- `RevealAuthorized` can be emitted only by ConditionEngine or its dedicated emitter called by ConditionEngine.
- every condition module routes terminal state through ConditionEngine.
- every reveal path checks ShredRegistry.
- every shred path checks `post_challenge_reveal_in_progress`.
- every legal-effect PDA rejects Phase 1 G4.
- every legal-effect PDA rejects `cealis_class_wide_halt_opt_out`.
- every V2 launch PDA rejects conditional recipient Mode 3.
- every Cealis-governed V3 registry plus OracleSchemaRegistry supports historical lookup.
- every Cealis-governed V3 registry supports DeprecationFlag disclosure and auto-clear; SupersededCommitRegistry follows the §9.10B carve-out instead.
- every UUPS upgrade is timelocked.
- every custom error avoids plaintext PII and σ bytes.
- no public/external function accepts custody σ bytes.
- no event emits custody σ bytes.
- no contract computes file_key, Shamir shares, or DEK. *(Distinguishing note: this prohibits any contract from acting as a custodian / computing the actual DEK. Stage 3 view helpers may mirror public identifier inputs for auditor-side reproducibility, but they cannot accept σ values, wrapped shares, or recovered shares.)*
- no contract stores plaintext, ciphertext payload, or vault object bytes.
- no module can call arbitrary caller-supplied external addresses.
- every external call target is PDA-bound, registry-bound, or timelock-governed.

### §21.10 BP-N candidates surfaced by S2-2

S2-2 currently surfaces no open S2-1 BP-N candidates. The prior `commit_AAD` byte-count note and BP-13/BP-14/BP-15 split-brain are closed by the 2026-05-05 backprop cycle.

### §21.11 Auditor threat matrix

| Threat | Contract defense | Residual owner |
|---|---|---|
| Module emits reveal directly | only ConditionEngine/emitter has event path | Stage 3 tests |
| Shred races post-challenge reveal | ShredRegistry checks `postChallengeRevealInProgress` | S2-5 vault coordination |
| Registry race | historical lookup at authorization block | S2-3/S2-5 clients use correct block |
| Modified plugin | PluginHashRegistry and S2-1 combiner check | S2-6 distribution |
| G4 Phase 1 used for legal-effect PDA | contract/configurator guardrail | S2-4 UI/API |
| Class-wide halt opt-out on legal-effect PDA | contract/configurator guardrail | S2-4 UI/API |
| Mode 3 activated silently | contract rejection plus no governance toggle | S2-6 activation ceremony |
| Oracle plaintext leaks on-chain | digest-only attestation storage | S2-5 artifact handling |
| σ leakage on-chain | no σ calldata/storage/events | S2-3/S2-5 transport |
| Challenge resolver overreach | bounded halt/confirm/extend only | S2-6 resolver ops |
| Upgrade rewrites history | UUPS timelock plus append-only storage | governance review |
| Emergency deprecation abuse | disclosure, auto-clear, cooldown | S2-6 governance |
| Passkey rotation forgery | prior-key WebAuthn assertion chain | S2-3 WebAuthn verification |
| Supersession rewrite | timelocked RekeyGovernance and append-only lineage | S2-6 ceremony |
| SD/escrow crossing | DisclosureRegistry isolated from ConditionEngine release path | S2-7 |

Auditor focus should stay on whether the contract implementation preserves the separation between "authorization event visible on chain" and "decryption key material off chain". Most serious failures collapse that boundary either by emitting too much, accepting too much, or letting a bypass event stand in for the predefined condition.

### §21.12 Implementation handoff boundaries

The Solidity engineer implementing Stage 3 should treat S2-2 as an interface and invariant spec, not as a mandate to place every named surface in a separate contract. Consolidation is allowed if it preserves:

- independent upgrade blast radius where this spec requires it.
- externally visible ABI compatibility for named interfaces.
- role separation.
- event semantics.
- storage history.
- audit readability.

For example, OracleRegistry and OracleSchemaRegistry may share an implementation if the ABI still exposes both surfaces and schema history cannot be corrupted by oracle rotation. Condition modules may share a base class. RevealAuthorizedEmitter may be omitted if ConditionEngine remains small enough and event ABI stability is otherwise protected. Conversely, if a combined implementation makes storage layout or upgrade review harder, split the contract even if gas would be slightly higher.

### §21.13 Contract review checklist

Before marking a Stage 3 implementation of S2-2 ready for external audit, reviewers should answer:

1. Can any non-ConditionEngine contract emit `RevealAuthorized` or equivalent?
2. Can any state-changing function publish σ bytes?
3. Can any calldata path require σ bytes to be sent to chain?
4. Can any module accept an arbitrary external contract address from calldata?
5. Can a PDA be registered without the shred guardrail?
6. Can a legal-effect PDA be registered under Phase 1?
7. Can a legal-effect PDA opt out of class-wide halt?
8. Can Mode 3 be selected through a hidden update path?
9. Can a registry deprecation be set without disclosure hash?
10. Can a registry deprecation persist past 72h without disclosure?
11. Can the security multisig re-deprecate during cooldown?
12. Can a deployer EOA retain upgrade power?
13. Can storage upgrade reorder existing fields?
14. Can a challenge resolver grant content or only halt/confirm/extend?
15. Can shred finalize during post-challenge reveal-in-progress?
16. Can a consumed nonce be reused?
17. Can old registry entries become unverifiable after rotation?
18. Can oracle plaintext enter logs or events?
19. Can SD verifier state affect escrow reveal authorization?
20. Can a re-key lineage record be overwritten?

Any "yes" answer is a blocking issue unless the specific behavior is intentionally re-specified in a later Simon-approved Stage-2 amendment.

### §21.14 Stage 3 readiness packet

Stage 3 implementation must treat S2-2 as an interface and invariant source, not as prose inspiration. A Solidity engineer beginning Stage 3 should create an implementation checklist with one row for every App. A interface, one row for every custom error, and one row for every event. Each row maps to a concrete Solidity file, a Foundry unit-test file, and at least one negative test. If an interface function is intentionally omitted because the implementation folds two contracts together, the omission must be documented in the Stage 3 conformance report with the replacement function name and the reason the observable ABI remains equivalent for downstream consumers.

The first Stage 3 milestone is not deployment. It is compilation of empty or minimally functional contract shells that expose the complete App. A ABI, define the complete role constants, inherit the correct upgradeability base classes, and compile under Solidity 0.8.28 with Cancun enabled. This shell milestone catches naming drift, inheritance drift, and role-surface omissions before implementation logic spreads across files. The second milestone wires storage and initializers. No condition logic should be implemented before the initializer and storage layout discipline has been reviewed, because UUPS mistakes are expensive to unwind after tests begin to assume state shape.

The third milestone implements pure helper libraries from §3: identifier recomputation, registry ref recomputation, struct hashing, and event ID derivation. These functions have the cleanest deterministic test surface and should be locked before ConditionEngine or registries call them. The fourth milestone implements registries, because ConditionEngine, AttestationGate, ShredRegistry, and DSL evaluation all depend on registry read semantics. The fifth milestone implements ConditionEngine plus modules. The sixth milestone implements AttestationGate and G4 refusal integration. The final milestone composes the reveal, challenge, and shred paths and runs invariant suites over cross-contract state.

Every Stage 3 PR should state whether it changes only ABI, only storage, only logic, or a combination. ABI changes after App. A import require S2-2 patch review. Storage changes after the storage milestone require storage-layout diff evidence. Logic changes require Foundry tests and one sentence explaining which universal-tripwire path they preserve. This is intentionally strict: the smart-contract layer is the public enforcement surface, so silent "small" changes to ABI or storage are architecture changes.

### §21.15 Auditor traceability packet

An external auditor should be able to audit from four artifacts without reading project history: S2-1 for cryptographic constructions, S2-2 for contract surfaces, the Stage 3 implementation, and the Stage 3 conformance report. The conformance report must include a table with columns: S2-2 section, implementation file, test file, invariant ID, and residual risk. For example, §10 ShredRegistry maps to its Solidity implementation, `ShredRegistry.t.sol`, invariant tests proving no shred can finalize during `post_challenge_reveal_in_progress`, and residual risk around off-chain vault deletion that is explicitly forwarded to S2-5/S2-6 rather than hidden.

Auditors should start with the universal tripwire rather than with individual contracts. The first trace is positive: configured PDA -> condition fires -> `RevealAuthorized` event -> gate metadata and refusal reads remain coherent -> off-chain gates can produce the required σ authorizations. The second trace is negative: configured PDA -> challenge opens -> challenge active/refused -> ConditionEngine cannot emit a second reveal -> G4 refusal state blocks σ_G4 -> shred cannot bypass the active challenge. The third trace is governance: registry deprecates an authority -> historical commits still resolve their original authority -> new commits reject deprecated authority after timelock/cooldown. The fourth trace is privacy: no calldata, storage, event, revert argument, or registry entry contains plaintext PII or custody σ bytes.

The auditor should treat every `try*` view function as SDK convenience only. A successful `tryEvaluateCondition`, `tryVerifyGateBundle`, or `tryEvaluateDSL` call is not a permission grant unless the corresponding state-changing function runs and emits the correct event under the correct role and pause posture. Conversely, a reverting state-changing path is not a bug merely because a view predicted success at an older block. Freshness is part of the state-changing function, not the view.

The auditor should also separate phase logic from scope logic. Phase 1 G4 and Phase 2 G4 both exist in the registry surface; a legal-effect PDA cannot choose Phase 1, but the chain must still read historical Phase 1 commits after cutover. Mode 3 is different: it is not a phased capability at V2 launch. It is reserved and must be rejected at every configurator and contract entry path. Treating Mode 3 like Phase 1/Phase 2 is a category error.

### §21.16 Downstream change-control rules

Downstream specs may reference S2-2 but may not silently redefine its contract names, event names, role names, or identifier meanings. S2-3 may define the off-chain custody calls that watch `RevealAuthorized`, but it may not add σ-bearing calldata to AttestationGate. S2-4 may define configurator UX and PDA templates, but it may not allow Mode 3 selection or legal-effect Phase 1 selection. S2-5 may define ingestion-delivery API idempotency and vault deletion, but it may not emit alternative reveal events. S2-6 may define operational ceremonies and registry governance runbooks, but it may not weaken timelock, cooldown, or tombstone semantics. S2-7 may define DisclosureRegistry and PLONK verifier details, but it may not route SD failure into escrow failure.

If a downstream author believes one of those surfaces is wrong, the change path is explicit: write a BP-N candidate or S2-2 erratum, cite the exact section and downstream breakage, and ask Simon/Claude Code to decide whether to patch S2-2. The downstream document should then carry an `imports patched S2-2 revision` note. This preserves S2-2's role as the canonical contract surface and prevents a later spec from creating a second, incompatible ABI through casual wording.

## App. A - Full Contract Interface Enumeration

The interfaces below are binding external surfaces. Implementations may split internal libraries differently, but public/proxy behavior must remain compatible.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

enum CeremonyAxis { Reveal, Shred }
enum ConditionMode { None, ModeF, ModeP }
enum G3Choice { Dcipher, Drand }
enum G4Phase { None, Phase1, Phase2 }
enum PauseAuthorityMode { Partner, Joint, None }
/// @dev None == 0 is an invalid Solidity sentinel and is not PDA-selectable.
enum ShredAuthorityMode { None, Subject, Joint, Operator, Timelock, Disabled }
enum ConditionalRecipientMode { None, PasskeyAccount, WalletEOA, WalletEIP1271Reserved }
enum GateKind { LitV3, Dcipher, Drand, G4, ConditionalRecipient }
enum ShredState { None, Requested, Authorized, Finalized, Blocked, ChallengeOpen, Shredded }
enum LifecycleState {
    Unregistered,
    Registered,
    RevealConditionMet,
    RevealChallengeOpen,
    PostChallengeRevealInProgress,
    RevealCompleted,
    ShredConditionMet,
    ShredChallengeOpen,
    Shredded,
    Paused
}

uint64 constant MAX_OPERATIONAL_PAUSE_SECONDS = 259200; // 72 hours
uint64 constant MAX_REGISTRY_PAUSE_SECONDS = 604800; // 7 days
uint64 constant MAX_EMERGENCY_PAUSE_SECONDS = 604800; // 7 days

struct PdaRootFields {
    bytes32 pdaId;
    uint64 pdaVersion;
    uint8 revealConditionMode;
    bytes32 revealConditionSpecHash;
    uint8 shredConditionMode;
    bytes32 shredConditionSpecHash;
    bytes32 oracleReferencesRoot;
    bytes32 dslVersion;
    bytes32 wasmPredicateHashesRoot;
    bytes32 submitterSetsRoot;
    bytes32 pauseAuthorityId;
    bytes32 ceremonyResolverId;
    bytes32 eligibleChallengersRevealRoot;
    bytes32 eligibleChallengersShredRoot;
    bytes32 templateId;
    bytes32 partnerId;
    uint8 subjectAuthenticatorClass;
    bytes32 qtspProviderRef;
    bool art9Scoped;
    uint8 art9BasisId;
    bool legalEffectExpected;
    bool cealisClassWideHaltOptOut;
    uint64 minimumShredLatency;
    bytes32 applicableJurisdiction;
    bool conditionalRecipientsUpdatable;
    bool subjectLivenessRequiredAtFire;
    bool emergencyResponseBrickingAcknowledgment;
    bool timeCriticalPdaFlag;
    bool pdaUpdatable;
}

struct HCommitFields {
    bytes32 authorizationId;
    bytes32 pdaRoot;
    bytes32 schemaDigest;
    bytes32 ciphertextDigest;
    bytes32 aadDigest;
    bytes32 compositeIdentityDigest;
    bytes32 endpointAttestationDigest;
    uint64 retentionWindow;
    bytes32 shredAuthorityId;
    bytes32 recipientsRoot;
    uint32 revealChallengeWindow;
    uint32 shredChallengeWindow;
    uint8 g3Choice;
    uint8 phase;
    uint16 commitVersion;
}

struct AxisConfig {
    ConditionMode mode;
    bytes32 conditionRef;
    bytes32 conditionSpecHash;
    uint32 challengeWindow;
    bytes32 eligibleChallengersRoot;
    bytes32 resolverId;
}

struct RegistryRefs {
    bytes32 pluginVersionDigest;
    bytes32 g4AuthorityRef;
    bytes32 g3AuthorityRef;
    bytes32 oracleReferencesRoot;
    bytes32 oracleSchemaRoot;
    bytes32 dslVersionRef;
    bytes32 qtspProviderRef;
    bytes32 gateRecipientPubkeyRoot;
}

struct LegalFlags {
    bool legalEffectExpected;
    bool cealisClassWideHaltOptOut;
    bool qesRequired;
    bool art9Scoped;
    uint8 art9BasisId;
    uint8 subjectAuthenticatorClass;
    G4Phase requiredG4Phase;
}

struct PDARegistration {
    PdaRootFields pdaRootFields;
    HCommitFields hCommitFields;
    AxisConfig revealAxis;
    AxisConfig shredAxis;
    RegistryRefs registryRefs;
    LegalFlags legalFlags;
    PauseAuthorityMode pauseAuthorityMode;
    bool shredGuardrailCompiled;
    bytes32 conditionalRecipientPolicyDigest;
    ConditionalRecipientMode[] conditionalRecipientModes;
}

struct FSMAdvanceResult {
    bool terminal;
    uint32 newState;
    bytes32 conditionRef;
}

struct DeprecationFlag {
    bool deprecated;
    uint64 deprecationBlockTimestamp;
    uint8 deprecationReasonCode;
    bytes32 disclosureCid;
    bytes32 disclosureCommitHash;
    uint64 disclosureVerifiedBlock;
    uint64 autoClearTimestamp;
    bool isCanonicalAtSet;
}

interface ICealisIdentifierHelpers {
    /// @notice Imports TAG_SUBJECT_V3 from S2-1 §2.3.1.
    function computeSubjectCommitmentV3(bytes32 personKey, bytes32 partnerNamespace, bytes32 registrationNonce)
        external
        pure
        returns (bytes32);

    /// @notice Imports TAG_AUTHID_V3 from S2-1 §2.3.1.
    function computeAuthorizationId(bytes32 subjectCommitmentV3, bytes32 pdaId, uint64 pdaVersion, uint64 epoch, bytes32 nonce)
        external
        pure
        returns (bytes32);

    /// @notice Imports TAG_PDA_ROOT_V3 from S2-1 §2.3.1 and S2-1 §3.3 field order.
    function computePdaRoot(PdaRootFields calldata fields) external pure returns (bytes32);

    /// @notice Imports TAG_COMMIT_V3 from S2-1 §2.3.1 and S2-1 §3.4 field order.
    function computeHCommit(HCommitFields calldata fields) external pure returns (bytes32);

    /// @notice Imports TAG_PLUGIN_VERSION_V3 from S2-1 §2.3.4.
    function computePluginVersionDigest(bytes32 canonicalBinaryHash) external pure returns (bytes32);

    /// @notice Imports TAG_G4_ATTESTATION_AUTHORITY_V3 from S2-1 §2.3.3.
    function computeG4AuthorityRef(bytes calldata authorityPubkey) external pure returns (bytes32);

    /// @notice Imports TAG_SUPERSEDED_COMMIT_REGISTRY_V3 from S2-1 §2.3.4.
    function computeSupersededCommitLookup(bytes32 supersededCommitRef, uint16 commitGeneration)
        external
        pure
        returns (bytes32);
}

interface IConditionEngine {
    error ConditionUnknownAuthorization(bytes32 authorizationId);
    error ConditionAlreadyRegistered(bytes32 authorizationId);
    error ConditionInvalidMode(uint8 mode);
    error ConditionPaused(bytes32 authorizationId);
    error ConditionShredded(bytes32 hCommit);
    error ConditionNotMet(bytes32 authorizationId, CeremonyAxis axis);
    error ConditionChallengeWindowActive(bytes32 authorizationId, CeremonyAxis axis);
    error ConditionMode3Reserved(bytes32 authorizationId);
    error ConditionLegalEffectPhaseInvalid(bytes32 authorizationId, uint8 phase);
    error ConditionLegalEffectHaltOptOutForbidden(bytes32 authorizationId);
    error ConditionShredGuardrailMissing(bytes32 authorizationId);
    error ConditionPdaRootMismatch(bytes32 computed, bytes32 supplied);
    error ConditionHCommitPdaRootMismatch(bytes32 hCommitPdaRoot, bytes32 computedPdaRoot);
    error ConditionPauseAuthorityInvalid(uint8 mode);

    event PDARegistered(bytes32 indexed authorizationId, bytes32 indexed hCommit, bytes32 indexed pdaRoot, bytes32 partnerId);
    event RevealAuthorized(
        bytes32 indexed authorizationId,
        bytes32 indexed hCommit,
        bytes32 indexed pdaRoot,
        uint64 authorizationBlock,
        uint64 authorizationTimestamp,
        uint32 challengeWindow,
        bytes32 conditionRef
    );
    event ShredAuthorized(
        bytes32 indexed authorizationId,
        bytes32 indexed hCommit,
        bytes32 indexed pdaRoot,
        uint64 authorizationBlock,
        uint64 authorizationTimestamp,
        uint32 challengeWindow,
        bytes32 conditionRef
    );
    event LifecycleStateChanged(bytes32 indexed authorizationId, LifecycleState oldState, LifecycleState newState);

    /// @notice Recomputes pdaRoot/hCommit from concrete fields, validates guardrails, and stores the concrete fields.
    function registerPDA(PDARegistration calldata registration) external;

    /*
    Hash-only registration is forbidden. A conforming implementation validates:
    - computePdaRoot(registration.pdaRootFields)
    - registration.hCommitFields.pdaRoot == computed pdaRoot
    - computeHCommit(registration.hCommitFields)
    - reveal/shred axis configs, challenge windows, G3/G4 phase, registry refs, legal flags,
      pause authority, shred guardrail, and conditional-recipient modes.
    */

    function authorizeReveal(bytes32 authorizationId, bytes32 evidenceRef) external;
    function authorizeShred(bytes32 authorizationId, bytes32 evidenceRef) external;
    function advanceFSM(
        bytes32 authorizationId,
        CeremonyAxis axis,
        bytes32 transitionId,
        bytes32 attestationDigest,
        bytes calldata transitionProof
    ) external returns (FSMAdvanceResult memory result);
    function canGatesSign(bytes32 authorizationId) external view returns (bool);
    function postChallengeRevealInProgress(bytes32 authorizationId) external view returns (bool);
    function lifecycleState(bytes32 authorizationId) external view returns (LifecycleState);
}

interface IConditionModule {
    error ModuleUnauthorizedCaller(address caller);
    error ModuleUnknownAuthorization(bytes32 authorizationId);
    error ModuleConditionFalse(bytes32 authorizationId);
    error ModuleInvalidEvidence(bytes32 evidenceRef);
    error ModuleGasBudgetExceeded(bytes32 authorizationId);

    event ModuleConfigured(bytes32 indexed authorizationId, bytes32 indexed moduleRef, bytes32 configDigest);
    event ModuleAdvanced(bytes32 indexed authorizationId, bytes32 indexed evidenceRef, bool terminal);

    function configure(bytes32 authorizationId, bytes32 moduleRef, bytes calldata config) external;
    function advance(bytes32 authorizationId, bytes32 evidenceRef, bytes calldata proof) external returns (bool terminal);
    function evaluate(bytes32 authorizationId, bytes32 contextRef) external view returns (bool);
}

interface IFSMInterpreter {
    error FSMUnknown(bytes32 authorizationId, CeremonyAxis axis);
    error FSMInvalidTransition(bytes32 authorizationId, uint32 fromState, bytes32 transitionId);
    error FSMUnauthorizedSubmitter(bytes32 authorizationId, address submitter);
    error FSMUnauthorizedCaller(address caller);
    error FSMHashMismatch(bytes32 authorizationId, bytes32 expected, bytes32 actual);
    error FSMGasBudgetExceeded(bytes32 authorizationId);

    event FSMAdvanced(
        bytes32 indexed authorizationId,
        CeremonyAxis indexed axis,
        uint32 fromState,
        uint32 toState,
        bytes32 transitionId,
        bool terminal
    );

    function advanceFSM(
        bytes32 authorizationId,
        CeremonyAxis axis,
        address actor,
        bytes32 transitionId,
        bytes32 attestationDigest,
        bytes calldata transitionProof
    ) external returns (FSMAdvanceResult memory result);

    function currentState(bytes32 authorizationId, CeremonyAxis axis) external view returns (uint32);
}

interface IClaimDSL {
    error DSLUnsupportedVersion(bytes32 dslVersionRef);
    error DSLInvalidOperator(uint8 op);
    error DSLTypeMismatch(uint16 nodeIndex);
    error DSLGasBudgetExceeded(bytes32 claimRef);
    error DSLCustomPredicateReserved(bytes32 wasmHash);

    event DSLVersionUsed(bytes32 indexed dslVersionRef, bytes32 indexed claimRef);

    function evaluateClaim(bytes32 dslVersionRef, bytes32 claimRef, bytes32 contextRef)
        external
        view
        returns (bool);
}

interface IAttestationGate {
    error AttestationOracleUnknown(bytes32 oracleId);
    error AttestationSchemaMismatch(bytes32 oracleId, bytes32 schemaId);
    error AttestationSignatureInvalid(bytes32 oracleId, bytes32 attestationDigest);
    error AttestationStale(bytes32 attestationDigest);
    error AttestationClaimFalse(bytes32 claimRef);
    error AttestationSigmaBytesForbidden();

    event OracleAttestationAccepted(
        bytes32 indexed authorizationId,
        bytes32 indexed oracleId,
        bytes32 indexed attestationDigest,
        bytes32 schemaId,
        bytes32 claimRef
    );

    function verifyOracleAttestation(
        bytes32 authorizationId,
        bytes32 oracleId,
        bytes32 schemaId,
        bytes32 attestationDigest,
        bytes calldata oracleSignature,
        bytes32 claimRef
    ) external returns (bool);
}

interface IBaseRegistry {
    error RegistryEntryUnknown(bytes32 id);
    error RegistryEntryNotEffective(bytes32 id, uint64 blockNumber);
    error RegistryEntryTombstoned(bytes32 id, uint64 blockNumber);
    error RegistryEntryDeprecated(bytes32 id);
    error RegistryDisclosureTooLarge(uint256 size);
    error RegistryDisclosureHashMismatch(bytes32 expected, bytes32 actual);
    error RegistryCooldownActive(bytes32 id, uint64 until);

    event EntryAdded(bytes32 indexed id, uint64 effectiveBlock);
    event EntryTombstoned(bytes32 indexed id, uint64 tombstoneBlock);
    event DeprecationFlagSet(bytes32 indexed id, uint8 reasonCode, bytes32 disclosureCid, bytes32 disclosureCommitHash);
    event DisclosurePublished(bytes32 indexed id, bytes summaryContent);
    event DeprecationAutoCleared(bytes32 indexed id, uint64 cooldownUntil);

    function deprecationFlag(bytes32 id) external view returns (DeprecationFlag memory);
    function getEntry(bytes32 id) external view returns (bytes memory encodedEntry);
    function getEntryAt(bytes32 id, uint64 blockNumber) external view returns (bytes memory encodedEntry);
    function publishDisclosure(bytes32 id, bytes calldata summaryContent) external;
    function triggerAutoClear(bytes32 id) external;
}

interface IPluginHashRegistry is IBaseRegistry {
    struct PluginEntry {
        bytes32 canonicalBinaryHash;
        bytes32 sourceCommitDigest;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    function addPlugin(bytes32 pluginVersionDigest, PluginEntry calldata entry) external;
    function getPluginAt(bytes32 pluginVersionDigest, uint64 blockNumber) external view returns (PluginEntry memory);
}

interface IG4AuthorityRegistry is IBaseRegistry {
    struct G4AuthorityEntry {
        uint8 phase;
        bytes authorityPubkey;
        bytes32 binaryHashOrMeasurement;
        bytes32 dcapVerifierRef;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    function addG4Authority(bytes32 g4AuthorityRef, G4AuthorityEntry calldata entry) external;
    function getG4AuthorityAt(bytes32 g4AuthorityRef, uint64 blockNumber) external view returns (G4AuthorityEntry memory);
}

interface IDSLVersionRegistry is IBaseRegistry {
    struct DSLVersionEntry {
        address interpreter;
        bytes32 capSetHash;
        bool customPredicateEnabled;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    function addDSLVersion(bytes32 dslVersionRef, DSLVersionEntry calldata entry) external;
    function getDSLVersionAt(bytes32 dslVersionRef, uint64 blockNumber) external view returns (DSLVersionEntry memory);
}

interface IOracleRegistry is IBaseRegistry {
    struct OracleEntry {
        bytes oraclePubkeyOrAddress;
        uint8 oracleType;
        bytes32 schemaId;
        bytes32 canonicalExamplesHash;
        uint8 trustTier;
        bytes32 metadataHash;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    function addOracle(bytes32 oracleId, OracleEntry calldata entry) external;
    function getOracleAt(bytes32 oracleId, uint64 blockNumber) external view returns (OracleEntry memory);
}

interface IOracleSchemaRegistry is IBaseRegistry {
    struct OracleSchemaEntry {
        bytes32 schemaHash;
        bytes32 validExamplesHash;
        bytes32 invalidExamplesHash;
        uint32 schemaVersion;
        bytes32 metadataHash;
        uint256 supportedOracleTypesMask;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    error OracleSchemaUnknown(bytes32 schemaId);
    event OracleSchemaAdded(bytes32 indexed schemaId, bytes32 schemaHash, bytes32 validExamplesHash, bytes32 invalidExamplesHash, uint64 effectiveBlock);

    function addSchema(bytes32 schemaId, OracleSchemaEntry calldata entry) external;
    function getSchema(bytes32 schemaId) external view returns (OracleSchemaEntry memory);
    function getSchemaAt(bytes32 schemaId, uint64 blockNumber) external view returns (OracleSchemaEntry memory);
}

interface IQTSPRegistry is IBaseRegistry {
    struct QTSPEntry {
        bytes32 qtspRootPubkeyHash;
        bytes2 jurisdiction;
        bytes32 eidasStatusUrlHash;
        bytes32 metadataHash;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        DeprecationFlag deprecationFlag;
        bool isCanonical;
    }

    function addQTSP(bytes32 qtspProviderRef, QTSPEntry calldata entry) external;
    function getQTSPAt(bytes32 qtspProviderRef, uint64 blockNumber) external view returns (QTSPEntry memory);
}

interface ILitV3Assignment {
    error LitAssignmentExists(bytes32 authorizationId);
    error LitAssignmentMissing(bytes32 authorizationId);
    error LitUnauthorizedBridge(address caller);

    event LitAssignmentRecorded(
        bytes32 indexed authorizationId,
        bytes32 indexed assignedTeeId,
        uint64 assignmentBlock,
        bytes32 sourceGovernanceDigest
    );

    function recordAssignment(bytes32 authorizationId, bytes32 assignedTeeId, uint64 assignmentBlock, bytes calldata assignedTeePubkey, bytes32 sourceGovernanceDigest) external;
    function getAssignment(bytes32 authorizationId) external view returns (bytes32 assignedTeeId, uint64 assignmentBlock, bytes memory assignedTeePubkey, bytes32 sourceGovernanceDigest);
}

interface IGateRecipientPubkeyRegistry {
    struct GateRecipientPubkeyEntry {
        bytes32 authorizationId;
        uint8 gateKind;
        uint16 conditionalRecipientIndex;
        bytes kemPubkey;
        bytes32 attestationRef;
        uint64 effectiveBlock;
        uint64 tombstoneBlock;
        bool perCommitEphemeral;
    }

    error GatePubkeyUnknown(bytes32 authorizationId, uint8 gateKind, uint16 conditionalRecipientIndex);
    error GatePubkeyMismatch(bytes32 authorizationId, uint8 gateKind);
    error GatePubkeyTimelockRequired(uint8 gateKind);

    event GateRecipientPubkeyPublished(
        bytes32 indexed authorizationId,
        uint8 indexed gateKind,
        uint16 indexed conditionalRecipientIndex,
        bytes32 attestationRef
    );

    function publishPubkey(GateRecipientPubkeyEntry calldata entry) external;
    function getPubkeyAt(bytes32 authorizationId, uint8 gateKind, uint16 conditionalRecipientIndex, uint64 blockNumber)
        external
        view
        returns (GateRecipientPubkeyEntry memory);
}

interface IShredRegistry {
    error ShredUnknownCommit(bytes32 hCommit);
    error ShredAuthorityInvalid(bytes32 hCommit, address caller);
    error ShredConditionFalse(bytes32 hCommit);
    error ShredRevealInProgress(bytes32 authorizationId);
    error ShredAlreadyFinalized(bytes32 hCommit);
    error ShredLatencyNotElapsed(bytes32 hCommit, uint64 earliestFinalization);
    error ShredUnauthorizedConditionEngine(address caller);

    event ShredRequested(bytes32 indexed authorizationId, bytes32 indexed hCommit, ShredAuthorityMode authorityMode);
    event ShredStateChanged(bytes32 indexed authorizationId, bytes32 indexed hCommit, ShredState oldState, ShredState newState);
    event ShredFinalized(bytes32 indexed authorizationId, bytes32 indexed hCommit, bytes32 proofShred);

    function requestShred(bytes32 authorizationId, bytes32 hCommit, bytes32 evidenceRef) external;
    function recordShredAuthorized(bytes32 authorizationId, bytes32 hCommit, uint32 challengeWindow, bytes32 conditionRef) external;
    function finalizeShred(bytes32 authorizationId, bytes32 hCommit) external returns (bytes32 proofShred);
    function isShredded(bytes32 hCommit) external view returns (bool);
    function currentShredState(bytes32 hCommit) external view returns (ShredState);
}

interface IG4RefusalRegistry {
    error RefusalUnknown(bytes32 authorizationId);
    error RefusalInvalidReason(uint8 reasonCode);
    error RefusalSensitiveReasonMustBeEncrypted(uint8 reasonCode);
    error RefusalAdvisoryReasonNotBlocking(uint8 reasonCode);
    error RefusalBlockingReasonRequired(uint8 reasonCode);

    event RefusalSignal(bytes32 indexed authorizationId, bytes32 indexed hCommit, uint8 reasonCode, bool blocking);
    event RefusalReasonPublic(bytes32 indexed authorizationId, uint8 reasonCode, bytes32 proofRef);
    event RefusalReasonEncrypted(bytes32 indexed authorizationId, bytes encryptedReasonBlob);
    event AdvisorySignal(bytes32 indexed authorizationId, bytes32 indexed hCommit, uint8 reasonCode);

    function recordSignal(bytes32 authorizationId, bytes32 hCommit, uint8 reasonCode, bool blocking, bytes calldata reasonData) external;
    function refusePublic(bytes32 authorizationId, bytes32 hCommit, uint8 reasonCode, bytes32 proofRef) external;
    function refuseEncrypted(bytes32 authorizationId, bytes32 hCommit, uint8 reasonCode, bytes calldata encryptedReasonBlob) external;
    function recordAdvisorySignal(bytes32 authorizationId, bytes32 hCommit, uint8 reasonCode) external;
    function refusalState(bytes32 authorizationId) external view returns (bool refused, uint8 reasonCode, bool encrypted);
    function signalState(bytes32 authorizationId) external view returns (bool signaled, uint8 reasonCode);
}

interface IPausableSurface {
    error PauseUnauthorized(bytes32 scope, address caller);
    error PauseUntilInvalid(bytes32 scope, uint64 until);
    error PauseDurationTooLong(bytes32 scope, uint64 requestedUntil, uint64 maxUntil);

    event PauseSet(bytes32 indexed scope, uint64 until, bytes32 reasonRef, PauseAuthorityMode authorityMode);
    event PauseCleared(bytes32 indexed scope);
    event PauseExpired(bytes32 indexed scope, uint64 expiredAt);

    function pause(bytes32 scope, uint64 until, bytes32 reasonRef) external;
    function unpause(bytes32 scope) external;
    function isPaused(bytes32 scope) external view returns (bool active, uint64 until, bytes32 reasonRef);
}

interface IPasskeyRotationLog {
    error RotationAccountUnknown(bytes32 accountId);
    error RotationIndexNonmonotonic(bytes32 accountId, uint32 expected, uint32 actual);
    error RotationPasskeyChainBroken(bytes32 accountId);
    error RotationMlkemChainBroken(bytes32 accountId);
    error RotationWebAuthnInvalid(bytes32 accountId, uint32 entryIndex);
    error RotationContractAddressMismatch(address expected, address actual);

    event PasskeyRotationAppended(bytes32 indexed accountId, uint32 indexed entryIndex, bytes32 entryDigest);

    function appendRotation(bytes32 accountId, bytes calldata entry, bytes32 rotationAuthorizationDigest) external;
    function getHead(bytes32 accountId) external view returns (uint32);
    function getEntry(bytes32 accountId, uint32 entryIndex) external view returns (bytes memory entry);
    function getEntries(bytes32 accountId, uint32 fromInclusive, uint32 toExclusive) external view returns (bytes[] memory entries);
    /// @notice Imports TAG_ROTATION_LOG_ANCHOR_V3 from S2-1 §2.3.4.
    function computeRotationLogAnchor(address contractAddress, bytes32 accountId, uint32 entryIndex, bytes calldata passkeyPubkey, bytes calldata mlkemPubkey) external pure returns (bytes32);
}

interface ISupersededCommitRegistry {
    struct SupersessionEntry {
        bytes32 oldHCommit;
        bytes32 newHCommit;
        uint16 generation;
        bytes32 lookupHash;
        bytes32 governanceRef;
        uint64 effectiveBlock;
        bool correction;
        bytes32 correctedLookupHash;
    }

    error SupersessionUnauthorized(address caller);
    error SupersessionTimelockNotExpired(bytes32 supersededCommitRef);
    error SupersessionGenerationOverflow(uint16 generation);
    error SupersessionUnknown(bytes32 supersededCommitRef);
    error SupersessionImmutable(bytes32 lookupHash);

    event CommitSuperseded(bytes32 indexed oldHCommit, bytes32 indexed newHCommit, uint16 generation, bytes32 lookupHash);
    event SupersessionCorrectionRecorded(bytes32 indexed oldHCommit, bytes32 indexed rejectedLookupHash, bytes32 indexed correctedLookupHash, bytes32 governanceRef);

    function recordSupersession(bytes32 oldHCommit, bytes32 newHCommit, uint16 generation, bytes32 governanceRef) external;
    function recordSupersessionCorrection(bytes32 oldHCommit, bytes32 rejectedLookupHash, bytes32 correctedLookupHash, bytes32 governanceRef) external;
    function successorOf(bytes32 oldHCommit) external view returns (bytes32 newHCommit, uint16 generation);
    function successorOfAt(bytes32 oldHCommit, uint64 blockNumber) external view returns (bytes32 newHCommit, uint16 generation);
    function lineageCheckpoint(bytes32 oldHCommit, uint64 blockNumber) external view returns (SupersessionEntry memory entry);
}

interface IChallengeRegistry {
    enum ChallengeStatus { None, Open, ConfirmedNoIntervention, Halted, Expired, Withdrawn, Dismissed }
    enum ChallengeReason {
        OracleAttestationDisputed,
        ConditionMisapplied,
        LegalHoldAsserted,
        Art22InterventionRequested,
        DataSubjectErasureInvoked,
        IntegrityClaim
    }

    error ChallengeWindowClosed(bytes32 authorizationId, CeremonyAxis axis);
    error ChallengeWindowZero(bytes32 authorizationId, CeremonyAxis axis);
    error ChallengeIneligibleCaller(bytes32 authorizationId, CeremonyAxis axis, address caller);
    error ChallengeAlreadyOpen(bytes32 authorizationId, CeremonyAxis axis);
    error ChallengeBondTooLow(bytes32 authorizationId, uint256 required, uint256 provided);
    error ChallengeCounterAttestationMalformed(bytes32 authorizationId, bytes32 counterAttestationRef);
    error ChallengeResolverUnauthorized(bytes32 authorizationId, address caller);
    error ChallengeExtensionCapReached(bytes32 authorizationId, CeremonyAxis axis);

    event ChallengeOpened(
        bytes32 indexed authorizationId,
        CeremonyAxis indexed axis,
        ChallengeReason reason,
        bytes32 counterAttestationRef,
        address challenger,
        uint256 bond
    );
    event ChallengeResolved(
        bytes32 indexed authorizationId,
        CeremonyAxis indexed axis,
        ChallengeStatus status,
        bytes32 resolverActionRef
    );
    event ChallengeExtended(bytes32 indexed authorizationId, CeremonyAxis indexed axis, uint64 newDeadline);
    event ChallengeWithdrawn(bytes32 indexed authorizationId, CeremonyAxis indexed axis, address challenger);

    function openChallenge(
        bytes32 authorizationId,
        CeremonyAxis axis,
        ChallengeReason reason,
        bytes32 counterAttestationRef,
        uint256 bondAmount
    ) external payable;

    function confirmNoIntervention(bytes32 authorizationId, CeremonyAxis axis, bytes32 resolverActionRef) external;
    function haltCeremony(bytes32 authorizationId, CeremonyAxis axis, bytes32 resolverActionRef) external;
    function extendChallenge(bytes32 authorizationId, CeremonyAxis axis, uint64 newDeadline) external;
    function withdrawChallenge(bytes32 authorizationId, CeremonyAxis axis) external;
    function challengeStatus(bytes32 authorizationId, CeremonyAxis axis) external view returns (ChallengeStatus);
}

interface IPaymentObligationModule is IConditionModule {
    error PaymentObligationInactive(bytes32 obligationRef);
    error PaymentObligationAlreadyDefaulted(bytes32 obligationRef);
    error PaymentObligationCureWindowActive(bytes32 obligationRef);
    error PaymentObligationEvidenceMismatch(bytes32 obligationRef, bytes32 evidenceRef);

    event PaymentObserved(bytes32 indexed authorizationId, bytes32 indexed obligationRef, bytes32 paymentDigest);
    event DefaultObserved(bytes32 indexed authorizationId, bytes32 indexed obligationRef, bytes32 defaultDigest);
    event CureObserved(bytes32 indexed authorizationId, bytes32 indexed obligationRef, bytes32 cureDigest);

    function registerObligation(bytes32 authorizationId, bytes32 obligationRef, bytes32 configDigest) external;
    function markPaymentObserved(bytes32 obligationRef, bytes32 paymentDigest) external;
    function markDefaultObserved(bytes32 obligationRef, bytes32 defaultDigest) external;
    function obligationStatus(bytes32 obligationRef) external view returns (uint8 status, uint64 dueAt, uint64 cureDeadline);
}

interface ITimeLockModule is IConditionModule {
    error TimeLockTargetInvalid(bytes32 authorizationId);
    error TimeLockNotReached(bytes32 authorizationId, uint64 target, uint64 currentTime);
    error TimeLockWindowExpired(bytes32 authorizationId);

    event TimeLockConfigured(bytes32 indexed authorizationId, uint64 targetTimestamp, uint8 clockSource);
    event TimeLockReached(bytes32 indexed authorizationId, uint64 reachedAt);

    function configureTimeLock(bytes32 authorizationId, bytes32 configDigest, uint64 targetTimestamp, uint8 clockSource) external;
    function evaluateTimeLock(bytes32 authorizationId) external view returns (bool);
}

interface ISubjectInitiatedModule is IConditionModule {
    error SubjectInitiatedNonceConsumed(bytes32 authorizationId, uint256 nonce);
    error SubjectInitiatedExpired(bytes32 authorizationId, uint64 expiresAt);
    error SubjectInitiatedInvalidSigner(bytes32 authorizationId);
    error SubjectInitiatedAxisMismatch(bytes32 authorizationId, CeremonyAxis expected, CeremonyAxis actual);

    event SubjectActionAccepted(bytes32 indexed authorizationId, CeremonyAxis indexed axis, bytes32 actionDigest, uint256 nonce);

    function submitSubjectInitiated(
        bytes32 authorizationId,
        CeremonyAxis axis,
        bytes32 actionDigest,
        bytes calldata signatureEnvelopeRef,
        uint256 nonce,
        uint64 expiresAt
    ) external;
}

interface IHeartbeatMissedModule is IConditionModule {
    error HeartbeatTooEarly(bytes32 authorizationId, uint64 nextAllowedAt);
    error HeartbeatNotMissed(bytes32 authorizationId, uint64 deadline);
    error HeartbeatInvalidActor(bytes32 authorizationId, address caller);

    event HeartbeatRecorded(bytes32 indexed authorizationId, bytes32 indexed actorRef, uint64 nextDeadline);
    event HeartbeatMissed(bytes32 indexed authorizationId, bytes32 indexed actorRef, uint64 missedAt);

    function recordHeartbeat(bytes32 authorizationId, bytes32 heartbeatDigest, bytes calldata signatureEnvelopeRef) external;
    function heartbeatDeadline(bytes32 authorizationId) external view returns (uint64);
}

interface IOracleAttestationModule is IConditionModule {
    error OracleAttestationDigestConsumed(bytes32 attestationDigest);
    error OracleAttestationRootMismatch(bytes32 authorizationId, bytes32 oracleId);
    error OracleAttestationFreshnessExpired(bytes32 attestationDigest);

    event OracleConditionAccepted(bytes32 indexed authorizationId, bytes32 indexed oracleId, bytes32 indexed attestationDigest);

    function submitOracleAttestation(
        bytes32 authorizationId,
        bytes32 oracleId,
        bytes32 schemaId,
        bytes32 attestationDigest,
        bytes calldata oracleSignature,
        bytes calldata proof
    ) external;
}

interface IMultiPartySignalModule is IConditionModule {
    error MultiPartySignalSignerIneligible(bytes32 authorizationId, address signer);
    error MultiPartySignalDuplicateSigner(bytes32 authorizationId, address signer);
    error MultiPartySignalThresholdNotMet(bytes32 authorizationId, uint16 count, uint16 threshold);
    error MultiPartySignalDigestMismatch(bytes32 authorizationId, bytes32 expected, bytes32 actual);

    event SignalSubmitted(bytes32 indexed authorizationId, bytes32 indexed signalDigest, address indexed signer);
    event MultiPartySignalThresholdMet(bytes32 indexed authorizationId, bytes32 indexed signalDigest, uint16 count, uint16 threshold);

    function submitSignal(bytes32 authorizationId, address signer, bytes32 signalDigest, bytes calldata signatureEnvelopeRef, bytes calldata proof) external;
    function signalCount(bytes32 authorizationId, bytes32 signalDigest) external view returns (uint16 count, uint16 threshold);
}

interface IDeadManSwitchModule is IConditionModule {
    error DeadManSwitchGraceActive(bytes32 authorizationId, uint64 deadline);
    error DeadManSwitchRecipientPolicyMismatch(bytes32 authorizationId);

    event DeadManSwitchTriggered(bytes32 indexed authorizationId, bytes32 missedHeartbeatRef);

    function recordDeadManHeartbeat(bytes32 authorizationId, bytes32 heartbeatDigest, bytes calldata signatureEnvelopeRef) external;
    function deadManDeadline(bytes32 authorizationId) external view returns (uint64);
}

interface IConsentGateModule is IConditionModule {
    error ConsentAuthorityIneligible(bytes32 authorizationId, address authority);
    error ConsentDigestMismatch(bytes32 authorizationId, bytes32 expected, bytes32 actual);
    error ConsentExpired(bytes32 authorizationId, uint64 expiresAt);

    event ConsentAccepted(bytes32 indexed authorizationId, bytes32 indexed authorityRef, bytes32 consentDigest);

    function submitConsent(bytes32 authorizationId, address authority, bytes32 consentDigest, bytes calldata signatureEnvelopeRef, bytes calldata proof) external;
}

interface IComposedModule is IConditionModule {
    error ComposedChildCountInvalid(bytes32 authorizationId, uint16 childCount);
    error ComposedDepthExceeded(bytes32 authorizationId, uint16 depth);
    error ComposedChildFalse(bytes32 authorizationId, bytes32 childRef);

    event ComposedConditionMet(bytes32 indexed authorizationId, bytes32 indexed compositionRoot);

    function evaluateComposed(bytes32 authorizationId) external view returns (bool);
}

interface IRevealAuthorizedEmitter {
    error RevealEmitterUnauthorized(address caller);
    event RevealAuthorized(
        bytes32 indexed authorizationId,
        bytes32 indexed hCommit,
        bytes32 indexed pdaRoot,
        uint64 authorizationBlock,
        uint64 authorizationTimestamp,
        uint32 challengeWindow,
        bytes32 conditionRef
    );

    function emitRevealAuthorized(
        bytes32 authorizationId,
        bytes32 hCommit,
        bytes32 pdaRoot,
        uint32 challengeWindow,
        bytes32 conditionRef
    ) external;
}

interface ICealisSecurityMultisig {
    error SecurityMultisigUnauthorized(address caller);
    error SecurityMultisigCanonicalDelayRequired(bytes32 registryId, bytes32 entryId);
    error SecurityMultisigSuspended(uint64 until);

    event SecurityDeprecationRequested(bytes32 indexed registryId, bytes32 indexed entryId, uint8 reasonCode);
    event SecurityAuthoritySuspended(uint64 until, bytes32 reasonRef);

    function deprecateNonCanonical(bytes32 registryId, bytes32 entryId, uint8 reasonCode, bytes32 disclosureCid, bytes32 disclosureCommitHash) external;
    function requestCanonicalDeprecation(bytes32 registryId, bytes32 entryId, uint8 reasonCode, bytes32 disclosureCid, bytes32 disclosureCommitHash) external;
}

interface IEmergencyGovernance {
    error EmergencyGovernanceUnauthorized(address caller);
    error EmergencySuspensionTooLong(uint64 requested, uint64 maxAllowed);

    event SecurityCouncilSuspended(uint64 until, bytes32 reasonRef);
    event SecurityCouncilRestored(bytes32 reasonRef);

    function suspendSecurityCouncil(uint64 until, bytes32 reasonRef) external;
    function restoreSecurityCouncil(bytes32 reasonRef) external;
}

interface IDisclosureRegistry {
    error DisclosureVerifierUnknown(bytes32 verifierRef);
    error DisclosureProofInvalid(bytes32 disclosureId);
    error DisclosureUnknown(bytes32 disclosureId);
    error RevocationRegistryUnavailable();
    event DisclosureCommitted(bytes32 indexed disclosureId, bytes32 indexed authorizationId, bytes32 proofDigest);
    event DisclosureProofVerified(bytes32 indexed disclosureId, bytes32 indexed authorizationId, bytes32 verifierRef);

    function commitDisclosure(bytes32 disclosureId, bytes32 authorizationId, bytes32 proofDigest) external;
    function verifyDisclosureProof(
        bytes32 disclosureId,
        bytes32 authorizationId,
        bytes32 sdMerkleRoot,
        bytes32 verifierRef,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool);
    function verifyAndCommitDisclosure(
        bytes32 disclosureId,
        bytes32 authorizationId,
        bytes32 sdMerkleRoot,
        bytes32 verifierRef,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 proofDigest
    ) external returns (bool);
    function disclosureDigest(bytes32 disclosureId) external view returns (bytes32);
    function disclosureRevoked(bytes32 disclosureId) external view returns (bool);
    function revocationRegistry() external view returns (address);
}

interface IDisclosureRevocationRegistry {
    error DisclosureUnknown(bytes32 disclosureId);
    error DisclosureAlreadyRevoked(bytes32 disclosureId);
    error DisclosureRevocationUnauthorized(bytes32 disclosureId);
    event DisclosureRegistered(
        bytes32 indexed disclosureId,
        bytes32 indexed authorizationId,
        bytes32 indexed claimId,
        bytes32 verifierRef,
        uint64 expiryTimestamp,
        address authorizedRevoker
    );
    event DisclosureRevoked(
        bytes32 indexed disclosureId,
        bytes32 indexed authorizationId,
        uint8 reasonCode,
        bytes32 evidenceRef
    );

    function registerDisclosure(
        bytes32 disclosureId,
        bytes32 authorizationId,
        bytes32 claimId,
        bytes32 verifierRef,
        uint64 expiryTimestamp,
        address authorizedRevoker
    ) external;
    function revokeDisclosure(bytes32 disclosureId, uint8 reasonCode, bytes32 evidenceRef) external;
    function isRevoked(bytes32 disclosureId) external view returns (bool);
    function authorizedRevoker(bytes32 disclosureId) external view returns (address);
    function expiryTimestamp(bytes32 disclosureId) external view returns (uint64);
}

// ─────────────────────────────────────────────────────────────────────────────
// Controlled-use access sessions (controlled-use only; commit_version = 0x0303)
// Per S2-8 + §4.11.5 + §9.16A-§9.16D + §11.5. Active on PDAs with
// token_policy_config.enabled = true; absent otherwise.
// ─────────────────────────────────────────────────────────────────────────────

enum TokenOpKind { None, Read, Write, ComposedRead, ComposedWrite }
enum CosignGate { None, G2_LIT, G3_DCIPHER, G3_DRAND }

struct AnchorEntry {
    uint64 firstPresentationBlock;
    uint64 firstPresentationTimestamp;
    bytes32 holderBindingPubkeyRef;
    bytes32 masterCredentialAnchorRef;
}

struct SliceLayoutEntry {
    bytes32 sliceLatestSealedEnvelopeRef;
    uint64 slicePosition;
    uint64 lastUpdateBlock;
}

struct MasterRevocationEntry {
    uint64 revokedAt;
    address revokerAuthority;
    bytes32 evidenceRef;
}

interface IPresentedTokenConditionModule is IConditionModule {
    error AnchorNotFound(bytes32 credentialDigest);
    error RevokedMaster(bytes32 credentialDigest, uint256 revokedAt);
    error RevokedSubToken(bytes32 subTokenDigest, uint256 revokedAt);
    error InvalidHolderSignature(bytes32 presentationDigest);
    error ScopeOutOfToken(bytes32 sliceId, bytes32 tokenScope);
    error TokenClassNotPermitted(uint8 tokenClass, uint8 opKind);
    error TtlExpired(uint256 ttlExpiry, uint256 currentTime);
    error ForbiddenCompositionDeadManSwitch();
    error FirstPresentationRequiresInTxPubkey();

    event PresentedTokenConditionMet(
        bytes32 indexed authorizationId,
        bytes32 indexed credentialDigest,
        bytes32 indexed sliceId,
        uint8 opKind
    );
    event WriteAuthorized(
        bytes32 indexed authorizationId,
        bytes32 indexed hCommit,
        bytes32 indexed pdaRoot,
        bytes32 sliceId,
        uint8 opKind,
        uint64 authorizationBlock
    );

    function evaluate(
        bytes32 authorizationId,
        bytes32 credentialDigest,
        bytes32 subTokenDigest,
        bytes32 sliceId,
        uint8 opKind,
        bytes calldata sigmaHolder,
        bytes32 presentationDigest
    ) external returns (bool);
    function isFirstPresentation(bytes32 credentialDigest) external view returns (bool);
}

interface ICredentialAnchorRegistry {
    error AnchorAlreadyExists(bytes32 credentialDigest);
    error WriteAuthorityNotModule(address caller);
    error RevokedMasterAtAnchorTime(bytes32 credentialDigest, uint256 revokedAt);

    event AnchorWritten(
        bytes32 indexed credentialDigest,
        uint64 blockNumber,
        uint64 timestamp,
        bytes32 holderBindingPubkeyRef
    );

    function getAnchor(bytes32 credentialDigest) external view returns (AnchorEntry memory);
    function isAnchored(bytes32 credentialDigest) external view returns (bool);
    function writeAnchor(
        bytes32 credentialDigest,
        bytes32 holderBindingPubkeyRef,
        bytes32 masterCredentialAnchorRef
    ) external;
}

interface ISliceLayoutRegistry {
    error SliceNotInPdaLayout(bytes32 pdaRoot, bytes32 sliceId);
    error SlicePositionMustIncrement(uint64 prior, uint64 proposed);
    error WriteAuthorityNotConditionEngine(address caller);

    event SliceLayoutUpdated(
        bytes32 indexed pdaRoot,
        bytes32 indexed sliceId,
        bytes32 hCommit,
        uint64 slicePosition
    );

    function getSliceLatestSealedEnvelopeRef(bytes32 pdaRoot, bytes32 sliceId)
        external view returns (bytes32);
    function getSlicePosition(bytes32 pdaRoot, bytes32 sliceId)
        external view returns (uint64);
    function getSliceLayoutEntry(bytes32 pdaRoot, bytes32 sliceId)
        external view returns (SliceLayoutEntry memory);
    function updateSliceHead(
        bytes32 pdaRoot,
        bytes32 sliceId,
        bytes32 hCommit,
        uint64 slicePosition
    ) external;
}

interface IMasterTokenRevocationRegistry {
    error RevocationAlreadyRecorded(bytes32 masterCredentialDigest, uint64 priorRevokedAt);
    error UnauthorizedRevoker(address caller, bytes32 masterCredentialDigest);

    event MasterRevoked(
        bytes32 indexed masterCredentialDigest,
        uint64 revokedAt,
        address indexed revokerAuthority,
        bytes32 evidenceRef
    );

    function isRevoked(bytes32 masterCredentialDigest) external view returns (bool);
    function getRevocation(bytes32 masterCredentialDigest) external view returns (MasterRevocationEntry memory);
    function revokeMaster(bytes32 masterCredentialDigest, bytes32 evidenceRef) external;
}

interface ITokenRevocationRegistry {
    // Opt-in registry; deployed only for PDAs electing revocation_mode = MASTER_AND_SUB_CRL.
    // Errors + event shapes mirror IMasterTokenRevocationRegistry.
    error RevocationAlreadyRecorded(bytes32 subTokenDigest, uint64 priorRevokedAt);
    error UnauthorizedRevoker(address caller, bytes32 subTokenDigest);

    event SubTokenRevoked(
        bytes32 indexed subTokenDigest,
        uint64 revokedAt,
        address indexed revokerAuthority,
        bytes32 evidenceRef
    );

    function isRevoked(bytes32 subTokenDigest) external view returns (bool);
    function getRevocation(bytes32 subTokenDigest) external view returns (MasterRevocationEntry memory);
    function revokeSubToken(bytes32 subTokenDigest, bytes32 evidenceRef) external;
}

// Mode T cosign-gate enforcement errors per §11.5 (raised at PDA validation
// inside ConditionEngine PDA registration for controlled-use PDAs).
error CosignGateInvalid(bytes32 pdaRoot, uint8 declaredCosignGate);
error CosignGateVendorFamilyMismatch(bytes32 pdaRoot, uint8 g3Choice, uint8 cosignGate);
```

## App. B - Test Vectors PLACEHOLDER

Stage 3 reference implementation produces full vectors. Categories required:

1. `subject_commitment_v3` helper vectors.
2. `authorizationId` helper vectors.
3. `pda_root` 29-field vectors, including zeroed conditional fields.
4. `h_commit` vectors for Phase 1 and Phase 2.
5. `plugin_version_digest`, `g4_authority_ref`, rotation, and supersession helper vectors.
6. Claim DSL operator vectors for all 12 operators.
7. Claim DSL malformed AST rejection vectors.
8. FSM transition vectors, including terminal firing states.
9. OracleRegistry historical lookup vectors.
10. DeprecationFlag 72h auto-clear and 30-day cooldown vectors.
11. ShredRegistry guardrail vectors.
12. Mode 3 rejection vectors.
13. PasskeyRotationLog append and walk vectors.
14. Challenge-window vectors for zero-window and Tier B/C non-zero windows.
15. UUPS authorization negative vectors.

## App. C - Scope-Out Enumeration

| Out-of-scope item | Owner |
|---|---|
| Cryptographic preimage definitions | S2-1 |
| σ construction and σ verification bytes | S2-1/S2-3 |
| Library version pins | S2-3 |
| Lit/dcipher/drand SDK calls | S2-3 |
| Automata zkDCAP integration details | S2-3 |
| PDA configurator UI/API | S2-4 |
| Partner parameter-review UX | S2-4 |
| REST ingestion/delivery APIs | S2-5 |
| Vault ciphertext deletion implementation | S2-5 |
| RevealArtifactBundle JSON | S2-5 |
| Plugin distribution and reproducible-build ceremony | S2-6 |
| Emergency governance operating runbook | S2-6 |
| Mode 3 activation ceremony | S2-6 |
| SD field commitments, circuits, Poseidon, PLONK | S2-7 |
| Stage 3 Solidity source files | Stage 3 implementation |
| Measured gas numbers | Stage 3 Foundry gas snapshots |
| Counsel legal interpretation | Phase 2b/counsel |

S2-2's contract surfaces are necessary but not sufficient for deployment. A conforming implementation also needs S2-1 cryptographic conformance, S2-3 SDK conformance, S2-4 configurator validation, S2-5 API/vault behavior, S2-6 operations, and S2-7 SD isolation.
