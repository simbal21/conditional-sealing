# Cealis V2 System, V3 Custody — Operational Ceremonies Specification (S2-6)

**Version:** 1.0-draft
**Status:** Stage-2 mandatory specification. Ceremony logic, not runbook.
**Audience:** Cealis internal operations and governance; external auditors verifying governance discipline, on-chain visibility, and historical verification claims.

---

## §0 — Front matter

### §0.1 Document identity

This is S2-6, the operational-ceremonies specification for the Cealis V2 system with V3 custody. It specifies each ceremony logically: trigger, actors, order, governance delay, registry/state mutation, audit output, and invariants. It is not a step-by-step runbook. S3-1 turns this specification into procedural checklists, communication templates, custody-of-keys controls, and incident-specific operator steps.

S2-6 consumes S2-1 for cryptographic constructions, S2-2 for contract surfaces and roles, S2-3 for custody adapter behavior and version pins, S2-4 for PDA/PDA+ governance classification, and S2-7 for SD isolation boundaries. If this document appears to redefine those siblings, the sibling owning spec wins and S2-6 must be patched.

### §0.2 Audience and reading order

Cealis operations reads §1 through §4 first, then the relevant ceremony section. Governance and security reviewers read §13, §14, §16, §17, and App. B. External auditors read §0.6 source ordering, §1.3 at-commit-block discipline, §13 cross-ceremony invariants, §18 event surface, and App. B before sampling individual ceremonies.

### §0.3 Terminology discipline

- **Ceremony:** a bounded operational state transition with a trigger, authorized actor set, governance path, on-chain event trail, and verifier-visible consequence.
- **7-day timelock:** standard TimelockController delay for additions, activations, interpreter deployments, canonical plugin/G4/oracle/DSL entry additions, and rule additions.
- **24h expedited delay:** canonical-in-use registry deprecation path used when a currently active dependency must be halted quickly but still needs a partner/recipient observation window.
- **Instant deprecation:** non-canonical entry deprecation by CealisSecurityMultisig, because historical or superseded entries are not the current dependency for new commits.
- **Tombstone tuple:** `(hash_or_ref, effective_block, tombstone_block)`. An entry is valid at block `B` only if `effective_block <= B` and either `tombstone_block == 0` or `B < tombstone_block`.
- **Deprecation flag:** emergency halt metadata attached to a registry entry. It is separate from tombstoning. Tombstone governs future eligibility; deprecation governs halt/refusal.
- **σ-as-authorization:** σ values are authorization evidence, not DEK material. They authorize per-stanza Shamir-share release. Secrecy attaches to Shamir shares, decap material, DEK, and plaintext.
- **Stanza-addition:** re-key adds new envelope stanzas that wrap the same Shamir share values under newer primitives. It is not payload re-encryption and not DEK regeneration.
- **Gate authority key:** signing/attestation key used by a gate to produce σ or attest eligibility. Rotating it does not rotate the payload DEK.

### §0.4 What this spec does NOT cover

This spec does not cover contract implementation code (S2-2), cryptographic byte layouts (S2-1), adapter SDK calls and exact dependency pins (S2-3), partner-facing REST payloads and notification templates (S2-5), SD trusted-setup/proof/revocation ceremonies (S2-7), or unplanned incident playbooks (S3-3). App. C enumerates scope-outs and handoffs.

### §0.5 Status of this document

This draft is implementable at ceremony-logic level. The priority ceremonies are fully specified: G4 binary-hash update, G4 authority key rotation, plugin-version update, and oracle onboarding. Re-key is specified normatively at invariant and sequencing level; low-level coordination mechanics are deliberately handed to S3-1 for the first real trigger, because re-key is rare and signal-dependent.

### §0.6 Source-of-truth ordering

1. Current Stage-2 sibling specs.
2. Current WP prose where sibling specs explicitly import it.
3. Committed design docs under `docs/designs/`.
4. Recorded design decisions only where they capture a locked design not fully restated in the current specs.
5. Reference-only V1 closure documents (V1 archive; not included in this repository) for historical ceremony depth, not V2/V3 architecture.

Key verified anchors used by S2-6: S2-6 scope in the internal Stage-2 audit plan; WP shred in `wp.md:419-478`; WP configurability/oracles in `wp.md:479-637`; WP banned phrasing boundaries in `wp.md:828-907`; WP storage/crypto-aging in `wp.md:984-1073`; WP operational posture in `wp.md:1074-1176`; S2-1 σ-as-authorization in `cryptography-spec.md:44-46`; S2-1 endpoint attestation in `cryptography-spec.md:2968-3185`; S2-1 registries in `cryptography-spec.md:3199-3665`; S2-1 re-key in `cryptography-spec.md:4334-4606`; S2-2 registry/oracle/shred/pause/role surfaces in `smart-contracts-spec.md:228-286`, `954-1219`, `1227-1280`, `1398-1443`, and `1463-1519`; S2-3 cross-vendor/pubkey/G4/version pins in `custody-integration-spec.md:211-230`, `447-525`, and `680-722`; S2-4 PDA+ governance classes in `configurator-pda-spec.md:628-723`; launch oracle set in the internal Stage-0 decisions record; retention and pause legal constraints in the internal legal-constraints rules; shred guardrail rationale in the recorded shred-condition design decision.

### §0.7 Document discipline anchors

Every section must preserve:

- the universal tripwire: no release path bypasses the on-chain-verified predefined condition;
- σ-as-authorization: no ceremony turns σ into key material;
- full-engine scope: the full ceremony catalog is included;
- asymmetric registry governance: 7-day additions, 24h expedited canonical-in-use deprecations, instant non-canonical deprecations;
- no-shred-mid-reveal: every shred condition requires `post_challenge_reveal_in_progress == false`;
- at-commit-block reading: historical commitments verify against registry state at their commit/authorization block, not current head;
- SD asymmetric isolation: SD ceremonies do not block escrow ceremonies.

### §0.8 Cross-reference index

S2-1 owns: σ construction, endpoint attestation, registry verification, re-key cryptographic invariants, combiner verification. S2-2 owns: contracts, events, roles, registry getters, ShredRegistry, pause/halt, upgrade controls. S2-3 owns: vendor adapters, cross-vendor TEE normalization, gate-recipient-pubkey lifecycle, version pins. S2-4 owns: PDA/PDA+ classification, configurator validation, WASM/DSL admissibility, governance sub-classes. S2-5 owns: API, delivery, partner notification payloads, vault execution hooks. S2-7 owns: SD-side ceremonies and isolation. S3-1 owns: runbooks.

### §0.9 PII content statement

Operational ceremony outputs are non-PII governance metadata: registry ids, hashes, block numbers, CIDs, encrypted blobs, role ids, and event ids. Ceremony logs MUST NOT contain plaintext, ciphertext, σ bytes, Shamir shares, DEK, oracle attestation plaintext, subject identity, or sensitive refusal text. Refusal codes `0x02` and `0x03` default to encrypted-reason mode.

## §1 — Conventions

### §1.1 Ceremony notation conventions

Timeline notation:

`T0 trigger -> T1 proposal -> T2 queue -> T3 observation -> T4 execute -> T5 verify`.

Actors:

- `TimelockController`: standard 7-day governance executor.
- `CealisSecurityMultisig`: emergency deprecation authority.
- `EmergencyGovernance`: circuit breaker over the security multisig.
- `RekeyGovernance`: role authorized to write supersession lineage after timelock.
- `G4`: Cealis verification component, Phase 1 sealed-code or Phase 2 rented TEE.
- `Combiner`: recipient-side verifier/decrypter; not Cealis-operated.

### §1.2 Timelock conventions

Standard activations use 7-day TimelockController. Canonical-in-use deprecations use 24h expedited delay plus disclosure binding. Non-canonical deprecations are instant. Per-operation material, such as per-commit gate-recipient pubkeys, is not a platform governance addition and does not use the 7-day delay, but it must remain historically readable.

### §1.3 At-commit-block reading discipline

NORMATIVE: every verifier reads registry and assignment state at the block bound to the commitment's authorization context, not at current head. S2-1 calls this the commit's `RevealAuthorized` block in registry verification. S2-6 uses `commit_block` as shorthand for that historical lookup block. A later plugin, G4 key, DSL, oracle, QTSP, Lit assignment, or G3 committee rotation MUST NOT alter verification for an already committed object.

### §1.4 Tombstone tuple discipline

An entry is valid for block `B` if `effective_block <= B` and (`tombstone_block == 0` or `B < tombstone_block`). Tombstoning is forward-looking. It prevents future commits from binding the entry after tombstone, but it does not erase historical verifiability for commits whose block falls before tombstone.

### §1.5 Logging discipline

Every ceremony emits on-chain events or registry-visible state changes. No ceremony event includes σ bytes, share bytes, DEK, plaintext, ciphertext, or oracle attestation plaintext. Events contain digests, refs, CIDs, encrypted reason blob hashes, and state ids.

### §1.6 Phase 1 vs Phase 2 governance posture

> public-copy-sensitive.

At V2 launch, CealisSecurityMultisig and EmergencyGovernance exist but may have all seats held by Cealis. This is Governance Phase 1. It provides process friction and on-chain visibility, not independent-domain defense. Governance Phase 2 seats external advisors before the first paying partner or within 90 calendar days of V2 launch, whichever comes first. Until Phase 2, public material must name both current and target posture.

### §1.7 Error model

Ceremony failures are classified as:

- `CEREMONY_ERR_GOVERNANCE_TIMEOUT`: queued proposal not executed or expires.
- `CEREMONY_ERR_REGISTRY_COLLISION`: proposed id already exists with incompatible payload.
- `CEREMONY_ERR_QUORUM_MISSING`: required multisig or role threshold absent.
- `CEREMONY_ERR_TIMELOCK_NOT_EXPIRED`: execution attempted before delay.
- `CEREMONY_ERR_TOMBSTONE_CONFLICT`: proposed effective/tombstone interval overlaps invalidly.
- `CEREMONY_ERR_DEPRECATION_DISCLOSURE_MISSING`: 72h disclosure not published; flag becomes permissionlessly auto-clearable.
- `CEREMONY_ERR_COMMIT_BLOCK_MISMATCH`: verifier attempted current-head lookup for historical commit.
- `CEREMONY_ERR_TRIPWIRE_BYPASS`: proposed path can emit σ or release shares without G1 condition.
- `CEREMONY_ERR_PII_IN_LOG`: proposed event/log field contains prohibited content.

Abort preserves audit trail. Failed proposals remain visible through TimelockController queue events, registry rejection events, or governance transaction hashes.

## §2 — Ceremony catalog (NORMATIVE)

| # | Ceremony | Governance shape | Frequency | Contract/registry surfaces | Downstream effects |
|---|---|---|---|---|---|
| 1 | G4 binary-hash registry update | 7-day addition; 24h/0h deprecation if compromised | Phase 1 dev and emergency | G4AuthorityRegistry, G4RefusalRegistry | New Phase 1 binary valid only after effective block; old commits verify historically |
| 2 | G4 authority key rotation | 7-day addition plus Phase 2 DCAP acceptance gate; emergency deprecation | scheduled or compromise | G4AuthorityRegistry | New σ_G4-producing key for new commits; old key valid for historical commits |
| 3 | Plugin-version update and signed distribution | 7-day addition; deprecation paths | release cadence, CVE | PluginHashRegistry, signed distribution manifest | Combiners and G4 ingestion prechecks update after effective block |
| 4 | Oracle onboarding | 7-day addition | per new condition source | OracleRegistry, OracleSchemaRegistry, role grants | New condition source becomes PDA-eligible |
| 5 | Oracle rotation | 7-day addition plus tombstone | operator key/schema changes | OracleRegistry, OracleSchemaRegistry | Old pubkey/schema verify historical commits; new commits use new entry |
| 6 | QTSPRegistry onboarding/root rotation | OracleRegistry-style 7-day addition plus tombstone; QTSP-specific counsel/commercial vetting | QES provider or root change | QTSPRegistry | QES subject path eligibility; old QES signatures verify at commit block |
| 7 | Re-key/stanza-addition | 7-day RekeyGovernance ceremony | rare crypto-aging | SupersededCommitRegistry, vault envelope | New stanza generation, same DEK/share values |
| 8 | DSL version update | 7-day addition/deployment | interpreter change | DSLVersionRegistry, ClaimDSL | Existing PDAs keep old semantics; new PDAs may bind new interpreter |
| 9 | PDA+ governance sub-class ceremonies | S2-4 sub-classes 1-5 | platform config changes | PDA+ config, template/default tables, registries, validator code | Partner inspection output and PDA+ allow-list/rule updates |
| 10 | WASM predicate whitelist update | PDA+ governance, usually 7-day | audited predicate addition | PDA+ config, DSL/WASM refs | Predicate binary hash becomes selectable and bound in `pda_root` |
| 11 | Shred triggering | per-PDA authority plus condition | per commit lifecycle | ConditionEngine, ShredRegistry, G4, vault | Permanent triple block and `proof_shred` |
| 12 | Pause vs shred | per-PDA pause authority, bounded | operational vulnerability response | ConditionEngine, modules, registries, ShredRegistry | Reversible halt; no deletion and no release |
| 13 | ChallengeRegistry pause/resolution | PDA-bound resolver role; halt-only | legal-effect challenge windows | ChallengeRegistry, G4RefusalRegistry, ConditionEngine | Confirm/halt/extend active challenges without granting reveal |
| 14 | Cross-ceremony invariant audit | continuous | every ceremony | all governed surfaces | Detects drift in timelock, event, tripwire, lookup discipline |
| 15 | Disaster recovery | emergency governance + standard follow-up | rare | G4AuthorityRegistry, PluginHashRegistry, OracleRegistry, EmergencyGovernance | Halt/rotate without granting reveal or altering content |
| 16 | Vault operator transition | 7-day transition; emergency read-halt path | storage operator migration or compromise | vault roots, audit-log roots, retention/shred state | Maintains ciphertext availability and custody continuity |

The five Cealis-governed V3 registries are `PluginHashRegistry`, `G4AuthorityRegistry`, `DSLVersionRegistry`, `OracleRegistry`, and `QTSPRegistry`. S2-6 must carry a ceremony path for each registry; adjacent surfaces such as `OracleSchemaRegistry`, `LitV3Assignment`, and gate-recipient pubkey records are consumed where their owning ceremony needs them but are not counted as the five.

## §3 — G4 binary-hash registry updates (Phase 1)

### §3.1 Trigger conditions

Triggers are reproducible-build release, Phase 1 daemon bugfix, sealed-code runtime hardening, compiler/toolchain update, or suspected Phase 1 server compromise. Phase 1 is dev-scaffold only. Any observed partner-facing Phase 1 use is severity critical.

### §3.2 Proposal phase

The proposer publishes the source commit digest, reproducible-build instructions, binary hash, build environment digest, test vector digest, and intended `effective_block`. The proposed entry binds to `G4AuthorityRegistry` and carries phase metadata `phase = 1`. The proposal must state whether it is an addition, tombstone, or emergency deprecation.

### §3.3 7-day governance

Normal Phase 1 binary additions queue through TimelockController for 7 days. `g4_authority_ref` uses class-CRYPTO TAG-prefix discipline from S2-1 and the v3-registry class design. Security review during the window verifies binary reproducibility, source/hash match, no PII logging, and S2-3 adapter compatibility.

### §3.4 Activation event and visibility

Execution writes the registry entry and exposes the S2-2 G4AuthorityRegistry addition surface (`EntryAdded` plus the entry fields). The entry is not eligible before `effective_block`.

### §3.5 Old binary remains historically valid

Old binary hashes continue verifying for commits whose `commit_block` falls in the old entry's validity interval. A client MUST NOT reject a historical Phase 1 dev commit merely because a newer binary is canonical.

### §3.6 Client-side historical check

Clients and combiners MUST call historical lookup (`getEntryAt(ref, commit_block)` or equivalent) and verify the Phase 1 σ_G4 Ed25519 signature against the binary hash effective at that block. Current-head lookup for a historical commit is non-conformant.

### §3.7 Disaster path

If the canonical Phase 1 binary is compromised, CealisSecurityMultisig initiates deprecation. If the compromised entry is canonical-in-use, the deprecation waits 24h expedited delay and binds disclosure CID plus disclosure commit hash; if non-canonical, it can be instant. Absence of verified disclosure within 72h auto-clears per registry discipline.

### §3.8 Audit and announcement protocol

> public-copy-sensitive.

S2-6 requires a governance announcement containing only hash refs, source commit, build digest, reason code, affected phase, and effective block. Partner-facing copy is S2-5/S3-1, but the announcement metadata is governed here.

### §3.9 Cross-reference index

S2-1 §9 and §11 define σ_G4 and endpoint attestation. S2-1 §12 defines G4AuthorityRegistry verification. S2-2 §9.6 defines contract entry shape. S2-3 §7 defines adapter behavior.

## §4 — G4 authority key rotation

### §4.1 Trigger conditions

Triggers are scheduled key hygiene, key compromise suspicion, migration from Phase 1 to Phase 2 authority, TEE measurement change, DCAP verifier change, or cryptographic primitive aging affecting G4 signing/attestation. This rotates σ_G4-producing authority. It does not rotate DEK.

### §4.2 Proposal and tombstone tuple semantics

The proposal includes new authority pubkey or TEE measurement, phase, binary/measurement hash, DCAP verifier ref where Phase 2 applies, metadata hash, `effective_block`, and intended tombstone block for the old entry. The operational tuple is `(hash, effective_block, tombstone_block)`, where `hash` is the `g4_authority_ref` / binary-hash / TEE-measurement reference appropriate to the phase.

### §4.2.1 Phase 2 G4 DCAP acceptance gate

Before a Phase 2 G4 authority entry can execute after timelock, Cealis operations MUST publish and verify a pre-activation acceptance packet. The packet includes `g4_authority_ref`, `phase = 2`, authority pubkey/ref, TEE measurement, `DCAP verifier ref`, `effective_block`, metadata hash, and the admission-authoritative verification mode.

The DCAP verifier config names Automata DCAP Attestation release channel, chain id, deployed verifier contract address, verifier type, quote-version support, and zkVM program identifier where SNARK-backed verification is used. The acceptance packet also states the accepted production TCB statuses, the vendor-family classification for the G4 TEE, and the Lit/G4 cross-vendor disjointness check result. Unknown or ambiguous vendor-family classification is a fail-closed rejection path and blocks activation before TimelockController execution.

The measurement proof binds the hardware attestation result to the proposed Cealis authority eligibility result: quote/proof digest, collateral freshness, vendor root, TCB status, TEE measurement, report/user-data binding, quote freshness, and S2-1 `user_data_digest` test vector digest. If the 7-day timelock makes collateral freshness or TCB status stale, the acceptance gate is re-run immediately before execution; stale or downgraded status aborts the activation.

### §4.3 7-day timelock

Normal rotation queues through TimelockController for 7 days. Emergency deprecation may use §13.6 fast paths, but adding the replacement authority still uses standard 7-day activation unless the contract already contains a queued standby entry.

### §4.4 Migration semantics

Commits during the transition bind whichever entry is effective at their commit block. A commit just before new effective block uses old key. A commit at or after new effective block uses new key. If a commit attempts to bind an entry not yet effective or already tombstoned, commit/reveal verification fails.

### §4.5 Client and combiner verification

Client and combiner verification reads `G4AuthorityRegistry` at `commit_block`. A current key cannot validate an old commit unless that key was effective at the old commit block. Phase 2 also verifies DCAP quote, TEE measurement, and Lit/G4 cross-vendor disjointness.

### §4.6 Old-key validity window

Old keys remain valid only for historical verification within their tuple interval. Deprecation can halt pending or pre-authorization work pinned to an unsafe entry, subject to in-flight protection. It cannot grant reveal, rewrite content, or change old commit semantics.

### §4.7 Cross-reference index

S2-1 §12.3, S2-1 §11, S2-2 §9.6, S2-2 §18.4, S2-3 §7.5, and WP §N Phase 1 to Phase 2 discipline.

## §5 — Plugin-version updates (PluginHashRegistry)

### §5.1 Trigger conditions

Triggers are plugin release, reproducible-build patch, dependency CVE, SDK compatibility update, new stanza-generation support, deprecation of a vulnerable plugin, or client upgrade required by re-key.

### §5.2 Proposal phase

The proposal includes canonical binary hash, source commit digest, semver/release digest, reproducible-build instructions, build environment digest, dependency lock digest, S2-3 version-pin impact, signed distribution manifest hash/CID, test vector digest, and `effective_block`.

### §5.3 7-day timelock

Additions queue through TimelockController for 7 days. The observation window lets recipients build from source and compare hash to the queued PluginHashRegistry entry.

### §5.4 At-commit-block verification

`plugin_version_digest` is verified against PluginHashRegistry at `commit_block`. Historical commits keep their original plugin verification path. A new plugin release applies to future commits or to re-key generations that explicitly bind it.

### §5.5 Client-side coordination

S2-3 owns dependency pins. S2-6 requires that plugin activation metadata name the minimum combiner SDK version, supported commit_version range, stanza-generation support, and downgrade/rollback policy. An old plugin may be deprecated only through §13.6 deprecation discipline, never silently removed from historical verification.

### §5.6 Signed distribution ceremony

The release candidate is built reproducibly from the source commit, lockfile, build environment digest, canonical binary hash, semver/release digest, dependency lock digest, and test vector digest. The signed distribution manifest MUST include `plugin_version_digest`, supported commit profile list, supported gate tuple layouts, the build hash used for `plugin_version_digest`, disabled profile list for deprecated gate layouts, minimum combiner SDK version, supported `commit_version` range, stanza-generation support, rollout channel, and rollback/disable policy.

The signed binary and manifest are published through an immutable distribution channel. The manifest hash/CID is included in PluginHashRegistry proposal metadata so recipients can rebuild and compare during the 7-day observation window. Activation requires both registry effectiveness and client-side verification of release signature, binary hash, manifest hash, and PluginHashRegistry state at `commit_block` before any σ handling.

Rollback is not a mutable channel flip. It is either deprecating the current entry and activating an already staged entry, or queuing a new signed binary through PluginHashRegistry. Disabled profiles are signed binary metadata, not remote feature flags. Remote disablement may add a block, but remote enablement MUST NOT revive a deprecated profile or gate layout without a new signed binary plus a PluginHashRegistry entry; remote enablement also cannot revive a profile deprecated through PDA+ or registry governance.

### §5.7 Cross-reference index

S2-1 §12.2, S2-2 §9.5 and §9.11, S2-3 §11, and WP §M plugin distribution.

## §6 — Oracle onboarding ceremony

### §6.1 Operator publication

The oracle operator publishes signing pubkey or contract address, oracle type, schema hash, valid example set hash, invalid example set hash, metadata hash, operational contact hash, trust-tier proposal, uptime/reputation evidence, and intended PDA template classes.

### §6.2 Cealis vetting

Cealis vets identity, operating history, legal basis, jurisdiction, trust tier, schema determinism, canonical examples, replay tests against Claim expressions, key custody posture, monitoring endpoint, and deprecation contact path. Vetting is off-chain but its digest is included in proposal metadata.

### §6.3 7-day registration

Registration is a TimelockController-7d addition. The queued operation includes both OracleRegistry and OracleSchemaRegistry entries. No PDA may bind the oracle until both entries are effective.

### §6.4 Registry state changes

Execution emits `OracleAdded` and `OracleSchemaAdded`. OracleRegistry stores pubkey/address, type, schema id, example hash, metadata, trust tier, effective block, tombstone block, deprecation flag, and canonical flag. OracleSchemaRegistry stores schema and examples hashes.

### §6.5 Submitter-role wiring

If the oracle path requires a relayer or signer to submit attestations on-chain, the same proposal packet names the submitter set and role scope. `ORACLE_SUBMITTER_ROLE` is granted by TimelockController or by the OracleRegistry-governed role path only after the oracle and schema entries are effective. Before first use, AttestationGate or the consuming module checks that the submitter is authorized for the oracle id and PDA scope. Revocation follows oracle rotation/deprecation: compromised or retired submitters are revoked, affected pending flows halt, and no submitter role may add, rotate, or deprecate registry entries.

### §6.6 Announcement and notification

The governance announcement names oracle id, schema id, trust tier, intended template classes, effective block, and vetting digest. It does not publish oracle attestation plaintext or partner data.

### §6.7 First-oracle ceremony specifics

The launch set is Chainlink Automation for time and SubjectInitiated self-oracle. These are normal registry entries, not special hardcoded paths. Chain-native block timestamp TimeLock can remain Tier A without oracle signature; SubjectInitiated verifies through subject-authenticator path.

The Chainlink time launch entry uses a schema whose examples cover valid timestamp reach, stale timestamp, wrong chain id, replayed automation report, and out-of-window report. The SubjectInitiated launch entry uses a schema whose examples cover valid subject action digest, wrong `authorizationId`, stale nonce, wrong ceremony axis, and authenticator mismatch. Both entries publish valid and invalid example set hashes before the 7-day registration queues, and any `ORACLE_SUBMITTER_ROLE` grant is scoped to the specific oracle id and launch PDA classes.

### §6.8 Cross-reference index

S2-2 §8, S2-1 §12.5, S2-4 §6.1, Stage-0 Q-0-8, and WP §F Oracle discipline.

## §7 — Oracle rotation

### §7.1 Trigger conditions

Triggers are signing-key rotation, schema change, operator reorganization, trust-tier change, compromise, deprecated oracle type, or operational SLA failure.

### §7.2 Timelock and tombstone semantics

Normal rotation adds a new OracleRegistry entry under 7-day timelock and tombstones the old entry for future commits. Compromise may add deprecation on the old entry through the emergency path; replacement still requires activation discipline unless a pre-queued standby exists.

### §7.3 Old and new pubkey validity

Old pubkey/schema remain valid for commitments whose `commit_block` predates tombstone. New pubkey/schema applies only to commits at or after the new entry's effective block. A tombstone after authorization does not retroactively break an in-flight ceremony.

### §7.4 Schema migration

If rotation includes schema change, OracleSchemaRegistry adds a new schema id and canonical examples. Existing PDAs retain old schema semantics. New PDAs may bind the new schema after effective block. Claims must be replay-tested before activation.

### §7.5 Cross-reference index

S2-2 §8.4 and §8.8, S2-1 §12.5, S2-4 §6.1/§6.2, and WP §F.

## §7A — QTSPRegistry onboarding and root rotation

### §7A.1 Trigger conditions

Triggers are first QTSP admission, QTSP signing-root rotation, eIDAS status change, jurisdictional eligibility change, counsel-reviewed provider replacement, or deprecation of a QTSP whose root or qualified status is no longer acceptable for new QES-bound commits.

### §7A.2 OracleRegistry-style governance with QTSP vetting

QTSPRegistry follows the same addition, tombstone, historical lookup, DeprecationFlag, disclosure, auto-clear, and cooldown governance shape as OracleRegistry and the other four Cealis-governed V3 registries (PluginHashRegistry, G4AuthorityRegistry, DSLVersionRegistry, OracleRegistry — QTSPRegistry itself is the fifth). The QTSP-specific proposal packet adds counsel/commercial vetting: provider legal name digest, jurisdiction, EU Trusted List evidence hash, eIDAS status URL hash, QTSP root pubkey hash, supported QES bundle profile, partner archetypes allowed to elect it, and counsel-review digest.

### §7A.3 Root rotation and historical QES verification

Root rotation adds a new QTSPRegistry entry under 7-day timelock and tombstones the old entry for future commits. Historical QES-bound σ_subject signatures verify against QTSPRegistry state at `commit_block`; a later root rotation, Trusted List removal, or tombstone cannot retroactively degrade a commit that was QES-valid at signing time.

### §7A.4 Deprecation and refusal interaction

QTSPRegistry deprecation uses the same 24h/0h asymmetric path as the other V3 registries. S2-1/S2-2 do not define a dedicated QTSP deprecation refusal code; G4 maps QTSP failure to `0x04 integrity_fail` unless the refusal enum is later extended. Recovery is a new subject signing ceremony with a non-deprecated QTSP or a non-QES subject-authenticator path where the PDA permits it.

### §7A.5 Cross-reference index

S2-1 §5.5 and §12.7, S2-2 §9.9 and §9.15, S2-4 QTSP PDA+ rows, and WP §K/§N legal-copy discipline.

## §8 — Re-key / stanza-addition ceremony (P21)

### §8.1 What re-key is and is not

Re-key is additive at the stanza layer. It adds a new generation of stanzas under fresher primitives. It does not touch payload bytes, regenerate DEK, mutate the original `h_commit`, or treat σ as entropy. It preserves Shamir share values and file_key across generations.

### §8.2 Trigger sources

Triggers are external cryptanalytic advance, NIST guidance, vendor advisory, TEE attestation root deterioration, SDK primitive deprecation, or risk-register threshold. Example thresholds include material security-margin reduction, vendor TCB status rejection, or scheduled long-retention review crossing a configured primitive age horizon.

### §8.3 Governance timelock

RekeyGovernance proposes a batch of affected commits, proposed primitive generation, client-support requirements, recipient-participation window, and supersession mappings. The ceremony initiation queues for 7 days. During the window, recipients and auditors can inspect parameters before execution.

### §8.4 Fresh σ generation

For the selected generation, Lit, G3, G4, and configured conditional-recipient threshold participants produce fresh σ over the existing lineage root context under the newer primitive or authority generation. G1 chain authorization remains the predefined on-chain condition; re-key does not create a release event without G1.

### §8.5 Stanza addition

After timelock, re-key executes a fresh commit-generation step. For generation `N`, the ceremony constructs `commit_AAD_vN` with prior fields unchanged except `superseded_commit_ref = oldHCommit` and `commit_generation = N`; computes `h_commit_vN` over `commit_AAD_vN` and the post-re-key serialized envelope; appends the new-generation stanzas; and stores the expanded envelope in the vault. The SupersededCommitRegistry write MUST map `oldHCommit -> newHCommit`, where `newHCommit = h_commit_vN`, and MUST record the same generation number `N`. The original envelope remains recoverable until governance-deprecated.

### §8.6 Combiner recovery

The recipient combiner walks SupersededCommitRegistry to the selected generation, verifies that generation's σ values and registry state, decaps Shamir shares from that same generation, and reconstructs the same DEK. AEAD verification MUST use the selected generation's `commit_AAD_vN` as additional authenticated data; using original-generation AAD against generation-N envelope state is invalid. Default implementation uses one generation's stanza set per recovery for audit simplicity.

### §8.7 Old-stanza invalidation

Old stanza support ends only after a separate governance deprecation trigger: new generation has been live for the grace period, risk register justifies retirement, recipient migration is below threshold, and SDKs have upgrade support. Deprecation is an operational gate; it does not delete historical envelope bytes.

### §8.8 Conditional-recipient impact

Mode 1 PASSKEY_ACCOUNT and Mode 2 WALLET_EOA require interactive recipient participation. Non-responding recipients keep old-generation access until old-generation deprecation. Mode 3 remains reserved at V2 launch.

### §8.9 SupersededCommitRegistry write

The registry write requires `REKEY_GOVERNANCE_ROLE` after timelock. It maps prior generation to successor generation, records commit generation, and anchors the `commit_AAD_vN`/`h_commit_vN` pair. Unauthorized writes abort; original `h_commit` remains chain head if write fails.

### §8.10 Operational mechanics handoff

Share values cross the re-key boundary only inside the hardened gate-adapter/combiner context: recover existing indexed Shamir shares, re-wrap them under generation-N primitives, persist only wrapped stanza material, and zeroize cleartext shares immediately. No retry queue, log, crash dump, diagnostic artifact, or audit event may contain σ bytes, share bytes, DEK, or plaintext.

S2-6 fixes trigger class, 7-day governance, fresh σ generation, `commit_AAD_vN`/`h_commit_vN` construction, stanza addition, share/file_key invariance, supersession lineage, and old-generation deprecation. S3-1 owns vendor coordination, recipient notification cadence, UX flows for WebAuthn/wallet participation, queue management, and first-trigger dry run.

META: This patch closes HARD-004 at S2-6 ceremony level only. It does not resolve IB-3 or redesign the AEAD invariant; see the Phase B IB-3 design analysis before locking that deeper question.

### §8.11 Cross-reference index

S2-1 §15, S2-2 §16 `REKEY_GOVERNANCE_ROLE`, S2-3 §11 version pins, WP §M crypto-aging.

## §9 — DSL version update (DSLVersionRegistry)

### §9.1 Trigger conditions

Triggers are interpreter bugfix, new Claim operator semantics, gas-bound fix, `custom_predicate` support change, deterministic-evaluation hardening, or deprecation of unsafe interpreter bytecode.

### §9.2 7-day deployment timelock

A new DSL interpreter contract deployment queues through TimelockController for 7 days with bytecode hash, contract address, AST version, cap-set hash, test vector digest, and compatibility statement. Activation writes DSLVersionRegistry entry.

### §9.3 Backward compatibility

Existing PDAs continue evaluating under the DSL version bound in their `pda_root` and commit_AAD. A new interpreter cannot reinterpret old Claim ASTs unless the old PDA explicitly binds that new version through a future supported update ceremony.

### §9.4 Historical verification

Combiner, ConditionEngine, and audit tooling read DSLVersionRegistry at `commit_block`. Current-head interpreter is irrelevant for historical commits.

### §9.5 Cross-reference index

S2-1 §12.4 class-CATALOG rule, S2-2 §9.7, S2-4 §6.1/§6.6.

## §10 — WASM predicate whitelist update

### §10.1 PDA+ governance shape

WASM predicate updates are PDA+ governance. A new audited predicate binary is a Sub-class 1 TimelockController-7d addition. Deprecating a vulnerable predicate is Sub-class 2 or 3 depending on exploit status. Gas/time cap changes are Sub-class 4. Adding a new predicate class rule is Sub-class 5 and requires code, tests, simulation vectors, inspection rendering, and author-lock review.

### §10.2 Timelock pattern

Normal whitelist additions queue for 7 days with binary hash, source digest, deterministic-runtime profile, gas/time bounds, audit digest, simulation vector hash, allowed input schema refs, and affected PDA template classes.

### §10.3 Binary hash in `pda_root`

The selected predicate binary hashes are bound in `wasm_predicate_hashes_root` inside `pda_root`. Historical PDAs keep their bound hashes. A later whitelist update does not rewrite existing roots.

### §10.4 Cross-reference index

S2-4 §6 and §9.3, Stage-0 Q-0-5, S2-2 ClaimDSL/DSLVersionRegistry, and S2-1 `pda_root`.

## §10A — PDA+ governance sub-class ceremonies

### §10A.1 Sub-class table

| Sub-class | Actor | Authority | Delay | State mutation | Event surface | Partner-inspection output | S3-1 handoff |
|---|---|---|---|---|---|---|---|
| 1 TimelockController-7d additions | Cealis operator proposes; TimelockController executes | `REGISTRY_ADMIN_ROLE` or PDA+ governance admin through TimelockController | 7 days | Adds template, schema, default row, registry entry, DSL/WASM ref, QTSP entry, plugin hash, or G4 authority | Timelock queue plus S2-2 `EntryAdded`/domain event | New allow-list row, `template_id`, default-table row, effective block, affected archetypes | Proposal packet, observation notice, inspection rendering update |
| 2 CealisSecurityMultisig deprecations | CealisSecurityMultisig | `SECURITY_COUNCIL_ROLE` | 0h non-canonical; 24h canonical-in-use | Sets `DeprecationFlag`; may tombstone future use | `DeprecationFlagSet`, `DisclosurePublished`, `DeprecationAutoCleared` | Deprecated row, reason digest, disclosure hash/CID, cooldown, affected PDAs | Disclosure publication, partner notices, safe replacement pointer |
| 3 CealisSecurityMultisig with circuit breaker | CealisSecurityMultisig and EmergencyGovernance | `SECURITY_COUNCIL_ROLE`, `EMERGENCY_GOVERNANCE_ROLE` | 0h/24h halt path; bounded circuit-breaker duration | Suspends unsafe class or Security Multisig authority; restores after bounded review | Security suspension/restoration plus deprecation events | Emergency scope, max duration, restoration state, affected inspection rows | Incident bridge, external advisor proof, restore checklist |
| 4 PDA+ conditional-rule constraint adjustment | Cealis operator proposes; TimelockController executes | PDA+ governance admin through TimelockController | 7 days | Changes parameter inside existing validator rule without code-shape change | Timelock queue plus PDA+ rule/config update event | Parameter diff, compatibility result, default-table diff, effective block | Compatibility test packet, partner delta notice |
| 5 PDA+ conditional-rule addition | Cealis operator proposes; code release + TimelockController executes | TimelockController; `UPGRADER_ROLE` if code path changes | 7 days after design/test lock | Adds a new cross-field validator or rule code path | Code/registry upgrade event plus PDA+ rule-added event | New rule explanation, simulation digest, inspection rendering, activation block | Design lock, author-lock review, code release, tests, rollback plan |

### §10A.2 Timelocked addition ceremony

Sub-class 1 expands platform capacity without altering historical PDA semantics. The proposal names the added content-addressed artifact, affected archetypes, validation stage, source/audit/test digests, effective block, and partner inspection rendering. The 7-day observation window lets partners, recipients, auditors, and watchdogs inspect the incoming PDA+ surface. Execution mutates only future-eligible PDA+ allow-lists or registry entries; existing `pda_root` and `pda_version` values remain historically valid.

### §10A.3 Deprecation ceremony

Sub-class 2 deprecates an existing PDA+ or registry entry through the asymmetric DeprecationFlag discipline. Non-canonical entries can be halted immediately. Canonical-in-use entries use the 24h expedited delay, disclosure hash/CID, 72h permissionless auto-clear if disclosure is missing, and 30-day cooldown before same-entry re-deprecation without TimelockController. Partner inspection output MUST show the deprecated row, reason digest, disclosure state, affected archetypes, and safe replacement where one exists.

### §10A.4 Emergency circuit-breaker ceremony

Sub-class 3 is halt-only and bounded. It covers class-wide safety failures, suspected Security Multisig compromise, or emergency disablement of an unsafe PDA+ surface. EmergencyGovernance may suspend Security Multisig deprecation authority for the bounded duration defined in S2-2/WP; it cannot grant reveal, change recipients, alter `pda_root`, delete ciphertext, or bypass `post_challenge_reveal_in_progress == false`. The partner inspection output names scope, max duration, restoration state, and affected rows.

### §10A.5 Constraint-adjustment ceremony

Sub-class 4 changes data inside an existing cross-field rule without changing the validator code shape. The required proposal packet contains parameter diff, compatibility check, simulation vector digest, impacted default-table diff, affected archetypes, and effective block. The change queues for 7 days and executes only if the existing validator still accepts historical PDAs under their original `pda_root` while applying the new bound to future PDA emissions.

### §10A.6 Rule-addition ceremony

Sub-class 5 is codepath-bound. It requires design lock, source/code release, test evidence, simulation vectors, partner-inspection rendering update, activation block, and author-lock review for S2-1/S2-2 impact. It does not require a `commit_version` bump unless the new rule changes byte layout, commit semantics, cryptographic construction, or historical verification. Rollout is staged through TimelockController and must include rollback/disable semantics before first activation.

### §10A.7 Cross-reference index

S2-4 §6.1-§6.7 and §14.3, S2-5 partner inspection, S2-2 registry/upgrader roles, and S3-1 PDA+ governance runbooks.

## §11 — Shred triggering semantics per authority mode

### §11.1 PDA-parametric authority

Shred authority is frozen per PDA/commit: Subject, Joint, Operator, Timelock, or Disabled. Authority is necessary but not sufficient. The shred condition must also evaluate true.

### §11.2 Per-mode trigger surface

- Subject: subject-authenticated request; proof is σ_subject-equivalent action digest.
- Joint: subject plus partner signatures over same `authorizationId`, `h_commit`, and shred reason.
- Operator: Cealis operator action with PDA-defined legal basis and reason digest.
- Timelock: scheduled block/timestamp plus condition truth; no discretionary signer.
- Disabled: no shred request can authorize; attempts revert.

### §11.3 Triple block

Finalized shred composes three blocks: G1 refuses future reveal authorization through ConditionEngine/ShredRegistry state; G4 refuses σ_G4 for future or still-haltable attempts; the vault deletes ciphertext after on-chain confirmation. This blocks future decryption and removes stored ciphertext.

### §11.4 Mandatory guardrail

Every shred condition AND-composes the explicit predicate `post_challenge_reveal_in_progress == false`. If the reveal has passed the challenge window and gates may sign, shred cannot authorize. This guardrail is PDA+ and not partner-configurable.

### §11.5 `proof_shred`

`proof_shred` is a public verification token for the shred event. It is not σ, not a Shamir share, not DEK material, and not a reveal authorization. It may be public because it proves ceremony finalization only.

### §11.6 Shred-first lifecycle bias

For PDAs whose use case permits early erasure, shred fires as soon as retention windows close. Retention floors still apply: vault ciphertext and wrapped shares follow obligation duration plus three years unless the PDA/legal posture permits earlier crypto-shred; access logs, delivery logs, and on-chain commitments follow their own retention rules.

### §11.7 Per-mode finalization conditions

Finalization requires valid authority proof, true shred condition, `post_challenge_reveal_in_progress == false`, challenge-window completion if non-zero, minimum shred latency elapsed, and no blocking G4/legal/refusal state that forces pause rather than shred. Disabled mode never finalizes.

### §11.8 Cross-reference index

WP §E, S2-2 §10, S2-4 shred guardrails, legal constraints retention table, and the recorded shred-condition design decision.

## §12 — Pause (P24) vs shred

### §12.1 Pause semantics

Pause is reversible and bounded. It blocks selected state advancement or new authorization emissions. It never deletes ciphertext, destroys keys, grants release, alters reveal content, or resets historical state.

### §12.2 Pause-authority modes

Pause authority is per-PDA and uses the pause-specific vocabulary `Partner / Joint / None`. It is not the same enum as shred authority. `Partner` means the partner or configured partner operator may request the bounded pause; `Joint` requires the configured joint authority set; `None` disables discretionary pause for that PDA except for registry-level emergency halts governed elsewhere.

### §12.3 Auto-lift

Pause duration MUST be no more than 90 days. The contract or operations surface must support auto-lift after expiry, and any extension is a new pause action subject to the same cap and authority.

### §12.4 On-chain visibility

Pause emits the S2-2 pause event surface with `pauseAuthorityMode`/`pauseAuthorityId`, reason digest, start block, and expiry block, plus the corresponding unpause/lifecycle event. Reason text is off-chain or digest/encrypted; no sensitive refusal text is emitted.

### §12.5 Pause vs shred

Pause is reversible and preserves ciphertext and historical state. Shred is permanent and triggers the triple block. A paused PDA can later unpause; a shredded commit cannot unshred.

### §12.6 Interaction with reveal flow

Pause blocks FSM advancement or gate-start eligibility where configured, but already emitted historical events remain part of chain-of-custody. Pause cannot erase `RevealAuthorized`, cannot alter delivery content, and cannot force G4 to sign.

### §12.7 ChallengeRegistry pause/resolution

ChallengeRegistry pause governance is halt-only. If configured, pause may block new challenges, but active legal-effect challenges remain resolvable. The PDA-scoped `CHALLENGE_RESOLVER_ROLE` is the only resolver authority and cannot act outside its PDA scope. Eligible resolver actions are exactly `confirmNoIntervention`, `haltCeremony`, and `extendChallenge`; the resolver cannot alter reveal content, emit release, force G4 to sign, delete state, or bypass refusal.

The event trail is `ChallengeOpened` for intake, `ChallengeResolved` for confirmation/halt/dismissal, and `ChallengeExtended` for bounded extension. `confirmNoIntervention` sets `ConfirmedNoIntervention` and only allows gate signing through the normal `canGatesSign` path. `haltCeremony` sets `Halted` and must route through the G4 refusal/artifact path; it does not erase `RevealAuthorized`. `extendChallenge` is only for legal or G4 evidence collection, must respect extension caps and the 90-day pause/freeze ceiling, and must carry a `resolverActionRef` hash/CID.

S3-1 owns resolver evidence packets, counter-attestation review, bond workflow, G4 refusal coordination, timer tracking, and partner/recipient notices. S2-6 fixes that challenge resolution cannot become a hidden reveal approval or deletion path.

### §12.8 Cross-reference index

WP P24, S2-2 §14 pause, S2-2 ChallengeRegistry interface/role surfaces, legal Art. 18 90-day freeze constraints.

## §13 — Cross-ceremony invariants (NORMATIVE)

### §13.1 Standard timelock invariant

All platform additions and activations use 7-day TimelockController unless explicitly classified as per-operation material or emergency deprecation.

### §13.2 Event invariant

Every ceremony produces an on-chain event or registry-visible state mutation. Absence of an event trail is non-conformant.

### §13.3 Historical verification invariant

Every registry-touching ceremony preserves at-commit-block verification. New registry state affects new commits; historical commits read historical state.

### §13.4 Universal tripwire invariant

No ceremony may release σ, shares, DEK, or plaintext unless the predefined on-chain condition has fired and all relevant gate checks pass. Governance can halt or extend; it cannot grant reveal.

### §13.5 σ-as-authorization invariant

No ceremony treats σ bytes as DEK material. Re-key, rotation, and refusal ceremonies operate on authorization, wrapping, or registry state only.

### §13.6 Asymmetric registry governance

Additions are 7-day. Non-canonical deprecations are instant by CealisSecurityMultisig. Canonical-in-use deprecations use 24h expedited delay. Voluntary or normal clearing of a disclosed deprecation flag uses 7-day TimelockController. Undisclosed deprecations do not use TimelockController to clear: after 72h without verified disclosure, any address may call `triggerAutoClear(entry_id)`, which clears the flag and starts the 30-day cooldown. During that cooldown, CealisSecurityMultisig cannot re-deprecate the same entry; TimelockController may queue a normal re-deprecation under 7-day delay.

### §13.7 Disclosure bound

Every deprecation binds reason code, disclosure CID, and disclosure commit hash. If no `publishDisclosure(bytes)` with matching keccak lands within 72h, the flag becomes permissionlessly auto-clearable via `triggerAutoClear(entry_id)`. Re-deprecating the same entry within 30 days after auto-clear requires 7-day timelock.

### §13.8 Halt-only invariant

Emergency response halts. It cannot grant reveals, cannot change recipient set, cannot alter reveal content, cannot bypass G1, and cannot override ShredRegistry permanence.

## §14 — Disaster-recovery ceremonies

### §14.1 G4 Phase 1 server compromise

Deprecate the compromised binary entry. If canonical-in-use, use 24h expedited path; if non-canonical, instant. Publish disclosure within 72h. Queue replacement binary through 7-day addition unless a standby entry already exists. Announce affected dev commitments and verification path.

### §14.2 G4 Phase 2 TEE compromise

Deprecate affected authority/measurement entry, invoke G4 refusal for pending/pre-authorization affected commits, and rotate to a disjoint TEE vendor path. Existing Phase 2 commits verify historically unless deprecation state at authorization block blocks them. Phase swap remains registry-state transition, not contract upgrade.

### §14.3 Vault operator transition

Vault transition moves sealed ciphertext, σ_subject storage, metadata, and append-only audit logs to successor storage. `h_commit` does not change. Retention floors and shred obligations survive migration. Transition logs contain hashes and audit-log roots, not ciphertext in public events.

Authority is TimelockController for planned transition and EmergencyGovernance plus CealisSecurityMultisig for emergency read-halt or source-freeze when the current vault operator is compromised. Planned transition queues for 7 days with source vault root, destination vault root, source audit-log root, destination audit-log root, retention-state root, shred-state root, migration manifest hash, rollback bound, and partner/subject notification hash. Emergency path may halt new vault reads/writes immediately, but replacement storage activation still requires either a pre-staged destination or standard 7-day activation.

The ceremony MUST preserve audit-log root continuity: the destination root commits to the full source audit-log root plus migration manifest, not a truncated replay. Retention floors, legal holds, active pauses, pending shreds, finalized shreds, and deletion proofs carry forward as state roots. Event surface is a logical `VaultTransitionQueued`/`VaultTransitionFinalized` mapping in §18. S3-1 owns migration logistics, dry-run checksum comparison, rollback drills, operator access revocation, and partner-visible migration notices.

### §14.4 Emergency plugin-hash rotation

Deprecate vulnerable plugin entry through asymmetric governance. G4 refuses with plugin-deprecated code for affected pending/pre-authorization commits; combiners abort on deprecation snapshot where applicable. Replacement plugin activation queues 7 days unless already staged.

### §14.5 Oracle compromise

Deprecate compromised oracle entry. Non-canonical entries deprecate instantly; canonical-in-use uses 24h expedited delay. Pending and pre-authorization flows halt. Replacement oracle onboarding uses §6. Historical commitments verify old entry at commit block unless deprecation was active at that block.

### §14.6 Disaster-recovery case matrix

| Affected surface | Emergency path | Replacement path | Disclosure path | In-flight behavior | Authority | S3-1/S3-3 handoff |
|---|---|---|---|---|---|---|
| G4 Phase 2 authority/measurement | DeprecationFlag on affected `g4_authority_ref`; G4 refusal for pending/pre-authorization commits; circuit breaker if Security Multisig is suspected | Rotate to disjoint TEE vendor path through §4.2.1 DCAP acceptance gate and 7-day activation unless standby exists | `publishDisclosure(bytes)` within 72h or permissionless auto-clear; reason and metadata hashes only | Existing authorizations verify historical state; pending/pre-authorization affected commits halt | CealisSecurityMultisig; EmergencyGovernance for circuit breaker | S3-3 incident playbook plus S3-1 partner notices and TEE evidence packet |
| Emergency plugin rotation | DeprecationFlag on vulnerable PluginHashRegistry entry; remote disable may add a block only | Activate already staged signed binary or queue new signed distribution through §5.6 | Disclosure within 72h; disabled profile list remains signed metadata | Combiners abort on deprecated snapshot; no remote enablement revives deprecated profile | CealisSecurityMultisig; TimelockController for replacement | S3-1 rollout/rollback notices; S3-3 CVE bridge |
| Oracle compromise | DeprecationFlag on oracle/schema entry; pause affected pending/pre-authorization flows | Onboard replacement through §6 with submitter-role wiring and launch schema examples | Disclosure within 72h; reason digest and affected oracle ids | Historical commitments verify old entry at commit block unless deprecation was active at authorization block | CealisSecurityMultisig; TimelockController for replacement | S3-1 oracle vetting packet; S3-3 incident forensics |

### §14.7 Cross-domain independence disclosure

> public-copy-sensitive.

During Governance Phase 1, disaster-recovery statements must state that multisig seats are Cealis-held and the security gain is process friction plus visibility. Phase 2 independence begins only after external advisor seats are active.

### §14.8 Cross-reference index

WP §N emergency response, S2-1 §12.8, S2-2 §9.12, S2-3 §12 monitoring, S3-3 incident playbooks.

## §15 — Phase 1 → Phase 2 G4 cutover

### §15.1 Cutover trigger

Cutover occurs when partner signing/funding makes Phase 2 operationally available. Partner-ready and legal-effect PDAs must use Phase 2.

### §15.2 Phase 2 registration

Register Phase 2 G4AuthorityRegistry entry with TEE measurement, authority pubkey/ref, DCAP verifier ref, vendor family, effective block, and metadata. Queue through 7-day timelock. Execution is blocked unless the §4.2.1 Phase 2 G4 DCAP acceptance gate passes with current collateral freshness, accepted TCB status, unambiguous vendor-family classification, and Lit/G4 cross-vendor disjointness.

### §15.3 Phase 1 historical validity

Phase 1 entries remain valid for Phase 1 dev commits after cutover. Historical lookup preserves those commits. They are not upgraded into legal-effect Phase 2 commits.

### §15.4 Partner-ready guardrail

Configurator and contract validation reject legal-effect or partner-ready commits under Phase 1. A Phase 1 dev commit that needs partner readiness must be recommitted under Phase 2 with fresh σ_subject over the new commit.

### §15.5 Verification API surface

S2-5 exposes verification metadata sufficient for clients to distinguish Phase 1 and Phase 2 artifacts. S2-6 requires the cutover announcement to publish effective block, Phase 2 authority ref, and Phase 1 historical-verification policy.

### §15.6 Cross-reference index

WP §N, S2-1 §9, S2-2 §18.4, S2-3 §7.5.

## §16 — Governance Phase 1 / Phase 2 honest posture

### §16.1 Launch posture

At V2 launch, CealisSecurityMultisig and EmergencyGovernance may be Cealis-held. They are still deployed with Phase 2-capable role structure.

### §16.2 Circuit breaker posture

EmergencyGovernance can suspend Security Multisig deprecation authority for bounded duration. In Phase 1 this is still Cealis-alone control; in Phase 2 it becomes cross-domain.

### §16.3 Phase 2 deadline

External advisor seats complete before first paying partner or within 90 days of V2 launch, whichever is sooner. The first paying partner trigger is observable as `partnerRegistered` on PartnerRegistry. Before accepting the first paying partner registration, and before any new onboarding after day 90, operations MUST verify external-advisor seating proof, role-grant events, and governance posture announcement hash. If verification fails, new partner onboarding halts.

### §16.4 Public-copy discipline

> public-copy-sensitive.

Any material invoking emergency governance during Phase 1 must name current and target posture. It may say halt is on-chain-visible and process-gated. It may not imply independent-domain defense before external seats exist.

### §16.5 Phase 2 transition ceremony

The transition queues member additions/removals through TimelockController, publishes member-role metadata hashes, verifies key control, rotates any temporary Cealis-only keys out, emits role-grant events, and publishes a governance posture announcement. Existing deprecation flags remain valid; authority composition changes future governance actions only.

### §16.6 Cross-reference index

WP §N Governance Phase 1/2, S2-2 §16.5.

## §17 — Per-ceremony role matrix

| Ceremony | Actor | Off-chain responsibility | On-chain role | Grantor | Timelock/emergency | Observable event |
|---|---|---|---|---|---|---|
| G4 binary-hash update | Registry admin via governance | Publish source, reproducible build, binary hash, test digest | `REGISTRY_ADMIN_ROLE` | TimelockController admin | 7-day addition | `EntryAdded` / G4 authority update mapping |
| G4 emergency deprecation | CealisSecurityMultisig | Publish reason/disclosure hash, partner notice | `SECURITY_COUNCIL_ROLE` | Phase-appropriate governance | 0h non-canonical; 24h canonical-in-use | `DeprecationFlagSet`, `DisclosurePublished`, `DeprecationAutoCleared` |
| G4 authority rotation | Registry admin | Key/measurement packet, tombstone tuple, Phase 2 DCAP acceptance | `REGISTRY_ADMIN_ROLE` | TimelockController admin | 7-day addition; emergency deprecation separate | `EntryAdded`, `EntryTombstoned` |
| Plugin update/distribution | Registry admin + release signer | Build signed binary/manifest, rollout/rollback packet | `REGISTRY_ADMIN_ROLE` | TimelockController admin | 7-day addition | `EntryAdded` plus signed manifest hash |
| Plugin deprecation | CealisSecurityMultisig | Disable unsafe profile, publish disclosure, coordinate client abort | `SECURITY_COUNCIL_ROLE` | Phase-appropriate governance | 0h/24h by canonical status | `DeprecationFlagSet`, `DisclosurePublished` |
| Oracle onboarding/rotation | Registry admin + oracle vetter | Vet operator/schema/examples, submitter set, trust tier | `REGISTRY_ADMIN_ROLE` | TimelockController admin | 7-day addition/tombstone | `OracleAdded`, `OracleSchemaAdded`, `EntryTombstoned` |
| Oracle attestation submit | Registered oracle/relayer | Submit scoped attestations only | `ORACLE_SUBMITTER_ROLE` | TimelockController / OracleRegistry path | Grant after registry effectiveness; revoke on rotation/deprecation | `OracleAttestationAccepted` |
| QTSP onboarding/root rotation | Registry admin + counsel/commercial vetter | Vet QTSP root, eIDAS evidence, jurisdiction, partner eligibility | `REGISTRY_ADMIN_ROLE` | TimelockController admin | 7-day addition/tombstone; 0h/24h deprecation | `EntryAdded`, `EntryTombstoned`, `DeprecationFlagSet` |
| Re-key | RekeyGovernance multisig | Batch selection, `commit_AAD_vN`/`h_commit_vN`, share re-wrap boundary | `REKEY_GOVERNANCE_ROLE` | TimelockController | 7-day initiation | `CommitSuperseded` |
| DSL version update | Registry admin + upgrader where contract deployed | Interpreter bytecode, cap set, compatibility vectors | `REGISTRY_ADMIN_ROLE`, `UPGRADER_ROLE` | TimelockController admin | 7-day addition/deployment | `EntryAdded`, `DSLVersionUsed` |
| PDA+ sub-class 1 addition | Cealis operator + TimelockController | Proposal packet, observation notice, inspection rendering | `REGISTRY_ADMIN_ROLE` or PDA+ governance admin | TimelockController admin | 7-day addition | `EntryAdded` or PDA+ config update mapping |
| PDA+ sub-class 2 deprecation | CealisSecurityMultisig | Disclosure, affected PDA analysis, safe replacement | `SECURITY_COUNCIL_ROLE` | Phase-appropriate governance | 0h/24h plus 72h disclosure | `DeprecationFlagSet`, `DisclosurePublished`, `DeprecationAutoCleared` |
| PDA+ sub-class 3 circuit breaker | EmergencyGovernance + CealisSecurityMultisig | Scope, max duration, restoration proof | `EMERGENCY_GOVERNANCE_ROLE`, `SECURITY_COUNCIL_ROLE` | Phase-appropriate governance | bounded emergency | security suspension/restoration events |
| PDA+ sub-class 4 constraint adjustment | Cealis operator + TimelockController | Parameter diff, compatibility check, default-table diff | PDA+ governance admin | TimelockController admin | 7-day addition | PDA+ config update mapping |
| PDA+ sub-class 5 rule addition | Cealis operator + code owner | Design lock, code release, tests, simulation, author-lock review | `UPGRADER_ROLE` where code changes; PDA+ governance admin | TimelockController admin | 7-day after evidence lock | code/registry upgrade plus PDA+ rule-added mapping |
| WASM whitelist | PDA+ governance | Audit predicate, runtime bounds, simulation vectors | PDA+ governance admin | TimelockController admin | 7-day addition; security deprecation via multisig | PDA+ config update mapping |
| Shred Subject | subject | Submit subject-authenticated shred request | PDA-bound authority proof | PDA terms | Per-PDA condition and latency | `ShredRequested`, `ShredFinalized` |
| Shred Joint | subject + partner | Co-sign same authorization/reason | PDA-bound authority proofs | PDA terms | Per-PDA condition and latency | `ShredRequested`, `ShredFinalized` |
| Shred Operator | Cealis ops | Legal-basis digest and reason | `OPERATOR_ROLE` or PDA-bound operator | PDA config / TimelockController | Per-PDA condition and latency | `ShredRequested`, `ShredFinalized` |
| Shred Timelock | contract/time condition | No discretionary action after schedule | no discretionary signer | PDA terms | Per-PDA condition and latency | `ShredRequested`, `ShredFinalized` |
| Pause | Partner / Joint authority | Bounded pause request and reason digest | `PAUSER_ROLE` scoped by PDA/config | PDA config / TimelockController | <=90 days; no deletion | pause/unpause lifecycle events |
| Challenge resolution | PDA-bound resolver | Evidence review, counter-attestation, confirm/halt/extend | `CHALLENGE_RESOLVER_ROLE` | PDA config / TimelockController | extension caps; halt-only | `ChallengeOpened`, `ChallengeResolved`, `ChallengeExtended` |
| Vault operator transition | TimelockController or emergency governance | Source/destination roots, audit continuity, retention/shred carry-forward | vault admin role via TimelockController; emergency read-halt authority | TimelockController / EmergencyGovernance | 7-day planned; emergency read-halt only | `VaultTransitionQueued`, `VaultTransitionFinalized` logical mapping |
| Emergency circuit breaker | EmergencyGovernance | Suspend/restore Security Multisig authority | `EMERGENCY_GOVERNANCE_ROLE` | Phase-appropriate governance | bounded duration | `SecurityCouncilSuspended`, `SecurityCouncilRestored` |
| Disclosure publication / auto-clear | any account for disclosure/auto-clear where matching hash or timeout applies | Publish bounded disclosure or trigger 72h auto-clear | public registry function | registry contract | <=72h disclosure; 30-day cooldown | `DisclosurePublished`, `DeprecationAutoCleared` |
| Governance Phase 2 transition | TimelockController + external advisors | Seat proof, key-control proof, posture announcement | role grants for governance seats | TimelockController admin | before first `partnerRegistered` or day 90 | role-grant events, governance posture hash |
| Contract upgrade | TimelockController only | Storage-layout diff, conformance packet, rollback plan | `UPGRADER_ROLE` | TimelockController admin | 7-day unless emergency pause-only | upgrade event |

## §18 — Per-ceremony on-chain event surface

Exact ABI names are S2-2 territory. S2-6 uses this logical mapping rather than pseudo-ABI:

| Ceremony surface | S2-2 event / registry-visible surface | S2-6 requirement |
|---|---|---|
| PDA registration / first-partner audit hook | `PDARegistered`; PartnerRegistry `partnerRegistered` | Onboarding proof must bind `authorizationId`, `hCommit`, `pdaRoot`, partner id, and governance Phase 2 readiness where applicable |
| Registry addition | `EntryAdded` or domain-specific add function result | Entry id, effective block, metadata/manifest hash observable through registry state |
| Registry tombstone | `EntryTombstoned` | Tombstone block and reason digest observable for future-eligibility decisions |
| Registry deprecation | `DeprecationFlagSet` | Reason code, disclosure CID, disclosure commit hash; applies to all five Cealis-governed V3 registries |
| Disclosure publication | `DisclosurePublished` | Summary content hash verifies against disclosure commit hash; no PII/secret material |
| Disclosure auto-clear | `DeprecationAutoCleared` | Cooldown start visible after permissionless 72h auto-clear |
| G4 binary/key registration | `EntryAdded` on G4AuthorityRegistry plus entry fields | Phase, binary hash or TEE measurement, DCAP verifier ref, metadata hash, effective block visible through registry state |
| Plugin distribution | `EntryAdded` on PluginHashRegistry plus signed manifest hash | Signed binary/manifest hash, supported profile list, disabled profile list, rollout channel in metadata |
| Oracle onboarding | `OracleAdded`, `OracleSchemaAdded` | Oracle id, schema id, schema/examples hashes, trust tier, effective block, submitter-scope metadata |
| QTSP onboarding/root rotation | `EntryAdded`, `EntryTombstoned` on QTSPRegistry | `qtsp_provider_ref`, root pubkey hash, jurisdiction, eIDAS status URL hash, effective/tombstone blocks |
| Re-key supersession | `CommitSuperseded` | `oldHCommit`, `newHCommit`, generation, lookup hash |
| Reveal authorization | `RevealAuthorized` | Authorization block/timestamp, challenge window, `pdaRoot`, condition ref |
| Shred request/finalization | `ShredRequested`, `ShredFinalized` | `post_challenge_reveal_in_progress == false` must be enforceable from state/event trail |
| Pause/unpause | S2-2 pause/unpause or lifecycle events | `pauseAuthorityMode`/`pauseAuthorityId`, reason digest, start, expiry, unpause reason/state |
| Challenge intake/resolution | `ChallengeOpened`, `ChallengeResolved`, `ChallengeExtended`, `ChallengeWithdrawn` | `CHALLENGE_RESOLVER_ROLE` action, status, resolverActionRef, bounded extension deadline |
| G4 refusal | `RefusalSignal`, `RefusalReasonPublic`, `RefusalReasonEncrypted` | Halt evidence for challenges/disasters; sensitive reasons encrypted where required |
| Gate-recipient pubkey | `GateRecipientPubkeyPublished` | Per-commit or long-lived KEM pubkey publication and attestation ref visible for combiner verification |
| Lit assignment | `LitAssignmentRecorded` | Lit assignment block and source governance digest visible for at-commit-block verification |
| Vault transition | logical `VaultTransitionQueued` / `VaultTransitionFinalized` mapping | Source/destination vault roots, audit-log roots, retention/shred state roots, migration manifest hash |
| Governance emergency | `SecurityAuthoritySuspended`, `SecurityCouncilSuspended`, `SecurityCouncilRestored` | Scope, max duration, reason ref, restore event visible |
| Contract upgrade | upgrade event plus role-grant events | Storage-layout diff and conformance packet hash referenced by governance metadata |

No event may include σ, shares, DEK, plaintext, ciphertext, or oracle attestation plaintext.

## §19 — Storage discipline

### §19.1 Ceremony state storage

Normative ceremony state lives on-chain: registry entries, contract state, event logs, and content-addressed metadata hashes. Off-chain artifacts may support execution or audit, but they are not ceremony state and cannot be required for a verifier decision unless their hash/CID is already anchored on-chain.

### §19.2 Audit trail

The audit trail is on-chain-first: queue event, execution event, registry state, disclosure publication where relevant, and final ceremony event. Off-chain artifacts are content-addressed by CID/hash and must be reproducible or archived according to S3-1.

## §20 — Error model + abort discipline

### §20.1 Per-ceremony failure modes

| Ceremony | Failure modes |
|---|---|
| G4 binary/key | reproducibility mismatch, registry collision, timelock expiry, phase-ineligible PDA, tombstone conflict, Phase 2 DCAP acceptance stale or ambiguous |
| Plugin | binary hash mismatch, semver/source mismatch, signed manifest mismatch, SDK unsupported, remote enablement attempted for deprecated profile, deprecation disclosure missing |
| Oracle | schema replay failure, operator vetting failure, trust-tier mismatch, examples hash mismatch, submitter role missing or over-scoped, tombstone conflict |
| QTSP | counsel/commercial vetting missing, eIDAS status evidence stale, root hash mismatch, jurisdiction mismatch, tombstone conflict |
| Re-key | unauthorized RekeyGovernance, missing recipient participation, `commit_AAD_vN`/`h_commit_vN` mismatch, supersession lineage break, generation overflow, share zeroization failure |
| DSL/WASM | interpreter bytecode mismatch, cap-set unsafe, predicate nondeterminism, gas/time bound failure |
| PDA+ governance | missing partner inspection rendering, default-table diff mismatch, author-lock review missing, rule changes byte layout without `commit_version` process |
| Shred | invalid authority, condition false, `post_challenge_reveal_in_progress != false`, minimum latency not elapsed, challenge active |
| Pause | duration over 90 days, authority mismatch, attempt to pause immutable historical state |
| Challenge resolution | unauthorized resolver, unrelated PDA scope, extension cap reached, missing `resolverActionRef`, halt without refusal artifact |
| Vault transition | source/destination root mismatch, audit-log root discontinuity, retention/shred carry-forward missing, rollback bound exceeded |
| Disaster | disclosure missing, circuit-breaker quorum missing, replacement not staged, public copy overclaim [public-copy-sensitive] |

### §20.2 Recovery paths

Recovery retries only after the failed precondition is corrected. If correction changes a commit-bound field, it is a new ceremony or new commit, not a retry. A failed re-key leaves original commitment valid. A failed shred leaves state unshredded. A failed registry addition leaves old canonical entry in effect.

### §20.3 Audit preservation

Aborted ceremonies retain their proposal hash, failure reason code, and block context. Failure logs follow §0.9 PII discipline.

## §21 — Cross-references

### §21.1 Sibling-spec import map

- S2-1: σ-as-authorization, A1+Shamir, endpoint attestation, registry verification, re-key invariants.
- S2-2: contract registry, events, role matrix, ShredRegistry, ChallengeRegistry, pause, UUPS.
- S2-3: adapters, gate-recipient pubkeys, G4 phase swap, cross-vendor TEE checks, dependency pins.
- S2-4: PDA+ governance sub-classes, configurator validation, WASM/DSL boundary.
- S2-5: API, delivery, notifications, vault action hooks.
- S2-7: SD operational isolation and SD ceremonies.

### §21.2 BP-N candidates surfaced during drafting

BP-S2-6-1: RESOLVED in this backprop. Pause authority remains the pause-specific `Partner / Joint / None` vocabulary. Shred authority remains the separate five-mode `Subject / Joint / Operator / Timelock / Disabled` vocabulary.

BP-S2-6-2: stack-wide σ wording cleanup. S2-6 follows σ-as-authorization: σ_Lit, σ_G3, σ_G4, and σ_conditional are authorization evidence, not DEK material. S2-1/S2-3 local gate sections should be aligned in Phase B/A2 wherever they still say a σ value is "not authorization evidence."

### §21.3 S3-1 runbook handoff pointers

S3-1 owns: G4 build reproducibility checklist; key custody ceremony steps; Phase 2 DCAP acceptance packet assembly; vendor coordination with Lit/dcipher/drand; plugin signed-distribution rollout and rollback notices; oracle vetting evidence collection; QTSP counsel/commercial vetting packet collection; PDA+ partner-inspection rendering updates; partner/recipient notification templates; ChallengeRegistry resolver evidence packets, counter-attestation review, bond workflow, G4 refusal coordination, and timer tracking; re-key recipient participation UX; old-generation migration tracking; incident page/bridge roles; vault migration logistics; disclosure publication text; external-advisor seating operational proof; monitoring thresholds; rehearsal cadence.

## App. A — Ceremony timeline diagrams

1. G4 binary hash:
`release trigger -> publish build/source/test digests -> queue addEntry 7d -> observe -> execute EntryAdded/G4 entry -> clients verify at commit_block`.

2. G4 authority rotation:
`rotation trigger -> propose new ref + tombstone old -> Phase 2 DCAP acceptance gate if applicable -> queue 7d -> re-check stale collateral/TCB -> execute new entry -> tombstone old for future -> historical clients read old at commit_block`.

3. Plugin version and signed distribution:
`plugin release/CVE -> reproducible build + signed manifest -> propose hash/CID + lock digest -> queue 7d -> EntryAdded -> clients verify signature/hash/registry state -> old plugin retained until deprecation`.

4. Oracle onboarding:
`operator publishes pubkey/schema/examples/submitter set -> Cealis vets -> queue OracleRegistry + OracleSchemaRegistry 7d -> OracleAdded + OracleSchemaAdded -> ORACLE_SUBMITTER_ROLE grant -> PDA templates may bind`.

5. Oracle rotation:
`key/schema trigger -> propose new oracle/schema -> queue 7d -> add new -> tombstone old -> old commits verify old entry`.

6. QTSP onboarding/root rotation:
`QTSP/root trigger -> counsel/commercial vetting + eIDAS evidence -> queue QTSPRegistry 7d -> EntryAdded or tombstone -> QES-bound commits verify provider at commit_block`.

7. Re-key:
`risk threshold -> batch commits -> RekeyGovernance proposal -> queue 7d -> collect fresh σ generation + recipient participation -> build commit_AAD_vN/h_commit_vN -> append stanzas -> CommitSuperseded oldHCommit -> newHCommit -> deprecation window starts`.

8. DSL update:
`interpreter change -> deploy candidate -> queue DSLVersionRegistry entry 7d -> execute -> new PDAs bind new version; old PDAs keep old`.

9. PDA+ governance:
`PDA+ change trigger -> classify sub-class 1-5 -> publish proposal/diff/evidence -> queue or emergency path -> execute -> partner inspection output updates`.

10. WASM whitelist:
`predicate request -> audit + simulation -> queue hash 7d -> whitelist active -> pda_root may include hash for future commits`.

11. Shred:
`authority submits/proves -> ConditionEngine evaluates condition + post_challenge_reveal_in_progress == false -> ShredRequested/Authorized -> challenge/latency if any -> ShredFinalized -> G1/G4/vault triple block`.

12. Pause:
`Partner/Joint pause trigger -> validate duration <=90d -> pause event/lifecycle change -> FSM/new auth blocked -> auto-lift or unpause`.

13. Challenge resolution:
`ChallengeOpened -> CHALLENGE_RESOLVER_ROLE reviews evidence -> confirmNoIntervention / haltCeremony / extendChallenge -> ChallengeResolved or ChallengeExtended -> normal canGatesSign or refusal path`.

14. Cross-invariant audit:
`ceremony proposed -> invariant checklist -> block if tripwire/lookup/event/logging fails -> execute only after invariant pass`.

15. Disaster recovery:
`incident trigger -> classify entry canonical/non-canonical -> deprecate 0h or 24h -> publish disclosure <=72h -> queue replacement/addition -> announce halt-only scope`.

16. Vault operator transition:
`transition trigger -> queue source/destination roots + audit roots 7d -> freeze/verify migration manifest -> finalize destination root -> carry retention/shred state forward`.

17. Governance Phase 2 transition:
`launch clock or first partnerRegistered trigger -> queue external advisor role grants -> verify key control -> emit role grants -> publish posture hash -> allow first paying partner/new onboarding`.

## App. B — Per-ceremony invariant cross-check table

| Ceremony | Timelock | Event | Historical lookup | Tripwire | σ-as-auth | Emergency discipline | Halt-only |
|---|---|---|---|---|---|---|---|
| G4 binary | 7d add; 24h/0h deprecate | update/deprecation | old binary at commit_block | no release path | σ_G4 key unchanged/verified | yes | yes |
| G4 key | 7d add plus Phase 2 DCAP gate | authority update | old key at commit_block | no release path | rotates signer, not DEK | yes | yes |
| Plugin | 7d add plus signed distribution | entry/manifest added | old plugin at commit_block | plugin cannot authorize reveal | no σ material | remote enable cannot revive deprecated profiles | yes |
| Oracle onboarding | 7d add plus submitter grant | oracle/schema added | future only | condition source only | no σ material | deprecatable | yes |
| Oracle rotation | 7d add/tombstone | rotate/tombstone | old pubkey/schema at commit_block | condition semantics frozen | no σ material | yes | yes |
| QTSP onboarding/root rotation | 7d add/tombstone | QTSP registry entry | QTSP at commit_block | QES path only | σ_subject remains off-chain | deprecatable; maps to 0x04 if refused | yes |
| Re-key | 7d initiation | `CommitSuperseded` | lineage walk | needs G1 condition for reveal | fresh σ authorizes shares only | old gen deprecation governed | yes |
| DSL update | 7d add | DSL entry | old interpreter at commit_block | cannot reinterpret old PDA | no σ material | deprecatable | yes |
| PDA+ governance | 7d / 0h / 24h / bounded circuit breaker by sub-class | PDA+ config/registry update | frozen `pda_root` remains | cannot weaken universal tripwire | no σ material | sub-class governed | yes |
| WASM whitelist | 7d add | whitelist entry | old predicate hash in pda_root | predicate cannot bypass G1 | no σ material | deprecatable | yes |
| Shred | per-PDA; challenge latency | ShredAuthorized/Finalized | current shred state plus frozen PDA | destruction tripwire mirrored | proof_shred not σ | refusal/deprecation honored | permanent halt |
| Pause | per-PDA, <=90d | pause/unpause | state preserved | cannot grant reveal | no σ material | reversible | halt-only |
| Challenge resolution | PDA-scoped resolver; bounded extension | challenge events | active challenge state | cannot grant reveal | no σ material | refusal path for halt | yes |
| Cross-invariant audit | before execution | audit/proposal refs | checks all | checks all | checks all | checks all | checks all |
| Disaster recovery | 0h/24h/7d by class | deprecation/disclosure | respects snapshots | cannot grant reveal | no DEK path | core subject | yes |
| Vault transition | 7d planned; emergency read-halt | vault transition roots | `h_commit` unchanged | cannot grant reveal | no σ material | source freeze only; replacement governed | yes |
| Governance Phase 2 | before first partner/day 90 | role grants/posture hash | future governance only | no release path | no σ material | onboarding halt if missing | yes |

## App. C — Scope-out reference

S2-6 excludes:

- step-by-step operator runbooks, on-call escalation trees, and chat templates (S3-1);
- incident-specific forensic playbooks after an unplanned ceremony failure (S3-3);
- contract implementations, storage packing, exact ABI authority if S2-2 later differs (S2-2);
- cryptographic byte layouts and TAG additions (S2-1);
- SDK function calls, package lockfiles, vendor-specific DCAP code, and adapter retries (S2-3);
- partner-facing API payload schemas and notification delivery protocols (S2-5);
- SD trusted setup, PLONK verifier rollout, SD revocation, and partner verifier SDK ceremonies (S2-7);
- pricing, partner contract terms, and legal-opinion substance.

None of these exclusions permits a degraded ceremony. It only identifies the owning document for procedural or implementation detail.
