> **SUPERSEDED 2026-05-19 (banner added 2026-06-10 at retirement)** — the 5.00/5 / "TARGET REACHED" / "path to 5/5" maturity claims and framing in this document are not credible per the 2026-05-19 five-input consolidated audit. See [`docs/audits/live-system-audit-synthesis.md`](../docs/audits/live-system-audit-synthesis.md) for the honest assessment (≈3.5/5 overall, Auditing ≈2/5). This file is retained as historical / working artifact only. Do NOT cite the maturity numbers in grants, diligence, or external outreach.

# V3 Contract Glossary

> **Deployment note:** the Base Sepolia deployment referenced in this document is testnet-only, and the deployed bytecode may lag or diverge from this source — see `deployments/README.md`.

Domain terminology for auditors + future contributors. Pairs with `MATURITY-SCORECARD.md` (Cat 6 Documentation: per ToB ToBest practices, audits expect a glossary capturing protocol-specific vocabulary).

## Core protocol

| Term | Meaning |
|---|---|
| **σ (sigma)** | A signature from a custody gate (Lit, G3, G4). Verified as authorization at reveal-time (σ-as-authorization doctrine, locked 2026-05-05). NOT key material — never used as HKDF input. |
| **σ-as-authorization** | Doctrine: gate signatures (σ values) authorize per-stanza wrap-decap; combiner reconstructs DEK via Shamir.combine over decapped shares; no HKDF over σ. Replaces earlier σ-as-IKM framing (retired May 2026). |
| **DEK** | Data Encryption Key. 32-byte symmetric key generated commit-time inside TEE, AEAD-encrypts the payload, then Shamir-split into n shares across gate-recipient public keys. |
| **FIXED_ONLY** | Recipient profile = 3-of-3 Shamir over {Lit, G3, G4}. σ_subject is commit-time consent (passkey assertion bound into commit_AAD), NOT a Shamir share. |
| **hCommit** | Commit hash (32 bytes). The on-chain handle for an escrowed commitment. Maps to a vault ciphertext blob; emitted via PDARegistered. |
| **commit_AAD** | Additional Authenticated Data block bound to a commit. Includes pda_root, sdMerkleRoot (BP-SD-1 fixed position), and other commit-time identifiers. Verified at AEAD decrypt. |

## On-chain components

| Term | Meaning |
|---|---|
| **ConditionEngine** | Central on-chain orchestrator. Emits `RevealAuthorized` and `ShredAuthorized` events when a PDA's predicate evaluates true. Also enforces the universal tripwire (no release path bypasses on-chain ConditionEngine). |
| **PDA** | Per-Deployment Agreement. The contract-level policy artifact partner-deployed per S2-4: schema, G3 choice, recipients, condition modules, shred authority. |
| **PDA+** | Platform-level configuration (oracle schema, DSL versions, etc.). Distinct from PDA per S2-4 §1.5. |
| **ConditionModule** | A predicate evaluator. 9 modules: PaymentObligation, TimeLock, SubjectInitiated, HeartbeatMissed, OracleAttestation, MultiPartySignal, DeadManSwitch, ConsentGate, Composed. |
| **AttestationGate** | On-chain verifier for oracle attestations. Checks oracle signature + claim DSL + freshness window. |
| **ClaimDSL** | On-chain interpreter for partner-defined predicates (over oracle attestations). |
| **FSMInterpreter** | Generic finite-state-machine advancer used by condition modules. |
| **ShredRegistry** | Records authorized shred state per hCommit. Triple-block: (1) ConditionEngine refuses to emit RevealAuthorized after ShredFinalized (Round 2 absence-of-event invariant); (2) vault deletes ciphertext; (3) G4 refuses σ_G4 at any future authorize. |
| **ChallengeRegistry** | Records challenge state per (authorizationId, axis). 3 resolver actions: confirmNoIntervention, haltCeremony, extendChallenge. 4 events: ChallengeOpened, ChallengeResolved, ChallengeExtended, ChallengeWithdrawn. |
| **DisclosureRegistry** | Selective Disclosure (SD) commitment + PLONK proof catalog. Filled by M6 PLONK verifier slot. |
| **DisclosureRevocationRegistry** | Revocation tracking for SD bundles. `DisclosureRevoked` event indexes disclosureId + authorizationId (NOT subject_commitment — privacy-default per App. I §I.11). |
| **G4RefusalRegistry** | Records G4 refusals per authorizationId with reason code. 10-code class split: 0x01-0x05 per-commit-blocking + 0x06-0x09 class-wide-deprecation + 0x0A advisory non-blocking. |
| **PluginHashRegistry** | Records plugin canonical binary hashes. Class-CRYPTO discipline per `v3-registry-class-discipline.md` (internal design note, not in this export). |
| **G4AuthorityRegistry** | Records G4 authority public keys per epoch. Class-CRYPTO. |
| **DSLVersionRegistry** | DSL version catalog. Class-CATALOG (raw 32-byte ref). |
| **OracleRegistry** | Oracle public keys + schemas. Class-CRYPTO. |
| **QTSPRegistry** | Qualified Trust Service Provider root certs (eIDAS). Class-CATALOG. |
| **OracleSchemaRegistry** | Oracle attestation schema definitions. |
| **SupersededCommitRegistry** | Records hCommit re-key generations per S2-1 §15. |
| **LitV3Assignment** | Lit V3 operator assignment per authorizationId. |
| **GateRecipientPubkeyRegistry** | Per-commit ephemeral gate-recipient public keys (Lit/G4/Conditional). |
| **PasskeyRotationLog** | Subject passkey rotation history per accountId. |

## Governance + access

| Term | Meaning |
|---|---|
| **CealisTimelockController** | OZ TimelockController with 7-day default delay on admin operations. |
| **CealisSecurityMultisig** | Routine governance multisig (Security Council). Distinct from Emergency. |
| **EmergencyGovernance** | Emergency governance multisig. Can suspend Security Multisig deprecation authority per §10A.4. |
| **17 access-control roles** | DEFAULT_ADMIN, UPGRADER, PAUSER, OPERATOR, ORCHESTRATOR, ISSUER, MODULE_ADMIN, REGISTRY_ADMIN, SECURITY_COUNCIL, EMERGENCY_GOVERNANCE, CHALLENGE_RESOLVER, REKEY_GOVERNANCE, ORACLE_SUBMITTER, LIT_GOVERNANCE_BRIDGE, GATE_PUBKEY_PUBLISHER, SD_OPERATOR, REVOCATION_ADMIN. |

## Cryptographic invariants

| Term | Meaning |
|---|---|
| **TAG_*_V3** | 30 domain-separation constants. Each is `keccak256(bytes(LABEL))`. Anti-collision discipline: every keccak input prepended with the appropriate TAG. Drift-protected by `test/foundation/TagDigests.t.sol`. |
| **Domain separation** | Distinct TAG prefixes prevent cross-context hash collision. Example: subject commitment (TAG_SUBJECT_V3) and plugin version digest (TAG_PLUGIN_VERSION_V3) of the same payload yield different digests by construction. |
| **At-commit-block reading** | Registry reads MUST take `commit_block` as required parameter (§1.3 NORMATIVE). Current-head reads are non-conformant. Enforced via `readEntryAt` wrapper. |
| **Tombstone tuple** | 3-tuple `(hash_or_ref, effective_block, tombstone_block)`. Validity: `effective_block ≤ B AND (tombstone_block == 0 OR B < tombstone_block)`. |

## Lifecycle states

| Term | Meaning |
|---|---|
| **LifecycleState** | enum: Unregistered, Registered, RevealConditionMet, RevealChallengeOpen, PostChallengeRevealInProgress, ShredConditionMet, ShredChallengeOpen, ShredFinalized, Shredded, Finalized. |
| **CeremonyAxis** | enum: Reveal, Shred. Used by ChallengeRegistry + ConditionEngine + FSMInterpreter. |
| **ConditionMode** | enum: ModeP (predicate), ModeF (FSM). PDA per-deployment choice. |
| **ShredAuthorityMode** | enum: Subject, Joint, Operator, Timelock, Disabled. PDA-configurable per S2-6 §11.1-2. |
| **PauseAuthorityMode** | enum: Partner, Joint, None. Distinct from ShredAuthorityMode per S2-6 §12.2 line 513. |
| **G4Phase** | enum: Phase1 (sealed-code server, pre-pilot dev), Phase2 (HSM TEE + DCAP, pilot+). |

## Asymmetric isolation (SD pipeline)

| Term | Meaning |
|---|---|
| **Asymmetric isolation** | SD pipeline failure does NOT block escrow (S2-7 §15.2 NORMATIVE). 7 stages each verified independently: schema validation, salt derivation, commitment build, proving, response assembly, partner verify, revocation check. |
| **Mode B incompatibility** | Mode B (subject-encrypt) + sd_enabled = forbidden per S2-7 §14.2. Defense-in-depth: rejected at both M5 (API) and M6 (SD module). |
| **DAY-ONE delivery** | SD bundle delivered to recipient at onboarding (T=0), parallel to escrow commit. Escrow bundle delivered at TimeLock fire (T+24h). Round 3 demonstrates. |
| **Cleartext modes** | `cleartext_zk_opened` (default per §4.4) vs `cleartext_attested`. |

## Refusal class split (G4)

| Code | Class | Meaning |
|---|---|---|
| 0x01 | per-commit-blocking | legal_compel |
| 0x02 | per-commit-blocking (encrypted-reason default) | art_17_erasure |
| 0x03 | per-commit-blocking (encrypted-reason default) | art_18_restriction |
| 0x04 | per-commit-blocking | integrity_fail |
| 0x05 | per-commit-blocking | chain_mismatch |
| 0x06 | class-wide-deprecation-blocking | plugin_deprecated |
| 0x07 | class-wide-deprecation-blocking | authority_deprecated |
| 0x08 | class-wide-deprecation-blocking | dsl_deprecated |
| 0x09 | class-wide-deprecation-blocking | oracle_deprecated |
| 0x0A | advisory non-blocking | opt_out_active |

## Test surfaces

| Term | Meaning |
|---|---|
| **Universal tripwire** | "No release path exists that bypasses the on-chain-verified predefined condition." Verified by `test/invariant/UniversalTripwire.t.sol` (3 invariants × 1024 calls × 0 reverts). |
| **STRUCTURAL mode** | Vitest test mode (no infra required); uses in-process synthesis. Default for `@cealis/v3-demo`'s round tests. |
| **LIVE mode** | Real infra mode (Postgres + Redis + anvil-fork or Base Sepolia); used for Phase G smoke + long-running tests. |

## References

- Stage-2 specs: `docs/specs/*-spec.md` (S2-1 through S2-7) + `docs/specs/wp.md`
- Design lockboxes: internal design notes (not in this export)
- TAG digest fixtures: `v3-crypto/test/fixtures/tag-digests.golden.json`
- Slither triage: `TRIAGE.md`
- Maturity scorecard: `MATURITY-SCORECARD.md`
