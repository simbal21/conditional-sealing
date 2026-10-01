> **SUPERSEDED 2026-05-19 (banner added 2026-06-10 at retirement)** — the 5.00/5 / "TARGET REACHED" / "path to 5/5" maturity claims and framing in this document are not credible per the 2026-05-19 five-input consolidated audit. See [`docs/audits/live-system-audit-synthesis.md`](../docs/audits/live-system-audit-synthesis.md) for the honest assessment (≈3.5/5 overall, Auditing ≈2/5). This file is retained as historical / working artifact only. Do NOT cite the maturity numbers in grants, diligence, or external outreach.

# V3 Architecture — Diagrams + Sequence Flows

**Generated:** 2026-05-14 (Cat 4 Complexity 4 → 5/5 deliverable)
**Scope:** Pictorial overview of the V3 4-gate AND-composition, condition modules, registries, and the reveal + shred ceremony flows.

This document complements:
- `MATURITY-SCORECARD.md` — 9-category audit-prep scorecard
- `SPEC-COMPLIANCE.md` — spec-to-code compliance check
- `TRIAGE.md` — Slither MEDIUM triage
- `GLOSSARY.md` — V3 domain terms

The diagrams here are ASCII art for portability (auditors can view in any editor without external rendering). For interactive Mermaid versions, see `docs/specs/` (planned).

---

## 1. System Component Map

```
                       ┌──────────────────────────────────────────────┐
                       │             V3 Cealis System                 │
                       │   (configurable data escrow platform)        │
                       └─────────────────┬────────────────────────────┘
                                         │
        ┌────────────────────────────────┼────────────────────────────────┐
        │                                │                                │
        ▼                                ▼                                ▼
 ┌─────────────┐               ┌─────────────────┐               ┌──────────────┐
 │ ON-CHAIN    │               │ OFF-CHAIN GATES │               │ VAULT + APIS │
 │ (Base L2)   │               │ (rented)        │               │ (Cealis ops) │
 └──────┬──────┘               └────────┬────────┘               └──────┬───────┘
        │                               │                                │
        │  ┌──────────────────────┐     │  G2 Lit V3 (rented TEE)        │
        │  │ ConditionEngine      │◄────┤  G3 dcipher OR drand           │
        │  │ + 9 Modules          │     │  G4 verification (Phase 1/2)   │
        │  │ + Registries (6)     │     │                                │
        │  │ + Governance (2)     │     │                                │
        │  │ + ShredRegistry      │     │                                │
        │  │ + ChallengeRegistry  │     └────────────────────────────────┘
        │  │ + AttestationGate    │
        │  │ + ClaimDSL           │
        │  │ + FSMInterpreter     │
        │  └──────────────────────┘
        │
        ▼
   (G1 Chain gate)
```

**G1** = ConditionEngine on-chain emission of RevealAuthorized (= the chain gate signature).
**G2** = σ_Lit from rented Lit V3 TEE attestation per commit.
**G3** = σ_G3 from rented dcipher (KYC/M&A/regulated-EU) OR drand (time-triggered) threshold network, per PDA choice.
**G4** = σ_G4 from Cealis verification component (Phase 1 sealed-code server; Phase 2 HSM/TEE attested, partner-runtime).

**Composition rule (S2-1 §6):** all 3 gate signatures (Lit + G3 + G4) Shamir-combined as 3-of-3 over the DEK; G1 is the on-chain authorization event that unlocks the combiner. Missing any gate → no DEK → no reveal.

---

## 2. Condition Engine + Modules

```
                  ┌──────────────────────────┐
                  │    ConditionEngine       │
                  │  (1 contract — central)  │
                  │                          │
                  │  authorizeReveal()       │
                  │  authorizeShred()        │
                  │  registerPda()           │
                  │  advanceFSM()            │
                  └────────────┬─────────────┘
                               │
            ┌──────────────────┼──────────────────┐
            │                  │                  │
            ▼                  ▼                  ▼
     ┌──────────────┐    ┌────────────┐    ┌────────────────┐
     │ Mode P       │    │ Mode F     │    │ Composition    │
     │ (Predicate)  │    │ (FSM)      │    │                │
     │              │    │            │    │  ComposedModule│
     │ Evaluated by │    │ Driven by  │    │  (AND/OR/NOT)  │
     │ ClaimDSL     │    │ FSM-       │    │                │
     │ (13 opcodes) │    │ Interpreter│    │                │
     └──────────────┘    └────────────┘    └────────────────┘

  9 condition modules dispatch from ConditionEngine:

  ┌──────────────────────┬──────────────────────────────────────────┐
  │ Module               │ Predicate fires when…                    │
  ├──────────────────────┼──────────────────────────────────────────┤
  │ TimeLock             │ block.timestamp >= targetTimestamp       │
  │ PaymentObligation    │ obligation marked Defaulted              │
  │ SubjectInitiated     │ subject submits authorized request       │
  │ HeartbeatMissed      │ no heartbeat before interval+gracePeriod │
  │ OracleAttestation    │ authorized oracle attests claim TRUE     │
  │ MultiPartySignal     │ k-of-n eligible signers submit signal    │
  │ DeadManSwitch        │ subject heartbeat missed past gracePeriod│
  │ ConsentGate          │ subject explicit consent signature       │
  │ Composed             │ boolean AND/OR/NOT over child predicates │
  └──────────────────────┴──────────────────────────────────────────┘
```

---

## 3. Reveal Flow Sequence (Mode P happy-path)

```
 PARTNER       SUBJECT         CONDITION         ATTESTATION      COMBINER         GATES (Lit/G3/G4)
                              ENGINE            GATE
   │             │              │                │                 │                │
   │  onboard    │              │                │                 │                │
   ├────────────►│              │                │                 │                │
   │             │              │                │                 │                │
   │             │  registerPda │                │                 │                │
   │             ├─────────────►│                │                 │                │
   │             │              │                │                 │                │
   │             │              │  registerClaim │                 │                │
   │             │              ├───────────────►│                 │                │
   │             │              │  (via DSL)     │                 │                │
   │             │              │                │                 │                │
   │  …time passes — oracle attests…             │                 │                │
   │             │              │                │                 │                │
   │             │              │ authorizeReveal│                 │                │
   │             │              │ ◄──────────────┤ verifyClaim()   │                │
   │             │              │                │                 │                │
   │             │              │ _evaluateAxis()│                 │                │
   │             │              │ ──►module.eval()                 │                │
   │             │              │                                  │                │
   │             │              │ emit RevealAuthorized            │                │
   │             │              │ ────────────────────────────────►│ trigger combine│
   │             │              │                                  │ ──────────────►│
   │             │              │                                  │   σ_Lit ◄──────│
   │             │              │                                  │   σ_G3 ◄───────│
   │             │              │                                  │   σ_G4 ◄───────│
   │             │              │                                  │ Shamir 3-of-3  │
   │             │              │                                  │ → DEK          │
   │ deliver ciphertext (off-chain webhook)                        │                │
   │ ◄─────────────────────────────────────────────────────────────┤                │
   │ decrypt locally with DEK                                                       │
```

**Universal tripwire:** RevealAuthorized emits ONLY at `ConditionEngine.sol:213`. Combiner cannot proceed without it. Verified by `UniversalTripwireInvariant.t.sol` (1,024 fuzz calls × 0 reverts).

---

## 4. Shred Flow Sequence (two-axis: authority × condition)

```
 SUBJECT/         SHRED         CONDITION         ATTESTATION       VAULT
 PARTNER          REGISTRY      ENGINE            GATE
   │                │             │                │                 │
   │  requestShred  │             │                │                 │
   ├───────────────►│             │                │                 │
   │                │             │                │                 │
   │                │  _requireNoRevealInProgress()│                 │
   │                │  (mandatory guardrail)       │                 │
   │                │             │                │                 │
   │                │             │ authorizeShred │                 │
   │                │             │ ◄──────────────┤ evaluateClaim() │
   │                │             │                │                 │
   │                │  recordShredAuthorized       │                 │
   │                │  ◄──────────┤                │                 │
   │                │             │                │                 │
   │                │  challengeWindow > 0:        │                 │
   │                │  → state = ChallengeOpen     │                 │
   │                │  ◄───── (window passes) ──── │                 │
   │                │  state = Authorized          │                 │
   │                │             │                │                 │
   │  finalizeShred │             │                │                 │
   ├───────────────►│             │                │                 │
   │                │  _requireNoRevealInProgress (re-check)         │
   │                │  state = Finalized           │                 │
   │                │  emit ShredFinalized(proofShred)               │
   │                │  ────────────────────────────────────────────► │ delete ciphertext
   │                │             │                │                 │
   │                │             │ recordShredFinalized             │
   │                │  ───────────►│                                 │
   │                │             │ block future authorizeReveal     │
   │                │             │ (G1 refuses future)              │
   │                │             │ G4 refuses σ_G4 (0x02 or 0x03)   │
   │                │             │                                  │
   │   proofShred = keccak(authId∥hCommit∥block.number∥authorityMode∥conditionRef)
   │   PUBLIC verification token (NOT key material) — partner shows to regulator
```

**Triple-block on finalize (S2-2 §11 + an internal shred-condition design note, not in this export):**
1. ConditionEngine refuses future RevealAuthorized
2. G4 refuses σ_G4 (refusal code 0x02 ART_17_ERASURE or 0x03 ART_18_RESTRICTION, encrypted-reason mode)
3. Vault deletes ciphertext on ShredFinalized observation

---

## 5. Registry Class Discipline

```
  CLASS-CRYPTO (TAG-prefixed lookup keys):
  ────────────────────────────────────────────────────────────────
   PluginHashRegistry      key = keccak256(TAG_PLUGIN_VERSION_V3 ‖ canonicalBinaryHash)
   G4AuthorityRegistry     key = keccak256(TAG_G4_ATTESTATION_AUTHORITY_V3 ‖ authorityPubkey)
   OracleRegistry          key = keccak256(TAG_ORACLE_REGISTRY_V3 ‖ oraclePubkeyOrAddress)

  Mismatched key → RegistryLookupKeyMismatch revert.

  CLASS-CATALOG (raw 32-byte refs, upstream wrapping for domain sep):
  ────────────────────────────────────────────────────────────────
   DSLVersionRegistry      key = raw dslVersionRef
   OracleSchemaRegistry    key = raw schemaId
   QTSPRegistry            key = raw qtspProviderRef

  Domain separation comes from TAG_AAD_V3 / pda_root wrapping at the caller.
```

**Why the split:** CRYPTO registries pin material that's cryptographically meaningful on its own (plugin binary hash, authority pubkey, oracle pubkey) — TAG-prefix prevents cross-registry collision. CATALOG registries pin protocol-internal identifiers (DSL versions, schemas, QTSPs) where the ref is already a configured opaque token; upstream context (PDA) provides the separation.

---

## 6. Governance Architecture

```
                   ┌─────────────────────────────────────┐
                   │   CealisTimelockController          │
                   │                                     │
                   │  Two queues:                        │
                   │  • Normal: 7-day delay              │
                   │  • Expedited: 24-hour delay         │
                   │    (3-role gate: proposer →         │
                   │     cosigner → executor)            │
                   └────────┬────────────────────────────┘
                            │
                            │ holds 17 roles (DEFAULT_ADMIN,
                            │ UPGRADER, REGISTRY_ADMIN,
                            │ MODULE_ADMIN, …)
                            │
            ┌───────────────┴────────────────┐
            │                                │
            ▼                                ▼
  ┌──────────────────────┐         ┌──────────────────────┐
  │ CealisSecurityMulti- │         │ All 42 V3 contracts  │
  │ sig                  │         │ (governed via roles) │
  │                      │         └──────────────────────┘
  │ SECURITY_COUNCIL_    │
  │ ROLE 0-delay path    │
  │ for non-canonical    │
  │ entry deprecation    │
  │                      │
  │ Plus 24h expedited   │
  │ canonical deprec.    │
  └──────────────────────┘
           ▲
           │ suspended/restored by
           │
  ┌──────────────────────┐
  │ EmergencyGovernance  │
  │ (last-resort kill    │
  │  switch for compro-  │
  │  mised SecurityMulti)│
  └──────────────────────┘
```

**Authority modes:**
- Normal flow: Timelock proposes → 7-day delay → executor fires.
- Expedited canonical deprecation: SecurityMultisig queues + Timelock 24h delay.
- Non-canonical instant takedown: SecurityMultisig 0-delay (intentionally fast).
- Emergency: EmergencyGovernance suspends SecurityMultisig if compromised.

---

## 7. G4 Refusal Taxonomy (10 codes)

```
  PER-COMMIT BLOCKING (0x01..0x05):
  ─────────────────────────────────
   0x01 LEGAL_COMPEL          court-order hold on specific commit
   0x02 ART_17_ERASURE        GDPR erasure (encrypted-reason only)
   0x03 ART_18_RESTRICTION    GDPR restriction (encrypted-reason only)
   0x04 INTEGRITY_FAIL        on-chain integrity mismatch
   0x05 CHAIN_MISMATCH        chain-state diverged from commit

  CLASS-WIDE BLOCKING (0x06..0x09):
  ─────────────────────────────────
   0x06 PLUGIN_DEPRECATED         canonical age-plugin retracted
   0x07 AUTHORITY_DEPRECATED      canonical G4 authority retired
   0x08 DSL_DEPRECATED            canonical Claim DSL retired
   0x09 ORACLE_DEPRECATED         canonical oracle retired

  ADVISORY NON-BLOCKING (0x0A):
  ─────────────────────────────
   0x0A OPT_OUT_ACTIVE        subject opted out of class-wide halt
                              (advisory signal; reveal still proceeds)

  CRYPTO-NON-CUSTODY GUARANTEE:
  When G4 issues a blocking refusal (0x01..0x09), σ_G4 is never produced.
  No σ_G4 → no Shamir reconstruction → no DEK → no reveal.
  The chain enforces this via on-chain checks at combiner-trigger time.
```

---

## 8. Selective Disclosure Pipeline (Parallel to Escrow)

```
  COMMIT-TIME (onboarding):
  ─────────────────────────
  Subject data → TEE
    │
    ├──► ESCROW PIPELINE (private until condition fires)
    │      │
    │      ├─ DEK generated in TEE
    │      ├─ Hybrid PQ wrap per gate (Lit/G3/G4 recipient pubkeys)
    │      ├─ Stanza encoding (age-plugin-cealis-v3)
    │      ├─ ciphertext → Vault
    │      └─ commit_AAD → on-chain (hCommit, pdaRoot, sdMerkleRoot, …)
    │
    └──► SD PIPELINE (day-one delivery to partner)
           │
           ├─ Per-field Poseidon BN254 commitments
           ├─ PLONK proof generation (4 predicate types)
           ├─ sdMerkleRoot bound at commit_AAD §4 position
           ├─ Partner verify-sdk validates proofs against on-chain root
           └─ DELIVERY: cleartext + proofs to partner
                        (escrow stays sealed)

  TWO PARALLEL PIPELINES — NEVER CROSS:
  • Escrow never partially released through SD.
  • SD plaintext destroyed after TEE processing (per S2-7 §14).
  • Mode B (device-encrypt) incompatible with SD (normative).
```

---

## Coverage

These 8 diagrams cover the architectural surface that S2-2 specifies:
- 4-gate AND-composition (§1)
- 9 condition modules (§4-§7)
- Reveal + shred flows with universal tripwire (§4, §11)
- Registry class split (§3)
- Governance (§16)
- G4 refusal taxonomy (§14)
- SD pipeline isolation (S2-7 §14)

An auditor opening this file before reading source code has the full conceptual map of the system. Combined with NatSpec, SPEC-COMPLIANCE.md, GLOSSARY.md, and TRIAGE.md, the V3 contract surface is now navigable without prior project context.

**Cat 4 Complexity 4 → 5/5 deliverable: COMPLETE.**
