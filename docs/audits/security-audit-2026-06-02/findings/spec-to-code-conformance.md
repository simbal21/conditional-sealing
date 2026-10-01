> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# S2-2 Spec-to-Code Conformance Audit — 2026-06-02

Spec: `docs/specs/smart-contracts-spec.md` (S2-2, 3424 lines)
Code: `contracts/src/` @ HEAD e87c108
Method: grep/read of actual code at HEAD (Rule 45). `forge build --offline` PASSES (32 contracts compile; only a `__gap` mixed-case lint NOTE, standard UUPS convention).

## Overall: CONFORMANT (one MEDIUM documentation/ownership gap + one LOW preimage discrepancy)

The non-controlled-use V3 contract surface (commit_version 0x0302) is a clean, faithful implementation of S2-2. All architecturally load-bearing tripwires, axis-separation, role discipline, and bounded-pause mechanics are present and correct.

---

## Verified CONFORMANT

### 9 ConditionEngine modules (§4.3–§4.11)
All 9 present, each `is IXModule` (compiler-enforced signature match), each with its spec-named advance function:
- PaymentObligationModule: `registerObligation`, `markPaymentObserved`, `markDefaultObserved` ✓
- TimeLockModule: `configureTimeLock`, `evaluateTimeLock` ✓
- SubjectInitiatedModule: `submitSubjectInitiated` (axis-bound, nonce, expiry) ✓
- HeartbeatMissedModule: `recordHeartbeat`, `heartbeatDeadline` ✓
- OracleAttestationModule: `submitOracleAttestation` ✓
- MultiPartySignalModule: `submitSignal`, `signalCount` ✓
- DeadManSwitchModule: `recordDeadManHeartbeat`, `deadManDeadline` ✓
- ConsentGateModule: `submitConsent` ✓
- ComposedModule: `setChildResult`, `evaluateComposed` ✓
Per-module interfaces in `engine/IConditionEngine.sol` carry full typed signatures + custom errors + events matching §4.x.

### 10th module — PresentedTokenCondition (§4.11.5) — INTENTIONALLY DEFERRED, not a gap
NOT in source. Spec §4.11.5 line 619 "full Solidity authoring deferred to BP-CU-1"; S2-8 §12 defers to "first pilot validation." commit_version 0x0303 / controlled-use profile. ProtocolVersion canonical in code = 0x0302 (`lib/Enums.sol`). Correct.

### 5 V3 registries + class discipline (§9) — CONFORMANT
PluginHashRegistry, G4AuthorityRegistry, DSLVersionRegistry, OracleRegistry, QTSPRegistry all present, all implement common shape (`getEntry`/`getEntryAt`, 7-day timelock add, tombstone, DeprecationFlag 72h auto-clear, 30-day cooldown) via IBaseRegistry.
- class-CRYPTO (TAG-prefixed key): PluginHashRegistry, G4AuthorityRegistry, OracleRegistry — code comments + key derivation confirm `TAG_*_V3`-prefixed lookup keys. OracleRegistry: `oracleId = keccak256(TAG_ORACLE_REGISTRY_V3 ‖ pubkey)` ✓
- class-CATALOG (raw 32-byte ref): DSLVersionRegistry, QTSPRegistry, OracleSchemaRegistry — code comments confirm "CONFIGURED raw 32-byte ref (NOT TAG-prefixed)" per BP-13/15 REJECTED. ✓
Matches `v3-registry-class-discipline.md` (internal design note, not in this export) exactly. (Controlled-use registries §9.16A-D NOT in source — deferred per above.)

### 17 V2 role names (§16 / §1.5) — CONFORMANT (exact)
`lib/Roles.sol` declares exactly the 17 canonical roles, matching internal solidity rules (not exported) §2 list verbatim: DEFAULT_ADMIN_ROLE(0x00), UPGRADER, PAUSER, OPERATOR, ORCHESTRATOR, ISSUER, MODULE_ADMIN, REGISTRY_ADMIN, SECURITY_COUNCIL, EMERGENCY_GOVERNANCE, CHALLENGE_RESOLVER, REKEY_GOVERNANCE, ORACLE_SUBMITTER, LIT_GOVERNANCE_BRIDGE, GATE_PUBKEY_PUBLISHER, SD_OPERATOR, REVOCATION_ADMIN. GUARDIAN_ROLE (V1) intentionally absent + comment forbids reintroduction. CONDITION_ENGINE_ROLE (controlled-use only, §16.1) absent — consistent with 0x0303 deferral.
PostDeploy.s.sol grants all operational roles via `Roles.*` constants (25 grants) — cross-checked per audit instruction; operational grants correctly in PostDeploy, governance grants in initialize.

### ShredRegistry two-axis + NOT-post-challenge guardrail (§10) — CONFORMANT
- Authority axis: `ShredAuthorityMode {None=0(invalid sentinel), Subject, Joint, Operator, Timelock, Disabled}` ✓
- Condition axis: Mode P / Mode F via ConditionEngine reuse ✓
- Mandatory guardrail `_requireNoRevealInProgress` → reverts `ShredRevealInProgress` checked at ALL THREE entry points (requestShred:94, recordShredAuthorized:132, finalizeShred:163) — defense-in-depth exceeds spec minimum. ✓
- ShredRegistry NEVER emits ShredAuthorized (doc comment + grep confirm); only ConditionEngine emits. `recordShredAuthorized` is ConditionEngine-only (`ShredUnauthorizedConditionEngine`). ✓
- Triple block: G1 (ConditionEngine refuses future RevealAuthorized via `_isShreddedView`), G4 (refusal read), vault (off-chain S2-5). ✓

### RevealAuthorized / ShredAuthorized emission tripwire (§4.2, §6.3, §12) — CONFORMANT
`emit RevealAuthorized` appears EXACTLY ONCE (engine/ConditionEngine.sol:214). `emit ShredAuthorized` EXACTLY ONCE (ConditionEngine.sol:247). Event declared only in IConditionEngine. No module/registry/manager emits. FSMInterpreter never calls back into ConditionEngine. Universal tripwire holds. ✓

### AttestationGate (§5) — CONFORMANT
`verifyOracleAttestation` ABI matches §5.2. σ-shape guard: rejects 96-byte (canonical σ_Lit/G3/G4 length) signatures via `AttestationSigmaBytesForbidden` (defense vs σ-as-IKM regression). `tryEvaluateOracleAttestation` follows §5.7 tryEvaluate naming discipline. ✓

### FSMInterpreter (§6) — CONFORMANT
`advanceFSM(authorizationId, axis, actor, transitionId, attestationDigest, transitionProof)` — explicit `actor` arg (NOT msg.sender), ConditionEngine-only caller (`FSMUnauthorizedCaller`), submitter validated against `actor` not msg.sender (§6.2), bounded gas via maxTransitions → `FSMGasBudgetExceeded` (§6.4). ✓

### Halt/pause bounded-duration (§14) — CONFORMANT
`base/BoundedPausable.sol`: scoped pause ABI `pause(scope,until,reasonRef)/unpause(scope)/isPaused(scope)` (§14.1A). Enforces max duration (`PauseDurationTooLong`), non-zero `until>block.timestamp`, AUTO-EXPIRES on read (`active = until!=0 && block.timestamp<until`). Explicit V1 `freezeReveals()` anti-pattern guard in comment. Constants (lib/Enums.sol PauseConstants): OPERATIONAL=259200(72h), REGISTRY=604800(7d), EMERGENCY=604800(7d) — match §14.1A table. G4 refusal reason enum 0x01-0x0A matches §14.2 (blocking 0x01-0x09 + advisory 0x0A) verbatim. ✓

### Claim DSL (§7) — CONFORMANT
13 op constants in dsl/ClaimDSL.sol: OP_EQ=1, OP_NE=2, OP_LT=3, OP_LTE=4, OP_GT=5, OP_GTE=6, OP_AND=7, OP_OR=8, OP_NOT=9, OP_IN=10, OP_PATH_ACCESS=11, OP_WITHIN_TIME_WINDOW=12 (the 12 live operators §7.1) + OP_CUSTOM_PREDICATE=13 reserved → reverts `DSLCustomPredicateReserved` unless customPredicateEnabled (§7.2). ✓

### Deploy order (§17.1) — CONFORMANT
Deploy.s.sol sequence matches §17.1 steps 1-17 for non-controlled-use deployment: Timelock(1) → SecurityMultisig+EmergencyGov(2, lines124-127 BEFORE registries) → 6 registries(3) → GateRecipient(4) → LitV3(5) → DisclosureRegistry(6) → G4Refusal(7) → PasskeyRotationLog(8) → SupersededCommit(9) → ChallengeRegistry(10) → ClaimDSL(11) → FSMInterpreter(12) → modules → AttestationGate(15) → ShredRegistry(16) → ConditionEngine(17). Controlled-use steps 13/14-portion correctly skipped. ✓

### Mode 3 rejection (§11.1) + legal-effect guardrails — CONFORMANT
ConditionEngine `_validateRegistration` rejects WalletEIP1271Reserved → `ConditionMode3Reserved`; shred-guardrail-compiled check → `ConditionShredGuardrailMissing`; QES/QTSP, Art.9-basis, synced-passkey-forbidden, pause-authority-mode validation. `_requireRevealPreconditions` re-reads pause+shred+registry+blocking-refusal at reveal time (§4.2). ✓

---

## DEVIATIONS

### [MEDIUM] EIP-712 named domains not declared in any V3 contract (§15.1)
spec_ref: §15.1 ("S2-2 owns contract-side domain declarations for") + §15.2
code_ref: grep of all `*.sol` (src+test+script) for `CealisRevealManager|CealisConditionalRecipient|CealisSubjectInitiated|CealisConsentGate|CealisMultiPartySignal` = ZERO hits.
Detail: §15.1 explicitly assigns ownership of 5 EIP-712 typed-data domains to the S2-2 contract layer. None are declared anywhere. No contract inherits OZ `EIP712` / uses `_hashTypedDataV4` / `_domainSeparatorV4`. The only on-chain signature recovery is AttestationGate.sol:257 `ECDSA.recover(attestationDigest, oracleSignature)` — a RAW recover, NOT bound to any EIP-712 typed domain. The signature-consuming modules (SubjectInitiated, ConsentGate, MultiPartySignal) accept `signatureEnvelopeRef`/`signatureEnvelope` but perform only presence/eligibility checks (e.g., ConsentGateModule `_submitConsent`: `signatureEnvelopeRef.length == 0` revert + eligibility-map lookup) — full signature verification is the off-chain combiner path.
Assessment: PARTIALLY mitigated by design — §4.5/§4.10/§5.6 permit full signature verification off-chain under σ-as-authorization, and §15.1 itself notes the verifying contract may be `address(0)` in off-chain context. BUT §15.1 still says "S2-2 owns contract-side domain declarations" and they are absent, and App. C scope-out does NOT list these as off-chain/deferred. Real risk surfaces only if/when on-chain typed-domain recovery is needed (notably Mode 2 ConditionalRecipient `ECDSA.recover` referenced in §15.1, and any future on-chain σ_subject/consent recovery). This is a documentation/ownership gap between spec and code rather than an exploitable security hole at the current off-chain-verification posture.

### [LOW] proof_shred preimage includes extra leading authorizationId field (§10.5)
spec_ref: §10.5 line 1555 `proofShred = keccak256(abi.encodePacked(hCommit, shredFinalizedBlock, shredAuthorityMode, shredConditionRef))` (4 fields)
code_ref: shred/ShredRegistry.sol:183-187 `keccak256(abi.encodePacked(authorizationId, hCommit, uint64(block.number), uint8(record.authorityMode), record.conditionRef))` (5 fields, leading authorizationId)
Detail: Impl prepends `authorizationId` to the preimage. proof_shred is explicitly "a public verification token ... NOT key material" (§10.5, §5.6) — an audit handle only that "does not derive, wrap, or reveal any DEK." The extra field STRENGTHENS domain binding (benign), but the byte layout differs from the spec's stated formula. Any off-chain auditor recomputing proof_shred from the §10.5 formula would mismatch. Trivially fixable in either direction; zero security impact. Worth aligning spec ↔ code so the audit-handle reconstruction is deterministic for external verifiers.

---

## Notes on STALE prior-audit context
The May-14/19 audit predates the combiner/profile-dispatch/g4-phase1 rework. None of the above findings depend on off-chain TS — they are pure on-chain S2-2 surface checks against current HEAD. The on-chain contract surface is materially MORE conformant than the inflated 5.00/5 scorecard implied (scorecard graded self-authored docs); the actual Solidity is a faithful S2-2 implementation with the two minor deviations above.
