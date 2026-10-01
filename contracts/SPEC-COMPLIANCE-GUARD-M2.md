# SPEC-COMPLIANCE-GUARD — M2 Smart Contracts (`contracts/`)

**Mandatory pre-read for every M2 Codex chunk (B/C/D1/D2/E).** This file is the load-bearing anti-drift guardrail for the M2 mission. If anything in your chunk's brief contradicts this file, halt and surface to the human reviewer before writing code.

**Authoring discipline.** Spec quotes below are byte-pinned to S2-2 / S2-1 / App. A line numbers verified by `grep -nE "^### §" docs/specs/smart-contracts-spec.md`. App. A is normative per S2-2 §0.6. When prose and App. A diverge, App. A wins.

**Phase-A enforcement.** Most invariants below are enforced upstream by Phase A foundation files under `src/lib/`, `src/base/`, and `src/helpers/`, plus `test/foundation/`. Codex chunks IMPORT these foundations rather than re-author them. The "How M2 enforces it" line names which foundation file or which Codex chunk owns the trip-wire.

---

## §1 — Universal tripwire: only ConditionEngine emits `RevealAuthorized` AND `ShredAuthorized`

**What.** No module, registry, governance contract, helper, or library may emit `RevealAuthorized` or `ShredAuthorized` directly. The only legal exception is `RevealAuthorizedEmitter` (§18.5) called by ConditionEngine via `onlyCondition`.

**Spec quote (S2-2 §0.7 L71):**
> "Universal tripwire. No release path exists that bypasses the on-chain-verified predefined condition. In S2-2 terms: only ConditionEngine may emit `RevealAuthorized`; every module path routes through either Mode F terminal state or Mode P predicate evaluation; challenge windows, shred state, pause state, registry deprecation, G4 refusal, and Mode 3 rejection cannot be bypassed by alternate emitters."

**Spec quote (S2-2 §12.1 L1336):**
> "`RevealAuthorized` is emitted only by ConditionEngine or by RevealAuthorizedEmitter called by ConditionEngine. No module, registry, or governance contract may emit it directly."

**App. A note (L2280):** `event ShredAuthorized` lives on `IConditionEngine`, NOT on `IShredRegistry`. ShredRegistry only RECORDS shred state via `ShredStateChanged` after ConditionEngine has emitted `ShredAuthorized` in the same transaction.

**How M2 enforces it.**
- Phase D1 condition modules implement `IConditionModule` only — no `RevealAuthorized` event declaration permitted in module sources (Phase D1 brief grep gate).
- Phase D2 ConditionEngine is the sole declared emitter of `RevealAuthorized` and `ShredAuthorized` in `src/engine/`.
- Phase D2 invariant test `test/invariant/UniversalTripwire.t.sol` (`invariant_OnlyConditionEngineCausesReveal`) handler attempts emit-from-module + emit-from-registry; both MUST revert.
- If the optional `RevealAuthorizedEmitter` is extracted under §18.5: its `emitRevealAuthorized` is `onlyCondition`-modified, custom error `RevealEmitterUnauthorized(address)`; event topic0 byte-identical to `IConditionEngine.RevealAuthorized` (Foundry test compares `keccak256(<event signature>)` of both interfaces).

**Failure mode.** If a Codex chunk discovers a "convenient" emit path (e.g., a registry helper that emits for SDK convenience), STOP, write to `~/m2-<X>-codex-summary.md`, exit. Do NOT add a second emitter.

---

## §2 — σ-as-authorization: σ values NEVER in calldata, storage, or events

**What.** `σ_subject`, `σ_Lit`, `σ_G3`, `σ_G4`, `σ_conditional` are post-verification authorization booleans. They MUST NOT appear as calldata bytes to S2-2 contracts, MUST NOT be stored in any contract storage slot, MUST NOT be emitted in any event payload. On-chain bindings reference commitment metadata, registered authority state, assignment records, gate-recipient pubkeys, refusal state — never σ bytes.

**Spec quote (S2-1 §0.3 / preamble L44):**
> "σ as authorization (P22 doctrine, revisited 2026-05-05): Throughout this spec, σ values (σ_Lit, σ_G3, σ_G4, σ_conditional) are conventional verification signatures or attestation outputs over `(authorizationId, h_commit, block_hash)` under the gate authority state that was valid at the commit block. They are authorization evidence, not DEK material."

**Spec quote (S2-1 §0.3 / preamble L97):**
> "σ-as-authorization + AEAD orthogonality: σ values authorize per-stanza share release. They are not DEK material and may appear in the reveal artifact after verification. PII protection is via AEAD and Shamir threshold reconstruction: the protected materials are Shamir shares, decap material, DEK, and plaintext."

**Spec quote (S2-2 §12.2 L1352):**
> "No σ in event payload. No event in S2-2 emits σ values, σ digests, gate partials, or DEK material."

**Spec quote (S2-2 §1.3 L130):**
> "Error arguments must be typed enough for forensics but must not include PII, σ bytes, plaintext bytes, partial AAD bytes, or oracle attestation plaintext. Hashes and IDs are acceptable."

**App. A enforcement.** `IAttestationGate` declares `error AttestationSigmaBytesForbidden();` (App. A L2382) — wired into AttestationGate's `verifyOracleAttestation` reject path when calldata pattern looks like a σ-shaped blob. AttestationGate is NOT a σ verifier; σ verification stays off-chain in the combiner per S2-1 §14.

**How M2 enforces it.**
- Phase D1 AttestationGate: brief enforces NO `bytes` parameter named `sigma*` or shaped like the 96-byte tuple in any verifier function.
- Phase F final: Slither + manual grep of `event*` declarations across all contracts looking for `bytes` payloads on reveal/refusal/disclosure events.
- Phase D2 ConditionEngine: `RevealAuthorized` and `ShredAuthorized` payloads (App. A L2271-2288) deliberately omit any σ field — implementations MUST NOT add one.

**Failure mode.** If a chunk needs to pass σ bytes through a contract for "convenience" or "auditability," STOP — that's an off-chain combiner concern (S2-1 §14, M3 territory). Do NOT add a σ field anywhere. Surface and exit.

---

## §3 — 30 TAG_*_V3 constants must match M1 hex digests

**What.** S2-2 imports the 30 `TAG_*_V3` names from S2-1 §2 verbatim. Every contract using TAG-prefixed lookups (PluginHashRegistry, G4AuthorityRegistry, OracleRegistry, helpers in `ICealisIdentifierHelpers`) reads the constant from a single source-of-truth Solidity module: `src/lib/Tags.sol` (Phase A).

**Spec quote (S2-2 §1.7 L194):**
> "Every `TAG_*_V3` name in S2-2 imports S2-1 §2. S2-2 may define Solidity `bytes32 constant` values derived from S2-1 labels, but the label and preimage meaning remain S2-1's responsibility."

**Spec quote (S2-2 §0.7 L73):**
> "TAG import. S2-2 imports `TAG_*_V3` names from S2-1 §2 only. It does not define new tags. BP-13 is rejected (`dsl_version_ref` remains raw catalog ref), BP-14 is accepted (`TAG_ORACLE_REGISTRY_V3` active), and BP-15 is rejected (`qtsp_provider_ref` remains raw catalog ref)."

**Class split** (per `v3-registry-class-discipline.md` (internal design note, not in this export)):
- **class-CRYPTO** (TAG-prefixed lookup keys): `PluginHashRegistry`, `G4AuthorityRegistry`, `OracleRegistry`
- **class-CATALOG** (raw 32-byte refs, NO TAG prefix): `DSLVersionRegistry`, `QTSPRegistry`
- BP-13 REJECTED → `dsl_version_ref` raw 32-byte
- BP-14 ACCEPTED → `oracle_id = keccak256(TAG_ORACLE_REGISTRY_V3 ‖ oracle_pubkey_or_addr)`
- BP-15 REJECTED → `qtsp_provider_ref` raw 32-byte

**How M2 enforces it.**
- Phase A `src/lib/Tags.sol` is the sole declaration site for the 30 `TAG_*_V3` constants. Every other contract imports from this file.
- Phase A `test/foundation/TagDigests.t.sol` asserts on-chain `keccak256(bytes("CEALIS_V3_*_V3"))` matches the M1 `@cealis/v3-crypto` hex digest for each of the 30 entries — single load-bearing trip-wire.
- Phase B PluginHashRegistry / G4AuthorityRegistry / OracleRegistry use TAG-prefixed lookup helpers from `ICealisIdentifierHelpers`.
- Phase B DSLVersionRegistry / QTSPRegistry consume raw 32-byte refs (no TAG prefix in lookup keys).

**Failure mode.** If a chunk needs a TAG that isn't in the 30-entry registry, STOP — S2-2 may not introduce new TAGs (§1.7). Surface to S2-1 owner and exit.

---

## §4 — 10-state `LifecycleState` enum verbatim from App. A

**What.** ConditionEngine's `LifecycleState` enum has exactly 10 values in this exact order. No additions, no reorderings, no enum-value renames. The enum is shared infrastructure: emitted in `LifecycleStateChanged` (App. A L2289), returned from `lifecycleState(authorizationId)` view (App. A L2314), consumed by indexers + S2-5 SDK.

**Spec quote (App. A L2095-2106):**
> ```solidity
> enum LifecycleState {
>     Unregistered,
>     Registered,
>     RevealConditionMet,
>     RevealChallengeOpen,
>     PostChallengeRevealInProgress,
>     RevealCompleted,
>     ShredConditionMet,
>     ShredChallengeOpen,
>     Shredded,
>     Paused
> }
> ```

**Spec quote (S2-2 §4.1 L466-477):**
> "The ConditionEngine state machine is: 1. `Registered`: commit exists but no reveal or shred authorization has fired. 2. `RevealConditionMet`: reveal condition evaluated true and `RevealAuthorized` emitted. 3. `RevealChallengeOpen`: non-zero reveal challenge window active. 4. `PostChallengeRevealInProgress`: challenge window closed or zero-window path reached; gates may sign. 5. `RevealCompleted`: delivery side reports completion digest, if PDA tracks completion. 6. `ShredConditionMet`: shred condition evaluated true and `ShredAuthorized` emitted. 7. `ShredChallengeOpen`: non-zero shred challenge window active. 8. `Shredded`: permanent shred finalized. 9. `Paused`: overlay state that blocks advancement but does not erase base state."

**Note:** §4.1 prose enumerates 9 states (does not separately number `Unregistered = 0`); App. A normatively pins all 10 including `Unregistered`. **App. A is the source-of-truth count; implementation enums are 10-value.**

**How M2 enforces it.**
- Phase A `src/lib/Enums.sol` declares the 10-state enum verbatim. Single source-of-truth.
- Phase D2 ConditionEngine emits `LifecycleStateChanged(authorizationId, oldState, newState)` on every transition.
- Phase D2 `test/engine/ConditionEngineLifecycle.t.sol` asserts enum values numerically: `Unregistered == 0`, `Registered == 1`, ..., `Paused == 9`. Fuzz reachability test covers all 10 states.
- Phase D2 invariant: no contract introduces an 11th state value.

**Failure mode.** If Codex thinks a state is "missing" (e.g., wants to add `RevealQueued` or `ShredQueued`), STOP — this is the V2 launch enum surface, locked. Surface design pressure and exit.

---

## §5 — 10-code G4 refusal enum (NOT 5)

**What.** `G4RefusalRegistry` supports a 10-code refusal-reason enum, NOT 5. Codes 0x01-0x09 are blocking; 0x0A is advisory-only (non-blocking, audit-trail only). Per-function gates differ for blocking vs advisory.

**Spec quote (S2-2 §14.2 L1465-1481):**
> "G4RefusalRegistry supports the five base reason codes from `flows-spec-final.md` §425:
> - `0x01 legal_compel`
> - `0x02 art_17_erasure`
> - `0x03 art_18_restriction`
> - `0x04 integrity_fail`
> - `0x05 chain_mismatch`
>
> S2-1 §12/§16 also references deprecation refusal codes `0x06` through `0x0A`. S2-2 supports an extensible enum range but separates blocking refusal state from advisory signal state. Codes `0x01`-`0x09` are blocking refusal reasons that can prevent σ_G4. Code `0x0A` is an advisory transparency signal only:
> - `0x06 plugin_deprecated`
> - `0x07 authority_deprecated`
> - `0x08 dsl_deprecated`
> - `0x09 oracle_deprecated`
> - `0x0A opt_out_active` (advisory, non-blocking)"

**Spec quote (S2-2 §14.3 L1485-1493 — encrypted-reason mode):**
> "For reason codes `0x02` and `0x03`, default storage is encrypted reason: ... The plaintext reason is not emitted. Public-reason mode for these codes requires PDA-level opt-out with explicit subject acknowledgment and partner attestation; legal-effect PDAs should not use public-reason mode unless counsel has approved. The `RefusalSignal`/`refusalState` channel is blocking-only. Advisory-only `0x0A` uses `AdvisorySignal`/`signalState` and must not appear as `refused == true`."

**Spec quote (S2-2 §16.2 L1566-1567 — per-function gates):**
> "`IG4RefusalRegistry.refusePublic` / `refuseEncrypted` / `recordSignal(blocking=true)` | `OPERATOR_ROLE`; rejects advisory-only `0x0A`."
> "`IG4RefusalRegistry.recordAdvisorySignal` / `recordSignal(blocking=false)` | `OPERATOR_ROLE`; accepts advisory-only `0x0A` unless S2-6 later adds other advisory codes."

**App. A note (L2598-2601):** Three event surfaces: `RefusalSignal`, `RefusalReasonEncrypted`, `AdvisorySignal`. Errors include `RefusalSensitiveReasonMustBeEncrypted(uint8)`, `RefusalAdvisoryReasonNotBlocking(uint8)`, `RefusalBlockingReasonRequired(uint8)`.

**How M2 enforces it.**
- Phase C `src/g4-refusal/G4RefusalRegistry.sol` declares all 10 codes (0x01-0x0A) as `uint8 constant` values matching the spec assignments.
- Phase C `refusePublic` / `refuseEncrypted` / `recordSignal(blocking=true)` reject `reasonCode == 0x0A` with `RefusalAdvisoryReasonNotBlocking`.
- Phase C `recordAdvisorySignal` rejects any `reasonCode != 0x0A` with `RefusalBlockingReasonRequired` (until S2-6 adds advisory codes).
- Phase C codes 0x02/0x03 default to encrypted-reason path; `refusePublic` for 0x02/0x03 reverts unless the PDA opt-out flag is set (test asserts this gate).
- Phase C tests assert all 10 codes round-trip through their correct event surface.

**Failure mode.** If a chunk implements only 5 codes (0x01-0x05), STOP — that's the predecessor framing from `flows-spec-final.md §425` BEFORE the 0x06-0x0A deprecation extension landed. The 10-code surface is normative.

---

## §6 — 4-param `getPubkeyAt` per App. A (NOT 3-param §9 prose)

**What.** `IGateRecipientPubkeyRegistry.getPubkeyAt` is **4 parameters** per App. A. S2-2 §9 prose at L794 abbreviates to 3 params; this is a known prose/App. A discrepancy, and **App. A is normative per §0.6**.

**Spec quote (App. A L2565-2569):**
> ```solidity
> function getPubkeyAt(bytes32 authorizationId, uint8 gateKind, uint16 conditionalRecipientIndex, uint64 blockNumber)
>     external
>     view
>     returns (GateRecipientPubkeyEntry memory);
> ```

**Spec quote (S2-2 §0.6 L57):**
> "Source-of-truth ordering. ... When prose narrative diverges from App. A interface enumeration, App. A wins."

**Why.** GateRecipientPubkeyEntry is keyed by `(authorizationId, gateKind, conditionalRecipientIndex)` — the conditional-recipient index is required to disambiguate Mode 2 multi-recipient PDAs. Dropping it breaks M3 SDK consumption and breaks Mode 2 multi-recipient delivery (reveal selects the wrong stanza).

**How M2 enforces it.**
- Phase C `src/gate-recipient/GateRecipientPubkeyRegistry.sol` implements the 4-param signature verbatim from App. A L2565.
- Phase C tests cover: per-commit ephemeral entry written by `GATE_PUBKEY_PUBLISHER_ROLE`; long-lived drand committee entry under 7-day timelock by `REGISTRY_ADMIN_ROLE`; historical lookup at `blockNumber < tombstoneBlock` returns the entry; lookup at `blockNumber >= tombstoneBlock` reverts `RegistryEntryTombstoned`.
- Phase C summary writeup MUST include a META note: "S2-2 §9 L794 prose abbreviates `getPubkeyAt` to 3 params; App. A L2565 is normative 4 params; implementing the 4-param form."
- Phase F: closes Linear PRO-497 (R1).

**Failure mode.** If a chunk reads §9 prose and silently picks the 3-param form, STOP — App. A wins. Surface the discrepancy and implement the 4-param form.

---

## §7 — Phase 1 G4 banned on legal-effect PDAs

**What.** ConditionEngine `registerPDA` MUST reject any registration where `legalFlags.legalEffectExpected == true` AND `legalFlags.requiredG4Phase == G4Phase.Phase1` with `ConditionLegalEffectPhaseInvalid(authorizationId, phase)`.

**Spec quote (S2-2 §3.4 L398):**
> "`phase == 2` when legal-effect PDA template requires Phase 2 G4."

**Spec quote (S2-2 §0.3 — terminology discipline) and §20.3 — invariant test:**
> "No legal-effect PDA with Phase 1 G4."

**App. A note (L2263):** `error ConditionLegalEffectPhaseInvalid(bytes32 authorizationId, uint8 phase);` is declared on `IConditionEngine`. This error is the load-bearing signal.

**Why.** Phase 1 G4 is the sealed-code-server scaffold (operational-grade attestation, NOT cryptographic-non-custody). Legal-effect PDAs need §371a ZPO admissibility, which requires Phase 2 (rented TEE with cryptographic attestation). A legal-effect PDA paired with Phase 1 G4 is a §0.7 universal-tripwire violation.

**How M2 enforces it.**
- Phase D2 ConditionEngine `registerPDA`: validates `if (registration.legalFlags.legalEffectExpected && registration.legalFlags.requiredG4Phase == G4Phase.Phase1) revert ConditionLegalEffectPhaseInvalid(authorizationId, 1);`
- Phase D2 invariant `invariant_NoLegalEffectPdaWithPhase1G4` covers fuzz registration attempts.
- Phase D2 negative test in §20.5 explicitly attempts a legal-effect Phase 1 registration and asserts revert.

**Failure mode.** If the validation is moved to a PDA-config helper instead of ConditionEngine, the contract-level guarantee is weakened (configurator could be bypassed). KEEP the check in ConditionEngine `registerPDA`.

---

## §8 — Class-wide halt opt-out forbidden on legal-effect PDAs

**What.** ConditionEngine `registerPDA` MUST reject any registration where `legalFlags.legalEffectExpected == true` AND `pdaRootFields.cealisClassWideHaltOptOut == true` with `ConditionLegalEffectHaltOptOutForbidden(authorizationId)`.

**Spec quote (S2-2 §3.4 L397):**
> "`cealis_class_wide_halt_opt_out == false` when `legal_effect_expected == true`."

**Spec quote (S2-2 §14.4 L1495):**
> "`cealis_class_wide_halt_opt_out == true` is forbidden when `legal_effect_expected == true`. Contract validators enforce this at PDA registration."

**App. A note (L2264):** `error ConditionLegalEffectHaltOptOutForbidden(bytes32 authorizationId);` is declared on `IConditionEngine`.

**How M2 enforces it.**
- Phase D2 ConditionEngine `registerPDA` validates the pair before storing.
- Phase D2 invariant `invariant_NoLegalEffectPdaWithHaltOptOut`.
- Phase D2 negative test in §20.5.

---

## §9 — Mode 3 σ_conditional REJECTED at every PDA-registration entry point

**What.** Any function that registers, updates, or validates conditional-recipient policy for an active PDA MUST reject `ConditionalRecipientMode.WalletEIP1271Reserved` (the App. A enum value 0x03) with `ConditionMode3Reserved(authorizationId)`. Layer 1 of the §11.2 defense-in-depth.

**Spec quote (S2-2 §11.1 L1316-1318):**
> "Any function that registers, updates, or validates conditional-recipient policy for an active PDA must reject `deliveryMode == 0x03` with `Mode3Reserved`. This includes ConditionEngine PDA registration, PDA config registry validation, and any helper used by S2-4."

**Spec quote (S2-2 §11.2 L1322-1330):**
> "Layer 1: S2-2/S2-4 configurator entry rejects Mode 3.
> Layer 2: subject-side verifier rejects a Mode 3 stanza before σ_subject signing. This is S2-3/S2-4 implementation detail but S2-2 preserves the rejection reason.
> Layer 3: combiner rejects Mode 3 at reveal with `ERR_MODE_3_NOT_SHIPPED_AT_V2`. This is S2-1/S2-3/S2-5 surface.
> S2-2 must not expose a governance toggle that silently activates Mode 3."

**App. A enum (L2092):** `enum ConditionalRecipientMode { None, PasskeyAccount, WalletEOA, WalletEIP1271Reserved }` — `WalletEIP1271Reserved = 3`.

**App. A error (L2262):** `error ConditionMode3Reserved(bytes32 authorizationId);` on `IConditionEngine`.

**How M2 enforces it.**
- Phase A `src/lib/Enums.sol` declares `ConditionalRecipientMode` exactly as App. A.
- Phase D2 ConditionEngine `registerPDA`: iterates `registration.conditionalRecipientModes[]` and reverts `ConditionMode3Reserved` if any entry equals `WalletEIP1271Reserved`.
- Phase D2 same check in any PDA-update helper (per §11.1's "broader than just registerPDA").
- Phase D2 invariant `invariant_NoMode3ActivePdaAtV2Launch`.
- Phase D2 negative test §20.5: "Mode 3 recipient hidden in mixed recipient set" — registration MUST reject when mode 3 appears anywhere in the modes array.
- M2 deliberately does NOT expose any governance toggle to enable Mode 3.

**Failure mode.** If a chunk thinks "we'll surface a feature flag for future enable," STOP — Mode 3 activation requires S2-1 + S2-6 + configurator coordination per §11.2. M2 contracts MUST NOT include such a flag.

---

## §10 — `commit_version 0x0302` enforced as compile-time and PDA-registration invariant

**What.** `BUILD_PROTOCOL_VERSION = 0x0302` is the active V3 protocol version (per `.cealis-rc.json` and S2-1 §0.3). PDA registration MUST reject any `HCommitFields.commitVersion != 0x0302`.

**Spec quote (S2-1 §0.3 / preamble L20):**
> "The protocol version this spec normatively encodes is `commit_version = 0x0302` ... the previous version `0x0301` (flat-Shamir, broken under 4-gate AND for surplus conditional-recipient access structures) is historical/invalid for new partner-ready commits unless explicitly migrated."

**App. A struct (L2144-2160):** `struct HCommitFields { ...; uint16 commitVersion; }` — `commitVersion` is `uint16`.

**How M2 enforces it.**
- Phase A `src/lib/Enums.sol` (`PauseConstants` + `ProtocolVersion` libraries) declares `uint16 constant BUILD_PROTOCOL_VERSION = 0x0302;`
- Phase A `src/lib/Structs.sol` mirrors App. A's `HCommitFields` byte-for-byte (15 fields, `commitVersion: uint16` at the end).
- Phase D2 ConditionEngine `registerPDA`: validates `if (registration.hCommitFields.commitVersion != BUILD_PROTOCOL_VERSION) revert ConditionInvalidMode(registration.hCommitFields.commitVersion);` (or a dedicated `ConditionInvalidCommitVersion(uint16)` if one is added — verify against App. A errors before introducing).
- Phase D2 negative test: registration with `commitVersion = 0x0301` MUST revert; with `commitVersion = 0x0303` MUST revert.

**Failure mode.** If a chunk relaxes this to "accept any 0x03xx for forward compat," STOP — protocol version bumps require coordinated rollout per S2-1 §2.8. The check MUST be byte-exact equality.

---

## §11 — Bounded-duration pause: every pausable surface implements `IPausableSurface`

**What.** Every pausable contract in M2 MUST implement `IPausableSurface` per App. A L2611-2623. Pauses auto-expire on `block.timestamp > until` even without an `unpause` transaction. Max durations are constants (§11 below). The V1 `RevealManager.freezeReveals()` unbounded-pause pattern is FORBIDDEN.

**Spec quote (S2-2 §14.1A L1444-1452):**
> ```solidity
> function pause(bytes32 scope, uint64 until, bytes32 reasonRef) external;
> function unpause(bytes32 scope) external;
> function isPaused(bytes32 scope) external view returns (bool active, uint64 until, bytes32 reasonRef);
> ```
> "`scope` is either a contract-wide scope id, a PDA/authorization scope id, or a module/registry-entry scope id defined by that contract. `until` must be non-zero and no later than the applicable max duration. Pauses auto-expire for read and state-transition checks once `block.timestamp > until`, even if no `unpause` transaction was sent."

**Spec quote (S2-2 §14.1A L1454-1461 — max durations):**
> "| Operational contract/module pause | 72 hours |
> | Registry-addition/tombstone pause | 7 days |
> | Emergency governance circuit-breaker pause | 7 days |
> | ChallengeRegistry new-challenge pause | 72 hours unless S2-6 legal ceremony explicitly grants a stricter PDA-bound window |"

**App. A constants (L2108-2110):**
> ```solidity
> uint64 constant MAX_OPERATIONAL_PAUSE_SECONDS = 259200; // 72 hours
> uint64 constant MAX_REGISTRY_PAUSE_SECONDS = 604800;     // 7 days
> uint64 constant MAX_EMERGENCY_PAUSE_SECONDS = 604800;    // 7 days
> ```

**How M2 enforces it.**
- Phase A `src/lib/Enums.sol` (`PauseConstants` + `ProtocolVersion` libraries) declares the 3 `MAX_*_PAUSE_SECONDS` constants verbatim from App. A.
- Phase A `src/base/IPausableSurface.sol` declares the ABI interface verbatim from App. A L2611-2623.
- Phase A `src/base/BoundedPausable.sol` abstract base implements pause/unpause/isPaused with `MAX_*_PAUSE_SECONDS` enforcement, auto-expire on `block.timestamp > until`, and `PauseAuthorityMode` validation refusing shred-axis values (per §12 below).
- Every pausable contract in Phases B/C/D1/D2/E inherits `BoundedPausable` and selects which `MAX_*` constant applies via constructor/initializer parameter.
- ChallengeRegistry (Phase C) uses `MAX_OPERATIONAL_PAUSE_SECONDS = 259200` (72h) for its new-challenge pause.

**Failure mode.** If a Codex chunk introduces a pause without `until` or with `until == 0`, STOP — that's the V1 `freezeReveals()` anti-pattern. Surface and re-spec.

---

## §12 — `PauseAuthorityMode` enum is `Partner | Joint | None` ONLY

**What.** Pause authority and shred authority are TWO separate enums. `PauseAuthorityMode` has exactly 3 values: `Partner`, `Joint`, `None`. The shred-authority values (`Subject`, `Operator`, `Timelock`, `Disabled`) MUST NOT be reused for pause authority.

**Spec quote (S2-2 §14.1A L1463):**
> "Pause authority uses `PauseAuthorityMode`, not `ShredAuthorityMode`. The only pause-authority values are `Partner`, `Joint`, and `None`; shred authority values (`Subject`, `Operator`, `Timelock`, `Disabled`) must not be reused for pause authority."

**App. A enums (L2089-2091):**
> ```solidity
> enum PauseAuthorityMode { Partner, Joint, None }
> /// @dev None == 0 is an invalid Solidity sentinel and is not PDA-selectable.
> enum ShredAuthorityMode { None, Subject, Joint, Operator, Timelock, Disabled }
> ```

**App. A error (on `IConditionEngine` L2268):** `error ConditionPauseAuthorityInvalid(uint8 mode);`

**How M2 enforces it.**
- Phase A `src/lib/Enums.sol` declares BOTH enums separately, verbatim from App. A. Two distinct enums, not a shared one.
- Phase A `src/base/BoundedPausable.sol` `pause()` checks `if (uint8(authorityMode) > 2) revert ConditionPauseAuthorityInvalid(uint8(authorityMode));` (rejects values >= 3 which would be `Subject`/`Operator`/`Timelock`/`Disabled` from the wrong enum).
- Phase D2 ConditionEngine `registerPDA` validates `registration.pauseAuthorityMode` is one of `Partner | Joint | None`.

**Failure mode.** If a chunk reuses `ShredAuthorityMode` for a pause-authority field (saving an enum declaration), STOP — App. A explicitly forbids this. Two separate enums.

---

## §13 — `ShredAuthorityMode.None == 0` is invalid sentinel only

**What.** `ShredAuthorityMode.None == 0` is an invalid Solidity sentinel — it is NOT a PDA-selectable value. Real PDA shred authority is `Subject`, `Joint`, `Operator`, `Timelock`, or `Disabled`. `requestShred` rejects `None` calls.

**Spec quote (App. A L2090-2091):**
> ```solidity
> /// @dev None == 0 is an invalid Solidity sentinel and is not PDA-selectable.
> enum ShredAuthorityMode { None, Subject, Joint, Operator, Timelock, Disabled }
> ```

**Spec quote (S2-2 §16.2 L1563):**
> "`IShredRegistry.requestShred` | PDA-bound `ShredAuthorityMode`; `None == 0` is invalid."

**How M2 enforces it.**
- Phase A `src/lib/Enums.sol` documents the enum-value 0 invalid-sentinel rule in NatSpec.
- Phase D2 ShredRegistry `requestShred`: `if (authorityMode == ShredAuthorityMode.None) revert ShredAuthorityInvalid(hCommit, msg.sender);`
- Phase D2 ConditionEngine `registerPDA`: rejects PDAs whose `pdaRootFields.shredAuthorityId` resolves to `None`.

---

## §14 — Read freshness: re-read all live preconditions per §2.6

**What.** Every state-changing function that emits a ceremony event MUST re-read all live preconditions in the same transaction. No snapshot-once preparatory check followed by emission later. This is Cealis Rule 25 (universal "snapshot, never re-check" anti-pattern) applied at the contract layer.

**Spec quote (S2-2 §2.6 L332-341):**
> "Every state-changing function that emits a ceremony event must re-read all live preconditions in the same transaction:
> - lifecycle state has not advanced to shredded or reveal-in-progress conflict state.
> - PDA pause is not active.
> - registry entries required for the condition are effective at the relevant block and not tombstoned before authorization.
> - challenge-window guardrail still matches module trust tier.
> - `post_challenge_reveal_in_progress` is false for shred.
> - blocking G4 refusal state has not already blocked the authorization; advisory G4 signal state is audit-only.
>
> S2-2 inherits Cealis Rule 25: snapshot-once multi-step flows are a known failure mode. Implementations must not validate preconditions in a preparatory transaction and then emit `RevealAuthorized` later without re-validation."

**How M2 enforces it.**
- Phase D2 ConditionEngine `authorizeReveal` / `authorizeShred`: re-reads pause, lifecycle, challenge, registry deprecation, refusal state in the same call — does NOT trust prior snapshots.
- Phase D2 invariant tests fuzz the timing window: a precondition that was true at preparatory call N MAY be false by emission call N+1; emission MUST observe the live state.

**Failure mode.** If a chunk introduces a "fast path" that snapshots preconditions to save gas, STOP — that's the §2.6 violation Rule 25 names by example. Re-read, always.

---

## §15 — UUPS discipline: BOTH `Initializable` AND `UUPSUpgradeable` (V1 PRO-264 lesson)

**What.** Every upgradeable Cealis contract MUST inherit BOTH `Initializable` AND `UUPSUpgradeable` separately. OZ v5.x `UUPSUpgradeable` does NOT inherit from `Initializable` — must import + add to inheritance chain. Storage layout is append-only; field reordering is forbidden.

**Spec quote (S2-2 §0.7 L77):**
> "UUPS discipline. Every upgradeable Cealis contract inherits `Initializable` and `UUPSUpgradeable`. `_authorizeUpgrade(address)` is `internal override onlyRole(UPGRADER_ROLE)`. `UPGRADER_ROLE` is held exclusively by TimelockController after deployment. Storage layout is append-only; field reordering is forbidden."

**Spec quote (S2-2 §18.1 L1692):**
> "Every Cealis upgradeable contract inherits `Initializable` and `UUPSUpgradeable`. Contracts that use access control inherit `AccessControlUpgradeable`. Contracts with pause inherit `PausableUpgradeable`. Initializers call all parent initializers exactly once."

**Spec quote (S2-2 §1.2 L121-126):**
> "Every Cealis upgradeable contract uses one of two storage patterns: 1. OZ v5 namespaced storage when the contract naturally fits ERC-7201 namespacing. 2. Explicit append-only storage structs with a `uint256[N] __gap` when namespacing is not used. The invariant is the same: initial field ordering is frozen at deployment; future versions append new fields only."

**V1 PRO-264 lesson.** OZ v5.x `@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol` does NOT inherit from `Initializable`. Must import `Initializable` separately and add to the inheritance chain. All 9 V1 UUPS contracts had this fixed in PRO-264 (Apr 5, 2026). Don't repeat.

**How M2 enforces it.**
- Phase A `foundry.toml` pins OpenZeppelin submodule version under `lib/openzeppelin-contracts`.
- Every UUPS contract in Phases B/C/D1/D2/E inherits `Initializable, UUPSUpgradeable` as separate parents (verify with grep on each contract head).
- `_authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE)` is the canonical override signature.
- Each upgradeable contract reserves `uint256[50] private __gap;` when explicit storage is used (S2-2 §1.2 case 2). Both `DisclosureRegistry` and `DisclosureRevocationRegistry` (Phase C) MUST reserve the gap.
- Phase F: `forge inspect <contract> storage-layout` snapshot for every UUPS contract; storage diff against snapshot is a future-upgrade gate.

**Failure mode.** If a Codex chunk inherits `UUPSUpgradeable` only (missing `Initializable`), the contract compiles but `initialize()` cannot guard against re-init. Phase F build will catch — but cheaper to enforce at write time.

---

## §16 — NO `getStateAtBlock` and NO `HistoricalRegistry` contract

**What.** Historical lookup on registries is via `IBaseRegistry.getEntryAt(bytes32 id, uint64 blockNumber)`. There is NO method called `getStateAtBlock` and NO contract called `HistoricalRegistry` in S2-2. Both were authoring errors in the original brief and Linear PRO-465 is named with the "HistoricalRegistry" misnomer (which Phase F closes by overriding the description).

**Spec quote (S2-2 §9.13 L1206-1213):**
> "`getEntryAt(id, blockNumber)` binary-searches checkpoints or reads direct effective/tombstone fields if each id has only one lifecycle. `OracleSchemaRegistry.getSchemaAt(schemaId, blockNumber)` follows the same semantics even though OracleSchemaRegistry is a schema registry rather than one of the five Cealis-governed V3 registries. Stage 3 chooses exact data structure. The external semantics are fixed:
> - if no entry effective at `blockNumber`, revert `RegistryEntryUnknown`.
> - if entry effective after `blockNumber`, revert `RegistryEntryNotEffective`.
> - if tombstone block is non-zero and <= `blockNumber`, revert `RegistryEntryTombstoned`.
> - if deprecation was set before or at `blockNumber` and not cleared before `blockNumber`, return entry plus active flag; caller decides halt behavior by lifecycle state."

**Spec quote (S2-2 §9.13 L1213 — historical-lookup semantics NORMATIVE):**
> "Historical-lookup semantics (NORMATIVE; resolves §8.4 + §4.16 alignment). The `blockNumber` argument is the block at which the historical state is being read — typically the commit's `RevealAuthorized` block per S2-1 §12.6 at-commit-block reading discipline. The four reverts above MUST be evaluated against the lifecycle state visible at that block, not at current state. Worked example: a commit registered at block N consumes oracle entry E whose tombstone was set at block M > N. A reveal-time `getEntryAt(E, N)` MUST return E as effective (tombstone block M > queried block N → tombstone-after, not tombstone-before). The `RegistryEntryTombstoned` revert fires only when the tombstone block is at or before the queried block."

**App. A interface (L2402-2422):** `IBaseRegistry` is the shared abstract surface. Function: `function getEntryAt(bytes32 id, uint64 blockNumber) external view returns (bytes memory encodedEntry);`

**How M2 enforces it.**
- Phase A `src/base/IBaseRegistry.sol` declares the abstract `IBaseRegistry` interface verbatim from App. A L2402-2422 + 7 inherited custom errors.
- Phase B 5 V3 registries + OracleSchemaRegistry (and Phase C registries that share lookup semantics) all inherit `IBaseRegistry` and implement `getEntryAt` per the §9.13 worked example.
- Phase B `test/registries/_HistoricalLookup.t.sol` shared test fixture covers the §9.13 worked example: commit at block N + tombstone at M > N → `getEntryAt(E, N)` returns effective; `getEntryAt(E, M)` reverts `RegistryEntryTombstoned`.
- Stage 3 implementation choice (binary-search checkpoints vs direct effective/tombstone fields) is internal — the EXTERNAL semantics are fixed.
- NO `getStateAtBlock` method anywhere. Closes Linear R3 (M2 on-chain mitigation component only — M3 + M7 hold remaining components per R12 HARD-2).

**Failure mode.** If a chunk reads the original brief title "HistoricalRegistry" (PRO-465) and tries to author a contract by that name, STOP — that's an authoring error. The functional satisfier is `IBaseRegistry` inherited by every V3 registry + OracleSchemaRegistry.

---

## §17 — Failure modes Codex MUST surface (do NOT silently work around)

If any of these arises mid-chunk, **stop, do not work around, surface to human reviewer**:

1. **EIP-170 size hit on ConditionEngine** (Phase D2). If `forge build --sizes` shows ConditionEngine runtime > 23,500 bytes (mandatory extraction review per §19.6), apply mitigation hierarchy in this order:
   - Step 1: enable `via_ir = true` in `foundry.toml` (Phase A pre-set).
   - Step 2: extract `RevealAuthorizedEmitter` per §18.5 + App. A L2841-2860, `onlyCondition`-modified, event topic0 byte-identical to `IConditionEngine.RevealAuthorized` (Foundry test).
   - Step 3: extract internal libraries for module dispatch / registry decoding / pure helpers. Extraction MUST NOT create an alternate `RevealAuthorized` path.
   - If steps 1-3 don't get under 24,000 bytes (block-merge gate per §19.6), STOP — surface to reviewer.

2. **App. A vs prose conflict.** If §X prose appears to specify behavior that App. A's interface enumeration contradicts (signature differences, error names, struct fields), App. A wins per §0.6. Note the discrepancy in your run summary; do NOT silently pick the prose version.

3. **`@cealis/v3-crypto` golden vector or type shape mismatch.** If a TAG digest, identifier helper output, or structural type from M1 doesn't match what S2-1 says, M1 is the source of truth on byte-exact crypto. If M2 needs something M1 didn't ship, surface as M0+M1 incomplete and exit. Do NOT silently re-implement crypto in Solidity.

4. **`@cealis/v3-crypto` import path or version drift.** Phase A pins the v3-crypto version. If a Codex chunk needs a newer/older version, STOP — Phase A is authoritative on the dep manifest.

5. **No-touch path violation.** If a chunk's DoD requires writing to a no-touch path (cross-chunk owned directory), STOP — re-scope to your owned paths or surface a conflict.

6. **Spec self-contradiction.** If a spec section appears under-specified, internally inconsistent, or contradicts an App. A interface declaration, STOP — surface to human reviewer with the exact contradiction.

7. **Sourcify rate limit during Phase E.** If Sourcify verification fails for ≥3 contracts in a row, fall back to BaseScan (with API key from env). Document fallback in Phase E summary.

8. **OZ v5.x `Initializable` import miss.** If a UUPS contract compiles but `initialize()` doesn't have re-init protection because `Initializable` wasn't separately inherited (V1 PRO-264 lesson), STOP and add the inheritance.

The cost of pausing is low. The cost of silent drift is the entire mission.

---

## §18 — Stop discipline (mirrors M1's §8)

**Every chunk MUST end with a stop marker on its own line as the last action.**

Successful completion (all DoD items checked, all tests green, no failure mode triggered):
```
{X}-CHUNK-COMPLETE — awaiting human review
```

Blocked (any failure mode triggered, or any DoD item cannot be completed):
```
{X}-CHUNK-BLOCKED — <one-line reason>
```

After printing the stop marker, **exit**. Do NOT auto-continue to a next item. Do NOT start another chunk.

The summary write to `~/m2-{X}-codex-summary.md` MUST happen BEFORE the stop marker. The summary covers:
- Files written (tree)
- Test results (count + pass/fail + coverage %)
- Contract sizes (`forge build --sizes`) for any contract within 1KB of EIP-170
- Spec deviations + rationale
- Any failure-mode triggers
- Open questions / decisions deferred for the human reviewer

---

## §19 — Cross-references

**Spec source of truth:** `docs/specs/smart-contracts-spec.md` (S2-2, normative; App. A is the interface contract).

**Cryptography spec dependency:** `docs/specs/cryptography-spec.md` (S2-1, byte-exact; §2 TAG registry, §3 composite identifiers, §0.3 σ-as-authorization doctrine).

**Design lockboxes:**
- `v3-registry-class-discipline.md` (internal design note, not in this export) (class-CRYPTO/CATALOG split, BP-13/14/15 verdicts)
- `4-gate-and-shamir-access-structure.md` (internal design note, not in this export) (4-gate AND framing)
- `h-commit-acyclic-schedule.md` (internal design note, not in this export) (commit-context ordering)
- `conditional-recipient.md` (internal design note, not in this export) (Mode 3 architectural framing — REJECTED at V2 launch)

**Project rules:**
- internal solidity rules (not exported) §2 (V2 system binding rules — TAG_*_V3 set, 17 V3 roles, V3 registries, ShredRegistry 2-axis, RevealAuthorized tripwire)
- internal testing rules (not exported) (Foundry conventions, fuzz/invariant patterns)
- internal infrastructure rules (not exported) (UUPS proxy pattern, deploy order)
- internal legal-constraints rules (not exported) (Art. 6(1)(b), retention, EIP-712 evidentiary, §371a ZPO)

**M1 source dependency:** `v3-crypto/src/index.ts` (importable from M1: TAG_*_V3 hex digests, identifier helpers reference vectors, σ verifier types).

**M1 anti-drift sheet:** `v3-crypto/SPEC-COMPLIANCE-GUARD.md` (model for this file's shape; M2-specific invariants supersede where they overlap).

**Phase plan + chunk briefs:** internal Stage-3 build briefs (not in this export).
