> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

# Solidity Adversarial Audit Report — Cealis V3

**Files audited:** All 42 contracts under `contracts/src/**/*.sol`
**Audit date:** 2026-05-14
**Auditor model:** Claude Sonnet 4.6
**Audit scope:** Five adversarial lenses per brief (cross-contract reentrancy, role escalation, signature replay, snapshot vs re-check, universal tripwire / event spoofing)
**Excluded (per brief):** F-01 (_disableInitializers), F-02 (chainId in attestation digest)

---

## Summary

- Total lens areas: 5
- PASS: 3 | FAIL: 4 | PARTIAL/NOTE: 2
- CRITICAL: 0 | HIGH: 0 | MEDIUM: 2 | LOW: 2 | INFORMATIONAL: 2

**Revision note (post-advisor review, 2026-05-14):** F-04 removed — the finding was wrong. No external calls exist between ShredRegistry.sol:162 and :194; all writes in that range are local state assignments and emits. On the single-threaded EVM no external state change can occur in that window. F-03 downgraded from HIGH to LOW — the attack path requires a compromised `_conditionEngine` address, which already has direct authority to finalize any shred without needing reentrancy as a vehicle. F-05 widened to system-wide pattern — EmergencyGovernance.sol carries the same admin-not-validated-against-timelock gap.

---

## Findings

---

### F-03 [LOW] Cross-contract reentrancy: ShredRegistry.finalizeShred → ConditionEngine.recordShredFinalized has no reentrancy guard (code hygiene; not exploitable without compromised ConditionEngine)

**File:** `contracts/src/shred/ShredRegistry.sol:160-194`
**Lens:** Lens 1 — Cross-contract reentrancy

**What is wrong:**

`ShredRegistry.finalizeShred()` is a permissionless external function with no reentrancy guard of any kind. Its execution sequence is:

1. (line 161) `_requireMatchingCommit` — calls `ConditionEngine.hCommitForAuthorization` (external view)
2. (line 162) `_requireNoRevealInProgress` — calls `ConditionEngine.postChallengeRevealInProgress` (external view)
3. (lines 181-193) State changes: `record.state = ShredState.Finalized`, `record.proofShred = proofShred`, `_shredded[hCommit] = true`, plus three `emit` calls
4. (line 194) External call: `IConditionEngineShredRead(_conditionEngine).recordShredFinalized(authorizationId)`

The external call at step 4 (`recordShredFinalized`) transitions `ConditionEngine`'s lifecycle state to `Shredded` and writes `record.postChallengeReveal = false`. This call happens AFTER the local state is written and AFTER `_shredded[hCommit] = true` is set, so the `_shredded` guard will correctly protect against re-entry into `finalizeShred` for the same `hCommit`.

For a different `authorizationId`, the missing `nonReentrant` guard means that a re-entrant call via `recordShredFinalized` COULD finalize a second shred mid-callback. However, the only contract that can reach this callback path is `_conditionEngine` itself — `finalizeShred` calls `IConditionEngineShredRead(_conditionEngine).recordShredFinalized`, and `recordShredFinalized` in ConditionEngine (lines 324-329) contains zero outgoing external calls (it only writes local state). A re-entrant path back into `finalizeShred` would require a compromised or malicious ConditionEngine that overrides `recordShredFinalized` to call back into ShredRegistry. Such a ConditionEngine already has direct authority to write any authorization state it wants — reentrancy is not needed as a vehicle.

The real concern is code hygiene: `ShredRegistry` does NOT inherit `ReentrancyGuardTransient`, while peer contracts (`ConditionEngine`, `OracleAttestationModule`) both do. The absence is inconsistent with the codebase's own convention and creates risk if `recordShredFinalized` is later refactored to include outgoing calls.

**Why it matters:**

In the current implementation, not practically exploitable without a compromised ConditionEngine (which would already have full protocol authority). Forward-looking risk: if `recordShredFinalized` ever gains an external call in a future upgrade, the missing guard on `ShredRegistry.finalizeShred` would become an exploitable reentrancy path with no code change required to ShredRegistry itself.

**Fix hint:** Add `ReentrancyGuardTransient` (or at minimum `ReentrancyGuard`) inheritance to `ShredRegistry` and apply `nonReentrant` to `finalizeShred`. Consistent with `ConditionEngine.authorizeShred` and `OracleAttestationModule.submitOracleAttestation`.

**Confidence:** HIGH (current code is safe); LOW (as a future-proofing hygiene finding)

---

### Considered, not reported: ShredRegistry.finalizeShred snapshot-vs-recheck of postChallengeRevealInProgress

**File:** `ShredRegistry.sol:162` vs `:194`
**Lens:** Lens 4 — Snapshot vs re-check

**Why this was not reported as a finding:**

The initial draft raised this as F-04 [HIGH]. Post-advisor review and empirical grep verification determined the finding is incorrect.

`_requireNoRevealInProgress` is called at line 162. Between that check and the external callback at line 194, the code at lines 163-193 performs ONLY local state writes (`record.state`, `record.proofShred`, `_shredded[hCommit]`) and `emit` statements. There are zero external calls in this range. On the single-threaded EVM, no other transaction can execute and modify ConditionEngine state between line 162 and line 194 within the same transaction. The snapshot is therefore identical to a re-check — no gap exists.

A block-ordering attack (a prior tx in the same block sets `postChallengeRevealInProgress = true`) would have caused the `_requireNoRevealInProgress` check itself to revert, stopping `finalizeShred` from executing at all. There is no window where the flag transitions from false-at-check to true-at-callback within a single transaction.

---

### F-05 [MEDIUM] Role escalation: UPGRADER_ROLE granted to `admin` without asserting `admin == timelockController_` in governance initializers (system-wide pattern)

**Files:**
- `contracts/src/governance/CealisSecurityMultisig.sol:60-78`
- `contracts/src/governance/EmergencyGovernance.sol:30-50`

**Lens:** Lens 2 — Role escalation

**What is wrong:**

Both governance contracts grant `UPGRADER_ROLE` to an `admin` parameter without validating that `admin` equals the `timelockController_` parameter also passed to the same `initialize()` call.

`CealisSecurityMultisig.initialize()` (lines 72-73):
```
_grantRole(Roles.DEFAULT_ADMIN_ROLE, admin);
_grantRole(Roles.UPGRADER_ROLE, admin);
```

`EmergencyGovernance.initialize()` (lines 36-37):
```
_grantRole(Roles.DEFAULT_ADMIN_ROLE, admin);
_grantRole(Roles.UPGRADER_ROLE, admin);
```

In both contracts, `admin` and `timelockController_` are separate parameters with no cross-validation. Per the project's internal Solidity rules: "UPGRADER_ROLE is held exclusively by TimelockController after deployment." This is the intended invariant, but it is enforced only by deploy-script convention, not by on-contract assertion.

If either parameter is misconfigured — even accidentally — an EOA or a less-governed multisig could hold `UPGRADER_ROLE` on a governance contract and call `_authorizeUpgrade` directly, bypassing the 7-day timelock.

The same `admin != timelockController_` unvalidated assumption exists across all 42 UUPS contracts (every initializer receives a `timelock` or `admin` parameter without asserting it against a known TimelockController interface). The governance contracts are the most consequential instances because an upgrade to CealisSecurityMultisig or EmergencyGovernance could remove the `_requireCouncil` check entirely, giving the upgrader unrestricted protocol deprecation authority with no delay.

**Why it matters:**

`UPGRADER_ROLE` on any UUPS contract is protocol-admin-equivalent. CealisSecurityMultisig upgraded to a malicious implementation loses `_requireCouncil`, enabling arbitrary registry deprecation. EmergencyGovernance upgraded loses the `MAX_EMERGENCY_PAUSE_SECONDS` cap, enabling indefinite suspension of the SecurityCouncil. Both are one misconfigured deploy parameter away from protocol capture.

**Fix hint:** In both `initialize()` functions, add: `require(admin == timelockController_, "admin must equal timelock")` before the role grants, OR consolidate to a single parameter (accept only `timelockController_` and derive `admin` from it). The convention should become an enforced invariant.

**Confidence:** HIGH

---

### F-06 [MEDIUM] Signature replay: MultiPartySignalModule and ConsentGateModule accept `signer` as a caller-supplied parameter without on-chain signature verification

**File:** `contracts/src/modules/MultiPartySignalModule.sol:78-87` and `contracts/src/modules/ConsentGateModule.sol:63-74`
**Lens:** Lens 3 — Signature replay

**What is wrong:**

`MultiPartySignalModule.submitSignal()` at line 78-87 accepts a `signer` address as a calldata parameter (line 80: `address signer`). The `_submitSignal` internal function (lines 151-173) then checks `_eligibleSigner[authorizationId][signer]` and `_submitted[authorizationId][signalDigest][signer]` using this caller-supplied `signer` value directly — without verifying that `msg.sender == signer` or that any cryptographic proof ties the signer address to the signal.

The `signatureEnvelopeRef` parameter (line 81) is accepted and checked only for non-zero length (line 164). Its actual content is never verified on-chain; there is no `ECDSA.recover` or EIP-1271 `isValidSignature` call.

The same pattern exists in `ConsentGateModule.submitConsent()` (lines 63-74, `authority` parameter line 65) — the `authority` address is accepted as a supplied parameter, checked only for eligibility (line 137: `_eligibleAuthority[authorizationId][authority]`), and never cryptographically proven to have produced a signature.

Since both modules are `onlyConditionEngine`, the immediate attack surface is limited: only `ConditionEngine` can call `submitSignal` or `submitConsent`. But `ConditionEngine.advanceFSM` (line 275-292) is permissionless and passes `msg.sender` as the `actor` — which the FSM interpreter uses for allowedSubmitter checks. In Mode P (`_evaluateAxis`, line 484-487), any `msg.sender` that knows the interface can call `IConditionModule(module).evaluate(authorizationId, evidenceRef)`, which does NOT go through `submitSignal`.

The more direct concern is that any entity with access to call `ConditionEngine.authorizeReveal` or `authorizeShred` (both permissionless) can supply an `evidenceRef`, which in Mode P routes to `IConditionModule.evaluate`. The evaluate path in `MultiPartySignalModule._evaluateModule` (line 145-149) only checks the stored count — which was accumulated via `submitSignal`. But `submitSignal` is called via `ConditionEngine` only. If `ConditionEngine` is the sole caller, the `signer` attribution is set by whoever calls ConditionEngine. If that caller is a smart contract, it can claim any `signer` address as long as the `signer` is in the eligible set.

Concretely: a bot that is NOT an eligible signer can call `ConditionEngine.advanceFSM` with `evidenceRef` = the signalDigest, which routes through FSMInterpreter (Mode F), which calls `advanceFSM` on FSMInterpreter, which calls back... no, Mode F does not call submitSignal. In Mode P via `_evaluateAxis`, the `module.evaluate` is called, which reads stored state — the stored count. The count was set by a prior `submitSignal` call. The question is: who called that prior `submitSignal` call, and did they have to prove the signer's identity?

The answer is no. `ConditionEngine.advanceFSM` passes `msg.sender` as the `actor`, but this `actor` is used by `FSMInterpreter.allowedSubmitter` checks (line 146 in FSMInterpreter.sol), NOT passed to module `submitSignal`. The module's `submitSignal` is called separately via the IConditionModule interface's `advance()` method (ConditionModuleBase, line 66-76), and the `signer` parameter in `submitSignal` is passed directly from the `proof` bytes decoded by `_advanceModule` (MultiPartySignalModule line 133: `(address signer, ...) = abi.decode(proof, ...)`).

So the complete path: anyone can call `ConditionEngine.authorizeReveal` → `_evaluateAxis` (Mode P) → `IConditionModule.evaluate` which calls `_evaluateModule` directly reading stored count. To increment that count, someone must have previously called `ConditionEngine.advanceFSM` (or via `advance()` on the module directly via `onlyConditionEngine` path, which requires ConditionEngine as msg.sender). The `proof` bytes decoding the signer address is caller-controlled. So the "signer" who supposedly signed is just a bytes32 decoded from the proof — never verified on-chain.

**Why it matters:**

The module architecture assumes signer attribution is verified off-chain (e.g., by the Orchestrator before calling ConditionEngine). This is a trust assumption that should be documented explicitly. If the Orchestrator is compromised or incorrectly implemented, any eligible signer's identity can be impersonated to accumulate signal counts without that party actually signing anything. For court-order or M&A multi-judge endorsement use cases, this would allow the Orchestrator to fabricate consent without actual signer participation.

**Fix hint:** Either (a) add on-chain ECDSA signature verification inside `_submitSignal`/`_submitConsent` using the `signatureEnvelopeRef` as the actual signature bytes (requiring a digest to be constructed from `authorizationId + signalDigest + nonce + chainId`), OR (b) document explicitly in the contract NatDoc and the S2-2 spec that signal authenticity is Orchestrator-enforced off-chain and the on-chain contract trusts the Orchestrator's attestation of signer identity. The current absence of on-chain verification is not inherently wrong (trusted-Orchestrator model), but it is not documented and may be unexpected for auditors expecting on-chain cryptographic binding.

**Confidence:** MEDIUM (this may be intentional trusted-Orchestrator design, but it is undocumented)

---

### F-07 [LOW] ChallengeRegistry.withdrawChallenge uses state-change-then-ETH-send pattern without reentrancy guard; exploitable only by a challenger who is a malicious contract

**File:** `contracts/src/challenge/ChallengeRegistry.sol:231-248`
**Lens:** Lens 1 — Cross-contract reentrancy

**What is wrong:**

`ChallengeRegistry.withdrawChallenge()` (lines 231-248) follows a CEI pattern that sets `record.status = ChallengeStatus.Withdrawn` and `record.bond = 0` BEFORE sending ETH (lines 241-242, then 244). This is correct — state is written before the external call.

However, there is no `nonReentrant` guard on `withdrawChallenge`. In the narrow case where the challenger address is a malicious contract, it could reenter `withdrawChallenge` mid-call. The CEI pattern's defensive write of `record.status = ChallengeStatus.Withdrawn` happens before the send, so a re-entrant call would hit line 234 (`record.status != ChallengeStatus.Open`) and revert — the guard holds.

The LOW severity rating is because the CEI order does provide protection, and the reentrancy path reverts correctly. The concern is that future modifications to this function (e.g., adding a condition that does not check status first) would silently introduce a vulnerability. The absence of `nonReentrant` is a code hygiene issue given that every other ETH-touching function in the codebase uses explicit guards.

**Why it matters:**

Low direct risk. Status-as-reentrancy-guard is a recognized pattern and works here. The risk is forward-looking: without the `nonReentrant` modifier, a future developer adding logic between lines 241-243 might inadvertently break the protection.

**Fix hint:** Add `ReentrancyGuard` or `ReentrancyGuardTransient` inheritance to `ChallengeRegistry` and apply `nonReentrant` to `withdrawChallenge`. ChallengeRegistry currently has no reentrancy protection at all.

**Confidence:** HIGH (that the current code is safe), LOW (as a hygiene finding)

---

## Lens Verdicts by Area

### Lens 1: Cross-contract reentrancy call graph

**ConditionEngine.authorizeReveal → _evaluateAxis → FSMInterpreter.advanceFSM:**
`advanceFSM` is gated by `msg.sender != _conditionEngine` (FSMInterpreter.sol:132), so FSMInterpreter cannot call back into ConditionEngine via any public path. FSMInterpreter has no outgoing external calls to ConditionEngine or any other contract. The path is a dead end for re-entry. **PASS.**

**ConditionEngine.authorizeShred → ShredRegistry.recordShredAuthorized:**
`recordShredAuthorized` is gated by `msg.sender != _conditionEngine` (ShredRegistry.sol:129). Within that function, it calls back into ConditionEngine via `pdaShredAuthority` (view) and `pdaMinimumShredLatency` (view) — both read-only, no state changes. No re-entry path. **PASS.**

**ShredRegistry.finalizeShred → ConditionEngine.recordShredFinalized:**
`finalizeShred` has no `nonReentrant` guard. A malicious/compromised ConditionEngine could call back into `finalizeShred` for a DIFFERENT authorization mid-callback. However, `recordShredFinalized` in the current ConditionEngine implementation (lines 324-329) contains zero outgoing external calls, so re-entry through the current implementation is impossible. Exploitability requires a compromised ConditionEngine that already has direct protocol authority — reentrancy adds nothing to that threat model. Code hygiene gap only. **LOW — F-03.**

**AttestationGate.verifyOracleAttestation → OracleRegistry.getOracleAt:**
`getOracleAt` is a view function on OracleRegistry. OracleRegistry has no callback path to AttestationGate. `verifyOracleAttestation` itself is called from within `OracleAttestationModule._submitOracleAttestation` which IS protected by `nonReentrant`. The chain is: ConditionEngine (nonReentrant) → OracleAttestationModule.submitOracleAttestation (nonReentrant) → AttestationGate.verifyOracleAttestation (not guarded but called from nonReentrant context) → OracleRegistry (view only). No cross-path re-entry risk. **PASS.**

**ChallengeRegistry.withdrawChallenge → msg.sender.call:**
CEI pattern holds; re-entrant call reverts on status check. No reentrancy guard. **LOW — F-07.**

### Lens 2: Role separation / escalation paths

**Role hierarchy in AccessControl:**
`DEFAULT_ADMIN_ROLE` can grant any role including `UPGRADER_ROLE`. `UPGRADER_ROLE` holders can call `_authorizeUpgrade` to swap contract implementations. The intended invariant is that only TimelockController holds `DEFAULT_ADMIN_ROLE` and `UPGRADER_ROLE` post-initialization. This invariant is enforced by convention (the initializers pass `timelock` for these roles) but NOT by on-chain assertion that `timelock` is actually the timelock. **F-05 above covers the specific gap in CealisSecurityMultisig.**

Across the remaining 41 contracts: every `initialize()` function grants `DEFAULT_ADMIN_ROLE` and `UPGRADER_ROLE` to a timelock address parameter. None validate that the passed address is actually the `CealisTimelockController`. This is the same pattern weakness as F-05 but universally present. However, since the deploy script controls initialization parameters and the risk is only at deploy time, this is not separately reportable beyond the F-05 notation.

**EmergencyGovernance → CealisSecurityMultisig escalation path:**
`EmergencyGovernance.suspendSecurityCouncil` calls `ISecurityCouncilSuspender(securityMultisig).suspendSecurityCouncil`. The suspension freezes the SecurityMultisig's deprecation authority but does NOT grant EmergencyGovernance any ability to call `grantRole` on any contract. EmergencyGovernance holds no roles on registries or ConditionEngine. **No escalation path exists. PASS.**

**SECURITY_COUNCIL_ROLE → registry impact:**
A SecurityCouncil member can call `deprecateNonCanonical` → `ICealisGovernedRegistry.deprecateEntry`, which modifies registry state. This function call is on an arbitrary address in `_registries[registryId]`. The registry address is set by `DEFAULT_ADMIN_ROLE` (`setRegistry`). If a SECURITY_COUNCIL_ROLE signer colluded with the DEFAULT_ADMIN_ROLE holder to point a registry slot to a malicious address, they could trigger arbitrary `deprecateEntry` calls on that address. This is a timelocked governance concern, not a direct escalation vulnerability.

**No role grants `MODULE_ADMIN_ROLE` or `REGISTRY_ADMIN_ROLE` to non-timelock addresses** in any initializer reviewed. These roles are all correctly limited to timelock at initialization. **PASS.**

### Lens 3: Signature replay

**OracleAttestationModule.submitOracleAttestation:**
Uses `_consumedAttestations[attestationDigest]` as a global once-and-only-once guard (line 141). The digest is not bound to a specific contract address, authorizationId, nonce, or deadline on-chain — it is whatever the oracle signed off-chain. The off-chain oracle is expected to include these fields in the signed data, but the on-chain module does not validate the digest structure. Replay across different contracts: not possible since `_consumedAttestations` is contract-local. Replay across different `authorizationId` within the same contract: explicitly blocked at line 141 (digest is global, not per-authorization). **Adequately protected within stated design assumptions. PASS.**

**MultiPartySignalModule.submitSignal / ConsentGateModule.submitConsent:**
No on-chain cryptographic verification of the signer's signature. `signer` / `authority` is caller-supplied. **F-06 above.**

**AttestationGate.verifyOracleAttestation:**
ECDSA.recover called on `attestationDigest` vs `oracleSignature`. The digest is treated as an opaque hash of the oracle's signed message — structure is off-chain. No replay protection at the AttestationGate level; replay is blocked at OracleAttestationModule via `_consumedAttestations`. The split protection works correctly given the call chain. **PASS.**

**PasskeyRotationLog.appendRotation:**
No EIP-712 typed signature or on-chain ECDSA recovery. `webauthnAssertion` and `rotationAuthorizationDigest` are accepted as raw bytes/bytes32 without any cryptographic verification. This is explicitly noted in the contract doc ("integrity check is INTERNAL") — the security model is monotonic chain chaining (prevPubkey must match prior newPubkey), contractAddress binding, and index monotonicity. This is a WebAuthn-outside-EVM design. The chain integrity checks prevent insertion of bogus entries in the middle of the chain. However, there is no replay protection on `rotationAuthorizationDigest` itself (same digest could be used on multiple calls if the chain hash allows it). On initial submission (index 0), ANY content is accepted as long as prevPubkey and webauthnAssertion are empty. For index > 0, `rotationAuthorizationDigest` must be non-zero (line 110) but is not consumed or tracked — the same digest value could appear in multiple rotation entries if someone were willing to break the pubkey chain invariant. Since the pubkey chain invariant is strong (keccak comparison of raw bytes), this is not practically exploitable, but the `rotationAuthorizationDigest` provides weaker protection than a nonce registry would. **INFORMATIONAL — no separate finding; intended design.**

**CealisSecurityMultisig signing:**
Does not use EIP-712 signatures for any multi-party signing. All actions are single-call authorized by the `SECURITY_COUNCIL_ROLE` holder (`msg.sender`). Salt in `requestCanonicalDeprecation` (line 169) includes `block.chainid`, preventing cross-chain replay of the timelock operationId. **PASS.**

### Lens 4: Snapshot vs re-check

**ConditionEngine.authorizeReveal:**
`_requireRevealPreconditions` is called before `_evaluateAxis`. Inside `_evaluateAxis`, for Mode P modules, `IConditionModule(module).evaluate()` is an external call. The `revealAuthorized` flag is set and events emitted AFTER `_evaluateAxis` returns (lines 212-228). No state can change mid-evaluation that `_requireRevealPreconditions` would have blocked, because the preconditions are checked before the module is called and `authorizeReveal` is `nonReentrant`. The `_isShreddedView` check at line 508 is a snapshot — but because `authorizeReveal` is `nonReentrant`, no concurrent shred can finalize during evaluation. **PASS.**

**ConditionEngine.authorizeShred → ShredRegistry.recordShredAuthorized:**
`_requireShredPreconditions` is evaluated before `_evaluateAxis`. After `ShredAuthorized` is emitted (lines 244-253), `recordShredAuthorized` is called on ShredRegistry. This is NOT re-checking preconditions; it is updating ShredRegistry with the result of the already-passed precondition check. The `nonReentrant` guard on `authorizeShred` prevents any concurrent state change to ConditionEngine during the ShredRegistry callback. **PASS.**

**ShredRegistry.finalizeShred snapshot gap — evaluated, not reported:**
Initial draft raised this as F-04 HIGH. Verified incorrect: between `_requireNoRevealInProgress` (line 162) and `recordShredFinalized` callback (line 194), ALL intervening operations are local state writes and emits — zero external calls. On the single-threaded EVM no external state change can occur in that window. Block-ordering attacks would have caused the check itself to revert. **PASS — no finding.**

**ChallengeRegistry:**
`openChallenge` checks `block.timestamp > config.windowEnd` (line 158-159) and `_records[key].status == ChallengeStatus.Open` (line 164). The config is snapshotted into memory (line 154: `ChallengeConfig memory config = _configs[key]`). The status re-check is against storage, not the memory snapshot. This is correct: the status check happens on the storage slot, so no TOCTOU within a single transaction. **PASS.**

### Lens 5: Universal tripwire integrity — event spoofing

**RevealAuthorized and ShredAuthorized event topic hashes:**
Confirmed that only `ConditionEngine.sol` emits these events at lines 213-221 and 244-253 respectively. No fallback or receive functions exist anywhere in the V3 contract surface that could relay an emit.

**Assembly inspection:**
`AttestationGate.sol` contains the ONLY two assembly blocks in the codebase (`_oracleAddress`, lines 291-298). Both are read-only memory operations (loading pubkey bytes from memory) with no `log` opcodes. No other contract contains assembly. **Verified via grep.**

**Fallback/receive functions:**
No contract in `src/**/*.sol` declares a `fallback()` or `receive()` function (other than CealisTimelockController which inherits OZ TimelockController's receive for ETH for bond purposes — the TimelockController inherits no event-relay logic). No fallback could emit a spoofed topic.

**Proxy-level event spoofing (OZ AccessControl event):**
The OZ AccessControl `RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)` event cannot be confused with `RevealAuthorized` or `ShredAuthorized` because these have entirely different topic hashes. No contract attempts to emit these events from an AccessControl role-grant path.

**Could a contract be deployed with matching event signatures:**
The event topic hash for `RevealAuthorized` is `keccak256("RevealAuthorized(bytes32,bytes32,bytes32,uint64,uint64,uint32,bytes32)")`. Only ConditionEngine defines and emits this exact signature. Any other contract emitting the same topic would have to be a different deployment — listeners/indexers anchored to ConditionEngine's address would not be fooled. However, an off-chain listener that monitors ALL contract events (no address filter) could be spoofed. This is an off-chain indexer concern, not an on-chain security concern. **PASS (on-chain); INFORMATIONAL (off-chain indexer advisory).**

---

## Consolidated Summary

| Finding | Severity | Lens | File |
|---------|----------|------|------|
| F-03: ShredRegistry.finalizeShred has no reentrancy guard (hygiene; not exploitable without compromised ConditionEngine) | LOW | Lens 1 | ShredRegistry.sol:160-194 |
| F-05: UPGRADER_ROLE granted to `admin` without asserting admin==timelockController_ in governance initializers | MEDIUM | Lens 2 | CealisSecurityMultisig.sol:60-78, EmergencyGovernance.sol:30-50 |
| F-06: MultiPartySignalModule / ConsentGateModule accept caller-supplied signer without on-chain crypto verification | MEDIUM | Lens 3 | MultiPartySignalModule.sol:78-87, ConsentGateModule.sol:63-74 |
| F-07: ChallengeRegistry.withdrawChallenge has no reentrancy guard (CEI correct, hygiene gap) | LOW | Lens 1 | ChallengeRegistry.sol:231-248 |

**Removed findings:**
- F-04 [was HIGH]: ShredRegistry snapshot-vs-recheck — incorrect; no external calls exist between lines 162 and 194; finding was wrong.

### Zero findings in:
- Lens 1: ConditionEngine → FSMInterpreter callback path (blocked by FSMUnauthorizedCaller)
- Lens 1: ConditionEngine → ShredRegistry.recordShredAuthorized callback path (view calls only)
- Lens 1: AttestationGate → OracleRegistry path (view-only, called under nonReentrant context)
- Lens 3: OracleAttestationModule replay (global digest consumption map)
- Lens 3: CealisSecurityMultisig replay (chainId-bound salt)
- Lens 4: ShredRegistry.finalizeShred snapshot-vs-recheck (no external calls in window; block-ordering attack would revert the check itself)
- Lens 5: RevealAuthorized / ShredAuthorized event spoofing (no assembly emitters, no fallback relay)
- Lens 2: EmergencyGovernance escalation to protocol roles beyond what F-05 covers (no cross-grant paths to registries or ConditionEngine)
