> **POINT-IN-TIME INTERNAL REVIEW — SUPERSEDED.** This is an internal adversarial review artifact, published for transparency. It is NOT an external/independent audit — the system was never externally audited. For the honest overall assessment see docs/audits/MATURITY-SCORECARD.md. Cealis was retired June 2026; the code is archived and unmaintained.

_Base Sepolia deployment note: testnet only; deployed bytecode may lag or diverge from this source. See deployments/README.md._

# Security Audit 2026-06-02 — engine/modules/attestation cluster
HEAD e87c108. Read-only. Rule 45: verdicts from actual code at HEAD via grep/read.

## F-02 — chainId not bound in oracle attestation digest preimage — OPEN (HIGH)
- `AttestationGate.verifyOracleAttestation` (attestation/AttestationGate.sol:157-210) recovers
  `ECDSA.recover(attestationDigest, oracleSignature)` (L257) over a raw caller-supplied
  `attestationDigest` (param L161). No chainId, no domain separation, no EIP-712 anywhere on the
  attestation path.
- `grep block.chainid` over contracts/src → ONLY hit is
  governance/CealisSecurityMultisig.sol:169. NEVER in attestation/modules/engine.
- Spec is NORMATIVE: smart-contracts-spec.md:1781 "Base Mainnet chain ID is the production domain.
  Base Sepolia is testnet. **Signatures must bind chain ID. Cross-chain replay is rejected.**"
- Module-level `_consumedAttestations` (OracleAttestationModule.sol:32) only protects within one
  chain's deployment. An oracle reusing the same secp256k1 key across Base Sepolia + Base Mainnet →
  a digest+signature valid on one chain is replayable on the other (different contract, fresh
  consumed-set). chainId must be bound into the digest preimage (off-chain construction + on-chain
  verification) OR AttestationGate must mix block.chainid into the recovered preimage.
- FIX: attestation/AttestationGate.sol — bind block.chainid into the signed preimage (e.g. recover
  over keccak(TAG ‖ chainId ‖ attestationDigest ‖ schemaId ‖ authorizationId)) and update the
  off-chain oracle signing construction in S2-3 SDK to match.

## BR-F — no per-attestation single-use; freshness-only window — PARTIAL (was HIGH → now LOW residual)
- Original finding located it at AttestationGate (~193). At HEAD the single-use guard lives in the
  MODULE: OracleAttestationModule.sol:32 `mapping(bytes32 => bool) _consumedAttestations`; checked
  L141 `if (_consumedAttestations[attestationDigest]) revert OracleAttestationDigestConsumed`; set
  L153 after successful verify. NatSpec L16-17: "global once-and-only-once."
  Plus per-PDA `state.consumed` + `freshnessWindow` one-shot (L142-144).
- So forging *fresh repeated* attestations of the SAME digest is now blocked globally per deployment.
- RESIDUAL: AttestationGate itself (the reusable verifier, called by other modules e.g.
  MultiPartySignal via oracle path, and `tryEvaluateOracleAttestation`) still has NO replay set — its
  observed-at map (L77,190-195) is freshness-only. Single-use is enforced only by the
  OracleAttestationModule wrapper, not by the gate. Any future caller of the gate that does not carry
  its own consumed-set inherits the original BR-F. Defense-in-depth: add the nullifier at the gate.

## BR-H — plugin-deprecation reveal-check uses block.number not commit_block — PARTIAL (MEDIUM)
- `_touchRegistryRefs` (engine/ConditionEngine.sol:571-577) reads at `targetBlock = uint64(block.number)`
  (L572) — CURRENT block — via `_registryReadAt`→`IBaseRegistry.getEntryAt(id, targetBlock)` (L582).
- The deprecation-blocks-reveal failure mode is FIXED: `getEntryAt` reverts on unknown / not-effective
  / tombstoned but NOT on deprecation (IBaseRegistry.sol error set L24-44; engine slither comment L581
  "Deprecated-but-not-tombstoned entries return normally by design — deprecation enforced off-chain
  by G4"). So a later-deprecated-but-not-tombstoned plugin no longer blocks a pre-existing commit.
- RESIDUAL (the underlying mechanism is still wrong): reads at block.number, NOT commit/authorization
  block. PdaRecord (L79-96) stores NO per-PDA commit block (`grep block.number` in engine = only
  L218/251 event emission + L572). Spec is NORMATIVE the other way:
  - smart-contracts-spec.md:1080 "A tombstone before authorization blocks use; **a tombstone after
    authorization does not retroactively break an in-flight ceremony.**"
  - :1115 reads "...at authorization block ... **never the mutable current schema view.**"
  - :90 "§11 endpoint attestation ... at-commit-block reading"; :873 `getEntryAt(ref, authorizationBlock)`.
  At block.number, a registry entry TOMBSTONED after authorization but before reveal reverts the
  reveal — retroactively breaking an in-flight ceremony, exactly what 1080 forbids.
- FIX: engine/ConditionEngine.sol — store registrationBlock in PdaRecord at registerPDA; pass it as
  targetBlock to _touchRegistryRefs instead of block.number.

## BR-D — configurator+ORCHESTRATOR compromise = DOS via shred; no minimumShredLatency floor — PARTIAL (MEDIUM)
- A per-PDA latency mechanism now EXISTS and is ENFORCED: PdaRecord.minimumShredLatency
  (ConditionEngine.sol:89, set L187 from registration), getter pdaMinimumShredLatency (L367); enforced
  at ShredRegistry.finalizeShred L176-178 `earliestFinalization = authorizedAt + minimumLatency;
  if (block.timestamp < earliestFinalization) revert ShredLatencyNotElapsed`. Plus _requireNoRevealInProgress
  guard at requestShred/recordShredAuthorized/finalizeShred and per-PDA challenge window.
- RESIDUAL: NO protocol-wide MINIMUM floor. `grep MIN.*LATENCY` → none. The value is free; PostDeploy
  example sets `minimumShredLatency: 0` (L394) + `shredChallengeWindow: 0` (L415). A compromised
  ORCHESTRATOR_ROLE (the registration authority) can register hostile PDAs with latency=0 + window=0 →
  immediate shred. The "floor" the finding asked for is still absent; the latency *mechanism* is the
  improvement.
- The full "ORCHESTRATOR compromise" threat is architectural: ORCHESTRATOR owns registration, so a
  fully-compromised key can always author hostile PDAs. Realistic hardening = a MIN_SHRED_LATENCY
  floor constant + minimum challenge window for legalEffect/non-disabled-shred PDAs.
- FIX: engine/ConditionEngine.sol _validateRegistration — enforce minimumShredLatency >= floor (and
  challengeWindow >= min) for non-Disabled shred authority modes.

## SC-F-06 — MultiPartySignal + ConsentGate accept caller-supplied signer/authority, no on-chain ECDSA recovery — OPEN (HIGH)
- MultiPartySignalModule.submitSignal (modules/MultiPartySignalModule.sol:78-87) → _submitSignal
  (L151-173): checks `_eligibleSigner[authorizationId][signer]` (L164) + `signatureEnvelopeRef.length==0`
  (L164) + duplicate guard (L167). NO recovery that `signer` actually signed `signalDigest`.
- ConsentGateModule.submitConsent (modules/ConsentGateModule.sol:63-74) → _submitConsent (L122-146):
  checks `_eligibleAuthority[authorizationId][authority]` (L137) + `signatureEnvelopeRef.length==0`
  (L137). NO recovery.
- `grep ECDSA|recover|EIP712|_hashTypedData` over both modules + ConditionModuleBase = ZERO hits.
- Spec REQUIRES on-chain verification: smart-contracts-spec.md:180 "S2-2 contracts use these EIP-712
  domains when an on-chain contract verifies a typed-data signature" with :187 `CealisConsentGate`,
  :188 `CealisMultiPartySignal`; :244 "submit **valid signatures**"; :560 same. The EIP-712 domains are
  defined but UNUSED. Caller (ConditionEngine, onlyConditionEngine) can claim any allow-listed
  signer/authority with arbitrary nonempty envelope bytes → forges k-of-n consensus → false RevealAuthorized.
- Both modules are LIVE: deployments/base-sepolia.json:7,20; wired PostDeploy.s.sol:326,328.
- FIX: modules/MultiPartySignalModule.sol + ConsentGateModule.sol — add EIP-712 typed-data recovery
  (CealisMultiPartySignal / CealisConsentGate domains, smart-contracts-spec.md:180-188), verify
  recovered signer == claimed signer over the digest before incrementing count.

## B3a — signer-set / authority-set never cleared on reconfigure — OPEN (MEDIUM)
- MultiPartySignal: configureSignal L64-66 + _configureModule L122-124 only ever set
  `_eligibleSigner[...] = true`. NO `delete` / `= false` anywhere (grep confirms). NatSpec L42-44 admits
  "Overwrites any prior config ... but does NOT reset existing signal counts."
- ConsentGate: configureConsent L46-48 + _configureModule L98-100 only set `_eligibleAuthority = true`.
  No clear.
- Effect: reconfiguring to remove a rotated/compromised signer leaves the old address STILL eligible.
  signerCount/threshold update but the per-address flag persists → removed party can still submit.
- FIX: clear prior signer/authority addresses before re-populating (track an address list per
  authorizationId and delete on reconfigure, or version the eligibility key).

## B3b — _evaluateAxis: no module-whitelist against _conditionModules — OPEN (HIGH)
- engine/ConditionEngine.sol _evaluateAxis L485 `address module = _addressFromRef(config.conditionSpecHash)`
  then L486-487 calls `IConditionModule(module).evaluate(...)` with only `module != address(0)` +
  `module.code.length != 0` (L486). NO membership check against `_conditionModules[9]` (stored L114,
  set L145, but NEVER consulted in _evaluateAxis).
- `config.conditionSpecHash` is supplied at registerPDA (ORCHESTRATOR_ROLE). A registration can point
  the reveal/shred condition at an attacker-controlled contract whose `evaluate()` returns true →
  authorization bypass. Gated only by ORCHESTRATOR_ROLE.
- FIX: engine/ConditionEngine.sol — assert `module` is a member of `_conditionModules` (or a
  module-registry membership check) before dispatching evaluate().

## B3c — recordRevealCompleted: no G4-refusal recheck — OPEN (LOW)
- engine/ConditionEngine.sol recordRevealCompleted L313-324: checks lifecycle ==
  PostChallengeRevealInProgress, transitions to RevealCompleted. NO _requireNoBlockingRefusal /
  _hasBlockingRefusal call (awk over L313-324 = empty). Rule-25 snapshot-never-recheck pattern.
- SEVERITY LOW: the crypto-enforced halt is at the gate-signing boundary, not here. canGatesSign
  (L333-338) DOES check `!_hasBlockingRefusal`; spec :690 confirms gate clients gate on canGatesSign.
  recordRevealCompleted is ORCHESTRATOR-only post-delivery accounting (spec :474 "delivery side reports
  completion digest"). A refusal arriving after gates signed/delivered cannot un-deliver — so this is a
  defense-in-depth/accounting gap, not an enforcement bypass.
- FIX (defense-in-depth): add _requireNoBlockingRefusal(authorizationId) at top of recordRevealCompleted
  so a late refusal blocks the completion-state write.
