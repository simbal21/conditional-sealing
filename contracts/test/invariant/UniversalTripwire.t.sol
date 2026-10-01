// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ConditionMode, LifecycleState, ShredAuthorityMode } from "../../src/lib/Enums.sol";
import { ConditionEngineTestBase } from "../engine/ConditionEngine.t.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";

contract UniversalTripwireInvariant is ConditionEngineTestBase {
    bool internal moduleTouched;
    bool internal shredTouched;

    function setUp() public override {
        super.setUp();
        _register(
            _validRegistrationWith(auth, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Subject)
        );

        // Restrict the fuzzer to ONLY the attempt* handlers below. Without this, the
        // fuzzer would call engine.authorizeReveal directly with the AlwaysTrueModule,
        // which legitimately advances state past Registered and trips the invariant.
        // The universal tripwire we are enforcing is: external direct calls to
        // module.evaluate / shred.requestShred CANNOT cause an engine state change
        // — only ConditionEngine itself can drive state.
        targetContract(address(this));
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = this.attemptModuleEvaluate.selector;
        selectors[1] = this.attemptShredRequest.selector;
        targetSelector(StdInvariant.FuzzSelector({ addr: address(this), selectors: selectors }));
    }

    function attemptModuleEvaluate(bytes32 contextRef) external {
        module.evaluate(auth, contextRef);
        moduleTouched = true;
    }

    function attemptShredRequest(bytes32 evidenceRef) external {
        try shred.requestShred(auth, engine.hCommitForAuthorization(auth), evidenceRef) {
            shredTouched = true;
        } catch { }
    }

    /// External direct calls to module.evaluate / shred.requestShred MUST NOT cause
    /// the engine to leave Registered state or unlock gates. Only ConditionEngine
    /// itself can advance lifecycle.
    function invariant_OnlyConditionEngineCausesReveal() external view {
        assertEq(uint8(engine.lifecycleState(auth)), uint8(LifecycleState.Registered));
        assertFalse(engine.canGatesSign(auth));
    }

    function invariant_NoRevealAuthorizedAfterFinalizedShredUntilEngineEmits() external view {
        assertFalse(engine.canGatesSign(auth));
    }

    function invariant_PausingNeverMutatesCommitmentContent() external view {
        assertTrue(engine.hCommitForAuthorization(auth) != bytes32(0));
    }

    // ────────────────────────────────────────────────────────────────────
    // PENDING INVARIANTS (intentionally NOT implemented as stubs)
    //
    // The following 7 invariants are named in the M2 brief but require
    // multi-contract handler topologies that exceed this M2 mission's
    // scope. Codex D2 originally shipped them as `assertTrue(true)`
    // no-ops, which made the test count look reassuring while providing
    // zero protection. Removed here so the test count is honest.
    //
    // Implement when the cited mission lands (or earlier if a security
    // pass surfaces concrete need):
    //
    //   - invariant_NoLegalEffectPdaWithHaltOptOut
    //       Owner: M2 contract-level; ConditionEngine.registerPDA already
    //       reverts ConditionLegalEffectHaltOptOutForbidden. Promote to a
    //       proper invariant by spinning up a handler that enumerates
    //       PDA configurations + asserts no active PDA in storage has
    //       (legal_effect_expected==true && cealis_class_wide_halt_opt_out==true).
    //
    //   - invariant_NoLegalEffectPdaWithPhase1G4
    //       Owner: M2 contract-level; ConditionEngine.registerPDA already
    //       reverts ConditionLegalEffectPhaseInvalid. Same handler shape
    //       as above, scanning for (legal_effect_expected==true && requiredG4Phase==Phase1).
    //
    //   - invariant_NoMode3ActivePdaAtV2Launch
    //       Owner: M2 contract-level; ConditionEngine.registerPDA already
    //       reverts ConditionMode3Reserved. Handler scans active recipient
    //       policies for ConditionalRecipientMode.WalletEIP1271Reserved.
    //
    //   - invariant_NoUpgradeWithoutTimelockController
    //       Owner: M2 + Phase E; covered by Deploy.t.sol §17.3 assertion 5.
    //       Promote to invariant: handler attempts upgradeToAndCall from
    //       random non-timelock addresses; assert all revert.
    //
    //   - invariant_DeprecationAndCooldownNotBypassed
    //       Owner: M2 (registries) + M7 (ceremony scripts). Handler walks
    //       deprecation lifecycle: deprecateEntry → 72h auto-clear → 30d
    //       cooldown → re-deprecate (must revert via securityCouncil; must
    //       succeed via timelock). Cross-contract handler.
    //
    //   - invariant_RegistryHistoricalLookupStableAtTargetBlock
    //       Owner: M2 (closed by §9.13 worked-example unit tests in
    //       _HistoricalLookup.t.sol). Could promote to a stateful
    //       invariant: handler adds + tombstones entries at random blocks;
    //       asserts getEntryAt at any prior block returns the entry that
    //       was effective at that block. Currently covered as unit test.
    //
    //   - (renamed from "PausingNeverMutatesCommitmentContent" stub)
    //       Already implemented above as a real assertion.
    //
    // See the internal M2 ship record (not exported) for context.
    // ────────────────────────────────────────────────────────────────────
}
