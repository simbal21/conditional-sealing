// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ConditionMode, ShredAuthorityMode, ShredState } from "../../src/lib/Enums.sol";
import { PDARegistration } from "../../src/lib/Structs.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { Tags } from "../../src/lib/Tags.sol";
import { ShredRegistry } from "../../src/shred/ShredRegistry.sol";
import { ConditionEngineTestBase } from "../engine/ConditionEngine.t.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

/// @title ShredB3Test - closure proofs for finding B3-shred (challenge-shred.md)
/// @notice Two sub-issues, two attack paths:
///   (1) CONTRACT — Joint authority mode (2) was satisfiable by a unilateral
///       OPERATOR_ROLE holder, identical to Operator mode (3). Joint provided
///       ZERO additional authority — no dual-consent. The tests prove Joint now
///       demands BOTH the operator side AND a bound subject co-consent envelope.
///   (2) DEPLOY — PostDeploy never revoked the initialize-granted OPERATOR_ROLE
///       from the deployer EOA on shredRegistry, leaving a residual unilateral
///       shred operator after handoff. The deploy test proves the residual is
///       revoked when a distinct operator EOA is configured.
contract ShredB3Test is ConditionEngineTestBase {
    function _jointRegistration() internal view returns (PDARegistration memory reg) {
        return
            _validRegistrationWith(auth, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Joint);
    }

    /// @dev Binding digest the contract derives for a co-consent envelope.
    function _coConsentDigest(bytes32 hCommit, bytes memory envelope) internal view returns (bytes32) {
        return keccak256(abi.encode(Tags.TAG_SUBJECT_V3, auth, hCommit, keccak256(envelope)));
    }

    // -------------------------------------------------------------------------
    // (1) CONTRACT — Joint dual-consent enforcement
    // -------------------------------------------------------------------------

    /// @notice ATTACK PATH (vulnerable code): a unilateral OPERATOR_ROLE holder
    ///         requests a shred on a Joint PDA via the bare 3-arg requestShred.
    ///         Against the pre-fix code this SUCCEEDED (Joint == Operator).
    ///         With the fix it MUST revert ShredJointRequiresCoConsent — Joint
    ///         cannot be satisfied without the subject co-consent envelope.
    function test_B3_shred_JointRejectsUnilateralOperator() external {
        bytes32 hCommit = _register(_jointRegistration());
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(ShredRegistry.ShredJointRequiresCoConsent.selector, hCommit));
        shred.requestShred(auth, hCommit, evidence);
        // State must be untouched — no Requested transition occurred.
        assertEq(uint8(shred.currentShredState(hCommit)), uint8(ShredState.None));
    }

    /// @notice The legitimate dual-consent path: OPERATOR_ROLE caller + a
    ///         non-empty subject co-consent envelope bound by the domain-separated
    ///         digest. This MUST succeed and progress to Requested.
    function test_B3_shred_JointSucceedsWithOperatorAndCoConsent() external {
        bytes32 hCommit = _register(_jointRegistration());
        bytes memory envelope = bytes("subject-co-consent-signed-by-passkey-verified-by-G4");
        bytes32 digest = _coConsentDigest(hCommit, envelope);
        vm.prank(operator);
        shred.requestShredWithCoConsent(auth, hCommit, evidence, envelope, digest);
        assertEq(uint8(shred.currentShredState(hCommit)), uint8(ShredState.Requested));
    }

    /// @notice The operator side is still mandatory: a non-operator (the subject
    ///         address, which holds NO role) presenting a perfectly valid
    ///         co-consent envelope MUST still be rejected at the operator gate.
    ///         Proves Joint is genuinely two-sided, not "either side suffices."
    function test_B3_shred_JointRejectsCoConsentWithoutOperator() external {
        bytes32 hCommit = _register(_jointRegistration());
        bytes memory envelope = bytes("subject-co-consent");
        bytes32 digest = _coConsentDigest(hCommit, envelope);
        vm.prank(subject);
        vm.expectRevert(abi.encodeWithSelector(ShredRegistry.ShredAuthorityInvalid.selector, hCommit, subject));
        shred.requestShredWithCoConsent(auth, hCommit, evidence, envelope, digest);
    }

    /// @notice A forged / unbound co-consent digest (does not hash the envelope
    ///         under the TAG_SUBJECT_V3 domain) MUST be rejected — an operator
    ///         cannot self-fabricate a co-consent token to fake the subject side.
    function test_B3_shred_JointRejectsMismatchedCoConsentDigest() external {
        bytes32 hCommit = _register(_jointRegistration());
        bytes memory envelope = bytes("subject-co-consent");
        bytes32 forged = keccak256("operator-fabricated-digest-not-bound-to-envelope");
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(ShredRegistry.ShredCoConsentInvalid.selector, hCommit));
        shred.requestShredWithCoConsent(auth, hCommit, evidence, envelope, forged);
    }

    /// @notice An empty envelope (with the matching all-empty digest) MUST be
    ///         rejected — presence of a real subject artifact is required, an
    ///         operator cannot pass coConsentPresent with a zero-length envelope.
    function test_B3_shred_JointRejectsEmptyCoConsentEnvelope() external {
        bytes32 hCommit = _register(_jointRegistration());
        bytes memory empty = bytes("");
        bytes32 digest = _coConsentDigest(hCommit, empty);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(ShredRegistry.ShredCoConsentInvalid.selector, hCommit));
        shred.requestShredWithCoConsent(auth, hCommit, evidence, empty, digest);
    }

    /// @notice Regression guard: Operator-mode PDAs are UNAFFECTED — a unilateral
    ///         OPERATOR_ROLE holder still succeeds via the bare 3-arg path. The
    ///         fix narrows Joint, not Operator.
    function test_B3_shred_OperatorModeUnchanged() external {
        PDARegistration memory reg =
            _validRegistrationWith(auth, ConditionMode.ModeP, ConditionMode.ModeP, 0, 0, ShredAuthorityMode.Operator);
        bytes32 hCommit = _register(reg);
        vm.prank(operator);
        shred.requestShred(auth, hCommit, evidence);
        assertEq(uint8(shred.currentShredState(hCommit)), uint8(ShredState.Requested));
    }

    // -------------------------------------------------------------------------
    // (2) DEPLOY — residual deployer-EOA OPERATOR_ROLE revoke
    // -------------------------------------------------------------------------

    /// @notice Mirrors the PostDeploy operator-handoff sequence in miniature.
    ///         A fresh ShredRegistry is initialized with `temporaryAdmin` (which
    ///         grants it OPERATOR_ROLE, per initialize:77). After the dedicated
    ///         operator EOA is granted, the residual deployer OPERATOR must be
    ///         revoked when the operator is a DISTINCT address — proving the
    ///         B3-shred(2) PostDeploy fix closes the leftover-operator hole.
    ///
    ///         ATTACK PATH (vulnerable code): the deployer EOA retained
    ///         OPERATOR_ROLE indefinitely after handoff (an extra unilateral
    ///         shred operator). With the fix it does not.
    function test_B3_shred_DeployRevokesResidualDeployerOperator() external {
        address temporaryAdmin = address(0xDEAD);
        address dedicatedOperator = address(0xB0B);
        ShredRegistry fresh = ShredRegistry(
            ProxyDeploy.deployProxy(
                address(new ShredRegistry()),
                abi.encodeCall(ShredRegistry.initialize, (temporaryAdmin, address(engine)))
            )
        );

        // initialize granted OPERATOR_ROLE to the deployer/temporaryAdmin.
        assertTrue(fresh.hasRole(Roles.OPERATOR_ROLE, temporaryAdmin), "precondition: deployer holds OPERATOR");

        // Replicate PostDeploy._grantOperationalRoles operator handoff for shred:
        //   grant operator EOA, then revoke the deployer residual IFF distinct.
        vm.startPrank(temporaryAdmin);
        if (!fresh.hasRole(Roles.OPERATOR_ROLE, dedicatedOperator)) {
            fresh.grantRole(Roles.OPERATOR_ROLE, dedicatedOperator);
        }
        if (dedicatedOperator != temporaryAdmin) {
            fresh.revokeRole(Roles.OPERATOR_ROLE, temporaryAdmin);
        }
        vm.stopPrank();

        // The dedicated operator holds the role; the deployer residual is gone.
        assertTrue(fresh.hasRole(Roles.OPERATOR_ROLE, dedicatedOperator), "operator EOA must hold OPERATOR");
        assertFalse(fresh.hasRole(Roles.OPERATOR_ROLE, temporaryAdmin), "residual deployer OPERATOR must be revoked");
    }

    /// @notice Default-deploy case (OPERATOR_ADDRESS unset => operator ==
    ///         temporaryAdmin): the role must NOT be revoked, otherwise the
    ///         registry is left with zero operators and Operator/Joint shred
    ///         breaks. Guards the `operator != temporaryAdmin` condition.
    function test_B3_shred_DeployKeepsOperatorWhenNotDistinct() external {
        address temporaryAdmin = address(0xDEAD);
        address dedicatedOperator = temporaryAdmin; // OPERATOR_ADDRESS unset
        ShredRegistry fresh = ShredRegistry(
            ProxyDeploy.deployProxy(
                address(new ShredRegistry()),
                abi.encodeCall(ShredRegistry.initialize, (temporaryAdmin, address(engine)))
            )
        );

        vm.startPrank(temporaryAdmin);
        if (!fresh.hasRole(Roles.OPERATOR_ROLE, dedicatedOperator)) {
            fresh.grantRole(Roles.OPERATOR_ROLE, dedicatedOperator);
        }
        if (dedicatedOperator != temporaryAdmin) {
            fresh.revokeRole(Roles.OPERATOR_ROLE, temporaryAdmin);
        }
        vm.stopPrank();

        assertTrue(fresh.hasRole(Roles.OPERATOR_ROLE, temporaryAdmin), "intended operator must retain OPERATOR");
    }

    /// @notice Binds the behavioral deploy tests above to the actual PostDeploy
    ///         script edit: the residual-OPERATOR revoke on shredRegistry must be
    ///         present in the script. Mirrors the source-read assertion idiom in
    ///         ShredRegistry.t.sol. If the script regresses (revoke removed), this
    ///         fails even though the standalone revoke-logic tests still pass.
    function test_B3_shred_PostDeployContainsResidualOperatorRevoke() external view {
        string memory source = vm.readFile("script/PostDeploy.s.sol");
        assertTrue(
            _contains(source, "_revokeIfHeld(addrs.shredRegistry, Roles.OPERATOR_ROLE, addrs.temporaryAdmin)"),
            "PostDeploy must revoke residual deployer OPERATOR on shredRegistry"
        );
        assertTrue(
            _contains(source, "if (operator != addrs.temporaryAdmin)"),
            "revoke must be guarded so the default operator==temporaryAdmin path keeps the role"
        );
    }

    function _contains(string memory haystack, string memory needle) private pure returns (bool) {
        bytes memory h = bytes(haystack);
        bytes memory n = bytes(needle);
        if (n.length == 0 || h.length < n.length) return false;
        for (uint256 i = 0; i <= h.length - n.length; ++i) {
            bool ok = true;
            for (uint256 j = 0; j < n.length; ++j) {
                if (h[i + j] != n[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return true;
        }
        return false;
    }
}
