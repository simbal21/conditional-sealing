// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Test } from "forge-std/Test.sol";

import { CealisIdentifierHelpers } from "../../src/helpers/CealisIdentifierHelpers.sol";
import { EmergencyGovernance } from "../../src/governance/EmergencyGovernance.sol";
import { CealisSecurityMultisig } from "../../src/governance/CealisSecurityMultisig.sol";
import { CealisTimelockController } from "../../src/governance/CealisTimelockController.sol";
import { Roles } from "../../src/lib/Roles.sol";
import { DeprecationFlag } from "../../src/lib/Structs.sol";
import { PluginHashRegistry } from "../../src/registries/PluginHashRegistry.sol";

contract CealisSecurityMultisigTest is Test {
    CealisIdentifierHelpers internal helper;
    CealisTimelockController internal timelock;
    CealisSecurityMultisig internal security;
    EmergencyGovernance internal emergency;
    PluginHashRegistry internal registry;

    address internal councilSigner = address(0xA11CE);
    address internal emergencySigner = address(0xEAA);
    address internal stranger = address(0xBEEF);
    address internal deployerAdmin = address(this);

    bytes32 internal registryId;
    bytes32 internal constant CID = keccak256("disclosure.cid");
    bytes32 internal constant SUMMARY_HASH = keccak256("summary");

    function setUp() public {
        vm.warp(1_000_000);
        vm.roll(100);

        address[] memory empty = new address[](0);
        timelock = new CealisTimelockController(7 days, empty, empty, address(this));

        address[] memory signers = new address[](1);
        signers[0] = councilSigner;
        security = CealisSecurityMultisig(
            address(
                new ERC1967Proxy(
                    address(new CealisSecurityMultisig()),
                    abi.encodeCall(
                        CealisSecurityMultisig.initialize, (address(this), address(timelock), address(1), signers)
                    )
                )
            )
        );

        address[] memory emergencySigners = new address[](1);
        emergencySigners[0] = emergencySigner;
        emergency = EmergencyGovernance(
            address(
                new ERC1967Proxy(
                    address(new EmergencyGovernance()),
                    abi.encodeCall(
                        EmergencyGovernance.initialize,
                        (address(this), address(security), address(timelock), emergencySigners)
                    )
                )
            )
        );
        security.setEmergencyGovernance(address(emergency));

        helper = new CealisIdentifierHelpers();
        registry = PluginHashRegistry(
            address(
                new ERC1967Proxy(
                    address(new PluginHashRegistry()),
                    abi.encodeCall(
                        PluginHashRegistry.initialize,
                        (address(this), address(security), address(emergency), address(this), address(helper))
                    )
                )
            )
        );
        registry.grantRole(Roles.REGISTRY_ADMIN_ROLE, address(timelock));

        registryId = bytes32(uint256(uint160(address(registry))));
        security.setRegistry(registryId, address(registry));

        timelock.grantRole(timelock.EXPEDITED_PROPOSER_ROLE(), address(security));
        timelock.grantRole(timelock.EXPEDITED_COSIGNER_ROLE(), address(emergency));
        timelock.grantRole(timelock.EXPEDITED_EXECUTOR_ROLE(), address(0));
    }

    function test_deprecateNonCanonicalSucceedsForSecurityCouncilHolder() external {
        bytes32 id = _addPlugin(false, "noncanonical");

        vm.prank(councilSigner);
        security.deprecateNonCanonical(registryId, id, 1, CID, SUMMARY_HASH);

        DeprecationFlag memory flag = registry.deprecationFlag(id);
        assertTrue(flag.deprecated);
        assertFalse(flag.isCanonicalAtSet);
    }

    function test_deprecateNonCanonicalRevertsForNonHolder() external {
        bytes32 id = _addPlugin(false, "unauthorized");

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(CealisSecurityMultisig.SecurityMultisigUnauthorized.selector, stranger));
        security.deprecateNonCanonical(registryId, id, 1, CID, SUMMARY_HASH);
    }

    function test_requestCanonicalDeprecationQueuesExpeditedDelay() external {
        bytes32 id = _addPlugin(true, "canonical");

        vm.prank(councilSigner);
        security.requestCanonicalDeprecation(registryId, id, 1, CID, SUMMARY_HASH);

        bytes32 operationId = security.lastQueuedOperationId();
        (uint64 readyAt, bool cosigned, bool done) = timelock.expeditedOperation(operationId);
        assertEq(readyAt, uint64(block.timestamp + 24 hours));
        assertFalse(cosigned);
        assertFalse(done);
    }

    function test_suspendAndRestoreSecurityCouncil() external {
        bytes32 id = _addPlugin(false, "suspended");
        uint64 until = uint64(block.timestamp + 1 days);

        vm.prank(emergencySigner);
        emergency.suspendSecurityCouncil(until, keccak256("incident"));

        vm.prank(councilSigner);
        vm.expectRevert(abi.encodeWithSelector(CealisSecurityMultisig.SecurityMultisigSuspended.selector, until));
        security.deprecateNonCanonical(registryId, id, 1, CID, SUMMARY_HASH);

        vm.prank(emergencySigner);
        emergency.restoreSecurityCouncil(keccak256("restored"));

        vm.prank(councilSigner);
        security.deprecateNonCanonical(registryId, id, 1, CID, SUMMARY_HASH);
        assertTrue(registry.deprecationFlag(id).deprecated);
    }

    function test_securityCouncilCannotGrantRegistryAdditionPower() external {
        vm.prank(councilSigner);
        vm.expectRevert();
        registry.grantRole(Roles.REGISTRY_ADMIN_ROLE, councilSigner);
    }

    /// @notice SC-F-05: UPGRADER_ROLE must be held by the timelock, never by the
    ///         deployer-admin, at init time. setUp seats admin=address(this) (the
    ///         deployer) distinct from timelockController_=address(timelock) — exactly
    ///         the Deploy.s.sol shape. Against the vulnerable code (which granted
    ///         UPGRADER to `admin`), the deployer held UPGRADER and could upgrade the
    ///         proxy in the window before PostDeploy._transferUUPSControl ran.
    function test_SC_F_05_upgraderRoleIsTimelockOnlyNotDeployerAdmin() external {
        assertTrue(security.hasRole(Roles.UPGRADER_ROLE, address(timelock)));
        assertFalse(security.hasRole(Roles.UPGRADER_ROLE, deployerAdmin));
        // Deployer-admin retains DEFAULT_ADMIN for setRegistry/setEmergencyGovernance wiring.
        assertTrue(security.hasRole(Roles.DEFAULT_ADMIN_ROLE, deployerAdmin));
        assertEq(security.timelockController(), address(timelock));
    }

    /// @notice SC-F-05 attack path: the deployer-admin cannot UUPS-upgrade the proxy
    ///         to an arbitrary impl in the pre-transfer window. Against the vulnerable
    ///         code this would have succeeded because the deployer held UPGRADER_ROLE.
    function test_SC_F_05_deployerAdminCannotUpgrade() external {
        address newImpl = address(new CealisSecurityMultisig());
        vm.prank(deployerAdmin);
        vm.expectRevert();
        security.upgradeToAndCall(newImpl, "");
    }

    function _addPlugin(bool canonical, string memory salt) internal returns (bytes32 id) {
        PluginHashRegistry.PluginEntry memory entry = PluginHashRegistry.PluginEntry({
            canonicalBinaryHash: keccak256(bytes(salt)),
            sourceCommitDigest: keccak256(abi.encodePacked("source", salt)),
            effectiveBlock: uint64(block.number),
            tombstoneBlock: 0,
            deprecationFlag: DeprecationFlag({
                deprecated: false,
                deprecationBlockTimestamp: 0,
                deprecationReasonCode: 0,
                disclosureCid: bytes32(0),
                disclosureCommitHash: bytes32(0),
                disclosureVerifiedBlock: 0,
                autoClearTimestamp: 0,
                isCanonicalAtSet: false
            }),
            isCanonical: canonical
        });
        id = helper.computePluginVersionDigest(entry.canonicalBinaryHash);
        registry.addPlugin(id, entry);
    }
}
