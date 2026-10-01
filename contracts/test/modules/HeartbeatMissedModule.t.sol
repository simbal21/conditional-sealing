// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IHeartbeatMissedModule } from "../../src/engine/IConditionEngine.sol";
import { HeartbeatMissedModule } from "../../src/modules/HeartbeatMissedModule.sol";
import { ModuleTestBase } from "./PaymentObligationModule.t.sol";
import { ProxyDeploy } from "../_helpers/ProxyDeploy.sol";

contract HeartbeatMissedModuleTest is ModuleTestBase {
    HeartbeatMissedModule internal module;

    // SC-F-06: the actor must be a real keypair so the module can recover the EIP-712 signer.
    uint256 internal pkActor = 0xA11CE;
    address internal actor;
    bytes32 internal actorRef;

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_NAME_HASH = keccak256("CealisHeartbeat");
    bytes32 private constant _DOMAIN_VERSION_HASH = keccak256("1");
    bytes32 private constant _HEARTBEAT_TYPEHASH =
        keccak256("Heartbeat(bytes32 authorizationId,bytes32 heartbeatDigest,address actor)");

    function setUp() public {
        vm.warp(1_000_000);
        actor = vm.addr(pkActor);
        actorRef = bytes32(uint256(uint160(actor)));
        module = HeartbeatMissedModule(
            ProxyDeploy.deployProxy(
                address(new HeartbeatMissedModule()),
                abi.encodeCall(HeartbeatMissedModule.initialize, (timelock, engine))
            )
        );
        module.configureHeartbeat(auth, actorRef, 100, 10, configDigest);
    }

    function _digest(bytes32 authorizationId, bytes32 heartbeatDigest, address signer)
        private
        view
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid, address(module)
            )
        );
        bytes32 structHash = keccak256(abi.encode(_HEARTBEAT_TYPEHASH, authorizationId, heartbeatDigest, signer));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
    }

    /// @dev Builds the `(address actor, bytes signature)` envelope, signing the
    ///      `Heartbeat` typed data as `signWith` but claiming `claimedActor`.
    function _envelope(uint256 signWith, address claimedActor, bytes32 authorizationId, bytes32 heartbeatDigest)
        private
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signWith, _digest(authorizationId, heartbeatDigest, claimedActor));
        return abi.encode(claimedActor, abi.encodePacked(r, s, v));
    }

    function test_heartbeatLifecycleGraceWindowAndTerminal() external {
        _assertNoAuthorizationEvents("src/modules/HeartbeatMissedModule.sol");
        assertEq(module.heartbeatDeadline(auth), block.timestamp + 110);

        // A correctly-signed heartbeat slides the deadline (proof-of-life accepted).
        module.recordHeartbeat(auth, keccak256("beat"), _envelope(pkActor, actor, auth, keccak256("beat")));
        assertEq(module.heartbeatDeadline(auth), block.timestamp + 110);

        vm.expectRevert(
            abi.encodeWithSelector(
                IHeartbeatMissedModule.HeartbeatNotMissed.selector, auth, module.heartbeatDeadline(auth)
            )
        );
        module.advance(auth, bytes32(0), "");

        vm.warp(module.heartbeatDeadline(auth) + 1);
        assertTrue(module.advance(auth, bytes32(0), ""));
        assertTrue(module.evaluate(auth, bytes32(0)));
    }

    /// SC-F-06: a forged proof-of-life must NOT slide the deadline. The heartbeat
    /// authenticates liveness; if a third party can forge it, they keep the dead-man
    /// release suppressed forever. Recovery must equal the claimed actor AND the actor
    /// must be the PDA-bound actorRef.
    /// FAILS against pre-fix code (which only checked envelope length != 0), PASSES with fix.
    function test_SC_F_06_forgedHeartbeatRejected() external {
        uint256 pkAttacker = 0xBAD;
        address attacker = vm.addr(pkAttacker);

        // (a) Well-formed envelope claiming the bound actor but with a junk 65-byte
        //     signature → tryRecover yields some address != actor → rejected.
        bytes memory junk = abi.encode(actor, abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), uint8(27)));
        vm.expectRevert(
            abi.encodeWithSelector(IHeartbeatMissedModule.HeartbeatInvalidActor.selector, auth, actor)
        );
        module.recordHeartbeat(auth, keccak256("beat"), junk);

        // (b) Attacker signs with their own key but claims to be the bound actor → recovery mismatch.
        bytes memory forged = _envelope(pkAttacker, actor, auth, keccak256("beat"));
        vm.expectRevert(
            abi.encodeWithSelector(IHeartbeatMissedModule.HeartbeatInvalidActor.selector, auth, actor)
        );
        module.recordHeartbeat(auth, keccak256("beat"), forged);

        // (c) Attacker validly signs as themselves, but they are NOT the PDA-bound actor → rejected.
        bytes memory wrongActor = _envelope(pkAttacker, attacker, auth, keccak256("beat"));
        vm.expectRevert(
            abi.encodeWithSelector(IHeartbeatMissedModule.HeartbeatInvalidActor.selector, auth, attacker)
        );
        module.recordHeartbeat(auth, keccak256("beat"), wrongActor);

        // (d) Cross-chain replay: signature bound to a different chainid → recovery fails.
        bytes32 wrongChainDomain = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _DOMAIN_NAME_HASH, _DOMAIN_VERSION_HASH, block.chainid + 1, address(module)
            )
        );
        bytes32 wrongChainStruct = keccak256(abi.encode(_HEARTBEAT_TYPEHASH, auth, keccak256("beat"), actor));
        bytes32 wrongChainDigest = keccak256(abi.encodePacked(hex"1901", wrongChainDomain, wrongChainStruct));
        (uint8 wv, bytes32 wr, bytes32 ws) = vm.sign(pkActor, wrongChainDigest);
        bytes memory replay = abi.encode(actor, abi.encodePacked(wr, ws, wv));
        vm.expectRevert(
            abi.encodeWithSelector(IHeartbeatMissedModule.HeartbeatInvalidActor.selector, auth, actor)
        );
        module.recordHeartbeat(auth, keccak256("beat"), replay);

        // None of the forged heartbeats moved the deadline — the dead-man release stays on track.
        assertEq(module.heartbeatDeadline(auth), block.timestamp + 110);

        // Sanity: the real subject's bound heartbeat is still accepted.
        module.recordHeartbeat(auth, keccak256("beat"), _envelope(pkActor, actor, auth, keccak256("beat")));
        assertEq(module.heartbeatDeadline(auth), block.timestamp + 110);
    }
}
