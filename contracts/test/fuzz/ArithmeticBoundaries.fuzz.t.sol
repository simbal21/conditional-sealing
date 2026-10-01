// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { PauseAuthorityMode, ShredAuthorityMode, ShredState, GateKind, CeremonyAxis, PauseConstants }
    from "../../src/lib/Enums.sol";

/// @title ArithmeticBoundariesFuzz - explicit uint64/uint8/uint16/uint32 boundary tests
/// @notice Cat 1 Arithmetic safety: verifies Solidity 0.8.28 default-checked math
///         catches every overflow/underflow on the protocol's primary integer widths
///         AND that enum cast guards reject out-of-range values.
contract ArithmeticBoundariesFuzzTest is Test {
    // ============ uint64 timestamp arithmetic (deadline computation) ============

    /// @notice Fuzz: lastHeartbeat + interval + gracePeriod MUST revert on overflow.
    /// @dev Mirrors the deadline computation in HeartbeatMissedModule + DeadManSwitchModule.
    function testFuzz_uint64_deadlineOverflow_reverts(uint64 lastHeartbeat, uint64 interval, uint64 gracePeriod)
        external
    {
        // Force overflow: interval + gracePeriod near max with lastHeartbeat > 0
        uint64 a = lastHeartbeat;
        uint64 b = interval;
        uint64 c = gracePeriod;
        unchecked {
            uint64 sum = a + b;
            // skip if no overflow yet
            if (sum >= a) {
                sum = sum + c;
                if (sum >= a + b) return; // no overflow
            }
        }
        // Overflow case — Solidity 0.8.x default math reverts
        vm.expectRevert();
        this.computeDeadline(a, b, c);
    }

    function computeDeadline(uint64 last, uint64 interval, uint64 grace) external pure returns (uint64) {
        // Default-checked addition — reverts on overflow per Solidity 0.8.x semantics
        return last + interval + grace;
    }

    /// @notice Fuzz: any deadline computation that does NOT overflow returns correct value.
    function testFuzz_uint64_deadlineNoOverflow_correct(uint32 last, uint32 interval, uint32 grace) external {
        // uint32 inputs guarantee no uint64 overflow
        uint64 result = this.computeDeadline(uint64(last), uint64(interval), uint64(grace));
        assertEq(result, uint64(last) + uint64(interval) + uint64(grace), "no-overflow case");
    }

    // ============ uint64 PauseConstants boundary ============

    /// @notice Fuzz: PauseConstants are the exact published values per S2-2.
    function testFuzz_pauseConstants_areHardcoded(uint8 selector) external pure {
        if (selector % 3 == 0) {
            assertEq(PauseConstants.MAX_OPERATIONAL_PAUSE_SECONDS, 259200, "72 hours");
        } else if (selector % 3 == 1) {
            assertEq(PauseConstants.MAX_REGISTRY_PAUSE_SECONDS, 604800, "7 days");
        } else {
            assertEq(PauseConstants.MAX_EMERGENCY_PAUSE_SECONDS, 604800, "7 days");
        }
    }

    // ============ uint8 enum cast boundary ============

    /// @notice Fuzz: PauseAuthorityMode cast MUST revert for any value > None (2).
    function testFuzz_uint8_pauseAuthorityMode_invalidCastReverts(uint8 raw) external {
        // PauseAuthorityMode: Partner=0, Joint=1, None=2 (3 values per S2-2 §14.1A)
        vm.assume(raw > 2);
        vm.expectRevert();
        this.castPauseAuthorityMode(raw);
    }

    function castPauseAuthorityMode(uint8 raw) external pure returns (PauseAuthorityMode) {
        return PauseAuthorityMode(raw);
    }

    /// @notice Fuzz: ShredAuthorityMode cast MUST revert for any value > Disabled (5).
    function testFuzz_uint8_shredAuthorityMode_invalidCastReverts(uint8 raw) external {
        // ShredAuthorityMode: None=0, Subject=1, Joint=2, Operator=3, Timelock=4, Disabled=5
        vm.assume(raw > 5);
        vm.expectRevert();
        this.castShredAuthorityMode(raw);
    }

    function castShredAuthorityMode(uint8 raw) external pure returns (ShredAuthorityMode) {
        return ShredAuthorityMode(raw);
    }

    /// @notice Fuzz: ShredState cast MUST revert for any value > Shredded (6).
    function testFuzz_uint8_shredState_invalidCastReverts(uint8 raw) external {
        // ShredState: None=0, Requested=1, Authorized=2, Finalized=3, Blocked=4, ChallengeOpen=5, Shredded=6
        vm.assume(raw > 6);
        vm.expectRevert();
        this.castShredState(raw);
    }

    function castShredState(uint8 raw) external pure returns (ShredState) {
        return ShredState(raw);
    }

    /// @notice Fuzz: GateKind cast MUST revert for any value > ConditionalRecipient (4).
    function testFuzz_uint8_gateKind_invalidCastReverts(uint8 raw) external {
        // GateKind: LitV3=0, Dcipher=1, Drand=2, G4=3, ConditionalRecipient=4
        vm.assume(raw > 4);
        vm.expectRevert();
        this.castGateKind(raw);
    }

    function castGateKind(uint8 raw) external pure returns (GateKind) {
        return GateKind(raw);
    }

    /// @notice Fuzz: CeremonyAxis cast MUST revert for any value > Shred (1).
    function testFuzz_uint8_ceremonyAxis_invalidCastReverts(uint8 raw) external {
        // CeremonyAxis: Reveal=0, Shred=1 — only 2 valid values
        vm.assume(raw > 1);
        vm.expectRevert();
        this.castCeremonyAxis(raw);
    }

    function castCeremonyAxis(uint8 raw) external pure returns (CeremonyAxis) {
        return CeremonyAxis(raw);
    }

    /// @notice Fuzz: any in-range uint8 cast succeeds (round-trip).
    function testFuzz_uint8_inRangeCastSucceeds(uint8 raw) external view {
        // PauseAuthorityMode 0..2 (only 3 valid values)
        if (raw <= 2) {
            PauseAuthorityMode mode = this.castPauseAuthorityMode(raw);
            assertEq(uint8(mode), raw, "round-trip");
        }
    }

    // ============ uint32 challenge extension counter ============

    /// @notice Fuzz: uint32 extension count + 1 reverts on overflow at type(uint32).max.
    function testFuzz_uint32_extensionOverflow_reverts(uint32 base, uint8 increment) external {
        vm.assume(increment > 0);
        uint32 a = base;
        uint8 inc = increment;
        unchecked {
            uint32 sum = a + uint32(inc);
            if (sum >= a) return; // no overflow
        }
        vm.expectRevert();
        this.addUint32(a, uint32(inc));
    }

    function addUint32(uint32 a, uint32 b) external pure returns (uint32) {
        return a + b;
    }

    // ============ uint16 generation counter (SupersededCommitRegistry) ============

    /// @notice Fuzz: uint16 generation + 1 reverts at type(uint16).max.
    function testFuzz_uint16_generationOverflow_reverts(uint16 base, uint8 increment) external {
        vm.assume(increment > 0);
        uint16 a = base;
        unchecked {
            uint16 sum = a + uint16(increment);
            if (sum >= a) return; // no overflow
        }
        vm.expectRevert();
        this.addUint16(a, uint16(increment));
    }

    function addUint16(uint16 a, uint16 b) external pure returns (uint16) {
        return a + b;
    }
}
