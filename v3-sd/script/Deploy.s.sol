// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Script } from "forge-std/Script.sol";

import { PlonkVerifierEquality } from "../contracts/PlonkVerifierEquality.sol";
import { PlonkVerifierNonEquality } from "../contracts/PlonkVerifierNonEquality.sol";
import { PlonkVerifierRange } from "../contracts/PlonkVerifierRange.sol";
import { PlonkVerifierSetMembership } from "../contracts/PlonkVerifierSetMembership.sol";

interface IDisclosureRegistryVerifierRegistration {
    function registerVerifierContract(bytes32 verifierRef, address verifierContract) external;
}

contract Deploy is Script {
    struct Addresses {
        address equality;
        address nonEquality;
        address range;
        address setMembership;
    }

    function run() external returns (Addresses memory addrs) {
        vm.startBroadcast();
        addrs = deployVerifiers();
        vm.stopBroadcast();
    }

    function deployAndRegister(address disclosureRegistry, bytes32[4] calldata verifierRefs)
        external
        returns (Addresses memory addrs)
    {
        vm.startBroadcast();
        addrs = deployVerifiers();
        IDisclosureRegistryVerifierRegistration registry =
            IDisclosureRegistryVerifierRegistration(disclosureRegistry);
        registry.registerVerifierContract(verifierRefs[0], addrs.equality);
        registry.registerVerifierContract(verifierRefs[1], addrs.nonEquality);
        registry.registerVerifierContract(verifierRefs[2], addrs.range);
        registry.registerVerifierContract(verifierRefs[3], addrs.setMembership);
        vm.stopBroadcast();
    }

    function deployVerifiers() internal returns (Addresses memory addrs) {
        addrs.equality = address(new PlonkVerifierEquality());
        addrs.nonEquality = address(new PlonkVerifierNonEquality());
        addrs.range = address(new PlonkVerifierRange());
        addrs.setMembership = address(new PlonkVerifierSetMembership());
    }
}
