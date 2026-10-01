// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Roles - V3 access-control role identifiers
/// @notice The 17 V3 role identifiers per S2-2 §1.5 + §16.
///
/// @dev V1 `GUARDIAN_ROLE` is intentionally absent and MUST NOT be reintroduced.
///      `DEFAULT_ADMIN_ROLE` matches OpenZeppelin AccessControl (`bytes32(0)`).
///      Every other role is `keccak256(bytes("ROLE_NAME"))`.
library Roles {
    /// @notice OZ AccessControl admin sentinel; held by TimelockController post-deploy.
    bytes32 internal constant DEFAULT_ADMIN_ROLE = 0x00;

    /// @notice keccak256("UPGRADER_ROLE"). Held only by TimelockController.
    bytes32 internal constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice keccak256("PAUSER_ROLE"). Bounded pause/unpause.
    bytes32 internal constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice keccak256("OPERATOR_ROLE"). Operational actions that don't alter policy.
    bytes32 internal constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice keccak256("ORCHESTRATOR_ROLE"). Backend-triggered lifecycle actions.
    bytes32 internal constant ORCHESTRATOR_ROLE = keccak256("ORCHESTRATOR_ROLE");

    /// @notice keccak256("ISSUER_ROLE"). External attestation issuer surface.
    bytes32 internal constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    /// @notice keccak256("MODULE_ADMIN_ROLE"). Adds/deprecates condition modules under timelock.
    bytes32 internal constant MODULE_ADMIN_ROLE = keccak256("MODULE_ADMIN_ROLE");

    /// @notice keccak256("REGISTRY_ADMIN_ROLE"). Adds registry entries under timelock.
    bytes32 internal constant REGISTRY_ADMIN_ROLE = keccak256("REGISTRY_ADMIN_ROLE");

    /// @notice keccak256("SECURITY_COUNCIL_ROLE"). Multisig instant/expedited deprecation.
    bytes32 internal constant SECURITY_COUNCIL_ROLE = keccak256("SECURITY_COUNCIL_ROLE");

    /// @notice keccak256("EMERGENCY_GOVERNANCE_ROLE"). Suspends security council deprecation.
    bytes32 internal constant EMERGENCY_GOVERNANCE_ROLE = keccak256("EMERGENCY_GOVERNANCE_ROLE");

    /// @notice keccak256("CHALLENGE_RESOLVER_ROLE"). PDA-bound challenge-window resolver.
    bytes32 internal constant CHALLENGE_RESOLVER_ROLE = keccak256("CHALLENGE_RESOLVER_ROLE");

    /// @notice keccak256("REKEY_GOVERNANCE_ROLE"). SupersededCommitRegistry writes.
    bytes32 internal constant REKEY_GOVERNANCE_ROLE = keccak256("REKEY_GOVERNANCE_ROLE");

    /// @notice keccak256("ORACLE_SUBMITTER_ROLE"). Oracle attestation submission.
    bytes32 internal constant ORACLE_SUBMITTER_ROLE = keccak256("ORACLE_SUBMITTER_ROLE");

    /// @notice keccak256("LIT_GOVERNANCE_BRIDGE_ROLE"). LitV3Assignment writes from Lit governance.
    bytes32 internal constant LIT_GOVERNANCE_BRIDGE_ROLE = keccak256("LIT_GOVERNANCE_BRIDGE_ROLE");

    /// @notice keccak256("GATE_PUBKEY_PUBLISHER_ROLE"). Per-commit gate-recipient pubkey writes.
    bytes32 internal constant GATE_PUBKEY_PUBLISHER_ROLE = keccak256("GATE_PUBKEY_PUBLISHER_ROLE");

    /// @notice keccak256("SD_OPERATOR_ROLE"). SD proof verification submission.
    bytes32 internal constant SD_OPERATOR_ROLE = keccak256("SD_OPERATOR_ROLE");

    /// @notice keccak256("REVOCATION_ADMIN_ROLE"). Cealis-controlled revocation authority.
    bytes32 internal constant REVOCATION_ADMIN_ROLE = keccak256("REVOCATION_ADMIN_ROLE");
}
