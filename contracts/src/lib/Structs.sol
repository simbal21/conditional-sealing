// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ConditionMode, ConditionalRecipientMode, G4Phase, PauseAuthorityMode } from "./Enums.sol";

/// @title Structs - V3 PDA / commit / lifecycle struct types
/// @notice Mirrored verbatim from S2-2 smart-contracts-spec App. A
///         (lines 2112-2220). App. A is normative per S2-2 §0.6.
///
/// @dev FIELD ORDER IS NORMATIVE per S2-1 §3.3 (`pda_root`) and §3.4
///      (`h_commit`) and S2-2 App. A. APPEND-ONLY: do NOT reorder; do NOT
///      delete; new fields go at the end with a corresponding S2-2 spec
///      amendment + commit_version bump per S2-1 §2.8.
///
///      Struct member layouts back the byte-exact recompute discipline in
///      `CealisIdentifierHelpers.sol`. Reordering or retyping these
///      members will break the differential test against M1 vectors at
///      `v3-crypto/test/fixtures/pda-root.golden.json`.

/// @notice 29-field struct backing `keccak256(TAG_PDA_ROOT_V3 ‖ <540-byte preimage>)`
///         per S2-1 §3.3.1 (16 original fields per §3.3.3 + 13 D1 additions per §3.3.4).
struct PdaRootFields {
    // §3.3.3 - original 16 fields
    bytes32 pdaId;
    uint64 pdaVersion;
    uint8 revealConditionMode;
    bytes32 revealConditionSpecHash;
    uint8 shredConditionMode;
    bytes32 shredConditionSpecHash;
    bytes32 oracleReferencesRoot;
    bytes32 dslVersion;
    bytes32 wasmPredicateHashesRoot;
    bytes32 submitterSetsRoot;
    bytes32 pauseAuthorityId;
    bytes32 ceremonyResolverId;
    bytes32 eligibleChallengersRevealRoot;
    bytes32 eligibleChallengersShredRoot;
    bytes32 templateId;
    bytes32 partnerId;
    // §3.3.4 - 13 D1 additions
    uint8 subjectAuthenticatorClass;
    bytes32 qtspProviderRef;
    bool art9Scoped;
    uint8 art9BasisId;
    bool legalEffectExpected;
    bool cealisClassWideHaltOptOut;
    uint64 minimumShredLatency;
    bytes32 applicableJurisdiction;
    bool conditionalRecipientsUpdatable;
    bool subjectLivenessRequiredAtFire;
    bool emergencyResponseBrickingAcknowledgment;
    bool timeCriticalPdaFlag;
    bool pdaUpdatable;
}

/// @notice 15-input struct backing `keccak256(TAG_COMMIT_V3 ‖ <340-byte preimage>)`
///         per S2-1 §3.4.1 (post-IB-1, with `commitVersion uint16`).
struct HCommitFields {
    bytes32 authorizationId;
    bytes32 pdaRoot;
    bytes32 schemaDigest;
    bytes32 ciphertextDigest;
    bytes32 aadDigest;
    bytes32 compositeIdentityDigest;
    bytes32 endpointAttestationDigest;
    uint64 retentionWindow;
    bytes32 shredAuthorityId;
    bytes32 recipientsRoot;
    uint32 revealChallengeWindow;
    uint32 shredChallengeWindow;
    uint8 g3Choice;
    uint8 phase;
    uint16 commitVersion;
}

struct AxisConfig {
    ConditionMode mode;
    bytes32 conditionRef;
    bytes32 conditionSpecHash;
    uint32 challengeWindow;
    bytes32 eligibleChallengersRoot;
    bytes32 resolverId;
}

struct RegistryRefs {
    bytes32 pluginVersionDigest;
    bytes32 g4AuthorityRef;
    bytes32 g3AuthorityRef;
    bytes32 oracleReferencesRoot;
    bytes32 oracleSchemaRoot;
    bytes32 dslVersionRef;
    bytes32 qtspProviderRef;
    bytes32 gateRecipientPubkeyRoot;
}

struct LegalFlags {
    bool legalEffectExpected;
    bool cealisClassWideHaltOptOut;
    bool qesRequired;
    bool art9Scoped;
    uint8 art9BasisId;
    uint8 subjectAuthenticatorClass;
    G4Phase requiredG4Phase;
}

struct PDARegistration {
    PdaRootFields pdaRootFields;
    HCommitFields hCommitFields;
    AxisConfig revealAxis;
    AxisConfig shredAxis;
    RegistryRefs registryRefs;
    LegalFlags legalFlags;
    PauseAuthorityMode pauseAuthorityMode;
    bool shredGuardrailCompiled;
    bytes32 conditionalRecipientPolicyDigest;
    ConditionalRecipientMode[] conditionalRecipientModes;
}

struct FSMAdvanceResult {
    bool terminal;
    uint32 newState;
    bytes32 conditionRef;
}

struct DeprecationFlag {
    bool deprecated;
    uint64 deprecationBlockTimestamp;
    uint8 deprecationReasonCode;
    bytes32 disclosureCid;
    bytes32 disclosureCommitHash;
    uint64 disclosureVerifiedBlock;
    uint64 autoClearTimestamp;
    bool isCanonicalAtSet;
}
