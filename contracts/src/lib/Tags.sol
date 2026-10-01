// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Tags - V3 domain-separation TAG_*_V3 constants
/// @notice The 30 active TAG_*_V3 constants per S2-1 cryptography-spec §2.3.
///         Each is `keccak256(bytes(<LABEL>))` per §2.1.
///
/// @dev LOCKED. These hex digests mirror the M1 source-of-truth at
///      `v3-crypto/src/tags.ts`. Any drift breaks every
///      TAG-prefixed lookup across the 4-gate stack.
///
///      Three labels deviate from the symbol-derived form per §2.3.1 / §2.3.2:
///        TAG_COMMIT_V3   -> "CEALIS_V3_COMMITMENT_HASH_V3"
///        TAG_AUTHID_V3   -> "CEALIS_V3_AUTH_ID_V3"
///        TAG_SUBJECT_V3  -> "CEALIS_V3_SUBJECT_V3"
///
///      The matching test fixture is at
///      `test/foundation/TagDigests.t.sol`, which loads
///      `../v3-crypto/test/fixtures/tag-digests.golden.json` and asserts
///      `keccak256(bytes(LABEL)) == DIGEST` for each of 30 entries plus
///      that the Solidity constant equals the digest.
library Tags {
    bytes32 internal constant TAG_COMMIT_V3 = 0x2d2217e4d967ed248e767e28fbd079ef83164a25c8cbcf94387c115336726615;
    bytes32 internal constant TAG_AUTHID_V3 = 0x2515365985f25edab9af1617075766433983edd0fd267b0a8a55d37e7d838890;
    bytes32 internal constant TAG_SUBJECT_V3 = 0x7a3cd7f29faeb061b53c59ce8eecfa833ecf1cbf49300f3a7c3302b29affc667;
    bytes32 internal constant TAG_SIGMA_SUBJECT_V3 = 0xd3444d111201f423e8497cbd494ea869283dacd59b3bbafe8c94e851a666685c;
    bytes32 internal constant TAG_PDA_ROOT_V3 = 0x2e9aef6890ee90a57f6cbc9f7301799f914fe95b03dd711065ebf5b8b3fa31ec;
    bytes32 internal constant TAG_AAD_V3 = 0x5f09deb22a5104e36edaa6ab19e7de91e965cd565b2b1ad45da57eaa2aae9072;
    bytes32 internal constant TAG_AEAD_V3 = 0x5a182280c02d67bf6e1451c6eaf643fe5ee7a53483bea0798e9a9089098a5cc7;
    bytes32 internal constant TAG_COMMIT_CONTEXT_V3 =
        0x48d671e728ee47bc98de43d61df5a39cd3905bd05b4486b31f2a7dd483b45963;
    bytes32 internal constant TAG_ATTESTATION_CONTEXT_V3 =
        0x04db9afc346d39bc8d5013db28b4f9d99797c28deed4d05c8c5e3be621a361f7;
    bytes32 internal constant TAG_LIT_ACC_BINDING_V3 =
        0xa6c12b5473ccee32383b9f18e6b91baee14ac94581f7f34b2c2282186ceaab47;
    bytes32 internal constant TAG_DCIPHER_IBE_BINDING_V3 =
        0xbdd10f2d92628b59bf15813a6126c1920c656bf8832ba29815b0646307d8b5db;
    bytes32 internal constant TAG_DRAND_ROUND_BINDING_V3 =
        0xfa773d04a6919087f36c35e8599e65570d1845b212874d45a2605bf9566bd507;
    bytes32 internal constant TAG_G3_BINDING_V3 = 0xf00f698c5e72aab567f4ee2ecd86d022744b1c708bd26d0905ef1e991038bd80;
    bytes32 internal constant TAG_G4_ATTESTATION_V3 =
        0x780a10ca68087b920d7f54d033295ea9f0bf2a3ade9fa4549f9d88bef964328d;
    bytes32 internal constant TAG_G4_ATTESTATION_AUTHORITY_V3 =
        0xc9d74396e5da1551f663c9b50d3058420dffba15eb9e7bf55d0265dbf56f4b5b;
    bytes32 internal constant TAG_COMPOSITE_IDENTITY_V3 =
        0xb6c2d731d84d245f6e37d6a113a0f7aac5e6f14f60c09d63d47efaee20596a21;
    bytes32 internal constant TAG_STANZA_MAC_V3 = 0x65b576700338e0f13084d7ee44e4c1dae77d778b0fc965f13b5ce3e38ffd6e86;
    bytes32 internal constant TAG_STANZA_WRAP_V3 = 0x60ca44a3bb83006680d19c1a11e6d5c12a34bbadd2097c33933dc4bd9ac48eeb;
    bytes32 internal constant TAG_STANZA_WRAP_NONCE_V3 =
        0x0856b03957f0a8f423634d6eccea6eb02dbe209e252e09a9060f711c2f0a1708;
    bytes32 internal constant TAG_CONDITIONAL_RECIPIENT_BINDING_V3 =
        0xdf3f00fda919fec58008c127c1822fdcec3d5612993e0177326e872d2d553522;
    bytes32 internal constant TAG_REVEAL_CHALLENGE_V3 =
        0x24424bcb1b985ce0b10aeef9cd15acf4cc94c29e9d3d71d3c0162c79e2d88818;
    bytes32 internal constant TAG_RECIPIENT_LEAF_V3 =
        0x308ac45ca3ee14f06f5ef15120925442de01d79048599779650c1b31c3f429ac;
    bytes32 internal constant TAG_P15_ATTESTATION_V3 =
        0x43295912c094bc7c0d669ec40c58fd05091f8845043fbdbbd6664b07ef3c15fd;
    bytes32 internal constant TAG_ARTIFACT_V3 = 0x5d36d4c5c19b3b62647633ca3a4bbffe0209c21bc1a51a63cfe856f0c08b360b;
    bytes32 internal constant TAG_PLUGIN_VERSION_V3 =
        0xf93f76d25d9c1610121890221228733a290725b01dd876e459493ea935106001;
    bytes32 internal constant TAG_ROTATION_LOG_ANCHOR_V3 =
        0xac6ecd58f3a10deaa3f644d147ec92e6672de21eb53d842804bce97df14dfafc;
    bytes32 internal constant TAG_CONDITIONAL_RECIPIENTS_POLICY_V3 =
        0x13bb7366e0f36195c405c280565aaebc46af8735e166ca1023e22e635170eaa9;
    bytes32 internal constant TAG_SUPERSEDED_COMMIT_REGISTRY_V3 =
        0xc9c3c0c6dd22412a9da1c864e5ea8144ee9c791543522c5da49ea0f14c70732e;
    bytes32 internal constant TAG_ROTATION_AUTHORIZATION_V3 =
        0x6ed7799d69ba728883ca59405d310aeaf96e4d0f90340302099537de7316d0f7;
    bytes32 internal constant TAG_ORACLE_REGISTRY_V3 =
        0x5fd88bdfc47cbf2f7b151337f5ee0f4bf08a20394311a0d85e60f921e2b36010;
}
