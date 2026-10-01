pragma circom 2.0.0;

include "./merkle.circom";

template SetMembershipClaim(depth) {
    signal input authorization_scalar;
    signal input h_commit_scalar;
    signal input partner_scalar;
    signal input pda_scalar;
    signal input claim_scalar;
    signal input field_set_digest_scalar;
    signal input sdMerkleRoot;
    signal input predicate_param_0;
    signal input predicate_param_1;
    signal input predicate_param_2;
    signal input expiry_timestamp;
    signal input revocation_scalar;
    signal input verifier_ref_scalar;
    signal input proof_context_scalar;

    signal input value;
    signal input salt;
    signal input field_id;
    signal input field_index;
    signal input policy_code;
    signal input merkle_siblings[depth];
    signal input merkle_path_indices[depth];
    signal input set_member_index;
    signal input set_siblings[depth];
    signal input set_path_indices[depth];

    component commitment = SdFieldCommitment();
    commitment.authorization_scalar <== authorization_scalar;
    commitment.field_id <== field_id;
    commitment.salt <== salt;
    commitment.value <== value;

    field_set_digest_scalar === field_id;
    predicate_param_1 === 0;
    predicate_param_2 === 0;

    component claimTag = SdTagClaim();
    component setLeafHash = SdPoseidon3();
    setLeafHash.in0 <== claimTag.out;
    setLeafHash.in1 <== set_member_index;
    setLeafHash.in2 <== value;

    component setMerkle = SdMerkleVerify(depth);
    setMerkle.leaf <== setLeafHash.out;
    for (var i = 0; i < depth; i++) {
        setMerkle.siblings[i] <== set_siblings[i];
        setMerkle.path_indices[i] <== set_path_indices[i];
    }
    setMerkle.root === predicate_param_0;

    component leaf = SdMerkleLeaf();
    leaf.field_index <== field_index;
    leaf.field_id <== field_id;
    leaf.field_commitment <== commitment.out;
    leaf.policy_code <== policy_code;

    component merkle = SdMerkleVerify(depth);
    merkle.leaf <== leaf.out;
    for (var i = 0; i < depth; i++) {
        merkle.siblings[i] <== merkle_siblings[i];
        merkle.path_indices[i] <== merkle_path_indices[i];
    }
    merkle.root === sdMerkleRoot;

    signal binding_use;
    binding_use <== h_commit_scalar + partner_scalar + pda_scalar + claim_scalar + expiry_timestamp + revocation_scalar + verifier_ref_scalar + proof_context_scalar;
}

component main { public [
    authorization_scalar,
    h_commit_scalar,
    partner_scalar,
    pda_scalar,
    claim_scalar,
    field_set_digest_scalar,
    sdMerkleRoot,
    predicate_param_0,
    predicate_param_1,
    predicate_param_2,
    expiry_timestamp,
    revocation_scalar,
    verifier_ref_scalar,
    proof_context_scalar
] } = SetMembershipClaim(16);
