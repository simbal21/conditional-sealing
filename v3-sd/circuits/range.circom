pragma circom 2.0.0;

include "./merkle.circom";
include "../../../node_modules/.pnpm/circomlib@2.0.5/node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/.pnpm/circomlib@2.0.5/node_modules/circomlib/circuits/bitify.circom";

template RangeClaim(depth) {
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
    signal input value_bits[64];
    signal input field_id;
    signal input field_index;
    signal input policy_code;
    signal input merkle_siblings[depth];
    signal input merkle_path_indices[depth];

    component commitment = SdFieldCommitment();
    commitment.authorization_scalar <== authorization_scalar;
    commitment.field_id <== field_id;
    commitment.salt <== salt;
    commitment.value <== value;

    component n2b = Num2Bits(64);
    n2b.in <== value;
    signal acc[65];
    acc[0] <== 0;
    for (var i = 0; i < 64; i++) {
        value_bits[i] === n2b.out[i];
        acc[i + 1] <== acc[i] + value_bits[i] * (1 << i);
    }
    acc[64] === value;

    component lower = GreaterEqThan(64);
    lower.in[0] <== value;
    lower.in[1] <== predicate_param_0;
    lower.out === 1;

    component upper = LessEqThan(64);
    upper.in[0] <== value;
    upper.in[1] <== predicate_param_1;
    upper.out === 1;

    predicate_param_2 === 64;
    field_set_digest_scalar === field_id;

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
] } = RangeClaim(16);
