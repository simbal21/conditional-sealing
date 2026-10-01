pragma circom 2.0.0;

include "./poseidon.circom";

template SdFieldCommitment() {
    signal input authorization_scalar;
    signal input field_id;
    signal input salt;
    signal input value;
    signal output out;

    component tag = SdTagField();
    component h = SdPoseidon5();
    h.in0 <== tag.out;
    h.in1 <== authorization_scalar;
    h.in2 <== field_id;
    h.in3 <== salt;
    h.in4 <== value;
    out <== h.out;
}

template SdMerkleLeaf() {
    signal input field_index;
    signal input field_id;
    signal input field_commitment;
    signal input policy_code;
    signal output out;

    component tag = SdTagMerkle();
    component h = SdPoseidon5();
    h.in0 <== tag.out;
    h.in1 <== field_index;
    h.in2 <== field_id;
    h.in3 <== field_commitment;
    h.in4 <== policy_code;
    out <== h.out;
}

template SdMerkleNode() {
    signal input left;
    signal input right;
    signal output out;

    component tag = SdTagMerkle();
    component h = SdPoseidon3();
    h.in0 <== tag.out;
    h.in1 <== left;
    h.in2 <== right;
    out <== h.out;
}

template SdMerkleVerify(depth) {
    signal input leaf;
    signal input siblings[depth];
    signal input path_indices[depth];
    signal output root;

    signal current[depth + 1];
    signal left[depth];
    signal right[depth];
    signal delta[depth];
    component nodes[depth];

    current[0] <== leaf;
    for (var i = 0; i < depth; i++) {
        path_indices[i] * (path_indices[i] - 1) === 0;
        delta[i] <== siblings[i] - current[i];
        left[i] <== current[i] + path_indices[i] * delta[i];
        right[i] <== siblings[i] - path_indices[i] * delta[i];
        nodes[i] = SdMerkleNode();
        nodes[i].left <== left[i];
        nodes[i].right <== right[i];
        current[i + 1] <== nodes[i].out;
    }

    root <== current[depth];
}
