pragma circom 2.0.0;

include "../../../node_modules/.pnpm/circomlib@2.0.5/node_modules/circomlib/circuits/poseidon.circom";

// OS2IP(TAG_SD_*_V3) mod p, generated from src/tags/tags.ts.
template SdTagField() {
    signal output out;
    out <== 10616565558337024268832812441807306647702700357471186337220733986053547943625;
}

template SdTagMerkle() {
    signal output out;
    out <== 20140787375993896470384773877394070856137159747959843757523163060061810412835;
}

template SdTagClaim() {
    signal output out;
    out <== 11614045815639004896707968084036073694093708135925582797465573164437456239414;
}

template SdPoseidon3() {
    signal input in0;
    signal input in1;
    signal input in2;
    signal output out;

    component h = Poseidon(3);
    h.inputs[0] <== in0;
    h.inputs[1] <== in1;
    h.inputs[2] <== in2;
    out <== h.out;
}

template SdPoseidon5() {
    signal input in0;
    signal input in1;
    signal input in2;
    signal input in3;
    signal input in4;
    signal output out;

    component h = Poseidon(5);
    h.inputs[0] <== in0;
    h.inputs[1] <== in1;
    h.inputs[2] <== in2;
    h.inputs[3] <== in3;
    h.inputs[4] <== in4;
    out <== h.out;
}
