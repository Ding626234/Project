pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template Poseidon2(n, t, d, C, S, M) {
    signal input private preimage[2];
    signal input public hash[1];

    component poseidon = Poseidon(n, t, d, C, S, M);

    // 连接输入
    for (var i = 0; i < 2; i++) {
        poseidon.inputs[i] <== preimage[i];
    }
    poseidon.inputs[2] <== 0; // 零填充，因为我们只处理一个block

    // 验证哈希值
    hash[0] === poseidon.out;
}

// 主电路
component main = Poseidon2(
    256, // n = 256 bits
    3,   // t = 3
    5,   // d = 5
    C,   // 替换为实际的常量值
    S,   // 替换为实际的S-box值
    M    // 替换为实际的MDS矩阵
);    