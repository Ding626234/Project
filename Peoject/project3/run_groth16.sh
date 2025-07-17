#!/bin/bash

# 编译电路
circom poseidon2.circom --r1cs --wasm --sym

# 生成见证
node generate_witness.js
node poseidon2_js/generate_witness.js poseidon2_js/poseidon2.wasm input.json witness.wtns

# 开始powers of tau仪式
snarkjs powersoftau new bn128 14 pot14_0000.ptau -v
snarkjs powersoftau contribute pot14_0000.ptau pot14_0001.ptau --name="First contribution" -v

# 准备phase2
snarkjs powersoftau prepare phase2 pot14_0001.ptau pot14_final.ptau -v

# 生成.zkey文件
snarkjs groth16 setup poseidon2.r1cs pot14_final.ptau poseidon2_0000.zkey
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_0001.zkey --name="1st Contributor Name" -v

# 导出验证密钥
snarkjs zkey export verificationkey poseidon2_0001.zkey verification_key.json

# 生成证明
snarkjs groth16 prove poseidon2_0001.zkey witness.wtns proof.json public.json

# 验证证明
snarkjs groth16 verify verification_key.json public.json proof.json

# 生成Solidity验证合约
snarkjs zkey export solidityverifier poseidon2_0001.zkey verifier.sol

# 使用验证合约验证
snarkjs generatecall | tee parameters.txt    