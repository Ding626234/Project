const { poseidonContract } = require("circomlibjs");
const fs = require("fs");

async function generateConstants() {
    // 生成Poseidon2所需的常量
    const poseidon = await require("circomlibjs").buildPoseidonOpt();
    const F = poseidon.F;
    
    // 常量值C
    const C = poseidon.C.map((c) => F.toObject(c));
    
    // S-box值S
    const S = poseidon.S.map((s) => F.toObject(s));
    
    // MDS矩阵M
    const M = poseidon.M.map((row) => row.map((element) => F.toObject(element)));
    
    // 输出到文件
    const constants = { C, S, M };
    fs.writeFileSync("poseidon_constants.json", JSON.stringify(constants, null, 2));
    
    console.log("常量值已生成并保存到poseidon_constants.json");
}

generateConstants().catch((err) => {
    console.error(err);
    process.exit(1);
});    