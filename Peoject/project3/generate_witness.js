const { buildPoseidonOpt } = require("circomlibjs");
const fs = require("fs");
const { stringifyBigInts, unstringifyBigInts } = require("ffjavascript").utils;

async function generateWitness() {
    // 加载Poseidon2
    const poseidon = await buildPoseidonOpt();
    const F = poseidon.F;
    
    // 隐私输入 - 哈希原象
    const preimage = [
        F.e("12345678901234567890123456789012345678901234567890123456789012"), // 示例值
        F.e("09876543210987654321098765432109876543210987654321098765432109")  // 示例值
    ];
    
    // 计算哈希值
    const hash = poseidon([preimage[0], preimage[1], F.e(0)]);
    
    // 准备输入JSON
    const input = {
        preimage: preimage.map((x) => F.toObject(x)),
        hash: [F.toObject(hash)]
    };
    
    // 保存到文件
    fs.writeFileSync("input.json", JSON.stringify(stringifyBigInts(input), null, 2));
    console.log("Witness输入已保存到input.json");
}

generateWitness().catch((err) => {
    console.error(err);
    process.exit(1);
});    