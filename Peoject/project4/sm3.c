#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// 文档中定义的初始哈希值IV 
static const uint32_t SM3_IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 文档中定义的常量Tj 
static const uint32_t SM3_T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

// 文档中定义的循环左移操作 
#define ROTL32(x, n) ((x << n) | (x >> (32 - n)))

// 文档中定义的FF函数 
#define FF(j, X, Y, Z) ((j) < 16 ? (X ^ Y ^ Z) : ((X & Y) | (X & Z) | (Y & Z)))

// 文档中定义的GG函数 
#define GG(j, X, Y, Z) ((j) < 16 ? (X ^ Y ^ Z) : ((X & Y) | ((~X) & Z)))

// 文档中定义的置换函数 
#define P0(X) (X ^ ROTL32(X, 9) ^ ROTL32(X, 17))
#define P1(X) (X ^ ROTL32(X, 15) ^ ROTL32(X, 23))

// 压缩函数（文档中迭代压缩步骤 ）
static void sm3_compress(uint32_t *state, const uint32_t *block) {
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;

    // 消息扩展（文档 ）
    for (j = 0; j < 16; j++) {
        W[j] = block[j];
    }
    for (j = 16; j < 68; j++) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15)) ^ ROTL32(W[j-13], 7) ^ W[j-6];
    }
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }

    // 初始化状态变量
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    // 64轮迭代（文档  4轮组合优化）
    for (j = 0; j < 64; j += 4) {
        // 第j轮
        SS1 = ROTL32((ROTL32(A, 12) + E + ROTL32(SM3_T[j], j)), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF(j, A, B, C) + D + SS2 + W1[j];
        TT2 = GG(j, E, F, G) + H + SS1 + W[j];
        D = C; C = ROTL32(B, 9); B = A; A = TT1;
        H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);

        // 第j+1轮
        j++;
        SS1 = ROTL32((ROTL32(A, 12) + E + ROTL32(SM3_T[j], j)), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF(j, A, B, C) + D + SS2 + W1[j];
        TT2 = GG(j, E, F, G) + H + SS1 + W[j];
        D = C; C = ROTL32(B, 9); B = A; A = TT1;
        H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);

        // 第j+2轮
        j++;
        SS1 = ROTL32((ROTL32(A, 12) + E + ROTL32(SM3_T[j], j)), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF(j, A, B, C) + D + SS2 + W1[j];
        TT2 = GG(j, E, F, G) + H + SS1 + W[j];
        D = C; C = ROTL32(B, 9); B = A; A = TT1;
        H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);

        // 第j+3轮
        j++;
        SS1 = ROTL32((ROTL32(A, 12) + E + ROTL32(SM3_T[j], j)), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF(j, A, B, C) + D + SS2 + W1[j];
        TT2 = GG(j, E, F, G) + H + SS1 + W[j];
        D = C; C = ROTL32(B, 9); B = A; A = TT1;
        H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);
    }

    // 更新状态
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// 消息填充（文档 ）
static size_t sm3_pad(uint8_t *msg, size_t len) {
    size_t l = len * 8;
    size_t k = (448 - l - 1) % 512;
    size_t padded_len = len + (k + 1 + 64) / 8;

    msg[len] = 0x80;
    memset(msg + len + 1, 0, padded_len - len - 1 - 8);

    // 填充消息长度（64位大端）
    for (int i = 0; i < 8; i++) {
        msg[padded_len - 8 + i] = (l >> (56 - 8 * i)) & 0xFF;
    }

    return padded_len;
}

// 基础SM3哈希实现
void sm3_hash(const uint8_t *msg, size_t len, uint8_t *digest) {
    uint32_t state[8];
    memcpy(state, SM3_IV, sizeof(SM3_IV));

    uint8_t *padded_msg = malloc(len + 64); // 最大填充需求
    memcpy(padded_msg, msg, len);
    size_t padded_len = sm3_pad(padded_msg, len);

    // 按512比特分组处理
    for (size_t i = 0; i < padded_len; i += 64) {
        uint32_t block[16];
        for (int j = 0; j < 16; j++) {
            block[j] = (padded_msg[i + j*4] << 24) | 
                      (padded_msg[i + j*4 + 1] << 16) | 
                      (padded_msg[i + j*4 + 2] << 8) | 
                       padded_msg[i + j*4 + 3];
        }
        sm3_compress(state, block);
    }

    // 输出256比特哈希值（大端）
    for (int i = 0; i < 8; i++) {
        digest[i*4] = (state[i] >> 24) & 0xFF;
        digest[i*4 + 1] = (state[i] >> 16) & 0xFF;
        digest[i*4 + 2] = (state[i] >> 8) & 0xFF;
        digest[i*4 + 3] = state[i] & 0xFF;
    }

    free(padded_msg);
}

// 长度扩展攻击实现（基于文档中迭代压缩特性 ）
bool sm3_length_extension_attack(const uint8_t *original_hash, size_t original_len,
                                const uint8_t *suffix, size_t suffix_len,
                                uint8_t *forged_hash, uint8_t **forged_msg, size_t *forged_len) {
    // 解析原始哈希为中间状态
    uint32_t state[8];
    for (int i = 0; i < 8; i++) {
        state[i] = (original_hash[i*4] << 24) | 
                  (original_hash[i*4 + 1] << 16) | 
                  (original_hash[i*4 + 2] << 8) | 
                   original_hash[i*4 + 3];
    }

    // 构造伪造消息：原始消息填充 + 后缀
    size_t original_padded_len = original_len + ((56 - (original_len % 64)) % 64) + 1 + 8;
    *forged_len = original_padded_len + suffix_len;
    *forged_msg = (uint8_t*)malloc(*forged_len);
    
    // 填充原始消息（仅模拟，实际攻击无需原始消息内容）
    uint8_t *dummy_pad = malloc(original_padded_len);
    sm3_pad(dummy_pad, original_len); // 生成填充格式
    memcpy(*forged_msg, dummy_pad, original_padded_len);
    memcpy(*forged_msg + original_padded_len, suffix, suffix_len);
    free(dummy_pad);

    // 基于中间状态计算伪造哈希
    uint8_t *padded_forged = malloc(*forged_len + 64);
    memcpy(padded_forged, *forged_msg, *forged_len);
    size_t padded_forged_len = sm3_pad(padded_forged, *forged_len);

    for (size_t i = 0; i < padded_forged_len; i += 64) {
        uint32_t block[16];
        for (int j = 0; j < 16; j++) {
            block[j] = (padded_forged[i + j*4] << 24) | 
                      (padded_forged[i + j*4 + 1] << 16) | 
                      (padded_forged[i + j*4 + 2] << 8) | 
                       padded_forged[i + j*4 + 3];
        }
        sm3_compress(state, block);
    }

    // 生成伪造哈希
    for (int i = 0; i < 8; i++) {
        forged_hash[i*4] = (state[i] >> 24) & 0xFF;
        forged_hash[i*4 + 1] = (state[i] >> 16) & 0xFF;
        forged_hash[i*4 + 2] = (state[i] >> 8) & 0xFF;
        forged_hash[i*4 + 3] = state[i] & 0xFF;
    }

    free(padded_forged);
    return true;
}

// Merkle树节点结构（基于RFC6962，参考文档哈希串联特性 ）
typedef struct {
    uint8_t hash[32];
    size_t left, right; // 子节点索引（-1表示叶子）
} MerkleNode;

// 构建Merkle树（10w叶子节点）
MerkleNode* merkle_build(const uint8_t *leaves, size_t leaf_count, size_t *tree_size) {
    size_t n = 1;
    while (n < leaf_count) n <<= 1; // 补全为2的幂
    *tree_size = 2 * n;
    MerkleNode *tree = malloc(*tree_size * sizeof(MerkleNode));

    // 初始化叶子节点
    for (size_t i = 0; i < leaf_count; i++) {
        sm3_hash(leaves + i*32, 32, tree[n + i].hash);
        tree[n + i].left = tree[n + i].right = -1;
    }
    for (size_t i = leaf_count; i < n; i++) {
        memset(tree[n + i].hash, 0, 32); // 填充空叶子
        tree[n + i].left = tree[n + i].right = -1;
    }

    // 构建非叶子节点（哈希串联后再哈希 ）
    for (size_t i = n - 1; i > 0; i--) {
        uint8_t concat[64];
        memcpy(concat, tree[2*i].hash, 32);
        memcpy(concat + 32, tree[2*i + 1].hash, 32);
        sm3_hash(concat, 64, tree[i].hash);
        tree[i].left = 2*i;
        tree[i].right = 2*i + 1;
    }

    return tree;
}

// 生成Merkle存在性证明
size_t merkle_prove(const MerkleNode *tree, size_t n, size_t leaf_idx, uint8_t *proof) {
    size_t proof_len = 0;
    size_t i = n + leaf_idx;
    while (i > 1) {
        size_t sibling = (i % 2) ? i + 1 : i - 1;
        memcpy(proof + proof_len, tree[sibling].hash, 32);
        proof_len += 32;
        i >>= 1;
    }
    return proof_len;
}

// 验证Merkle存在性证明
bool merkle_verify(const uint8_t *root, const uint8_t *leaf_hash,
                  const uint8_t *proof, size_t proof_len, size_t leaf_idx) {
    uint8_t current[32];
    memcpy(current, leaf_hash, 32);

    for (size_t i = 0; i < proof_len; i += 32) {
        uint8_t concat[64];
        if (leaf_idx % 2) { // 右子节点
            memcpy(concat, proof + i, 32);
            memcpy(concat + 32, current, 32);
        } else { // 左子节点
            memcpy(concat, current, 32);
            memcpy(concat + 32, proof + i, 32);
        }
        sm3_hash(concat, 64, current);
        leaf_idx >>= 1;
    }

    return memcmp(current, root, 32) == 0;
}

// 辅助函数：打印哈希值
void print_hash(const uint8_t *hash) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    // 测试1：基础SM3哈希
    printf("=== 基础SM3哈希测试 ===\n");
    const uint8_t msg[] = "test sm3 hash";
    uint8_t digest[32];
    sm3_hash(msg, strlen((char*)msg), digest);
    printf("消息: %s\n哈希值: ", (char*)msg);
    print_hash(digest);

    // 测试2：长度扩展攻击
    printf("\n=== 长度扩展攻击测试 ===\n");
    uint8_t original_hash[32];
    sm3_hash(msg, strlen((char*)msg), original_hash);
    printf("原始哈希: ");
    print_hash(original_hash);

    const uint8_t suffix[] = "_extended";
    uint8_t forged_hash[32], *forged_msg;
    size_t forged_len;
    sm3_length_extension_attack(original_hash, strlen((char*)msg), 
                               suffix, strlen((char*)suffix),
                               forged_hash, &forged_msg, &forged_len);
    printf("伪造哈希: ");
    print_hash(forged_hash);

    // 验证攻击结果
    uint8_t verify_hash[32];
    sm3_hash(forged_msg, forged_len, verify_hash);
    printf("验证结果: %s\n", memcmp(forged_hash, verify_hash, 32) ? "失败" : "成功");
    free(forged_msg);

    // 测试3：Merkle树（简化测试，使用1024个叶子模拟10w节点）
    printf("\n=== Merkle树测试 ===\n");
    size_t leaf_count = 1024;
    uint8_t *leaves = malloc(leaf_count * 32);
    for (size_t i = 0; i < leaf_count; i++) {
        memset(leaves + i*32, i % 256, 32); // 生成测试叶子
    }

    size_t tree_size;
    MerkleNode *tree = merkle_build(leaves, leaf_count, &tree_size);
    printf("根哈希: ");
    print_hash(tree[1].hash);

    // 验证第100个叶子的存在性
    size_t leaf_idx = 100;
    uint8_t proof[1024];
    size_t proof_len = merkle_prove(tree, tree_size/2, leaf_idx, proof);
    bool exists = merkle_verify(tree[1].hash, tree[tree_size/2 + leaf_idx].hash, proof, proof_len, leaf_idx);
    printf("第%zu个叶子存在性: %s\n", leaf_idx, exists ? "存在" : "不存在");

    free(leaves);
    free(tree);
    return 0;
}
