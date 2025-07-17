import threading
import os

class SM4:
    """SM4算法实现"""
    # 系统参数
    FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
    
    # 固定参数
    CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]
    
    # S盒
    SboxTable = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ]
    
    def __init__(self):
        # 初始化T表
        self._init_t_tables()
    
    def _init_t_tables(self):
        """初始化T表用于优化"""
        self.T1 = [0] * 256
        self.T2 = [0] * 256
        self.T3 = [0] * 256
        self.T4 = [0] * 256
        
        for i in range(256):
            # 计算S盒输出
            s = self.SboxTable[i]
            
            # 计算T1-T4表的值
            self.T1[i] = s
            self.T2[i] = s << 8 | s >> 24
            self.T3[i] = s << 16 | s >> 16
            self.T4[i] = s << 24 | s >> 8
    
    def s_box(self, byte):
        """S盒替换"""
        return self.SboxTable[byte]
    
    def l_function(self, word):
        """线性变换L"""
        return word ^ ((word << 2) | (word >> 30)) ^ ((word << 10) | (word >> 22)) ^ \
               ((word << 18) | (word >> 14)) ^ ((word << 24) | (word >> 8))
    
    def l_prime_function(self, word):
        """密钥扩展中的线性变换L'"""
        return word ^ ((word << 13) | (word >> 19)) ^ ((word << 23) | (word >> 9))
    
    def t_function(self, word):
        """合成置换T"""
        # 分解为4个字节
        a0 = (word >> 24) & 0xFF
        a1 = (word >> 16) & 0xFF
        a2 = (word >> 8) & 0xFF
        a3 = word & 0xFF
        
        # S盒替换
        b0 = self.s_box(a0)
        b1 = self.s_box(a1)
        b2 = self.s_box(a2)
        b3 = self.s_box(a3)
        
        # 重组并应用线性变换
        return self.l_function((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    
    def t_prime_function(self, word):
        """密钥扩展中的合成置换T'"""
        # 分解为4个字节
        a0 = (word >> 24) & 0xFF
        a1 = (word >> 16) & 0xFF
        a2 = (word >> 8) & 0xFF
        a3 = word & 0xFF
        
        # S盒替换
        b0 = self.s_box(a0)
        b1 = self.s_box(a1)
        b2 = self.s_box(a2)
        b3 = self.s_box(a3)
        
        # 重组并应用线性变换L'
        return self.l_prime_function((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    
    def key_expansion(self, key):
        """密钥扩展算法"""
        # 128位密钥分为4个32位字
        k = [0] * 36
        k[0] = (key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3]
        k[1] = (key[4] << 24) | (key[5] << 16) | (key[6] << 8) | key[7]
        k[2] = (key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11]
        k[3] = (key[12] << 24) | (key[13] << 16) | (key[14] << 8) | key[15]
        
        # 与系统参数FK异或
        k[0] ^= self.FK[0]
        k[1] ^= self.FK[1]
        k[2] ^= self.FK[2]
        k[3] ^= self.FK[3]
        
        # 生成32轮子密钥
        rk = [0] * 32
        for i in range(32):
            k[i+4] = k[i] ^ self.t_prime_function(k[i+1] ^ k[i+2] ^ k[i+3] ^ self.CK[i])
            rk[i] = k[i+4]
        
        return rk
    
    def encrypt_block(self, block, rk):
        """加密单个块"""
        # 128位明文分为4个32位字
        x = [0] * 36
        x[0] = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]
        x[1] = (block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]
        x[2] = (block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]
        x[3] = (block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]
        
        # 32轮迭代
        for i in range(32):
            x[i+4] = x[i] ^ self.t_function(x[i+1] ^ x[i+2] ^ x[i+3] ^ rk[i])
        
        # 反序输出
        encrypted = []
        for i in range(4):
            word = x[35 - i]
            encrypted.extend([(word >> 24) & 0xFF, (word >> 16) & 0xFF, 
                             (word >> 8) & 0xFF, word & 0xFF])
        
        return encrypted
    
    def decrypt_block(self, block, rk):
        """解密单个块"""
        # 解密使用与加密相同的结构，只是轮密钥顺序相反
        rk_reversed = rk[::-1]
        return self.encrypt_block(block, rk_reversed)
    
    def encrypt(self, plaintext, key):
        """加密函数"""
        # 扩展密钥
        rk = self.key_expansion(key)
        
        # 确保明文长度是16字节的倍数
        if len(plaintext) % 16 != 0:
            plaintext = self._pad(plaintext)
        
        # 分块加密
        ciphertext = []
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            encrypted_block = self.encrypt_block(block, rk)
            ciphertext.extend(encrypted_block)
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext, key):
        """解密函数"""
        # 扩展密钥
        rk = self.key_expansion(key)
        
        # 分块解密
        plaintext = []
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = self.decrypt_block(block, rk)
            plaintext.extend(decrypted_block)
        
        # 去除填充
        if self._is_padded(plaintext):
            plaintext = self._unpad(plaintext)
        
        return bytes(plaintext)
    
    def _pad(self, data):
        """PKCS#7填充"""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)
    
    def _is_padded(self, data):
        """检查是否有PKCS#7填充"""
        if not data:
            return False
        
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            return False
        
        for i in range(1, pad_len + 1):
            if data[-i] != pad_len:
                return False
        
        return True
    
    def _unpad(self, data):
        """去除PKCS#7填充"""
        pad_len = data[-1]
        return data[:-pad_len]

class SM4_GCM:
    """SM4-GCM工作模式实现"""
    def __init__(self, key):
        self.sm4 = SM4()  # 使用之前实现的SM4类
        self.key = key
        self.h = self._compute_hash_subkey()
    
    def _compute_hash_subkey(self):
        """计算哈希子密钥H"""
        # H = SM4-Encrypt(0^128)
        zero_block = bytes([0] * 16)
        return self.sm4.encrypt(zero_block, self.key)
    
    def _gcm_mult(self, x, y):
        """GF(2^128)上的乘法运算"""
        z = [0] * 16
        v = list(y)
        
        for i in range(128):
            bit = (x[i//8] >> (7 - (i % 8))) & 1
            if bit:
                z = [a ^ b for a, b in zip(z, v)]
            
            # 计算v = v * X
            carry = 0
            for j in reversed(range(16)):
                temp = (v[j] >> 7) & 1
                v[j] = ((v[j] << 1) | carry) & 0xFF
                carry = temp
            
            if carry:
                v[15] ^= 0xE1  # R = x^128 + x^7 + x^2 + x + 1
        
        return bytes(z)
    
    def _inc32(self, block):
        """对最后32位进行递增"""
        # 转换为整数
        n = int.from_bytes(block[:12], 'big')
        c = int.from_bytes(block[12:], 'big')
        
        # 递增
        c = (c + 1) % (1 << 32)
        
        # 转换回字节
        return n.to_bytes(12, 'big') + c.to_bytes(4, 'big')
    
    def _ghash(self, data, aad=b''):
        """计算GHASH函数"""
        # 计算块数
        data_len = len(data)
        aad_len = len(aad)
        
        # 填充AAD到块大小的倍数
        if aad_len % 16 != 0:
            aad += bytes([0] * (16 - (aad_len % 16)))
        
        # 填充数据到块大小的倍数
        if data_len % 16 != 0:
            data += bytes([0] * (16 - (data_len % 16)))
        
        # 计算块数
        m = len(aad) // 16
        n = len(data) // 16
        
        # 初始化Y
        y = bytes([0] * 16)
        
        # 处理AAD块
        for i in range(m):
            block = aad[i*16:(i+1)*16]
            y = [a ^ b for a, b in zip(y, block)]
            y = bytes(y)
            y = self._gcm_mult(y, self.h)
        
        # 处理数据块
        for i in range(n):
            block = data[i*16:(i+1)*16]
            y = [a ^ b for a, b in zip(y, block)]
            y = bytes(y)
            y = self._gcm_mult(y, self.h)
        
        # 处理长度块
        len_block = (aad_len * 8).to_bytes(8, 'big') + (data_len * 8).to_bytes(8, 'big')
        y = [a ^ b for a, b in zip(y, len_block)]
        y = bytes(y)
        y = self._gcm_mult(y, self.h)
        
        return y
    
    def encrypt(self, plaintext, nonce, aad=b'', tag_length=128):
        """加密并生成认证标签"""
        # 检查参数
        if len(nonce) != 12:
            raise ValueError("Nonce长度必须为12字节")
        
        # 生成初始计数器块
        j0 = nonce + bytes([0, 0, 0, 1])
        
        # 计算消息块数
        n_blocks = (len(plaintext) + 15) // 16
        
        # 生成密文
        ciphertext = bytearray()
        for i in range(n_blocks):
            # 计算计数器块
            counter_block = self._inc32(j0)
            
            # 加密计数器块
            encrypted_counter = self.sm4.encrypt(counter_block, self.key)
            
            # 异或生成密文块
            block = plaintext[i*16:(i+1)*16]
            cipher_block = bytes(a ^ b for a, b in zip(block, encrypted_counter[:len(block)]))
            ciphertext.extend(cipher_block)
        
        # 计算认证标签
        s = self.sm4.encrypt(j0, self.key)
        t = bytes(a ^ b for a, b in zip(self._ghash(bytes(ciphertext), aad), s))
        
        # 截取标签到指定长度
        tag_length_bytes = tag_length // 8
        tag = t[:tag_length_bytes]
        
        return bytes(ciphertext), tag
    
    def decrypt(self, ciphertext, nonce, aad=b'', tag=b'', tag_length=128):
        """解密并验证认证标签"""
        # 检查参数
        if len(nonce) != 12:
            raise ValueError("Nonce长度必须为12字节")
        
        # 生成初始计数器块
        j0 = nonce + bytes([0, 0, 0, 1])
        
        # 计算消息块数
        n_blocks = (len(ciphertext) + 15) // 16
        
        # 生成明文
        plaintext = bytearray()
        for i in range(n_blocks):
            # 计算计数器块
            counter_block = self._inc32(j0)
            
            # 加密计数器块
            encrypted_counter = self.sm4.encrypt(counter_block, self.key)
            
            # 异或生成明文块
            block = ciphertext[i*16:(i+1)*16]
            plain_block = bytes(a ^ b for a, b in zip(block, encrypted_counter[:len(block)]))
            plaintext.extend(plain_block)
        
        # 计算预期标签
        s = self.sm4.encrypt(j0, self.key)
        expected_tag = bytes(a ^ b for a, b in zip(self._ghash(ciphertext, aad), s))
        
        # 截取预期标签到指定长度
        tag_length_bytes = tag_length // 8
        expected_tag = expected_tag[:tag_length_bytes]
        
        # 验证标签
        if tag != expected_tag:
            print(f"原始标签: {tag.hex()}")
            print(f"计算标签: {expected_tag.hex()}")
            raise ValueError("认证标签验证失败")
        
        return bytes(plaintext)

class SM4_GCM_Optimized(SM4_GCM):
    """优化的SM4-GCM实现"""
    def __init__(self, key):
        super().__init__(key)
        self.h_as_int = int.from_bytes(self.h, 'big')
        self.lock = threading.Lock()  # 添加线程锁
    
    def _gcm_mult_optimized(self, x_bytes, y_bytes):
        """使用查表法优化的GF(2^128)乘法"""
        x = int.from_bytes(x_bytes, 'big')
        y = int.from_bytes(y_bytes, 'big')
        z = 0
        
        # 预计算y的位移表
        y_table = [0] * 8
        y_table[0] = y
        for i in range(1, 8):
            y_table[i] = (y_table[i-1] << 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        
        # 分段处理
        for i in range(16):
            byte = (x >> ((15 - i) * 8)) & 0xFF
            for j in range(8):
                if byte & (1 << (7 - j)):
                    z ^= y_table[j]
            
            # 右移y
            carry = y & 1
            y >>= 1
            if carry:
                y ^= 0xE1000000000000000000000000000000  # R = x^128 + x^7 + x^2 + x + 1
        
        return z.to_bytes(16, 'big')
    
    def _ghash_parallel(self, data, aad=b''):
        """使用多线程并行计算GHASH"""
        # 计算块数
        data_len = len(data)
        aad_len = len(aad)
        
        # 填充AAD到块大小的倍数
        if aad_len % 16 != 0:
            aad += bytes([0] * (16 - (aad_len % 16)))
        
        # 填充数据到块大小的倍数
        if data_len % 16 != 0:
            data += bytes([0] * (16 - (data_len % 16)))
        
        # 分块处理
        m = len(aad) // 16
        n = len(data) // 16
        
        # 确定线程数
        max_threads = 4  # 根据CPU核心数调整
        thread_count = min(max_threads, m + n)
        
        # 每个线程处理的块数
        aad_blocks_per_thread = m // thread_count
        data_blocks_per_thread = n // thread_count
        
        # 结果存储
        results = [bytes([0] * 16)] * thread_count
        
        # 处理AAD的线程函数
        def process_aad(thread_id):
            start = thread_id * aad_blocks_per_thread
            end = start + aad_blocks_per_thread
            if thread_id == thread_count - 1:
                end = m
            
            y = bytes([0] * 16)
            for i in range(start, end):
                block = aad[i*16:(i+1)*16]
                y = [a ^ b for a, b in zip(y, block)]
                y = bytes(y)
                y = self._gcm_mult_optimized(y, self.h)
            
            with self.lock:  # 使用锁保护共享资源
                results[thread_id] = y
        
        # 处理数据的线程函数
        def process_data(thread_id):
            start = thread_id * data_blocks_per_thread
            end = start + data_blocks_per_thread
            if thread_id == thread_count - 1:
                end = n
            
            y = bytes([0] * 16)
            for i in range(start, end):
                block = data[i*16:(i+1)*16]
                y = [a ^ b for a, b in zip(y, block)]
                y = bytes(y)
                y = self._gcm_mult_optimized(y, self.h)
            
            with self.lock:  # 使用锁保护共享资源
                results[thread_id] = y
        
        # 创建并启动线程
        threads = []
        for i in range(thread_count):
            if i < thread_count * aad_blocks_per_thread / (aad_blocks_per_thread + data_blocks_per_thread):
                t = threading.Thread(target=process_aad, args=(i,))
            else:
                t = threading.Thread(target=process_data, args=(i,))
            threads.append(t)
            t.start()
        
        # 等待所有线程完成
        for t in threads:
            t.join()
        
        # 合并结果
        y = bytes([0] * 16)
        for result in results:
            y = [a ^ b for a, b in zip(y, result)]
            y = bytes(y)
            y = self._gcm_mult_optimized(y, self.h)
        
        # 处理长度块
        len_block = (aad_len * 8).to_bytes(8, 'big') + (data_len * 8).to_bytes(8, 'big')
        y = [a ^ b for a, b in zip(y, len_block)]
        y = bytes(y)
        y = self._gcm_mult_optimized(y, self.h)
        
        return y
    
    def encrypt(self, plaintext, nonce, aad=b'', tag_length=128):
        """优化的加密函数"""
        # 生成密文（使用基础方法）
        ciphertext, tag = super().encrypt(plaintext, nonce, aad, tag_length)
        
        # 使用并行GHASH重新计算标签
        if len(plaintext) > 1024:  # 仅对大消息使用并行优化
            s = self.sm4.encrypt(nonce + bytes([0, 0, 0, 1]), self.key)
            t = bytes(a ^ b for a, b in zip(self._ghash_parallel(bytes(ciphertext), aad), s))
            tag = t[:tag_length // 8]
        
        return ciphertext, tag

def test_sm4():
    """测试SM4加密解密"""
    print("测试SM4加密解密:")
    # 128位密钥示例
    key = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])
    
    # 128位明文示例
    plaintext = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])
    
    # 创建SM4实例并加密
    sm4 = SM4()
    ciphertext = sm4.encrypt(plaintext, key)
    decrypted = sm4.decrypt(ciphertext, key)
    
    print(f"明文: {plaintext.hex()}")
    print(f"密文: {ciphertext.hex()}")
    print(f"解密结果: {decrypted.hex()}")
    print(f"解密是否成功: {decrypted == plaintext}")
    print()

def test_sm4_gcm():
    """测试SM4-GCM加密解密"""
    print("测试SM4-GCM加密解密:")
    # 128位密钥
    key = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])
    
    # 明文
    plaintext = b"Hello, SM4-GCM!"
    
    # 12字节nonce
    nonce = os.urandom(12)
    
    # 附加认证数据
    aad = b"Additional Authentication Data"
    
    # 创建SM4-GCM实例并加密
    sm4_gcm = SM4_GCM(key)
    ciphertext, tag = sm4_gcm.encrypt(plaintext, nonce, aad)
    
    # 解密
    decrypted = sm4_gcm.decrypt(ciphertext, nonce, aad, tag)
    
    print(f"明文: {plaintext}")
    print(f"密文: {ciphertext.hex()}")
    print(f"标签: {tag.hex()}")
    print(f"解密结果: {decrypted}")
    print(f"解密是否成功: {decrypted == plaintext}")
    print()

def test_sm4_gcm_optimized():
    """测试优化的SM4-GCM加密解密"""
    print("测试优化的SM4-GCM加密解密:")
    # 128位密钥
    key = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])
    
    # 较长的明文
    plaintext = b"Hello, SM4-GCM! This is a longer message to test the optimized implementation." * 100
    
    # 12字节nonce
    nonce = os.urandom(12)
    
    # 附加认证数据
    aad = b"Additional Authentication Data" * 10
    
    # 创建优化的SM4-GCM实例并加密
    sm4_gcm_opt = SM4_GCM_Optimized(key)
    
    # 测试优化前的性能
    import time
    start_time = time.time()
    ciphertext, tag = sm4_gcm_opt.encrypt(plaintext, nonce, aad)
    end_time = time.time()
    print(f"优化版加密时间: {end_time - start_time:.6f}秒")
    
    # 解密
    try:
        decrypted = sm4_gcm_opt.decrypt(ciphertext, nonce, aad, tag)
        print(f"明文长度: {len(plaintext)}字节")
        print(f"解密是否成功: {decrypted == plaintext}")
    except ValueError as e:
        print(f"解密失败: {e}")
    
    print()

if __name__ == "__main__":
    test_sm4()
    test_sm4_gcm()
    test_sm4_gcm_optimized()    