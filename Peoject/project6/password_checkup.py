import hashlib
import hmac
import os
from typing import Tuple, List
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class PasswordCheckupProtocol:
    """实现Google Password Checkup隐私保护密码验证协议"""
    
    def __init__(self):
        # 使用P-256椭圆曲线
        self.curve = ec.SECP256R1()
        # 协议中使用的哈希函数
        self.hash_alg = hashes.SHA256()
    
    def client_setup(self, password: str) -> Tuple[bytes, bytes, bytes]:
        """客户端初始化步骤，生成必要的密钥和哈希值
        
        参数:
            password: 用户密码
        
        返回:
            Tuple: (客户端私钥, 客户端公钥, 密码哈希值)
        """
        # 生成客户端椭圆曲线密钥对
        private_key = ec.generate_private_key(self.curve, default_backend())
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # 计算密码的哈希值 (h = H(pwd))
        password_hash = hashlib.sha256(password.encode()).digest()
        
        return private_key, public_key, password_hash
    
    def client_phase1(
        self, 
        private_key: ec.EllipticCurvePrivateKey,
        password_hash: bytes
    ) -> Tuple[bytes, bytes]:
        """客户端第一阶段，生成混淆后的密码哈希和共享密钥
        
        参数:
            private_key: 客户端私钥
            password_hash: 密码哈希值
        
        返回:
            Tuple: (混淆后的密码哈希, 共享密钥)
        """
        # 生成随机数r
        r = os.urandom(32)
        
        # 计算R = r*G (G是椭圆曲线的基点)
        R = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # 计算混淆后的密码哈希 H(r || h)
        blinded_hash = hashlib.sha256(r + password_hash).digest()
        
        # 计算共享密钥 K = H(r || sk)
        sk = private_key.private_numbers().private_value.to_bytes(32, 'big')
        shared_key = hashlib.sha256(r + sk).digest()
        
        return blinded_hash, shared_key
    
    def server_phase1(
        self, 
        blinded_hash: bytes,
        compromised_passwords: List[bytes]
    ) -> Tuple[bytes, bool]:
        """服务器第一阶段，检查混淆后的密码哈希是否在泄露列表中
        
        参数:
            blinded_hash: 混淆后的密码哈希
            compromised_passwords: 泄露密码哈希列表
        
        返回:
            Tuple: (服务器随机数, 是否匹配)
        """
        # 生成服务器随机数s
        s = os.urandom(32)
        
        # 检查混淆后的哈希是否在泄露列表中
        is_compromised = blinded_hash in compromised_passwords
        
        # 计算t = H(s || is_compromised)
        t = hashlib.sha256(s + str(is_compromised).encode()).digest()
        
        return t, is_compromised
    
    def client_phase2(
        self, 
        shared_key: bytes,
        t: bytes
    ) -> bool:
        """客户端第二阶段，验证服务器响应
        
        参数:
            shared_key: 共享密钥
            t: 服务器返回的t值
        
        返回:
            bool: 密码是否泄露
        """
        # 计算H(K || 0)和H(K || 1)
        h0 = hmac.new(shared_key, b'0', hashlib.sha256).digest()
        h1 = hmac.new(shared_key, b'1', hashlib.sha256).digest()
        
        # 判断密码是否泄露
        if t == h0:
            return False  # 密码未泄露
        elif t == h1:
            return True   # 密码已泄露
        else:
            raise ValueError("无效的服务器响应")

# 使用示例
def demonstrate_protocol():
    # 初始化协议
    protocol = PasswordCheckupProtocol()
    
    # 模拟一个泄露的密码
    compromised_password = "weakpassword123"
    compromised_hash = hashlib.sha256(compromised_password.encode()).digest()
    
    # 模拟服务器端的泄露密码列表
    server_compromised_hashes = [compromised_hash]
    
    # 客户端1: 检查一个泄露的密码
    print("测试泄露的密码:")
    client1 = PasswordCheckupProtocol()
    private_key1, public_key1, password_hash1 = client1.client_setup(compromised_password)
    blinded_hash1, shared_key1 = client1.client_phase1(private_key1, password_hash1)
    
    # 服务器处理
    t1, is_compromised1 = client1.server_phase1(blinded_hash1, server_compromised_hashes)
    
    # 客户端验证结果
    result1 = client1.client_phase2(shared_key1, t1)
    print(f"密码是否泄露: {result1} (预期: True)")
    
    # 客户端2: 检查一个安全的密码
    print("\n测试安全的密码:")
    client2 = PasswordCheckupProtocol()
    private_key2, public_key2, password_hash2 = client2.client_setup("SecurePassword456!")
    blinded_hash2, shared_key2 = client2.client_phase1(private_key2, password_hash2)
    
    # 服务器处理
    t2, is_compromised2 = client2.server_phase1(blinded_hash2, server_compromised_hashes)
    
    # 客户端验证结果
    result2 = client2.client_phase2(shared_key2, t2)
    print(f"密码是否泄露: {result2} (预期: False)")

if __name__ == "__main__":
    demonstrate_protocol()    