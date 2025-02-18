import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class SCT_Cipher:
    def __init__(self, key, salt=None):
        self.key_primary = self._key_expansion(key)
        
        # 安全参数配置
        self.rounds = 16
        self.block_size = 64  # 512-bit 块大小
        self.iv = os.urandom(16) if salt is None else salt[:16]
        
        # 子密钥初始化
        self.subkeys = self._generate_subkeys(self.key_primary)

    def _key_expansion(self, key):
        # 使用PBKDF2与SHA3-512进行密钥扩展
        salt = os.urandom(64)
        return hashlib.pbkdf2_hmac('sha3_512', key, salt, 500000, dklen=64)

    def _generate_subkeys(self, master_key):
        # 动态生成子密钥链
        subkeys = []
        current_seed = master_key
        for _ in range(self.rounds * 2):
            current_seed = hashlib.shake_256(current_seed).digest(64)
            subkeys.append(hashlib.sha3_512(current_seed).digest())
        return subkeys

    def _nonlinear_transform(self, data_block):
        # 非线性混淆层
        transformed = bytearray()
        for i in range(len(data_block)):
            transformed_byte = (data_block[i] ^ 0xAA) + i % 256
            transformed.append(transformed_byte % 256)
        return bytes(transformed)

    def _diffusion_layer(self, data_block):
        # AES-256扩散层
        cipher = AES.new(self.subkeys[0][:32], AES.MODE_CBC, self.iv)
        return cipher.encrypt(pad(data_block, AES.block_size))

    def _permutation(self, data_block):
        # 位级置换算法
        bits = ''.join(format(byte, '08b') for byte in data_block)
        permuted_bits = bits[-256:] + bits[:-256]  # 循环移位
        return bytes(int(permuted_bits[i:i+8], 2) for i in range(0, len(permuted_bits), 8))

    def encrypt(self, plaintext):
        # 预处理
        blocks = [plaintext[i:i+self.block_size] for i in range(0, len(plaintext), self.block_size)]
        
        # 多轮加密
        cipher_blocks = []
        for block_idx, block in enumerate(blocks):
            processed_block = block
            for round in range(self.rounds):
                # 非线性混淆
                processed_block = self._nonlinear_transform(processed_block)
                # AES扩散
                processed_block = self._diffusion_layer(processed_block)
                # 动态置换
                processed_block = self._permutation(processed_block)
            # 最终哈希绑定
            final_hash = hashlib.blake2b(processed_block, key=self.subkeys[-1][:64]).digest()
            cipher_blocks.append(final_hash + processed_block)
        return b''.join(cipher_blocks)


