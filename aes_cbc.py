# file: aes_cbc.py

class AES:
    def __init__(self, key: bytes) -> None:
        """AES-128-CBC实现，密钥必须为16字节"""
        if len(key) != 16:
            raise ValueError("密钥必须为16字节")
        self.key = key

        # AES S盒和逆S盒
        self.s_box = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

        self.inv_s_box = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]

        # 轮常数
        self.rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

        # 密钥扩展
        self.expanded_key = self.key_expansion(key)

    def key_expansion(self, key: bytes) -> list:
        """密钥扩展"""
        # 获取原始密钥长度，对于AES-128，key_size = 16
        key_size = len(key)

        # 将密钥转换为列表形式，便于后续操作
        expanded_key = list(key)

        # 扩展密钥到足够长度（AES-128需要176字节 = 11轮 × 16字节）
        # 4 * 4 * 11 = 176字节
        for i in range(key_size, 4 * 4 * 11):
            # 取前一个4字节作为临时变量
            temp = expanded_key[i - 4:i]

            # 每隔key_size个字节（即16字节）进行特殊处理
            if i % key_size == 0:
                # 字循环：将4字节循环左移一位
                # 例如 [a,b,c,d] -> [b,c,d,a]
                temp = temp[1:] + temp[:1]

                # 字节代换：使用AES S盒对每个字节进行替换
                temp = [self.s_box[b] for b in temp]

                # 轮常量异或：将第一个字节与轮常数异或
                # 轮常数随轮数递增，用于确保每轮密钥不同
                temp[0] ^= self.rcon[i // key_size - 1]

            # 将当前位置前key_size个字节与temp进行异或，扩展密钥
            # 这是AES密钥扩展的核心操作
            expanded_key.extend([expanded_key[i - key_size] ^ b for b in temp])

        # 返回扩展后的密钥列表（共176字节）
        return expanded_key

    def sub_bytes(self, state: list) -> list:
        """字节替换"""
        # 对状态矩阵中的每个字节应用AES S盒替换
        # S盒是一种非线性替换表，用于增加密码算法的复杂度
        # self.s_box 是预先定义的256字节替换表
        return [self.s_box[b] for b in state]

    def inv_sub_bytes(self, state: list) -> list:
        """逆字节替换"""
        # 对状态矩阵中的每个字节应用逆AES S盒替换
        # 在解密过程中使用，是sub_bytes的逆操作
        # self.inv_s_box 是预先定义的逆S盒替换表
        return [self.inv_s_box[b] for b in state]

    def shift_rows(self, state: list) -> list:
        """行移位"""
        # 创建一个16字节的结果数组，用于存储行移位后的状态
        result = [0] * 16

        # 第0行不变（偏移量为0）
        # 在4x4状态矩阵中，第0行的元素位置为 0, 4, 8, 12
        result[0] = state[0]  # 第0行第0列
        result[4] = state[4]  # 第0行第1列
        result[8] = state[8]  # 第0行第2列
        result[12] = state[12]  # 第0行第3列

        # 第1行左移1位（向左循环移动1个位置）
        # 原位置: 1, 5, 9, 13  ->  移位后位置: 1→5, 5→9, 9→13, 13→1
        result[1] = state[5]  # 原第1列移到第0列
        result[5] = state[9]  # 原第2列移到第1列
        result[9] = state[13]  # 原第3列移到第2列
        result[13] = state[1]  # 原第0列移到第3列

        # 第2行左移2位（向左循环移动2个位置）
        # 原位置: 2, 6, 10, 14  ->  移位后位置: 2→10, 6→14, 10→2, 14→6
        result[2] = state[10]  # 原第2列移到第0列
        result[6] = state[14]  # 原第3列移到第1列
        result[10] = state[2]  # 原第0列移到第2列
        result[14] = state[6]  # 原第1列移到第3列

        # 第3行左移3位（向左循环移动3个位置，等同于右移1位）
        # 原位置: 3, 7, 11, 15  ->  移位后位置: 3→7, 7→11, 11→15, 15→3
        result[3] = state[15]  # 原第3列移到第0列
        result[7] = state[3]  # 原第0列移到第1列
        result[11] = state[7]  # 原第1列移到第2列
        result[15] = state[11]  # 原第2列移到第3列

        # 返回行移位后的结果状态
        return result

    def inv_shift_rows(self, state: list) -> list:
        """逆行移位"""
        # 创建一个16字节的结果数组，用于存储逆行移位后的状态
        result = [0] * 16

        # 第0行不变（偏移量为0）- 与shift_rows中相同
        # 在4x4状态矩阵中，第0行的元素位置为 0, 4, 8, 12
        result[0] = state[0]  # 第0行第0列
        result[4] = state[4]  # 第0行第1列
        result[8] = state[8]  # 第0行第2列
        result[12] = state[12]  # 第0行第3列

        # 第1行右移1位（向右循环移动1个位置）- 与shift_rows中相反
        # 原位置: 1, 5, 9, 13  ->  移位后位置: 1←13, 5←1, 9←5, 13←9
        result[1] = state[13]  # 原第3列移到第0列
        result[5] = state[1]  # 原第0列移到第1列
        result[9] = state[5]  # 原第1列移到第2列
        result[13] = state[9]  # 原第2列移到第3列

        # 第2行右移2位（向右循环移动2个位置）- 与shift_rows中相反
        # 原位置: 2, 6, 10, 14  ->  移位后位置: 与左移2位相同（循环）
        result[2] = state[10]  # 原第2列保持在第0列（循环移位）
        result[6] = state[14]  # 原第3列移到第1列
        result[10] = state[2]  # 原第0列移到第2列
        result[14] = state[6]  # 原第1列移到第3列

        # 第3行右移3位（向右循环移动3个位置，等同于左移1位）- 与shift_rows中相反
        # 原位置: 3, 7, 11, 15  ->  移位后位置: 3←7, 7←11, 11←15, 15←3
        result[3] = state[7]  # 原第1列移到第0列
        result[7] = state[11]  # 原第2列移到第1列
        result[11] = state[15]  # 原第3列移到第2列
        result[15] = state[3]  # 原第0列移到第3列

        # 返回逆行移位后的结果状态
        return result

    def gmul(self, a: int, b: int) -> int:
        """伽罗瓦域乘法"""
        # 初始化结果为0
        p = 0

        # 执行8次迭代，对应于GF(2^8)域中的乘法运算
        for _ in range(8):
            # 如果b的最低位为1，则将a加到结果p中
            # 在GF(2^8)中，加法等同于异或运算
            if b & 1:
                p ^= a

            # 检查a的最高位是否为1（即第7位）
            hi_bit_set = a & 0x80

            # 将a左移1位
            a <<= 1

            # 如果a的最高位原来为1，左移后需要模GF(2^8)的不可约多项式
            # 0x1b 对应于多项式 x^8 + x^4 + x^3 + x + 1
            if hi_bit_set:
                a ^= 0x1b  # x^8 + x^4 + x^3 + x + 1

            # 将b右移1位，处理下一个位
            b >>= 1

        # 确保结果在字节范围内（0-255）
        return p & 0xff

    def mix_columns(self, state: list) -> list:
        """列混合"""
        # 创建一个16字节的结果数组，用于存储列混合后的状态
        result = [0] * 16

        # 对状态矩阵的每一列进行处理（共4列）
        for i in range(4):
            # 提取当前列的4个字节
            # state中按列优先存储：第i列的元素为 state[i*4], state[i*4+1], state[i*4+2], state[i*4+3]
            col = state[i * 4:(i + 1) * 4]

            # 对当前列应用AES标准的MixColumns变换矩阵：
            # [02 03 01 01]
            # [01 02 03 01]
            # [01 01 02 03]
            # [03 01 01 02]

            # 计算第0行结果：0x02 * col[0] ⊕ 0x03 * col[1] ⊕ 0x01 * col[2] ⊕ 0x01 * col[3]
            result[i * 4] = self.gmul(0x02, col[0]) ^ self.gmul(0x03, col[1]) ^ col[2] ^ col[3]

            # 计算第1行结果：0x01 * col[0] ⊕ 0x02 * col[1] ⊕ 0x03 * col[2] ⊕ 0x01 * col[3]
            result[i * 4 + 1] = col[0] ^ self.gmul(0x02, col[1]) ^ self.gmul(0x03, col[2]) ^ col[3]

            # 计算第2行结果：0x01 * col[0] ⊕ 0x01 * col[1] ⊕ 0x02 * col[2] ⊕ 0x03 * col[3]
            result[i * 4 + 2] = col[0] ^ col[1] ^ self.gmul(0x02, col[2]) ^ self.gmul(0x03, col[3])

            # 计算第3行结果：0x03 * col[0] ⊕ 0x01 * col[1] ⊕ 0x01 * col[2] ⊕ 0x02 * col[3]
            result[i * 4 + 3] = self.gmul(0x03, col[0]) ^ col[1] ^ col[2] ^ self.gmul(0x02, col[3])

        # 返回列混合后的结果状态
        return result

    def inv_mix_columns(self, state: list) -> list:
        """逆列混合"""
        # 创建一个16字节的结果数组，用于存储逆列混合后的状态
        result = [0] * 16

        # 对状态矩阵的每一列进行处理（共4列）
        for i in range(4):
            # 提取当前列的4个字节
            # state中按列优先存储：第i列的元素为 state[i*4], state[i*4+1], state[i*4+2], state[i*4+3]
            col = state[i * 4:(i + 1) * 4]

            # 对当前列应用AES标准的逆MixColumns变换矩阵：
            # [0e 0b 0d 09]
            # [09 0e 0b 0d]
            # [0d 09 0e 0b]
            # [0b 0d 09 0e]

            # 计算第0行结果：0x0e * col[0] ⊕ 0x0b * col[1] ⊕ 0x0d * col[2] ⊕ 0x09 * col[3]
            result[i * 4] = self.gmul(0x0e, col[0]) ^ self.gmul(0x0b, col[1]) ^ self.gmul(0x0d, col[2]) ^ self.gmul(
                0x09, col[3])

            # 计算第1行结果：0x09 * col[0] ⊕ 0x0e * col[1] ⊕ 0x0b * col[2] ⊕ 0x0d * col[3]
            result[i * 4 + 1] = self.gmul(0x09, col[0]) ^ self.gmul(0x0e, col[1]) ^ self.gmul(0x0b, col[2]) ^ self.gmul(
                0x0d, col[3])

            # 计算第2行结果：0x0d * col[0] ⊕ 0x09 * col[1] ⊕ 0x0e * col[2] ⊕ 0x0b * col[3]
            result[i * 4 + 2] = self.gmul(0x0d, col[0]) ^ self.gmul(0x09, col[1]) ^ self.gmul(0x0e, col[2]) ^ self.gmul(
                0x0b, col[3])

            # 计算第3行结果：0x0b * col[0] ⊕ 0x0d * col[1] ⊕ 0x09 * col[2] ⊕ 0x0e * col[3]
            result[i * 4 + 3] = self.gmul(0x0b, col[0]) ^ self.gmul(0x0d, col[1]) ^ self.gmul(0x09, col[2]) ^ self.gmul(
                0x0e, col[3])

        # 返回逆列混合后的结果状态
        return result

    def add_round_key(self, state: list, round_key: list) -> list:
        """轮密钥加"""
        # 对状态矩阵中的每个字节与对应的轮密钥字节进行异或运算
        # 这是AES算法中唯一使用密钥的步骤，提供了算法的混淆特性
        # 异或运算具有可逆性，加密和解密使用相同的操作
        return [state[i] ^ round_key[i] for i in range(16)]

    def encrypt_block(self, plaintext: bytes, iv: bytes) -> bytes:
        """加密一个16字节块（CBC模式）"""
        # 将明文转换为列表形式，便于后续操作
        state = list(plaintext)

        # CBC模式的第一步：与初始化向量(IV)异或
        # 这是CBC模式的核心特性，确保相同明文块产生不同密文块
        state = [state[i] ^ iv[i] for i in range(16)]

        # 初始轮：轮密钥加操作
        # 使用第一轮子密钥(0-15字节)与状态进行异或
        state = self.add_round_key(state, self.expanded_key[0:16])

        # 9轮主循环：执行标准的AES加密轮次
        # AES-128总共10轮，这里执行第1到第9轮
        for round_num in range(1, 10):
            # 字节替换：使用S盒对每个字节进行非线性替换
            state = self.sub_bytes(state)

            # 行移位：对状态矩阵的行进行循环移位
            state = self.shift_rows(state)

            # 列混合：对状态矩阵的列进行线性变换
            state = self.mix_columns(state)

            # 轮密钥加：与对应轮次的子密钥进行异或
            state = self.add_round_key(state, self.expanded_key[round_num * 16:(round_num + 1) * 16])

        # 最终轮：第10轮，与前面9轮不同，不执行列混合操作
        # 字节替换
        state = self.sub_bytes(state)

        # 行移位
        state = self.shift_rows(state)

        # 轮密钥加：使用最后一轮子密钥(160-175字节)
        state = self.add_round_key(state, self.expanded_key[160:176])

        # 将处理后的状态转换为字节串并返回
        return bytes(state)

    def decrypt_block(self, ciphertext: bytes, previous_block: bytes) -> bytes:
        """解密一个16字节块（CBC模式）"""
        # 将密文转换为列表形式，便于后续操作
        state = list(ciphertext)

        # 初始轮（逆最终轮）：执行解密的最后一轮变换
        # 注意解密顺序与加密顺序相反
        # 1. 轮密钥加：使用加密最后一轮的子密钥(160-175字节)
        state = self.add_round_key(state, self.expanded_key[160:176])

        # 2. 逆行移位：执行shift_rows的逆操作
        state = self.inv_shift_rows(state)

        # 3. 逆字节替换：执行sub_bytes的逆操作
        state = self.inv_sub_bytes(state)

        # 9轮主循环：执行解密的主要轮次（第9轮到第1轮）
        # 顺序与加密完全相反
        for round_num in range(9, 0, -1):
            # 1. 轮密钥加：使用对应轮次的子密钥
            state = self.add_round_key(state, self.expanded_key[round_num * 16:(round_num + 1) * 16])

            # 2. 逆列混合：执行mix_columns的逆操作
            state = self.inv_mix_columns(state)

            # 3. 逆行移位
            state = self.inv_shift_rows(state)

            # 4. 逆字节替换
            state = self.inv_sub_bytes(state)

        # 最终轮密钥加：解密的最后一轮变换
        # 使用加密第一轮的子密钥(0-15字节)
        state = self.add_round_key(state, self.expanded_key[0:16])

        # CBC模式处理：与前一个密文块（或IV）异或得到明文
        # 这是CBC模式解密的核心步骤
        state = [state[i] ^ previous_block[i] for i in range(16)]

        # 将处理后的状态转换为字节串并返回
        return bytes(state)

    def pkcs7_pad(self, data: bytes) -> bytes:
        """PKCS7填充"""
        # 计算需要填充的字节数
        # 如果数据长度不是16的倍数，则填充到下一个16字节边界
        # 填充的字节数 = 16 - (数据长度 % 16)
        pad_len = 16 - (len(data) % 16)
        # 在数据末尾添加pad_len个值为pad_len的字节
        # 例如：如果需要填充5个字节，则添加5个值为5的字节
        return data + bytes([pad_len] * pad_len)

    def pkcs7_unpad(self, data: bytes) -> bytes:
        """PKCS7去填充"""
        # 获取最后一个字节的值，该值表示填充的字节数
        pad_len = data[-1]
        # 去除末尾的pad_len个填充字节
        return data[:-pad_len]

    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        """
            加密数据（CBC模式）
            CBC模式特点：
            第一块明文与IV异或后再加密
            后续块明文与前一块密文异或后再加密
            相同明文块会产生不同密文块，增强安全性
        """
        # 如果输入是字符串，则将其编码为UTF-8字节串
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # 对明文进行PKCS7填充，确保数据长度是16字节的倍数
        padded_data = self.pkcs7_pad(plaintext)

        # 初始化密文结果和前一个密文块（初始为IV）
        ciphertext = b''  # 存储最终的密文结果
        previous_block = iv  # CBC模式中，第一个块与IV异或

        # 按16字节分块处理填充后的数据
        for i in range(0, len(padded_data), 16):
            # 提取当前16字节数据块
            block = padded_data[i:i + 16]

            # 使用AES加密当前块，CBC模式下需要与previous_block异或
            encrypted_block = self.encrypt_block(block, previous_block)

            # 将加密后的块添加到密文结果中
            ciphertext += encrypted_block

            # 更新previous_block为当前加密块，用于下一个块的CBC操作
            previous_block = encrypted_block

        # 返回完整的密文
        return ciphertext

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
            解密数据（CBC模式）
            CBC模式解密特点：
            第一块密文解密后与IV异或得到明文
            后续块密文解密后与前一块密文异或得到明文
            解密过程可以并行处理，但异或操作需要按顺序进行
        """
        # 初始化明文结果和前一个密文块（初始为IV）
        plaintext = b''  # 存储最终的明文结果
        previous_block = iv  # CBC模式中，第一个块需要与IV异或恢复明文

        # 按16字节分块处理密文数据
        for i in range(0, len(ciphertext), 16):
            # 提取当前16字节密文块
            block = ciphertext[i:i + 16]

            # 使用AES解密当前块，CBC模式下需要前一个密文块用于异或操作
            decrypted_block = self.decrypt_block(block, previous_block)

            # 将解密后的块添加到明文结果中
            plaintext += decrypted_block

            # 更新previous_block为当前密文块，用于下一个块的CBC操作
            previous_block = block

        # 对解密后的数据进行去填充操作，恢复原始数据
        return self.pkcs7_unpad(plaintext)


def hex_to_bytes(hex_string: str) -> bytes:
    """将十六进制字符串转换为字节串"""
    # 使用Python内置的bytes.fromhex()方法将十六进制字符串转换为字节串
    # 例如: "48656c6c6f" -> b'Hello'
    return bytes.fromhex(hex_string)

def bytes_to_hex(byte_data: bytes) -> str:
    """将字节串转换为十六进制字符串"""
    # 使用bytes对象的hex()方法将字节串转换为十六进制字符串
    # 例如: b'Hello' -> "48656c6c6f"
    return byte_data.hex()
