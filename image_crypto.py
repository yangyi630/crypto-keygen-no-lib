import numpy as np
from PIL import Image
import os
from aes_cbc import AES, hex_to_bytes, bytes_to_hex
import random


def generate_iv():
    """生成16字节的随机初始向量IV"""
    return bytes([random.randint(0, 255) for _ in range(16)])


def encrypt_image(image_path, key, output_path):
    """加密图像文件"""
    try:
        # 打开图像并转换为RGB模式
        img = Image.open(image_path)
        if img.mode == 'RGBA':
            img = img.convert('RGB')
        img_array = np.array(img)
        height, width, channels = img_array.shape
        # 生成IV并保存
        iv = generate_iv()
        # 准备AES加密器
        aes = AES(key)
        # 展平图像数组并转换为字节
        flat_array = img_array.flatten()
        image_bytes = flat_array.tobytes()
        # 加密
        encrypted_bytes = aes.encrypt(image_bytes, iv)
        #AES——279
        # 保存加密数据（IV + 加密数据 + 图像信息）
        with open(output_path, 'wb') as f:
            # 写入IV
            f.write(iv)
            # 写入图像尺寸和通道数
            f.write(height.to_bytes(4, byteorder='big'))
            f.write(width.to_bytes(4, byteorder='big'))
            f.write(channels.to_bytes(1, byteorder='big'))
            # 写入加密数据
            f.write(encrypted_bytes)
        return True, "图像加密成功", img  # 新增返回原始图像对象
    except Exception as e:
        return False, f"加密失败: {str(e)}", None


def decrypt_image(encrypted_path, key, output_path):
    try:
        # 读取加密数据
        with open(encrypted_path, 'rb') as f:
            # 读取IV
            iv = f.read(16)
            # 读取图像尺寸和通道数
            height = int.from_bytes(f.read(4), byteorder='big')
            width = int.from_bytes(f.read(4), byteorder='big')
            channels = int.from_bytes(f.read(1), byteorder='big')
            # 读取加密数据
            encrypted_bytes = f.read()
        # 准备AES解密器
        aes = AES(key)
        # 解密
        decrypted_bytes = aes.decrypt(encrypted_bytes, iv)
        #AES--320
        # 转换回图像数组
        pixel_count = height * width * channels
        flat_array = np.frombuffer(decrypted_bytes, dtype=np.uint8)
        # 确保数组长度正确
        if len(flat_array) < pixel_count:
            return False, "解密数据不完整，无法恢复图像", None
        flat_array = flat_array[:pixel_count]
        img_array = flat_array.reshape((height, width, channels))
        # 保存解密后的图像
        img = Image.fromarray(img_array)
        img.save(output_path)
        # 生成加密后的"图像"（实际是乱码像素，用于预览）
        encrypted_array = np.frombuffer(encrypted_bytes[:pixel_count], dtype=np.uint8)
        encrypted_array = encrypted_array[:pixel_count].reshape((height, width, channels))
        encrypted_img = Image.fromarray(encrypted_array)
        return True, "图像解密成功", img, encrypted_img  # 返回解密图像和加密预览图
    except Exception as e:
        return False, f"解密失败: {str(e)}", None, None


def validate_key(key_input):
    """验证密钥格式并转换为16字节密钥"""
    try:
        if len(key_input) == 16:
            return True, key_input.encode('utf-8')
        elif len(key_input) == 32:
            return True, hex_to_bytes(key_input)
        else:
            return False, "密钥长度不正确，请输入16个字符或32个十六进制字符"
    except ValueError:
        return False, "密钥格式错误，请输入有效的十六进制字符串（如果是十六进制形式）"