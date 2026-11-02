import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import os
import numpy as np
import random
import string
from image_crypto import encrypt_image, decrypt_image, validate_key


class ImageCryptoUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES图像加密解密工具")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)

        # 设置中文字体
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("SimHei", 10))
        self.style.configure("TButton", font=("SimHei", 10))
        self.style.configure("TEntry", font=("SimHei", 10))
        self.style.configure("TRadiobutton", font=("SimHei", 10))

        # 图像对象缓存
        self.original_img = None
        self.encrypted_preview_img = None
        self.decrypted_img = None

        # 选择操作变量
        self.operation_var = tk.StringVar(value="encrypt")

        # 路径和密钥变量
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.key_var = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 顶部控制区
        control_frame = ttk.LabelFrame(main_frame, text="操作控制", padding="10")
        control_frame.pack(fill=tk.X, pady=5)

        # 操作选择
        ttk.Label(control_frame, text="选择操作:").grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
        encrypt_radio = ttk.Radiobutton(
            control_frame, text="加密",
            variable=self.operation_var, value="encrypt",
            command=self.update_output_suffix
        )
        encrypt_radio.grid(row=0, column=1, sticky=tk.W, pady=5)
        decrypt_radio = ttk.Radiobutton(
            control_frame, text="解密",
            variable=self.operation_var, value="decrypt",
            command=self.update_output_suffix
        )
        decrypt_radio.grid(row=0, column=2, sticky=tk.W, pady=5, padx=10)

        # 密钥输入区（新增随机生成按钮）
        key_frame = ttk.Frame(control_frame)
        key_frame.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=5)

        ttk.Label(key_frame, text="密钥 (16字符或32十六进制字符):").pack(side=tk.LEFT, padx=5)
        key_entry = ttk.Entry(key_frame, textvariable=self.key_var, width=50, show="*")
        key_entry.pack(side=tk.LEFT, padx=5)

        # 新增密钥生成按钮
        ttk.Button(
            key_frame, text="随机生成",
            command=self.generate_random_key
        ).pack(side=tk.LEFT, padx=5)

        # 密钥显示切换（明文/密文）
        self.show_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            key_frame, text="显示密钥",
            variable=self.show_key_var,
            command=lambda: key_entry.config(show="" if self.show_key_var.get() else "*")
        ).pack(side=tk.LEFT, padx=5)

        # 输入文件
        ttk.Label(control_frame, text="输入文件:").grid(row=2, column=0, sticky=tk.W, pady=5, padx=5)
        ttk.Entry(control_frame, textvariable=self.input_path, width=50).grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Button(control_frame, text="浏览...", command=self.browse_input).grid(row=2, column=2, pady=5, padx=10)

        # 输出文件
        ttk.Label(control_frame, text="输出文件:").grid(row=3, column=0, sticky=tk.W, pady=5, padx=5)
        ttk.Entry(control_frame, textvariable=self.output_path, width=50).grid(row=3, column=1, sticky=tk.W, pady=5)
        ttk.Button(control_frame, text="浏览...", command=self.browse_output).grid(row=3, column=2, pady=5, padx=10)

        # 状态和按钮区
        status_frame = ttk.Frame(control_frame)
        status_frame.grid(row=4, column=0, columnspan=3, pady=10)

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_frame, textvariable=self.status_var, foreground="blue").pack(side=tk.LEFT, padx=20)

        ttk.Button(
            status_frame, text="执行", command=self.perform_operation, width=15
        ).pack(side=tk.LEFT, padx=10)

        ttk.Button(
            status_frame, text="清除", command=self.clear_fields, width=15
        ).pack(side=tk.LEFT, padx=10)

        ttk.Button(
            status_frame, text="退出", command=self.root.quit, width=15
        ).pack(side=tk.LEFT, padx=10)

        # 图像预览区
        preview_frame = ttk.LabelFrame(main_frame, text="图像预览", padding="10")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 原始图像预览
        self.original_frame = ttk.LabelFrame(preview_frame, text="原始图像", padding="5")
        self.original_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.original_label = ttk.Label(self.original_frame, text="未选择图像")
        self.original_label.pack(fill=tk.BOTH, expand=True)

        # 加密图像预览
        self.encrypted_frame = ttk.LabelFrame(preview_frame, text="加密后图像", padding="5")
        self.encrypted_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.encrypted_label = ttk.Label(self.encrypted_frame, text="未加密")
        self.encrypted_label.pack(fill=tk.BOTH, expand=True)

        # 解密图像预览
        self.decrypted_frame = ttk.LabelFrame(preview_frame, text="解密后图像", padding="5")
        self.decrypted_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.decrypted_label = ttk.Label(self.decrypted_frame, text="未解密")
        self.decrypted_label.pack(fill=tk.BOTH, expand=True)

        # 调整列宽
        control_frame.columnconfigure(1, weight=1)

    def generate_random_key(self):
        """生成随机16字符密钥（支持字母、数字、符号）"""
        # 密钥字符集：大小写字母 + 数字 + 常见符号
        characters = string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?`~'
        # 随机选择16个字符
        random_key = ''.join(random.choice(characters) for _ in range(16))
        # 设置到输入框
        self.key_var.set(random_key)
        # 提示用户保存密钥
        messagebox.showinfo(
            "密钥生成",
            f"随机密钥已生成：\n{random_key}\n\n请妥善保存此密钥用于解密！"
        )

    def browse_input(self):
        """浏览输入文件并预览原始图像"""
        if self.operation_var.get() == "encrypt":
            file_types = [("图像文件", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"), ("所有文件", "*.*")]
            title = "选择要加密的图像"
        else:
            file_types = [("加密文件", "*.enc"), ("所有文件", "*.*")]
            title = "选择要解密的文件"

        filename = filedialog.askopenfilename(
            title=title,
            filetypes=file_types
        )

        if filename:
            self.input_path.set(filename)
            self.update_output_suffix()

            # 加密操作时预览原始图像
            if self.operation_var.get() == "encrypt":
                try:
                    img = Image.open(filename)
                    self.original_img = img.copy()
                    self.show_image(img, self.original_label)
                except Exception as e:
                    messagebox.showerror("错误", f"无法预览图像: {str(e)}")

    def browse_output(self):
        """浏览输出文件"""
        if self.operation_var.get() == "encrypt":
            default_ext = ".enc"
            file_types = [("加密文件", f"*{default_ext}"), ("所有文件", "*.*")]
            title = "保存加密文件"
        else:
            default_ext = ".png"
            file_types = [("PNG图像", "*.png"), ("JPG图像", "*.jpg"), ("所有文件", "*.*")]
            title = "保存解密图像"

        filename = filedialog.asksaveasfilename(
            title=title,
            defaultextension=default_ext,
            filetypes=file_types
        )

        if filename:
            self.output_path.set(filename)

    def update_output_suffix(self):
        """根据操作类型更新输出文件后缀"""
        input_path = self.input_path.get()
        if not input_path:
            return

        if self.operation_var.get() == "encrypt":
            name, ext = os.path.splitext(input_path)
            self.output_path.set(f"{name}.enc")
        else:
            name, ext = os.path.splitext(input_path)
            if ext.lower() == ".enc":
                self.output_path.set(f"{name}.png")
            else:
                self.output_path.set(f"{input_path}.png")

    def clear_fields(self):
        """清除所有输入字段和图像预览"""
        self.input_path.set("")
        self.output_path.set("")
        self.key_var.set("")
        self.status_var.set("就绪")

        # 清空图像预览
        self.original_label.config(image="", text="未选择图像")
        self.encrypted_label.config(image="", text="未加密")
        self.decrypted_label.config(image="", text="未解密")
        self.original_img = None
        self.encrypted_preview_img = None
        self.decrypted_img = None

    def show_image(self, img, label):
        """在指定标签中显示图像（自动缩放）"""
        label_width = label.winfo_width() if label.winfo_width() > 100 else 300
        label_height = label.winfo_height() if label.winfo_height() > 100 else 200

        # 兼容不同版本的PIL/Pillow
        try:
            # 新版本PIL/Pillow
            img.thumbnail((label_width, label_height), Image.Resampling.LANCZOS)
        except AttributeError:
            # 旧版本PIL/Pillow
            img.thumbnail((label_width, label_height), Image.LANCZOS)
        
        tk_img = ImageTk.PhotoImage(img)

        label.config(image=tk_img, text="")
        label.image = tk_img

    def perform_operation(self):
        """执行加密或解密操作并更新图像预览"""
        input_path = self.input_path.get()
        output_path = self.output_path.get()
        key_input = self.key_var.get()

        # 验证输入
        if not input_path:
            messagebox.showerror("错误", "请选择输入文件")
            return

        if not output_path:
            messagebox.showerror("错误", "请选择输出文件")
            return

        if not key_input:
            messagebox.showerror("错误", "请输入密钥或点击'随机生成'")
            return

        # 验证密钥
        valid, key = validate_key(key_input)
        if not valid:
            messagebox.showerror("错误", key)
            return

        # 检查输入文件是否存在
        if not os.path.exists(input_path):
            messagebox.showerror("错误", "输入文件不存在")
            return

        # 执行操作
        self.status_var.set("正在处理...")
        self.root.update()

        try:
            if self.operation_var.get() == "encrypt":
                # 加密操作
                success, msg, original_img = encrypt_image(input_path, key, output_path)
                if success:
                    self.show_image(original_img, self.original_label)

                    # 生成加密预览图
                    with open(output_path, 'rb') as f:
                        iv = f.r



                        ead(16)
                        height = int.from_bytes(f.read(4), byteorder='big')
                        width = int.from_bytes(f.read(4), byteorder='big')
                        channels = int.from_bytes(f.read(1), byteorder='big')
                        encrypted_bytes = f.read()

                    pixel_count = height * width * channels
                    encrypted_array = np.frombuffer(encrypted_bytes[:pixel_count], dtype=np.uint8)
                    encrypted_array = encrypted_array[:pixel_count].reshape((height, width, channels))
                    encrypted_img = Image.fromarray(encrypted_array)
                    self.show_image(encrypted_img, self.encrypted_label)
                    self.decrypted_label.config(image="", text="未解密")

            else:
                # 解密操作
                success, msg, decrypted_img, encrypted_img = decrypt_image(input_path, key, output_path)
                if success:
                    self.show_image(decrypted_img, self.decrypted_label)
                    self.show_image(encrypted_img, self.encrypted_label)

                    # 尝试显示原始图像
                    original_path = os.path.splitext(input_path)[0]
                    if os.path.exists(original_path):
                        try:
                            orig_img = Image.open(original_path)
                            self.show_image(orig_img, self.original_label)
                        except:
                            pass

            self.status_var.set(msg)
            if success:
                messagebox.showinfo("成功", msg)
            else:
                messagebox.showerror("失败", msg)

        except Exception as e:
            error_msg = f"操作失败: {str(e)}"
            self.status_var.set(error_msg)
            messagebox.showerror("错误", error_msg)


if __name__ == "__main__":
    root = tk.Tk()
    app = ImageCryptoUI(root)
    root.mainloop()