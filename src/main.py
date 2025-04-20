import os
import random
import secrets
import hashlib
import base64
import zlib
from tkinter import Tk, Label, Frame, font, messagebox, filedialog, Button
from typing import Callable, List, Tuple
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# ======================== 加密算法池 ========================
class ChaosEncryptor:
    """提供多种高强度加密算法的集合"""
    
    @staticmethod
    def aes_encrypt(data: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
        """AES-256-CBC 加密"""
        if key is None:
            key = secrets.token_bytes(32)  # 256-bit key
        iv = secrets.token_bytes(16)       # 128-bit IV
        
        # 填充数据
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # 加密
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # 返回加密数据和密钥信息
        return encrypted_data, iv + key
    
    @staticmethod
    def chacha20_encrypt(data: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
        """ChaCha20 加密"""
        if key is None:
            key = secrets.token_bytes(32)  # 256-bit key
        nonce = secrets.token_bytes(16)    # 128-bit nonce
        
        # 加密
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # 返回加密数据和密钥信息
        return encrypted_data, nonce + key
    
    @staticmethod
    def camellia_encrypt(data: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
        """Camellia 加密"""
        if key is None:
            key = secrets.token_bytes(32)  # 256-bit key
        iv = secrets.token_bytes(16)       # 128-bit IV
        
        # 填充数据
        padder = padding.PKCS7(algorithms.Camellia.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # 加密
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # 返回加密数据和密钥信息
        return encrypted_data, iv + key
    
    @staticmethod
    def serpent_like_encrypt(data: bytes) -> Tuple[bytes, bytes]:
        """Serpent-like 加密 (使用AES模拟)"""
        key = secrets.token_bytes(32)      # 256-bit key
        iv = secrets.token_bytes(16)       # 128-bit IV
        
        # 填充数据
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # 使用AES-CTR模式模拟
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # 额外混淆
        encrypted_data = ChaosEncryptor.xor_with_key(encrypted_data, hashlib.sha256(key).digest())
        
        # 返回加密数据和密钥信息
        return encrypted_data, iv + key
    
    @staticmethod
    def blowfish_like_encrypt(data: bytes) -> Tuple[bytes, bytes]:
        """Blowfish-like 加密"""
        key = secrets.token_bytes(32)      # 使用长密钥
        iv = secrets.token_bytes(8)        # 64-bit IV
        
        # 使用AES进行模拟
        full_iv = iv + iv                  # 扩展到16字节
        cipher = Cipher(algorithms.AES(key), modes.OFB(full_iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # 返回加密数据和密钥信息
        return encrypted_data, iv + key
    
    @staticmethod
    def twofish_like_encrypt(data: bytes) -> Tuple[bytes, bytes]:
        """Twofish-like 加密 (使用AES + 额外操作模拟)"""
        key = secrets.token_bytes(32)      # 256-bit key
        iv = secrets.token_bytes(16)       # 128-bit IV
        
        # 填充数据
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # 使用AES-CFB模式
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # 额外混淆 - 使用密钥派生的另一个值
        derived_key = hashlib.sha512(key).digest()[:32]
        encrypted_data = ChaosEncryptor.xor_with_key(encrypted_data, derived_key)
        
        # 返回加密数据和密钥信息
        return encrypted_data, iv + key + derived_key
    
    @staticmethod
    def xor_with_key(data: bytes, key: bytes) -> bytes:
        """使用重复密钥进行XOR操作"""
        key_len = len(key)
        return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])
    
    @staticmethod
    def strong_xor_encrypt(data: bytes) -> Tuple[bytes, bytes]:
        """增强型XOR加密 - 使用随机密钥"""
        # 生成与数据等长的随机密钥
        key = secrets.token_bytes(len(data))
        encrypted = bytes([data[i] ^ key[i] for i in range(len(data))])
        return encrypted, key
    
    @staticmethod
    def byte_shuffle(data: bytes, seed: int = None) -> Tuple[bytes, bytes]:
        """字节级洗牌 - 可用于最终混淆"""
        if seed is None:
            seed_bytes = secrets.token_bytes(4)
            seed = int.from_bytes(seed_bytes, byteorder='big')
        else:
            seed_bytes = seed.to_bytes(4, byteorder='big')
            
        # 创建索引列表
        indices = list(range(len(data)))
        # 使用确定性种子设置随机状态
        r = random.Random(seed)
        r.shuffle(indices)
        
        # 按照洗牌后的索引重排字节
        result = bytes([data[indices[i]] for i in range(len(data))])
        return result, seed_bytes
    
    @staticmethod
    def compress_then_encrypt(data: bytes) -> Tuple[bytes, bytes]:
        """先压缩再加密 - 用于较大文件"""
        # 压缩数据
        compressed = zlib.compress(data, level=9)
        # 生成随机密钥并加密
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        
        # 使用AES-GCM模式
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(compressed) + encryptor.finalize()
        
        # 添加认证标签
        encrypted += encryptor.tag
        
        # 返回加密数据和密钥信息
        return encrypted, iv + key
    
    # 获取所有高强度加密算法
    @classmethod
    def get_strong_encryption_algorithms(cls) -> List[Tuple[str, Callable]]:
        return [
            ("AES-256-CBC", cls.aes_encrypt),
            ("ChaCha20", cls.chacha20_encrypt),
            ("Camellia-256", cls.camellia_encrypt),
            ("Serpent模拟", cls.serpent_like_encrypt),
            ("Blowfish模拟", cls.blowfish_like_encrypt),
            ("Twofish模拟", cls.twofish_like_encrypt),
            ("强化XOR", cls.strong_xor_encrypt),
            ("压缩加密", cls.compress_then_encrypt)
        ]
    
    # 获取附加混淆算法
    @classmethod
    def get_obfuscation_algorithms(cls) -> List[Tuple[str, Callable]]:
        return [
            ("字节洗牌", cls.byte_shuffle)
        ]

# ======================== 多层加密逻辑 ========================
def chaos_encrypt(data: bytes, min_layers: int = 2, max_layers: int = 4) -> Tuple[bytes, List[str]]:
    """
    混沌多层加密: 随机选择多个强加密算法串联加密
    
    Args:
        data: 输入数据
        min_layers: 最小加密层数
        max_layers: 最大加密层数
        
    Returns:
        (加密后数据, 使用的算法列表)
    """
    # 获取所有可用的加密算法
    encryption_algos = ChaosEncryptor.get_strong_encryption_algorithms()
    obfuscation_algos = ChaosEncryptor.get_obfuscation_algorithms()
    
    # 随机选择算法数量
    num_layers = random.randint(min_layers, max_layers)
    selected_algos = random.sample(encryption_algos, k=min(num_layers, len(encryption_algos)))
    
    # 总是添加一个混淆算法
    selected_algos.append(random.choice(obfuscation_algos))
    
    # 随机打乱算法顺序
    random.shuffle(selected_algos)
    
    encrypted_data = data
    used_algos = []
    all_keys = bytearray()
    
    # 应用选中的算法
    for algo_name, algo_func in selected_algos:
        try:
            result = algo_func(encrypted_data)
            if isinstance(result, tuple) and len(result) >= 2:
                encrypted_data, key_info = result
                # 将密钥信息附加到全局密钥中
                all_keys.extend(key_info)
            else:
                encrypted_data = result
            used_algos.append(algo_name)
        except Exception as e:
            print(f"算法 {algo_name} 执行失败: {str(e)}")
            pass
    
    # 最后应用SHA-256生成密钥指纹
    key_fingerprint = hashlib.sha256(all_keys).digest()
    
    # 将密钥指纹与加密数据拼接，然后销毁所有密钥
    final_data = key_fingerprint + encrypted_data
    del all_keys
    
    return final_data, used_algos


# ======================== DOS风格UI ========================
class DOSEncryptorUI:
    """DOS风格的加密工具UI"""
    
    def __init__(self):
        self.root = Tk()
        self.root.title("UntitleEncryptor v2.0")
        self.root.geometry("600x400")
        self.root.configure(bg="#000080")  # DOS蓝色背景
        
        # 尝试设置等宽字体
        available_fonts = font.families()
        mono_fonts = ["Terminal", "Consolas", "Courier New", "Courier", "Fixedsys"]
        selected_font = next((f for f in mono_fonts if f in available_fonts), "TkFixedFont")
        
        self.mono_font = font.Font(family=selected_font, size=10)
        
        # 标题
        title_frame = Frame(self.root, bg="#000080", pady=10)
        title_frame.pack(fill="x")
        
        Label(title_frame,
             text="【UntitleEncryptor v2.0】",
             font=(selected_font, 14, "bold"),
             bg="#000080",
             fg="#FFFFFF").pack()
        
        # 主界面
        self.frame = Frame(self.root, bg="#000080", padx=20)
        self.frame.pack(expand=True, fill="both")
        
        Label(self.frame,
             text="请选择要加密的文件:",
             font=self.mono_font,
             bg="#000080",
             fg="#FFFFFF").pack(anchor="w", pady=(20, 5))
        
        # 文件信息
        self.file_info = Label(self.frame,
                          text="未选择文件",
                          font=self.mono_font,
                          bg="#000080",
                          fg="#AAAAAA",
                          justify="left")
        self.file_info.pack(anchor="w", pady=5)
        
        # 状态信息
        self.status = Label(self.frame,
                          text="准备就绪...",
                          font=self.mono_font,
                          bg="#000080",
                          fg="#00FF00")
        self.status.pack(anchor="w", pady=5)
        
        # 算法信息
        self.algo_info = Label(self.frame,
                          text="",
                          font=self.mono_font,
                          bg="#000080",
                          fg="#FFFF00",
                          justify="left")
        self.algo_info.pack(anchor="w", pady=5)
        
        # 按钮容器
        btn_frame = Frame(self.frame, bg="#000080")
        btn_frame.pack(anchor="w", pady=20)
        
        # 添加按钮
        self.select_btn = Button(btn_frame,
                              text="选择文件",
                              font=self.mono_font,
                              bg="#0000AA",
                              fg="#FFFFFF",
                              relief="raised",
                              command=self.select_file)
        self.select_btn.pack(side="left", padx=5)
        
        self.encrypt_btn = Button(btn_frame,
                              text="加密文件",
                              font=self.mono_font,
                              bg="#0000AA",
                              fg="#FFFFFF",
                              relief="raised",
                              state="disabled",
                              command=self.confirm_encrypt)
        self.encrypt_btn.pack(side="left", padx=5)
        
        # 警告标签
        self.warning_label = Label(self.frame,
                           text="",
                           font=(selected_font, 9),
                           bg="#000080",
                           fg="#FF5555",
                           justify="left")
        self.warning_label.pack(anchor="w", pady=5)
        
        # 版权信息
        footer = Label(self.root,
                       text="MIT © 2025 Rubisco0326",
                       font=(selected_font, 10),
                       bg="#000080",
                       fg="#AAAAAA")
        footer.pack(side="bottom", pady=10)
        
        # 文件路径
        self.selected_file = None
    
    def select_file(self):
        """选择文件对话框"""
        filepath = filedialog.askopenfilename(
            title="选择要加密的文件",
            filetypes=[("所有文件", "*.*")]
        )
        
        if filepath:
            self.selected_file = filepath
            file_size = os.path.getsize(filepath)
            file_name = os.path.basename(filepath)
            
            self.file_info.config(
                text=f"已选择: {file_name}\n"
                     f"大小: {self._format_size(file_size)}"
            )
            self.status.config(text='文件已就绪，点击"加密文件"开始加密')
            self.encrypt_btn.config(state="normal")
            self.warning_label.config(
                text="警告: 加密后文件无法恢复！"
            )
    
    def confirm_encrypt(self):
        """确认加密操作"""
        if not self.selected_file:
            return
        
        result = messagebox.askquestion(
            "确认不可逆加密", 
            "警告: 此操作将使用多层加密算法加密您的文件，并销毁所有密钥！\n"
            "加密后的文件将无法被解密或恢复！\n\n"
            "您确定要继续吗？",
            icon='warning'
        )
        
        if result == 'yes':
            self.encrypt_file()
    
    def encrypt_file(self):
        """加密选定的文件"""
        if not self.selected_file:
            return
        
        try:
            self.status.config(text="正在加密...")
            self.algo_info.config(text="")
            self.root.update()
            
            # 读取文件
            with open(self.selected_file, 'rb') as f:
                original_data = f.read()
                original_size = len(original_data)
            
            # 应用多层加密
            encrypted_data, used_algos = chaos_encrypt(original_data, min_layers=2, max_layers=5)
            
            # 保存为.atlas文件
            filename = Path(self.selected_file).stem
            output_path = Path(f"{filename}.atlas")
            
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.algo_info.config(
                text=f"使用的加密算法:\n" + 
                     "\n".join(f"- {algo}" for algo in used_algos) + 
                     "\n所有加密密钥已被销毁，加密成功！"
            )
            
            self.status.config(text=f"加密完成! 保存为: {output_path}")
            messagebox.showinfo(
                "加密成功", 
                f"文件已加密并保存为:\n{output_path}\n\n"
                f"所有加密密钥已被销毁，加密成功！"
            )
            
        except Exception as e:
            self.status.config(text=f"加密失败: {str(e)}")
            messagebox.showerror("错误", f"加密过程中发生错误:\n{str(e)}")
    
    @staticmethod
    def _format_size(size_bytes):
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024 or unit == 'GB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
    
    def run(self):
        """运行UI主循环"""
        # 窗口居中
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        self.root.mainloop()


# ======================== 主程序 ========================
if __name__ == "__main__":
    try:
        app = DOSEncryptorUI()
        app.run()
    except Exception as e:
        messagebox.showerror("严重错误", f"程序无法启动:\n{str(e)}")