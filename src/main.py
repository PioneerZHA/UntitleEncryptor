import os
import random
import secrets
import hashlib
import base64
import zlib
import threading
import time
from tkinter import Tk, Label, Frame, font, messagebox, filedialog, Button
from tkinter import ttk  # 正确导入ttk
from typing import Callable, List, Tuple, Dict, Any
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from io import BytesIO

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
    def xor_with_key(data: bytes, key: bytes) -> bytes:
        """使用重复密钥进行XOR操作 - 高效实现"""
        key_len = len(key)
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ key[i % key_len]
        return bytes(result)
    
    @staticmethod
    def strong_xor_encrypt(data: bytes) -> Tuple[bytes, bytes]:
        """增强型XOR加密 - 使用随机密钥"""
        # 生成随机密钥 (对大文件使用较短密钥)
        if len(data) > 1024*1024:  # 如果大于1MB
            key_size = 1024  # 使用1KB密钥
        else:
            key_size = min(len(data), 16384)  # 最大16KB密钥
            
        key = secrets.token_bytes(key_size)
        encrypted = ChaosEncryptor.xor_with_key(data, key)
        return encrypted, key
    
    @staticmethod
    def byte_shuffle(data: bytes, seed: int = None) -> Tuple[bytes, bytes]:
        """字节级洗牌 - 分块处理，适合大文件"""
        if seed is None:
            seed_bytes = secrets.token_bytes(4)
            seed = int.from_bytes(seed_bytes, byteorder='big')
        else:
            seed_bytes = seed.to_bytes(4, byteorder='big')
        
        # 对于大文件，使用分块洗牌
        if len(data) > 1024*1024:  # 1MB以上使用分块
            block_size = 1024*1024  # 1MB块
            result = bytearray()
            
            # 处理每个块
            for i in range(0, len(data), block_size):
                block = data[i:i+block_size]
                # 创建索引列表
                indices = list(range(len(block)))
                # 使用确定性种子设置随机状态
                r = random.Random(seed + i)  # 每块使用不同种子
                r.shuffle(indices)
                
                # 按照洗牌后的索引重排字节
                shuffled_block = bytes([block[indices[j]] for j in range(len(block))])
                result.extend(shuffled_block)
                
            return bytes(result), seed_bytes
        else:
            # 小文件直接洗牌
            indices = list(range(len(data)))
            r = random.Random(seed)
            r.shuffle(indices)
            
            # 按照洗牌后的索引重排字节
            result = bytes([data[indices[i]] for i in range(len(data))])
            return result, seed_bytes
    
    @staticmethod
    def compress_then_encrypt(data: bytes) -> Tuple[bytes, bytes]:
        """先压缩再加密 - 用于较大文件"""
        # 只有可能被压缩的数据才尝试压缩
        if len(data) > 512:  # 太小的文件不值得压缩
            try:
                compressed = zlib.compress(data, level=1)  # 对大文件使用低压缩级别
                # 如果压缩后更小，才使用压缩数据
                if len(compressed) < len(data):
                    data = compressed
            except:
                pass  # 压缩失败，使用原始数据
        
        # 生成随机密钥并加密
        key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        
        # 使用AES-CTR模式 (流密码模式，速度更快)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        
        # 返回加密数据和密钥信息
        return encrypted, iv + key
    
    # 获取所有高效加密算法，适合大文件
    @classmethod
    def get_efficient_algorithms(cls) -> List[Tuple[str, Callable]]:
        return [
            ("强化XOR", cls.strong_xor_encrypt),
            ("压缩加密", cls.compress_then_encrypt),
            ("ChaCha20", cls.chacha20_encrypt),
            ("AES-256", cls.aes_encrypt)
        ]
    
    # 获取附加混淆算法
    @classmethod
    def get_obfuscation_algorithms(cls) -> List[Tuple[str, Callable]]:
        return [
            ("字节洗牌", cls.byte_shuffle)
        ]

# ======================== 分块加密处理 ========================
class ChunkProcessor:
    """分块处理器，用于高效处理大文件"""
    
    CHUNK_SIZE = 4 * 1024 * 1024  # 4MB块
    
    @staticmethod
    def process_file_in_chunks(input_path: str, output_path: str, 
                              callback: Callable[[bytes], bytes], 
                              progress_callback: Callable[[float], None] = None):
        """
        分块处理文件
        
        Args:
            input_path: 输入文件路径
            output_path: 输出文件路径
            callback: 处理函数，接受一个字节块，返回处理后的字节块
            progress_callback: 进度回调函数，接受一个0-1之间的浮点数表示进度
        """
        file_size = os.path.getsize(input_path)
        processed_size = 0
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            while True:
                chunk = infile.read(ChunkProcessor.CHUNK_SIZE)
                if not chunk:
                    break
                
                # 处理数据块
                processed_chunk = callback(chunk)
                outfile.write(processed_chunk)
                
                # 更新进度
                processed_size += len(chunk)
                if progress_callback:
                    progress_callback(processed_size / file_size)
    
    @staticmethod
    def quick_encrypt_file(input_path: str, output_path: str, 
                          min_layers: int = 2, max_layers: int = 3,
                          progress_callback: Callable[[float, str], None] = None):
        """
        高效加密大文件
        
        Args:
            input_path: 输入文件路径
            output_path: 输出文件路径
            min_layers: 最小加密层数
            max_layers: 最大加密层数
            progress_callback: 进度回调函数，接受进度和状态信息
        
        Returns:
            使用的算法列表
        """
        # 获取文件大小
        file_size = os.path.getsize(input_path)
        algorithms_used = []
        
        # 根据文件大小调整策略
        if file_size > 100 * 1024 * 1024:  # 100MB以上
            num_layers = min(2, max_layers)  # 最多使用2层
        elif file_size > 10 * 1024 * 1024:  # 10MB以上
            num_layers = min(min_layers + 1, max_layers)
        else:
            num_layers = random.randint(min_layers, max_layers)
        
        # 选择算法
        available_algos = ChaosEncryptor.get_efficient_algorithms()
        obfuscation_algos = ChaosEncryptor.get_obfuscation_algorithms()
        
        # 随机选择算法
        selected_algos = random.sample(available_algos, k=min(num_layers, len(available_algos)))
        # 总是添加一个混淆算法在最后
        selected_algos.append(random.choice(obfuscation_algos))
        
        # 记录所有密钥信息
        all_keys = bytearray()
        
        # 当前处理的数据文件
        current_file = input_path
        temp_files = []
        
        try:
            # 逐层加密
            for i, (algo_name, algo_func) in enumerate(selected_algos):
                if progress_callback:
                    progress_percent = i / len(selected_algos) * 0.9  # 90%进度分配给加密过程
                    progress_callback(progress_percent, f"应用 {algo_name} 加密...")
                
                # 创建临时文件名
                temp_output = f"{output_path}.temp{i}"
                temp_files.append(temp_output)
                
                # 为当前算法创建一个包装函数
                def process_chunk(chunk, algo=algo_func):
                    try:
                        result, key_info = algo(chunk)
                        nonlocal all_keys
                        all_keys.extend(key_info)
                        return result
                    except Exception as e:
                        print(f"处理块时出错: {str(e)}")
                        return chunk  # 错误时返回原始数据
                
                # 分块处理当前文件
                ChunkProcessor.process_file_in_chunks(
                    current_file, 
                    temp_output,
                    process_chunk,
                    lambda p: progress_callback(i / len(selected_algos) * 0.9 + p * 0.9 / len(selected_algos), 
                                               f"应用 {algo_name} 加密... {int(p*100)}%")
                )
                
                # 更新当前处理文件
                if i > 0:  # 不要删除原始输入文件
                    try:
                        if current_file != input_path:
                            os.remove(current_file)
                    except:
                        pass
                current_file = temp_output
                
                # 记录使用的算法
                algorithms_used.append(algo_name)
            
            # 最后一步：添加密钥指纹并完成加密
            if progress_callback:
                progress_callback(0.95, "生成密钥指纹...")
            
            # 计算所有密钥的指纹
            key_fingerprint = hashlib.sha256(all_keys).digest()
            
            # 最终文件：[密钥指纹][加密数据]
            with open(current_file, 'rb') as infile, open(output_path, 'wb') as outfile:
                outfile.write(key_fingerprint)  # 写入指纹
                
                # 复制加密数据
                while True:
                    chunk = infile.read(ChunkProcessor.CHUNK_SIZE)
                    if not chunk:
                        break
                    outfile.write(chunk)
            
            # 清理所有临时文件
            for temp_file in temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except:
                    pass
            
            # 删除所有密钥数据
            del all_keys
            
            if progress_callback:
                progress_callback(1.0, "加密完成！")
            
            return algorithms_used
        
        except Exception as e:
            # 清理所有临时文件
            for temp_file in temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except:
                    pass
            raise e

# ======================== DOS风格UI ========================
class DOSEncryptorUI:
    """DOS风格的加密工具UI"""
    
    def __init__(self):
        self.root = Tk()
        self.root.title("UntitleEncryptor v2.5")
        self.root.geometry("600x450")  # 增加高度以容纳进度条
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
             text="【UntitleEncryptor v2.5】",
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
        
        # 进度条 - 添加回来
        self.progress_frame = Frame(self.frame, bg="#000080")
        self.progress_frame.pack(fill="x", pady=5)
        
        self.progress = ttk.Progressbar(
            self.progress_frame, 
            orient="horizontal", 
            length=560, 
            mode="determinate"
        )
        self.progress.pack(fill="x")
        
        # 进度详情 - 添加回来
        self.progress_detail = Label(self.frame,
                                text="",
                                font=self.mono_font,
                                bg="#000080",
                                fg="#AAAAAA")
        self.progress_detail.pack(anchor="w", pady=2)
        
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
        
        # 取消按钮 (加密过程中显示) - 添加回来
        self.cancel_btn = Button(btn_frame,
                              text="取消加密",
                              font=self.mono_font,
                              bg="#AA0000",
                              fg="#FFFFFF",
                              relief="raised",
                              state="disabled",
                              command=self.cancel_encryption)
        
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
        
        # 文件路径和加密线程
        self.selected_file = None
        self.encryption_thread = None
        self.cancel_requested = False
        
        # 大小阈值设置 (MB)
        self.large_file_threshold = 50  # 50MB以上为大文件
    
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
            
            # 针对大文件显示特殊提示 - 添加回来
            if file_size > self.large_file_threshold * 1024 * 1024:
                self.status.config(text=f'大文件已就绪 ({self._format_size(file_size)}), 点击"加密文件"开始加密')
                self.warning_label.config(
                    text=f"警告: 检测到大文件! 加密过程可能需要几分钟。加密后文件无法恢复！"
                )
            else:
                self.status.config(text='文件已就绪，点击"加密文件"开始加密')
                self.warning_label.config(
                    text="警告: 加密后文件无法恢复！"
                )
            
            self.encrypt_btn.config(state="normal")
    
    def confirm_encrypt(self):
        """确认加密操作"""
        if not self.selected_file:
            return
        
        # 对大文件给予更明确的警告 - 添加回来
        file_size = os.path.getsize(self.selected_file)
        if file_size > self.large_file_threshold * 1024 * 1024:
            warning_msg = (
                f"警告: 您选择的文件大小为 {self._format_size(file_size)}，加密过程可能需要几分钟。\n\n"
                "此操作将使用多层加密算法加密您的文件，并销毁所有密钥！\n"
                "加密后的文件将无法被解密或恢复！\n\n"
                "您确定要继续吗？"
            )
        else:
            warning_msg = (
                "警告: 此操作将使用多层加密算法加密您的文件，并销毁所有密钥！\n"
                "加密后的文件将无法被解密或恢复！\n\n"
                "您确定要继续吗？"
            )
        
        result = messagebox.askquestion(
            "确认不可逆加密", 
            warning_msg,
            icon='warning'
        )
        
        if result == 'yes':
            self.start_encryption()
    
    def start_encryption(self):
        """在新线程中开始加密过程 - 添加回来"""
        # 禁用按钮，显示取消按钮
        self.encrypt_btn.pack_forget()
        self.select_btn.config(state="disabled")
        self.cancel_btn.pack(side="left", padx=5)
        self.cancel_btn.config(state="normal")
        
        # 重置进度和状态
        self.progress["value"] = 0
        self.progress_detail.config(text="准备加密...")
        self.algo_info.config(text="")
        self.cancel_requested = False
        
        # 启动加密线程
        self.encryption_thread = threading.Thread(target=self.encrypt_file_thread)
        self.encryption_thread.daemon = True
        self.encryption_thread.start()
        
        # 启动进度更新
        self.root.after(100, self.update_progress)
    
    def update_progress(self):
        """定期更新进度和UI - 添加回来"""
        if self.encryption_thread and self.encryption_thread.is_alive():
            # 线程仍在运行，继续检查
            self.root.after(100, self.update_progress)
        else:
            # 线程结束，恢复UI
            self.restore_ui_after_encryption()
    
    def restore_ui_after_encryption(self):
        """加密完成后恢复UI状态 - 添加回来"""
        # 移除取消按钮，恢复正常按钮
        self.cancel_btn.pack_forget()
        self.encrypt_btn.pack(side="left", padx=5)
        self.select_btn.config(state="normal")
    
    def cancel_encryption(self):
        """取消加密过程 - 添加回来"""
        if self.encryption_thread and self.encryption_thread.is_alive():
            self.cancel_requested = True
            self.progress_detail.config(text="正在取消加密...")
            self.cancel_btn.config(state="disabled")
    
    def update_encryption_progress(self, progress_value: float, status_text: str):
        """从加密线程更新进度条和状态 - 添加回来"""
        # 因为这个可能从线程调用，使用after方法确保在主线程更新UI
        self.root.after(0, lambda: self._update_progress_ui(progress_value, status_text))
    
    def _update_progress_ui(self, progress_value: float, status_text: str):
        """在主线程中更新UI - 添加回来"""
        self.progress["value"] = progress_value * 100
        self.progress_detail.config(text=status_text)
        self.root.update_idletasks()  # 确保UI立即更新
    
    def encrypt_file_thread(self):
        """在单独线程中执行加密 - 添加回来"""
        if not self.selected_file:
            return
        
        output_path = None
        temp_path = None
        
        try:
            # 准备输出路径
            filename = Path(self.selected_file).stem
            output_path = Path(f"{filename}.atlas")
            
            # 使用临时文件
            temp_path = Path(f"{filename}.atlas.temp")
            
            # 开始时间
            start_time = time.time()
            
            # 执行优化的分块加密
            used_algos = ChunkProcessor.quick_encrypt_file(
                self.selected_file, 
                temp_path,
                min_layers=2,
                max_layers=3,
                progress_callback=self.update_encryption_progress
            )
            
            # 检查是否请求取消
            if self.cancel_requested:
                # 删除临时文件
                if temp_path and temp_path.exists():
                    os.remove(temp_path)
                self.root.after(0, lambda: self.status.config(
                    text="加密已取消"))
                return
            
            # 移动临时文件到最终位置
            if temp_path.exists():
                # 如果目标文件存在，先删除
                if output_path.exists():
                    os.remove(output_path)
                os.rename(temp_path, output_path)
            
            # 计算耗时
            elapsed_time = time.time() - start_time
            time_str = f"{elapsed_time:.1f}秒" if elapsed_time < 60 else f"{elapsed_time/60:.1f}分钟"
            
            # 获取加密后文件大小
            original_size = os.path.getsize(self.selected_file)
            encrypted_size = os.path.getsize(output_path)
            size_change = encrypted_size - original_size
            
            # 计算百分比变化 - 修复百分比计算
            if original_size > 0:  # 避免除以零
                percentage_change = (size_change / original_size) * 100
            else:
                percentage_change = 0
                
            if size_change == 0:
                size_info = "大小完全相同！"
            else:
                size_info = f"大小变化: {'+' if size_change > 0 else ''}{self._format_size(abs(size_change))} " + \
                        f"({'+' if size_change > 0 else ''}{percentage_change:.1f}%)"
            
            # 更新最终状态
            def update_final_status():
                self.progress["value"] = 100
                self.progress_detail.config(text=f"加密完成！耗时: {time_str}")
                self.algo_info.config(
                    text=f"使用的加密算法:\n" + 
                        "\n".join(f"- {algo}" for algo in used_algos) + 
                        f"\n\n{size_info}\n" +
                        "所有加密密钥已被销毁，加密成功！"
                )
                self.status.config(text=f"加密完成! 保存为: {output_path}")
                
                messagebox.showinfo(
                    "加密成功", 
                    f"文件已加密并保存为:\n{output_path}\n\n"
                    f"{size_info}\n"
                    f"耗时: {time_str}\n\n"
                    f"所有加密密钥已被销毁，加密成功！"
                )
                
            self.root.after(0, update_final_status)
            
        except Exception as e:
            # 删除临时文件
            if temp_path and Path(temp_path).exists():
                try:
                    os.remove(temp_path)
                except:
                    pass
            
            # 更新错误状态
            error_msg = str(e)
            self.root.after(0, lambda: self.status.config(
                text=f"加密失败: {error_msg}"))
            
            # 显示错误信息
            self.root.after(0, lambda: messagebox.showerror(
                "错误", f"加密过程中发生错误:\n{error_msg}"))
    
    @staticmethod
    def _format_size(size_bytes):
        """格式化文件大小 - 修复后的版本"""
        abs_size = abs(size_bytes)
        if abs_size < 1024:
            return f"{size_bytes:.2f} B"
        
        size_kb = size_bytes / 1024.0
        if abs_size < 1024 * 1024:
            return f"{size_kb:.2f} KB"
        
        size_mb = size_kb / 1024.0
        if abs_size < 1024 * 1024 * 1024:
            return f"{size_mb:.2f} MB"
        
        size_gb = size_mb / 1024.0
        return f"{size_gb:.2f} GB"
    
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
