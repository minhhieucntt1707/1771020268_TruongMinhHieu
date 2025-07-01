import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import os
import random
import time
from datetime import datetime

# --- Yêu cầu: pip install cryptography ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# LỚP 1: CÁC HÀM TIỆN ÍCH MÃ HÓA
class CryptoUtils:
    """Chứa tất cả các hàm tĩnh cho việc mã hóa, giải mã, ký và xác thực."""
    
    @staticmethod
    def generate_rsa_keys():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def rsa_encrypt(data, public_key):
        return public_key.encrypt(
            data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    @staticmethod
    def rsa_decrypt(ciphertext, private_key):
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    @staticmethod
    def rsa_sign(message_hash, private_key):
        return private_key.sign(
            message_hash,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    @staticmethod
    def rsa_verify(message_hash, signature, public_key):
        try:
            public_key.verify(
                signature,
                message_hash,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def generate_aes_key():
        return os.urandom(32)

    @staticmethod
    def aes_encrypt(data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return iv + ct

    @staticmethod
    def aes_decrypt(iv_and_ct, key):
        iv = iv_and_ct[:16]
        ct = iv_and_ct[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    @staticmethod
    def generate_sha256_hash(data):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize()

# LỚP 2: ĐỐI TƯỢNG GIAO DỊCH
class Transaction:
    """Lớp chứa dữ liệu gốc của một giao dịch."""
    def __init__(self, from_acc, to_acc, amount):
        self.data = {
            "from_account": from_acc,
            "to_account": to_acc,
            "amount": amount,
            "timestamp": datetime.now().isoformat()
        }

    def to_bytes(self):
        """Chuyển dữ liệu giao dịch thành bytes để mã hóa và hash."""
        return json.dumps(self.data, sort_keys=True).encode('utf-8')

# LỚP 3: LOGIC CỦA GAME
class GameLogic:
    """Quản lý trạng thái game: điểm, cấp độ, tạo giao dịch."""
    def __init__(self):
        self.score = 0
        self.level = 1
        self.bank_private_key, self.bank_public_key = CryptoUtils.generate_rsa_keys()
        self.pending_transactions = {} # Dùng dict để dễ truy cập bằng ID

    def create_transaction(self):
        """Tạo một gói giao dịch mới, có thể hợp lệ hoặc lừa đảo."""
        transaction_id = f"TXN{int(time.time() * 1000)}"
        
        # Tạo dữ liệu giao dịch cơ bản
        from_acc = f"ACC{random.randint(10000, 99999)}"
        to_acc = f"ACC{random.randint(10000, 99999)}"
        amount = round(random.uniform(100, 5000) * self.level, 2)
        transaction = Transaction(from_acc, to_acc, amount)
        transaction_data_bytes = transaction.to_bytes()

        # Mô phỏng khách hàng tạo khóa và ký
        customer_private_key, customer_public_key = CryptoUtils.generate_rsa_keys()
        
        # Mặc định là giao dịch hợp lệ
        is_fraudulent = False
        fraud_type = "None"
        
        # Ở cấp độ cao hơn, có khả năng tạo giao dịch lừa đảo
        if self.level > 1 and random.random() < 0.3: # 30% cơ hội lừa đảo
            is_fraudulent = True
            fraud_type = random.choice(["tampered_data", "bad_signature"])

        # Tạo hash từ dữ liệu
        if is_fraudulent and fraud_type == "tampered_data":
            # Giao dịch bị thay đổi SAU KHI ký
            original_hash = CryptoUtils.generate_sha256_hash(transaction_data_bytes)
            signature = CryptoUtils.rsa_sign(original_hash, customer_private_key)
            # Thay đổi dữ liệu gốc trước khi mã hóa AES
            tampered_transaction = Transaction(from_acc, to_acc, amount + 1000)
            data_to_encrypt = tampered_transaction.to_bytes()
        else:
            # Giao dịch bình thường
            transaction_hash = CryptoUtils.generate_sha256_hash(transaction_data_bytes)
            if is_fraudulent and fraud_type == "bad_signature":
                # Ký bằng một khóa khác (của kẻ gian)
                hacker_private_key, _ = CryptoUtils.generate_rsa_keys()
                signature = CryptoUtils.rsa_sign(transaction_hash, hacker_private_key)
            else:
                # Ký bằng khóa của khách hàng
                signature = CryptoUtils.rsa_sign(transaction_hash, customer_private_key)
            data_to_encrypt = transaction_data_bytes

        # Mã hóa AES
        session_key = CryptoUtils.generate_aes_key()
        encrypted_data = CryptoUtils.aes_encrypt(data_to_encrypt, session_key)

        # Mã hóa khóa phiên AES bằng RSA public key của ngân hàng
        encrypted_session_key = CryptoUtils.rsa_encrypt(session_key, self.bank_public_key)

        # Đóng gói giao dịch để gửi đi
        packet = {
            "id": transaction_id,
            "encrypted_data": encrypted_data,
            "encrypted_session_key": encrypted_session_key,
            "signature": signature,
            "customer_public_key": customer_public_key,
            "is_fraudulent": is_fraudulent,
            "fraud_type": fraud_type
        }
        self.pending_transactions[transaction_id] = packet
        return packet
        
    def level_up_check(self):
        if self.score >= self.level * 50:
            self.level += 1
            return True
        return False

# LỚP 4: GIAO DIỆN VÀ TƯƠNG TÁC
class BankSecurityGame(tk.Tk):
    """Lớp chính của ứng dụng, quản lý GUI và luồng sự kiện."""
    
    def __init__(self):
        super().__init__()
        self.title("Game: Hệ Thống Mã Hóa Ngân Hàng")
        self.geometry("1000x700")
        
        self.logic = GameLogic()
        self.current_transaction_id = None
        
        # Lưu trữ trạng thái xử lý của giao dịch hiện tại
        self.processing_state = {}

        self._create_widgets()
        self.update_stats()
        self.start_game_loop()

    def _create_widgets(self):
        # --- Khung chính ---
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Cột trái: Danh sách giao dịch ---
        left_pane = ttk.Frame(main_frame, width=250)
        left_pane.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        ttk.Label(left_pane, text="Giao Dịch Đang Chờ", font=("Helvetica", 12, "bold")).pack(pady=5)
        self.pending_listbox = tk.Listbox(left_pane, height=25)
        self.pending_listbox.pack(fill=tk.BOTH, expand=True)
        self.pending_listbox.bind("<<ListboxSelect>>", self.on_transaction_select)

        # --- Cột giữa: Chi tiết và Log ---
        center_pane = ttk.Frame(main_frame)
        center_pane.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ttk.Label(center_pane, text="Chi Tiết Giao Dịch", font=("Helvetica", 12, "bold")).pack(pady=5)
        self.details_text = scrolledtext.ScrolledText(center_pane, height=15, state="disabled", wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(center_pane, text="Nhật Ký Hệ Thống", font=("Helvetica", 12, "bold")).pack(pady=5)
        self.log_text = scrolledtext.ScrolledText(center_pane, height=10, state="disabled", wrap=tk.WORD, bg="black", fg="lime green")
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # --- Cột phải: Điều khiển và thông tin ---
        right_pane = ttk.Frame(main_frame, width=200)
        right_pane.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        
        stats_frame = ttk.LabelFrame(right_pane, text="Thông Tin")
        stats_frame.pack(fill=tk.X, pady=5)
        self.score_label = ttk.Label(stats_frame, text="Điểm: 0", font=("Helvetica", 11, "bold"))
        self.score_label.pack(pady=5)
        self.level_label = ttk.Label(stats_frame, text="Cấp độ: 1", font=("Helvetica", 11, "bold"))
        self.level_label.pack(pady=5)

        actions_frame = ttk.LabelFrame(right_pane, text="Hành Động")
        actions_frame.pack(fill=tk.X, pady=10)

        self.btn_decrypt_key = ttk.Button(actions_frame, text="1. Giải Mã Khóa (RSA)", command=self.handle_decrypt_key, state="disabled")
        self.btn_decrypt_key.pack(fill=tk.X, pady=3, ipady=4)
        
        self.btn_decrypt_data = ttk.Button(actions_frame, text="2. Giải Mã Giao Dịch (AES)", command=self.handle_decrypt_data, state="disabled")
        self.btn_decrypt_data.pack(fill=tk.X, pady=3, ipady=4)
        
        self.btn_verify = ttk.Button(actions_frame, text="3. Xác Thực & Kiểm Tra (SHA/RSA)", command=self.handle_verify, state="disabled")
        self.btn_verify.pack(fill=tk.X, pady=3, ipady=4)
        
        approval_frame = ttk.LabelFrame(right_pane, text="Phê Duyệt")
        approval_frame.pack(fill=tk.X, pady=10)
        
        self.btn_approve = ttk.Button(approval_frame, text="CHẤP NHẬN", command=lambda: self.finalize_transaction(True), style="Success.TButton")
        self.btn_approve.pack(fill=tk.X, pady=3, ipady=5)
        self.btn_reject = ttk.Button(approval_frame, text="TỪ CHỐI", command=lambda: self.finalize_transaction(False), style="Danger.TButton")
        self.btn_reject.pack(fill=tk.X, pady=3, ipady=5)
        
        self.btn_approve.config(state="disabled")
        self.btn_reject.config(state="disabled")

        # Custom styles for buttons
        style = ttk.Style()
        style.configure("Success.TButton", foreground="green", font=('Helvetica', 10, 'bold'))
        style.configure("Danger.TButton", foreground="red", font=('Helvetica', 10, 'bold'))

    def log(self, message, level="INFO"):
        """Ghi log vào ô nhật ký với màu sắc."""
        self.log_text.config(state="normal")
        color = "lime green"
        if level == "SUCCESS": color = "cyan"
        if level == "ERROR": color = "red"
        if level == "WARN": color = "yellow"
        
        self.log_text.tag_config(level, foreground=color)
        self.log_text.insert(tk.END, f"[{level}] {message}\n", level)
        self.log_text.config(state="disabled")
        self.log_text.see(tk.END)
        
    def update_stats(self):
        self.score_label.config(text=f"Điểm: {self.logic.score}")
        self.level_label.config(text=f"Cấp độ: {self.logic.level}")

    def start_game_loop(self):
        """Vòng lặp chính của game, tạo giao dịch mới định kỳ."""
        self.logic.create_transaction()
        self.update_pending_listbox()
        
        # Tốc độ tạo giao dịch tăng theo cấp độ
        delay_ms = max(8000 - self.logic.level * 1000, 2000)
        self.after(delay_ms, self.start_game_loop)

    def update_pending_listbox(self):
        self.pending_listbox.delete(0, tk.END)
        for tx_id in self.logic.pending_transactions:
            self.pending_listbox.insert(tk.END, tx_id)

    def on_transaction_select(self, event):
        """Xử lý khi người chơi chọn một giao dịch từ danh sách."""
        selection = self.pending_listbox.curselection()
        if not selection:
            return
            
        selected_index = selection[0]
        self.current_transaction_id = self.pending_listbox.get(selected_index)
        
        # Reset trạng thái xử lý cho giao dịch mới
        self.processing_state = {
            "session_key_decrypted": None,
            "data_decrypted": None,
            "verified": None
        }

        self.update_details_display()
        self.reset_buttons()
        self.log(f"Đã chọn giao dịch {self.current_transaction_id}. Bắt đầu quy trình bảo mật.")

    def update_details_display(self):
        """Cập nhật ô chi tiết với thông tin hiện tại của giao dịch."""
        if not self.current_transaction_id:
            return
            
        self.details_text.config(state="normal")
        self.details_text.delete('1.0', tk.END)
        
        details = f"Giao dịch ID: {self.current_transaction_id}\n"
        details += "="*40 + "\n"
        
        if self.processing_state.get("data_decrypted"):
            data = json.loads(self.processing_state["data_decrypted"].decode('utf-8'))
            details += f"Trạng thái: Đã giải mã\n"
            details += f"  - Từ tài khoản: {data['from_account']}\n"
            details += f"  - Tới tài khoản: {data['to_account']}\n"
            details += f"  - Số tiền: ${data['amount']:.2f}\n"
            details += f"  - Thời gian: {data['timestamp']}\n"
        else:
            details += "Trạng thái: Đang mã hóa\n"
            details += "Nội dung: [Dữ liệu được bảo vệ bằng mã hóa AES]\n"

        details += "\n"
        
        if self.processing_state.get("session_key_decrypted"):
            details += "Khóa phiên AES: [Đã giải mã]\n"
        else:
            details += "Khóa phiên AES: [Đang mã hóa bằng RSA Public Key của ngân hàng]\n"

        details += "\n"
        if self.processing_state.get("verified") is True:
            details += "Xác thực (RSA/SHA): [HỢP LỆ ✓]\n"
        elif self.processing_state.get("verified") is False:
            details += "Xác thực (RSA/SHA): [KHÔNG HỢP LỆ ✗]\n"
        else:
            details += "Xác thực (RSA/SHA): [Chưa kiểm tra]\n"

        self.details_text.insert('1.0', details)
        self.details_text.config(state="disabled")

    def reset_buttons(self):
        self.btn_decrypt_key.config(state="normal")
        self.btn_decrypt_data.config(state="disabled")
        self.btn_verify.config(state="disabled")
        self.btn_approve.config(state="disabled")
        self.btn_reject.config(state="disabled")

    def handle_decrypt_key(self):
        """Hành động 1: Giải mã khóa phiên AES."""
        if not self.current_transaction_id: return
        
        packet = self.logic.pending_transactions[self.current_transaction_id]
        try:
            session_key = CryptoUtils.rsa_decrypt(packet['encrypted_session_key'], self.logic.bank_private_key)
            self.processing_state["session_key_decrypted"] = session_key
            self.log("Giải mã khóa phiên AES bằng Private Key của ngân hàng thành công!", "SUCCESS")
            
            self.btn_decrypt_key.config(state="disabled")
            self.btn_decrypt_data.config(state="normal")
        except Exception as e:
            self.log(f"Lỗi khi giải mã khóa: {e}", "ERROR")
        
        self.update_details_display()

    def handle_decrypt_data(self):
        """Hành động 2: Giải mã dữ liệu giao dịch."""
        if not self.processing_state.get("session_key_decrypted"): return
        
        packet = self.logic.pending_transactions[self.current_transaction_id]
        key = self.processing_state["session_key_decrypted"]
        
        try:
            decrypted_data = CryptoUtils.aes_decrypt(packet['encrypted_data'], key)
            self.processing_state["data_decrypted"] = decrypted_data
            self.log("Giải mã dữ liệu giao dịch bằng AES thành công!", "SUCCESS")

            self.btn_decrypt_data.config(state="disabled")
            self.btn_verify.config(state="normal")
        except Exception as e:
            self.log(f"Lỗi khi giải mã dữ liệu: {e}", "ERROR")

        self.update_details_display()

    def handle_verify(self):
        """Hành động 3: Xác thực chữ ký và kiểm tra toàn vẹn."""
        if not self.processing_state.get("data_decrypted"): return

        packet = self.logic.pending_transactions[self.current_transaction_id]
        data = self.processing_state["data_decrypted"]
        
        # Tạo hash từ dữ liệu vừa giải mã
        current_hash = CryptoUtils.generate_sha256_hash(data)
        
        # Xác thực chữ ký
        is_valid = CryptoUtils.rsa_verify(current_hash, packet['signature'], packet['customer_public_key'])
        
        self.processing_state["verified"] = is_valid
        
        if is_valid:
            self.log("Xác thực RSA và kiểm tra toàn vẹn SHA thành công. Giao dịch hợp lệ.", "SUCCESS")
        else:
            self.log("CẢNH BÁO! Chữ ký không hợp lệ hoặc dữ liệu đã bị thay đổi!", "WARN")
            
        self.btn_verify.config(state="disabled")
        self.btn_approve.config(state="normal")
        self.btn_reject.config(state="normal")
        
        self.update_details_display()

    def finalize_transaction(self, approved: bool):
        """Hành động cuối: Chấp nhận hoặc từ chối giao dịch và tính điểm."""
        if self.processing_state.get("verified") is None:
            self.log("Phải xác thực giao dịch trước khi phê duyệt!", "ERROR")
            return

        packet = self.logic.pending_transactions[self.current_transaction_id]
        is_fraud = packet['is_fraudulent']
        is_valid_in_reality = not is_fraud
        
        player_action_is_correct = (approved == is_valid_in_reality)

        if player_action_is_correct:
            self.log(f"Xử lý đúng! {'Đã chấp nhận giao dịch hợp lệ.' if approved else 'Đã từ chối giao dịch lừa đảo.'}", "SUCCESS")
            self.logic.score += 10
        else:
            self.log(f"Xử lý sai! {'Đã chấp nhận một giao dịch lừa đảo!' if approved else 'Đã từ chối một giao dịch hợp lệ.'}", "ERROR")
            self.logic.score -= 20

        # Dọn dẹp
        del self.logic.pending_transactions[self.current_transaction_id]
        self.current_transaction_id = None
        self.processing_state = {}
        
        self.details_text.config(state="normal")
        self.details_text.delete('1.0', tk.END)
        self.details_text.config(state="disabled")
        
        self.update_pending_listbox()
        self.reset_buttons()
        
        if self.logic.level_up_check():
            self.log(f"CHÚC MỪNG! BẠN ĐÃ LÊN CẤP {self.logic.level}!", "SUCCESS")

        self.update_stats()


if __name__ == "__main__":
    app = BankSecurityGame()
    app.log("Chào mừng quản trị viên bảo mật. Các giao dịch đang đến...")
    app.mainloop()