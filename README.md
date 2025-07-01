# 1771020268_TruongMinhHieu
NHOM 6 - TRUONG MINH HIEU - XAY DUNG GAME MA HOA NGAN HANG

# BankSecurityGame - Game Bảo Mật Giao Dịch Ngân Hàng

**BankSecurityGame** là một trò chơi giáo dục giúp người chơi tìm hiểu về các khái niệm mã hóa như RSA, AES, SHA256 và xác thực chữ ký số trong môi trường giả lập ngân hàng. Người chơi vào vai nhân viên bảo mật và phải xử lý các giao dịch được mã hóa để phát hiện giao dịch gian lận.

---

## Tính năng nổi bật

- Mã hóa RSA/AES toàn diện cho giao dịch  
- Tạo và xác minh chữ ký số bằng RSA/SHA256  
- Giao dịch có thể hợp lệ hoặc lừa đảo (giả mạo chữ ký hoặc chỉnh sửa dữ liệu)  
- Giao diện đồ họa trực quan bằng Tkinter  
- Tăng cấp độ và độ khó theo điểm số  
- Nhật ký hệ thống đầy màu sắc theo từng bước xử lý  

---

## Yêu cầu hệ thống

- Python 3.7+
- Thư viện ngoài:
  ```bash
  pip install cryptography

---

##  Cách chạy chương trình
Cài đặt thư viện  
```bash
pip install cryptography  

---

Chạy ứng dụng:
```bash 
python main.py

---

## thể lệ chơi
Giao dịch mới sẽ tự động xuất hiện định kỳ.  
Người chơi chọn một giao dịch từ danh sách bên trái.  
Thực hiện ba bước kiểm tra bảo mật:  
1. Giải mã khóa phiên (RSA)  
2. Giải mã dữ liệu giao dịch (AES)  
3. Xác thực chữ ký và kiểm tra toàn vẹn (RSA + SHA256)  
Phê duyệt hoặc từ chối giao dịch dựa trên kết quả kiểm tra.  
Hệ thống tự động tính điểm và cập nhật cấp độ.

---

## Kỹ thuật bảo mật được mô phỏng  
- RSA: dùng để mã hóa khóa AES và ký số dữ liệu  
- AES (CFB mode): mã hóa nội dung giao dịch  
- SHA256: tạo hash để kiểm tra toàn vẹn dữ liệu  
- Chữ ký số: đảm bảo tính xác thực và chống giả mạo

---

## Ví dụ về gian lận
- Tampered Data: Dữ liệu bị thay đổi sau khi ký → chữ ký không còn hợp lệ  
- Bad Signature: Chữ ký không khớp với public key cung cấp → giả mạo

---

 ## Giao diện game
- Cột trái: Danh sách giao dịch đang chờ  
- Cột giữa: Chi tiết và nhật ký hệ thống  
- Cột phải: Thông tin, hành động và phê duyệt

---

## Điểm số & Cấp độ
+10 điểm nếu xử lý chính xác  
-20 điểm nếu xử lý sai  
Tự động lên cấp khi đạt đủ điểm  

---

## Cấu trúc
-CryptoUtils: Các hàm mã hóa/giải mã và xác thực  
- Transaction: Mô hình dữ liệu giao dịch  
- GameLogic: Tạo giao dịch, điểm số và trạng thái trò chơi  
- BankSecurityGame: Giao diện và tương tác chính với người dùng

---

## Minh họa
![image](https://github.com/user-attachments/assets/c119e730-3e41-45d0-b658-5921f4b9870c)
