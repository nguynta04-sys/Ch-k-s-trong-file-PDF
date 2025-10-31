# Chu ky so trong-file-PDF
## BÀI TẬP VỀ NHÀ – MÔN: AN TOÀN VÀ BẢO MẬT THÔNG TIN
## I. MÔ TẢ CHUNG
Sinh viên thực hiện báo cáo và thực hành: phân tích và hiện thực việc nhúng, xác
thực chữ ký số trong file PDF.
Phải nêu rõ chuẩn tham chiếu (PDF 1.7 / PDF 2.0, PAdES/ETSI) và sử dụng công cụ
thực thi (ví dụ iText7, OpenSSL, PyPDF, pdf-lib).
## II. CÁC YÊU CẦU CỤ THỂ
1) Cấu trúc PDF liên quan chữ ký (Nghiên cứu)
- Mô tả ngắn gọn: Catalog, Pages tree, Page object, Resources, Content streams,
XObject, AcroForm, Signature field (widget), Signature dictionary (/Sig),
/ByteRange, /Contents, incremental updates, và DSS (theo PAdES).
- Liệt kê object refs quan trọng và giải thích vai trò của từng object trong
lưu/truy xuất chữ ký.
- Đầu ra: 1 trang tóm tắt + sơ đồ object (ví dụ: Catalog → Pages → Page → /Contents
; Catalog → /AcroForm → SigField → SigDict).
2) Thời gian ký được lưu ở đâu?
- Nêu tất cả vị trí có thể lưu thông tin thời gian:
 + /M trong Signature dictionary (dạng text, không có giá trị pháp lý).
 + Timestamp token (RFC 3161) trong PKCS#7 (attribute timeStampToken).
 + Document timestamp object (PAdES).
 + DSS (Document Security Store) nếu có lưu timestamp và dữ liệu xác minh.
- Giải thích khác biệt giữa thông tin thời gian /M và timestamp RFC3161.
3) Các bước tạo và lưu chữ ký trong PDF (đã có private RSA)
- Viết script/code thực hiện tuần tự:
 1. Chuẩn bị file PDF gốc.
 2. Tạo Signature field (AcroForm), reserve vùng /Contents (8192 bytes).
 3. Xác định /ByteRange (loại trừ vùng /Contents khỏi hash).
 4. Tính hash (SHA-256/512) trên vùng ByteRange.
 5. Tạo PKCS#7/CMS detached hoặc CAdES:
 - Include messageDigest, signingTime, contentType.
 - Include certificate chain.
 - (Tùy chọn) thêm RFC3161 timestamp token.
 6. Chèn blob DER PKCS#7 vào /Contents (hex/binary) đúng offset.
 7. Ghi incremental update.
 8. (LTV) Cập nhật DSS với Certs, OCSPs, CRLs, VRI.
- Phải nêu rõ: hash alg, RSA padding, key size, vị trí lưu trong PKCS#7.
- Đầu ra: mã nguồn, file PDF gốc, file PDF đã ký.
4) Các bước xác thực chữ ký trên PDF đã ký
- Các bước kiểm tra:
 1. Đọc Signature dictionary: /Contents, /ByteRange.
 2. Tách PKCS#7, kiểm tra định dạng.
 3. Tính hash và so sánh messageDigest.
 4. Verify signature bằng public key trong cert.
 5. Kiểm tra chain → root trusted CA.
 6. Kiểm tra OCSP/CRL.
 7. Kiểm tra timestamp token.
 8. Kiểm tra incremental update (phát hiện sửa đổi).
- Nộp kèm script verify + log kiểm thử.
# Bài Làm:

- em vào trang này để download Openssl https://slproweb.com/products/Win32OpenSSL.html
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/039c4f17-79c4-4254-a928-3f624db4fc97" />

- Em làm trước được 1 file pdf gốc:
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/01c257b9-20a5-47d8-be19-65aecc4f791d" />

- Em tạo mycert.pem và mykey.pem sử dụng Openssl để tạo chứng chỉ và khóa em được 2 file:
<img width="355" height="53" alt="image" src="https://github.com/user-attachments/assets/c2f33286-299d-4f22-879b-a46294291533" />

- Em tự kí trước 1 ảnh chữ kí của em:
<img width="1918" height="1080" alt="image" src="https://github.com/user-attachments/assets/1a008824-bae5-4ae4-92a1-a6273ef3391a" />

- Em tạo 1 file chukiso.py với cấu hình như sau:
- PDF_INPUT : chukiso.pdf
- PDF_OUTPUT: signed_output.pdf
- SIGN_IMAGE: signature.png
- PRIVATE_KEY: mykey.pem
- CERT_FILE: mycert.pem

-  Sau khi em chạy code .py, chữ kí từ ảnh png sẽ được đưa ra file chukiso.pdf và cho ra file signed_output.pdf đã được kí:
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/a41d505b-caa8-4595-a615-aa7ad19d4d72" />

- Em tạo 1 file .py nữa để kiểm tra xác thực chữ kí:
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/1d00eddc-2e53-40b5-9390-364c46bd5742" />

- Sau khi em chạy file: verify_log.py, xong sau đó sẽ tạo ra 1 file: verify_log.txt để hiển thị kết quả kiểm tra chứng chỉ và log lại time:
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/98770f59-3a63-426e-9f6f-cc2216f35de9" />

==> Kết luận bài: Đã kiểm tra và đáp ứng đủ các yêu cầu chữ kí, còn thiếu phần: Metadata (/M, /SubFilter) và DSS / DocTimeStamp 

