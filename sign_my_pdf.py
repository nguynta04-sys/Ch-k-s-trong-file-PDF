# sign_my_pdf.py
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from PyPDF2 import PdfReader, PdfWriter
from datetime import datetime
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.signers.pdf_signer import PdfSignatureMetadata
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko_certvalidator.context import ValidationContext
from pyhanko.sign.validation import validate_pdf_signature
from asn1crypto import x509
import base64
import os
import sys

# ===================== CẤU HÌNH =====================
PDF_INPUT = "chukiso.pdf"
PDF_TEMP = "chukiso_temp.pdf"
PDF_OUTPUT = "signed_output.pdf"
SIGN_IMAGE = "signature.png"
PRIVATE_KEY = "mykey.pem"
CERT_FILE = "mycert.pem"
NAME = "Nguyễn Tuấn Anh"
PHONE = "0919668434"
FONT_FILE = r"C:\Windows\Fonts\times.ttf"
FONT_NAME = "TimesNewRoman"
TSA_URL = "http://timestamp.digicert.com"
KEY_PASSPHRASE = None

# ===================== ĐĂNG KÝ FONT =====================
try:
    pdfmetrics.registerFont(TTFont(FONT_NAME, FONT_FILE))
except Exception as e:
    print("⚠️ Không load được font, dùng font mặc định. Lỗi:", e)

# ===================== BƯỚC 1: CHÈN ẢNH + THÔNG TIN =====================
overlay_path = "overlay.pdf"
c = canvas.Canvas(overlay_path, pagesize=A4)

img_x, img_y, img_w, img_h = 350, 300, 150, 70
if not os.path.exists(SIGN_IMAGE):
    print(f"❌ Không tìm thấy ảnh chữ ký: {SIGN_IMAGE}")
    sys.exit(1)

c.drawImage(SIGN_IMAGE, img_x, img_y, width=img_w, height=img_h)
c.setFont(FONT_NAME if FONT_NAME in pdfmetrics.getRegisteredFontNames() else "Helvetica", 10)
text_x, text_y = img_x, img_y - 15
c.drawString(text_x, text_y, f"Người ký: {NAME}")
c.drawString(text_x, text_y - 12, f"SĐT: {PHONE}")
c.drawString(text_x, text_y - 24, f"Ngày ký: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
c.save()
print("✅ Đã chèn ảnh chữ ký và thông tin vào overlay.pdf")

# ===================== BƯỚC 2: GHÉP OVERLAY VÀO PDF GỐC =====================
if not os.path.exists(PDF_INPUT):
    print(f"❌ Không tìm thấy file PDF gốc: {PDF_INPUT}")
    sys.exit(1)

reader = PdfReader(PDF_INPUT)
writer = PdfWriter()
overlay = PdfReader(overlay_path)
overlay_page = overlay.pages[0]
for page in reader.pages:
    page.merge_page(overlay_page)
    writer.add_page(page)

with open(PDF_TEMP, "wb") as f_out:
    writer.write(f_out)
print("✅ Đã gộp overlay vào file PDF tạm:", PDF_TEMP)

# ===================== BƯỚC 3: TẠO SIGNER =====================
if not os.path.exists(PRIVATE_KEY) or not os.path.exists(CERT_FILE):
    print("❌ Thiếu file private key hoặc certificate!")
    sys.exit(1)

try:
    signer = signers.SimpleSigner.load(
        key_file=PRIVATE_KEY,
        cert_file=CERT_FILE,
        ca_chain_files=None,
        key_passphrase=KEY_PASSPHRASE
    )
except Exception as e:
    print("❌ Không thể load private key / certificate. Lỗi:", e)
    sys.exit(1)

# ===================== BƯỚC 4: TSA + ValidationContext =====================
try:
    timestamper = HTTPTimeStamper(TSA_URL)
except Exception as e:
    print("⚠️ Không thể kết nối TSA:", e)
    timestamper = None

# Load certificate PEM -> asn1crypto.x509.Certificate
vc = None
try:
    with open(CERT_FILE, 'rb') as f:
        cert_data = f.read()
        if b"-----BEGIN" in cert_data:
            cert_data = b"".join(line for line in cert_data.splitlines() if not line.startswith(b"-----"))
            cert_data = base64.b64decode(cert_data)
        cert_obj = x509.Certificate.load(cert_data)
    vc = ValidationContext(trust_roots=[cert_obj])
    print("✅ ValidationContext created from CERT_FILE.")
except Exception as e:
    print("⚠️ Không tạo được ValidationContext từ CERT_FILE:", e)
    # vc vẫn có thể là None; script sẽ cố gắng ký nhưng không nhúng validation info

# ===================== BƯỚC 5: CẤU HÌNH THÔNG TIN KÝ =====================
# IMPORTANT: embed_validation_info=False để tránh bắt buộc phải có ValidationContext
meta = PdfSignatureMetadata(
    field_name="Signature1",
    reason="Phê duyệt báo cáo nhân sự",
    location="Đại học Kỹ thuật Công nghiệp - TNUT",
    md_algorithm="sha256",
    use_pades_lta=True,        # muốn PAdES-LTA nếu có thể
    embed_validation_info=False  # ĐẶT FALSE: tránh lỗi "must provide validation context"
)

# ===================== BƯỚC 6: KÝ PDF =====================
try:
    with open(PDF_TEMP, "rb") as pdf_in:
        pdf_writer = IncrementalPdfFileWriter(pdf_in)
        pdf_signer = signers.PdfSigner(
            signature_meta=meta,
            signer=signer,
            timestamper=timestamper,
            new_field_spec=SigFieldSpec(sig_field_name="Signature1")
        )

        signed_stream = pdf_signer.sign_pdf(pdf_writer)

        # Nếu có thể, cố gắng nhúng validation info sau khi ký
        # (một số phiên bản pyHanko cung cấp embed_validation_info)
        try:
            from pyhanko.sign.validation import embed_validation_info as _embed_vi
            if vc is not None:
                try:
                    _embed_vi(signed_stream, validation_context=vc)
                    print("✅ Đã nhúng validation info (OCSP/CRL) bằng embed_validation_info().")
                except Exception as sub_e:
                    print("⚠️ Không thể nhúng validation info dù có hàm embed_validation_info():", sub_e)
            else:
                print("⚠️ embed_validation_info có sẵn nhưng ValidationContext không hợp lệ — bỏ qua nhúng.")
        except ImportError:
            # Hàm embed_validation_info không tồn tại trong phiên bản pyHanko hiện tại
            print("⚠️ Hàm embed_validation_info không có trong pyHanko này — bỏ qua nhúng validation info.")
        except Exception as e:
            print("⚠️ Lỗi khi cố gắng import/embed validation info:", e)

        # Ghi file đầu ra
        with open(PDF_OUTPUT, "wb") as f_out:
            f_out.write(signed_stream.getbuffer())

    print("✅ Đã ký số thành công! File đầu ra:", PDF_OUTPUT)

except Exception as e:
    print("❌ Lỗi khi ký PDF:", e)
    sys.exit(1)

# ===================== BƯỚC 7: KIỂM TRA CHỮ KÝ =====================
try:
    with open(PDF_OUTPUT, "rb") as f:
        validation = validate_pdf_signature(f)
        print("\n🔍 Kết quả xác thực chữ ký:")
        print(validation.summary())
except Exception as e:
    print("⚠️ Không thể xác thực chữ ký:", e)

# ===================== DỌN DẸP FILE TẠM =====================
try:
    os.remove(overlay_path)
    os.remove(PDF_TEMP)
except Exception:
    pass

print("\n🎉 Hoàn tất! File PDF đã ký số:", PDF_OUTPUT)
