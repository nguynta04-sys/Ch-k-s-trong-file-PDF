#!/usr/bin/env python3
# verify_log.py

import os
import sys
import base64
import hashlib
import binascii
from datetime import datetime

from PyPDF2 import PdfReader
from asn1crypto import cms, x509, tsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError


# ============ HÀM HỖ TRỢ GHI LOG ============
def make_logger(log_path="verify_log.txt"):
    """Tạo hàm log in ra console và đồng thời ghi vào file"""
    def log(*args, **kwargs):
        msg = " ".join(str(a) for a in args)
        print(msg, **kwargs)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    # reset file cũ
    open(log_path, "w").close()
    return log


# ============ CÁC HÀM HỖ TRỢ KÝ ============
def to_bytes(obj):
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, str):
        return obj.encode("utf-8")
    return bytes(obj)


def extract_signature_field(reader: PdfReader, sig_field_name=None):
    root = reader.trailer.get("/Root")
    if hasattr(root, "get_object"):
        root = root.get_object()

    acro = None
    try:
        acro = root.get("/AcroForm")
        if hasattr(acro, "get_object"):
            acro = acro.get_object()
    except Exception:
        pass

    fields = []
    if acro:
        try:
            for ref in acro.get("/Fields", []):
                try:
                    f = ref.get_object()
                except Exception:
                    f = ref
                fields.append(f)
        except Exception:
            pass

    def walk_fields(flist):
        for f in flist:
            try:
                if f.get("/FT") == "/Sig" or f.get("/Subtype") == "/Widget":
                    yield f
                kids = f.get("/Kids")
                if kids:
                    for k in kids:
                        yield from walk_fields([k.get_object()])
            except Exception:
                pass

    sig_fields = list(walk_fields(fields))
    if not sig_fields:
        for p in reader.pages:
            for a in p.get("/Annots", []) or []:
                try:
                    ao = a.get_object()
                except Exception:
                    ao = a
                if ao.get("/FT") == "/Sig" or ao.get("/Subtype") == "/Widget":
                    sig_fields.append(ao)

    if not sig_fields:
        raise ValueError("❌ Không tìm thấy trường chữ ký trong PDF.")

    chosen = sig_fields[0]
    if sig_field_name:
        for s in sig_fields:
            if s.get("/T") == sig_field_name:
                chosen = s
                break

    sig_dict = chosen.get("/V") or chosen
    if hasattr(sig_dict, "get_object"):
        sig_dict = sig_dict.get_object()

    contents = sig_dict.get("/Contents")
    byte_range = sig_dict.get("/ByteRange")

    if contents is None or byte_range is None:
        raise ValueError("❌ Thiếu /Contents hoặc /ByteRange trong chữ ký.")

    if isinstance(contents, str):
        contents_b = binascii.unhexlify(contents)
    else:
        contents_b = contents.get_data() if hasattr(contents, "get_data") else to_bytes(contents)

    return {"contents": contents_b, "byte_range": [int(x) for x in byte_range], "sig_dict": sig_dict}


def parse_pkcs7(contents):
    ci = cms.ContentInfo.load(contents.rstrip(b"\x00"))
    if ci["content_type"].native != "signed_data":
        raise ValueError("❌ PKCS#7 không phải SignedData")
    return ci, ci["content"]


def compute_digest(pdf_path, byte_range):
    h = hashlib.sha256()
    with open(pdf_path, "rb") as f:
        for i in range(0, len(byte_range), 2):
            off, ln = byte_range[i], byte_range[i + 1]
            f.seek(off)
            h.update(f.read(ln))
    return h.digest()


def extract_message_digest(signer_info):
    for at in signer_info["signed_attrs"] or []:
        if at["type"].native == "message_digest":
            return at["values"][0].native
    return None


def verify_signature(signer_info, signer_cert):
    sig = signer_info["signature"].native
    data = signer_info["signed_attrs"].dump()
    pub = load_der_public_key(signer_cert.dump())

    digest_algo = signer_info["digest_algorithm"]["algorithm"].native
    hash_alg = {
        "sha1": hashes.SHA1(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }.get(digest_algo, hashes.SHA256())

    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(sig, data, padding.PKCS1v15(), hash_alg)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, data, ec.ECDSA(hash_alg))
    else:
        raise ValueError("Loại public key không hỗ trợ.")


def validate_chain(signer_cert, extra_certs, trust_roots=None):
    roots = []
    if trust_roots:
        for path in trust_roots:
            with open(path, "rb") as f:
                data = f.read()
                if b"-----BEGIN" in data:
                    b64 = b"".join(l for l in data.splitlines() if not l.startswith(b"-----"))
                    der = base64.b64decode(b64)
                else:
                    der = data
                roots.append(x509.Certificate.load(der))
    vc = ValidationContext(trust_roots=roots or None)
    CertificateValidator(signer_cert, intermediate_certs=extra_certs, validation_context=vc).validate_usage(set())


def extract_timestamp(signer_info):
    for at in signer_info["unsigned_attrs"] or []:
        if at["type"].dotted == "1.2.840.113549.1.9.16.2.14":
            try:
                ci = cms.ContentInfo.load(at["values"][0].dump())
                return ci["content"]["tst_info"]["gen_time"].native
            except Exception:
                return None
    return None


def detect_incremental_update(pdf_path, byte_range):
    file_size = os.path.getsize(pdf_path)
    covered = sum(byte_range[i + 1] for i in range(0, len(byte_range), 2))
    return file_size != covered, file_size, covered


# ============ MAIN ============
def inspect_pdf_signature(pdf_path, sig_field_name=None, trust_roots=None, log_path="verify_log.txt"):
    log = make_logger(log_path)
    log(f"🔍 Kiểm tra chữ ký PDF: {pdf_path}")
    reader = PdfReader(pdf_path)

    sig_data = extract_signature_field(reader, sig_field_name)
    contents = sig_data["contents"]
    br = sig_data["byte_range"]
    log(f"✅ Đã tìm thấy chữ ký, ByteRange={br}")

    ci, sd = parse_pkcs7(contents)
    signer_info = sd["signer_infos"][0]
    certs = [c.chosen for c in sd["certificates"] if isinstance(c.chosen, x509.Certificate)]
    signer_cert = certs[0]
    log(f"✅ PKCS#7 hợp lệ, có {len(certs)} certificate.")
    log("   Người ký:", signer_cert.subject.human_friendly)

    computed = compute_digest(pdf_path, br)
    msg_digest = extract_message_digest(signer_info)
    log("   SHA256(ByteRange) =", binascii.hexlify(computed).decode())
    log("   messageDigest     =", binascii.hexlify(msg_digest or b'').decode())

    if msg_digest and msg_digest == computed:
        log("✅ messageDigest khớp dữ liệu PDF")
    else:
        log("⚠️ messageDigest không khớp!")

    try:
        verify_signature(signer_info, signer_cert)
        log("✅ Xác minh chữ ký bằng public key: HỢP LỆ.")
    except Exception as e:
        log("❌ Lỗi xác minh chữ ký:", e)

    extra = [c for c in certs if c != signer_cert]
    try:
        validate_chain(signer_cert, extra, trust_roots)
        log("✅ Chain certificate hợp lệ đến CA tin cậy.")
    except Exception as e:
        log("⚠️ Lỗi kiểm tra chain:", e)

    ts = extract_timestamp(signer_info)
    if ts:
        log("✅ Timestamp:", ts)
    else:
        log("ℹ️ Không có timestamp trong chữ ký.")

    modified, size, covered = detect_incremental_update(pdf_path, br)
    if modified:
        log(f"⚠️ File đã bị thay đổi (size={size}, covered={covered})")
    else:
        log("✅ Không phát hiện sửa đổi sau khi ký.")

    log("\n🎯 Hoàn tất kiểm tra chữ ký PDF.")


# ============ CLI ============
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_log.py <signed.pdf> [SignatureName] [rootCA.pem ...]")
        sys.exit(1)

    pdf = sys.argv[1]
    field = sys.argv[2] if len(sys.argv) >= 3 else None
    roots = sys.argv[3:] if len(sys.argv) >= 4 else None

    inspect_pdf_signature(pdf, field, roots, log_path="verify_log.txt")
    print("\n📄 Kết quả đã được lưu vào: verify_log.txt")
