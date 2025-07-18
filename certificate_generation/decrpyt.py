import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# 取得.py所在的資料夾路徑
base_dir = os.path.dirname(os.path.abspath(__file__))

# 使用者輸入檔名，預設為 ca.pem
filename = input("請輸入 PEM 或 KEY 檔案名稱（預設 ca.pem）: ").strip()
if not filename:
    filename = "ca.pem"

# 拼出完整路徑
cert_path = os.path.join(base_dir+".\\cert", filename)

# 讀取與解析憑證
with open(cert_path, "rb") as f:
    cert_data = f.read()

if b"BEGIN CERTIFICATE" in cert_data:
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    public_key = cert.public_key()

    print("="*50)
    print("🔐 公鑰加密演算法：")
    if isinstance(public_key, rsa.RSAPublicKey):
        print(f"  - 類型: RSA")
        print(f"  - 金鑰長度: {public_key.key_size} bits")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        print(f"  - 類型: EC")
        print(f"  - 曲線: {public_key.curve.name}")
    else:
        print("  - ⚠️ 未知的公鑰類型")
    print("="*50)
    # 輸出憑證資訊
    print(f"Subject: {cert.subject}")
    print(f"Issuer: {cert.issuer}")
    print(f"Not Before: {cert.not_valid_before_utc}")
    print(f"Not After : {cert.not_valid_after_utc}")
    print("Extensions:")
    for ext in cert.extensions:
        print(f" - {ext.oid._name}: {ext.value}")
    print(f"Signature Algorithm: {cert.signature_hash_algorithm.name}")

elif b"BEGIN PRIVATE KEY" in cert_data or b"BEGIN RSA PRIVATE KEY" in cert_data or b"BEGIN EC PRIVATE KEY" in cert_data:
    # === 解析私鑰 ===
    private_key = serialization.load_pem_private_key(cert_data, password=None, backend=default_backend())
    print("="*50)
    print("🔐 檔案類型：私鑰 (.key)")
    if isinstance(private_key, rsa.RSAPrivateKey):
        print(f"  - 類型: RSA")
        print(f"  - 金鑰長度: {private_key.key_size} bits")
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        print(f"  - 類型: EC")
        print(f"  - 曲線: {private_key.curve.name}")
    else:
        print("  - ⚠️ 未知的私鑰類型")
else:
    print("⚠️ 無法識別的檔案內容：不是憑證 (.pem) 也不是私鑰 (.key)")