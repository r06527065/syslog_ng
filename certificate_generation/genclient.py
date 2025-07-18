import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509 import BasicConstraints, KeyUsage, ExtendedKeyUsage
from datetime import datetime, timedelta, timezone

# === 1. 路徑設定 ===
base_dir = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.join(base_dir, "cert")
os.makedirs(output_dir, exist_ok=True)

# === 2. 載入 CA 憑證與私鑰 ===
ca_cert_name = input("請輸入ca_cert_name（python-CA-key-sha.pem）: ")
ca_key_name = input("請輸入ca_key_name（python-CA-key-sha.key）: ")
ca_cert_path = os.path.join(output_dir, ca_cert_name)
ca_key_path = os.path.join(output_dir, ca_key_name)

with open(ca_cert_path, "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())
with open(ca_key_path, "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)

# === 3. 產生新的 client 金鑰對 ===
key_type = input("請輸入金鑰類型（rsa/ec，預設 rsa）: ").strip().lower()
if key_type not in ("rsa", "ec"):
    key_type = "rsa"

if key_type == "rsa":
    key_size_input = input("請輸入 RSA 金鑰大小（2048/4096，預設 2048）: ").strip()
    key_size = int(key_size_input) if key_size_input in ("1024","2048","3072","4096") else 2048
    curve_name = None
else:
    key_size = None
    # 若為 EC，選擇曲線
    ec_curve_input = input("請輸入 EC 曲線名稱（p256r1/p384r1/p521r1，預設 p256r1）: ").strip().lower()
    curve_map = {
        "p256r1": ec.SECP256R1(),
        "p384r1": ec.SECP384R1(),
        "p521r1": ec.SECP521R1(),
    }
    curve = curve_map.get(ec_curve_input, ec.SECP256R1())
    curve_name = ec_curve_input if ec_curve_input in curve_map else "p256r1"

hash_bits = input("請輸入雜湊長度（256/384，預設 256）: ").strip()
if hash_bits == "384":
    hash_algorithm = hashes.SHA384()
else:
    hash_bits = "256"
    hash_algorithm = hashes.SHA256()
# label
if key_type == "rsa":
    key_label = f"{key_type}{key_size}"
elif key_type == "ec":
    key_label = f"{key_type}-{curve_name}"
file_prefix = f"python-client-{key_label}-sha{hash_bits}"
# construction
if key_type == "rsa":
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
elif key_type == "ec":
    client_key = ec.generate_private_key(curve)  # 預設為 P-256
else:
    raise ValueError("不支援的金鑰類型")

# === 4. 構造 Subject ===
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Taiwan"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, file_prefix),
])

# === 5. 構造時間 ===
valid_from = datetime.now(timezone.utc)
valid_to = valid_from + timedelta(days=365 * 100)

# === 6. 建立證書內容 ===
builder = x509.CertificateBuilder()
builder = builder.subject_name(subject)
builder = builder.issuer_name(ca_cert.subject)
builder = builder.public_key(client_key.public_key())
builder = builder.serial_number(x509.random_serial_number())
builder = builder.not_valid_before(valid_from)
builder = builder.not_valid_after(valid_to)

# === 7. 加入 Extensions ===
builder = builder.add_extension(
    BasicConstraints(ca=False, path_length=None), critical=True
)
builder = builder.add_extension(
    KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=True,
        data_encipherment=True,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    ), critical=True
)
builder = builder.add_extension(
    ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
    critical=False
)

# === 8. 使用 CA 私鑰簽章 ===
client_cert = builder.sign(private_key=ca_key, algorithm=hash_algorithm)

# === 9. 儲存 output ===
with open(os.path.join(output_dir, f"{file_prefix}.key"), "wb") as f:
    f.write(client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open(os.path.join(output_dir, f"{file_prefix}.pem"), "wb") as f:
    f.write(client_cert.public_bytes(serialization.Encoding.PEM))

print("✔ Client certificate generated successfully.")
