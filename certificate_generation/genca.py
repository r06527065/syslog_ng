import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509 import BasicConstraints, KeyUsage
from datetime import datetime, timedelta, timezone

# file storage position
base_dir = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.join(base_dir, "cert")
os.makedirs(output_dir, exist_ok=True)

### Deal with configuration of input

key_type = input("請輸入金鑰類型（rsa/ec，預設 rsa）: ").strip().lower()
if key_type not in ("rsa", "ec"):
    key_type = "rsa"

# 2. 金鑰長度（僅 RSA 使用）
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

# 3. 雜湊演算法
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
file_prefix = f"python-CA-{key_label}-sha{hash_bits}"

# Step 1: Start Construction
if key_type == "rsa":
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
elif key_type == "ec":
    private_key = ec.generate_private_key(curve)  # 預設為 P-256
else:
    raise ValueError("不支援的金鑰類型")

public_key = private_key.public_key()

# Step 2: 建立 Subject / Issuer
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Taiwan"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, file_prefix),
])

# Step 3: 建立憑證內容
valid_from = datetime.now(timezone.utc)
valid_to = valid_from + timedelta(days=365 * 100)

builder = x509.CertificateBuilder()
builder = builder.subject_name(subject)
builder = builder.issuer_name(issuer)
builder = builder.public_key(public_key)
builder = builder.serial_number(x509.random_serial_number())
builder = builder.not_valid_before(valid_from)
builder = builder.not_valid_after(valid_to)

# Step 4: 加入 Extensions（等效於 OpenSSL req_ext 區塊）
builder = builder.add_extension(
    BasicConstraints(ca=True, path_length=None), critical=True
)
builder = builder.add_extension(
    KeyUsage(
        digital_signature=True,
        content_commitment=True,  # nonRepudiation
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False
    ),
    critical=True
)

# Step 5: 用私鑰簽署憑證
certificate = builder.sign(
    private_key=private_key,
    algorithm=hash_algorithm
)

# Step 6: 儲存檔案（私鑰 + 憑證）
with open(os.path.join(output_dir, f"{file_prefix}.key"), "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open(os.path.join(output_dir, f"{file_prefix}.pem"), "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))