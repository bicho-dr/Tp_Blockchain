from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

NODES = ["alice", "bob", "carol", "dave"]

# تحميل الـ CA
ca_key = serialization.load_pem_private_key(
    Path("ca/ca_key.pem").read_bytes(), password=b"ca-password"
)
ca_cert = x509.load_pem_x509_certificate(Path("ca/ca_cert.pem").read_bytes())

for node in NODES:
    out = Path("nodes") / node
    out.mkdir(parents=True, exist_ok=True)

    # 1) العقدة تولّد مفتاحها الخاص
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2) العقدة تنشئ CSR موقّعاً بمفتاحها (دليل امتلاك المفتاح الخاص)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Consortium Blockchain"),
            x509.NameAttribute(NameOID.COMMON_NAME, node.capitalize()),
        ]))
        .sign(key, hashes.SHA256())
    )

    # 3) الـ CA تتحقق من CSR ثم توقّع الشهادة
    assert csr.is_signature_valid
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                key_cert_sign=False, crl_sign=False, content_commitment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # 4) حفظ الملفات
    (out / f"{node}_key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    (out / f"{node}.csr").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    (out / f"{node}_cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[OK] {node}: certificate issued, serial {hex(cert.serial_number)[:14]}...")