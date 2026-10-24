from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OUT = Path("ca")
OUT.mkdir(exist_ok=True)

# 1) المفتاح الخاص للـ CA
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

# 2) هوية الـ CA (subject = issuer لأنها self-signed)
name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "DZ"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Consortium Blockchain"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Consortium Root CA"),
])

# 3) بناء الشهادة الجذرية وتوقيعها بمفتاح الـ CA نفسه
now = datetime.now(timezone.utc)
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    .sign(ca_key, hashes.SHA256())
)

# 4) حفظ المفتاح (مشفّر بكلمة سر) والشهادة
(OUT / "ca_key.pem").write_bytes(
    ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"ca-password"),
    )
)
(OUT / "ca_cert.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

print("CA created in ./ca/")
print("Subject:", ca_cert.subject.rfc4514_string())
print("Valid until:", ca_cert.not_valid_after_utc)