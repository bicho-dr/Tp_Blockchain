from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

# عنوان كل عقدة (localhost + منفذ خاص بها)
PEERS = {
    "alice": ("127.0.0.1", 9001),
    "bob":   ("127.0.0.1", 9002),
    "carol": ("127.0.0.1", 9003),
    "dave":  ("127.0.0.1", 9004),
}


def load_ca_cert():
    return x509.load_pem_x509_certificate(Path("ca/ca_cert.pem").read_bytes())


def load_cert(name):
    return x509.load_pem_x509_certificate(
        Path(f"nodes/{name}/{name}_cert.pem").read_bytes()
    )


def load_private_key(name):
    return serialization.load_pem_private_key(
        Path(f"nodes/{name}/{name}_key.pem").read_bytes(), password=None
    )


def verify_certificate(cert, ca_cert):
    """يرجع (True, 'OK') أو (False, سبب الرفض)."""
    # 1) هل أصدرتها الـ CA فعلاً؟ (مقارنة اسم المُصدِر)
    if cert.issuer != ca_cert.subject:
        return False, "issuer is not our CA"

    # 2) هل توقيع الـ CA على الشهادة صحيح؟
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception:
        return False, "invalid CA signature"

    # 3) هل هي ضمن فترة الصلاحية؟
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        return False, "certificate not yet valid"
    if now > cert.not_valid_after_utc:
        return False, "certificate expired"

    # 4) شهادة عقدة نهائية فقط، وليست CA
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            return False, "CA certificate cannot be used as a node certificate"
    except x509.ExtensionNotFound:
        return False, "missing basicConstraints"

    return True, "OK"