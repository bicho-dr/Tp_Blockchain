import sys
from cryptography import x509

path = sys.argv[1]
cert = x509.load_pem_x509_certificate(open(path, "rb").read())

print("Subject      :", cert.subject.rfc4514_string())
print("Issuer       :", cert.issuer.rfc4514_string())
print("Serial       :", hex(cert.serial_number))
print("Valid from   :", cert.not_valid_before_utc)
print("Valid until  :", cert.not_valid_after_utc)
print("Signature alg:", cert.signature_hash_algorithm.name)
print("Public key   :", type(cert.public_key()).__name__,
      cert.public_key().key_size, "bits")
for ext in cert.extensions:
    print("Extension    :", ext.oid._name, "| critical =", ext.critical)