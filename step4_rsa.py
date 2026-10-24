from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from common import load_cert, load_private_key

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

# Alice تأخذ المفتاح العمومي من شهادة Bob
bob_public = load_cert("bob").public_key()
message = b"salam bob, this is a secret"

c1 = bob_public.encrypt(message, OAEP)
c2 = bob_public.encrypt(message, OAEP)

print("Ciphertext size  :", len(c1), "bytes")
print("Ciphertext (hex) :", c1.hex()[:60], "...")
print("Same msg, 2nd enc:", c2.hex()[:60], "...")
print("c1 == c2 ?       :", c1 == c2, "(OAEP is randomized)")

# Bob يفك التشفير بمفتاحه الخاص
bob_private = load_private_key("bob")
print("Bob decrypts     :", bob_private.decrypt(c1, OAEP))

# Carol تحاول فك التشفير بمفتاحها: يجب أن تفشل
try:
    load_private_key("carol").decrypt(c1, OAEP)
    print("Carol decrypts   : SUCCESS (should never happen!)")
except ValueError:
    print("Carol decrypts   : FAILED (as expected)")

# رسالة أطول من الحد الأقصى
try:
    bob_public.encrypt(b"A" * 191, OAEP)
except ValueError as e:
    print("191 bytes        : REFUSED ->", e)