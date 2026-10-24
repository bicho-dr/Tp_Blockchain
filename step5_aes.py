import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

key = AESGCM.generate_key(bit_length=256)   # 32 بايت
aes = AESGCM(key)

message = b"A long message, " * 1000          # 16 KB، أكبر بكثير من حد RSA
nonce = os.urandom(12)                         # 12 بايت، يجب ألا يتكرر مع نفس المفتاح
ciphertext = aes.encrypt(nonce, message, None)

print("Plaintext size  :", len(message), "bytes")
print("Ciphertext size :", len(ciphertext), "bytes (= plaintext + 16 tag)")
print("Decrypt OK      :", aes.decrypt(nonce, ciphertext, None) == message)

# العبث: نقلب بتاً واحداً في الشيفر
tampered = bytearray(ciphertext)
tampered[10] ^= 0x01
try:
    aes.decrypt(nonce, bytes(tampered), None)
    print("Tampered decrypt: SUCCESS (should never happen!)")
except InvalidTag:
    print("Tampered decrypt: FAILED -> InvalidTag (tampering detected)")

# مفتاح خاطئ
try:
    AESGCM(AESGCM.generate_key(256)).decrypt(nonce, ciphertext, None)
except InvalidTag:
    print("Wrong key       : FAILED -> InvalidTag")