import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common import load_cert, load_private_key

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def raw(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def make_hello(name):
    """يولّد مفتاحاً مؤقتاً ويوقّع عموميّه بمفتاح RSA الخاص بالعقدة."""
    eph_priv = X25519PrivateKey.generate()
    eph_pub = raw(eph_priv.public_key())
    sig = load_private_key(name).sign(eph_pub, PSS, hashes.SHA256())
    return eph_priv, eph_pub, sig


def derive_key(my_eph_priv, peer_eph_pub, peer_name, peer_sig, a, b):
    """يتحقق من توقيع الطرف الآخر ثم يشتق مفتاح AES."""
    load_cert(peer_name).public_key().verify(peer_sig, peer_eph_pub, PSS, hashes.SHA256())
    shared = my_eph_priv.exchange(X25519PublicKey.from_public_bytes(peer_eph_pub))
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=f"tp1-session|{a}|{b}".encode(),
    ).derive(shared)


# ---- Alice و Bob يتبادلان hello ----
a_priv, a_pub, a_sig = make_hello("alice")
b_priv, b_pub, b_sig = make_hello("bob")

key_alice = derive_key(a_priv, b_pub, "bob", b_sig, "alice", "bob")
key_bob = derive_key(b_priv, a_pub, "alice", a_sig, "alice", "bob")

print("Same session key :", key_alice == key_bob)
print("Key (hex)        :", key_alice.hex()[:32], "...")

# ---- عدة رسائل ----
aes_a, aes_b = AESGCM(key_alice), AESGCM(key_bob)
for i, text in enumerate([b"hello bob", b"block #1 proposal", b"vote: yes"]):
    nonce = os.urandom(12)
    ct = aes_a.encrypt(nonce, text, None)
    print(f"msg {i}: ct={ct.hex()[:24]}...  ->  Bob reads: {aes_b.decrypt(nonce, ct, None)}")

# ---- هجوم MITM: مهاجم يستبدل المفتاح المؤقت بمفتاحه ----
m_priv = X25519PrivateKey.generate()
try:
    derive_key(a_priv, raw(m_priv.public_key()), "bob", b_sig, "alice", "bob")
    print("MITM             : SUCCESS (should never happen!)")
except Exception:
    print("MITM             : REJECTED (signature does not match)")