import asyncio
import base64
import json
import os
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common import *

CA = load_ca_cert()
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
b64 = lambda b: base64.b64encode(b).decode()
unb64 = base64.b64decode


async def send_msg(w, obj):
    data = json.dumps(obj).encode()
    w.write(struct.pack(">I", len(data)) + data)
    await w.drain()


async def recv_msg(r):
    (n,) = struct.unpack(">I", await r.readexactly(4))
    return json.loads(await r.readexactly(n))


def raw(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def cert_der(cert):
    return b64(cert.public_bytes(serialization.Encoding.DER))


def cn(cert):
    return cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value


def make_hello(me, my_cert):
    eph = X25519PrivateKey.generate()
    pub = raw(eph.public_key())
    sig = load_private_key(me).sign(pub, PSS, hashes.SHA256())
    return eph, {"cert": cert_der(my_cert), "eph": b64(pub), "sig": b64(sig)}


def finish(eph, hello, initiator, me):
    """يتحقق من الشهادة والتوقيع ويشتق مفتاح الجلسة. يرجع (اسم الطرف، AESGCM)."""
    cert = x509.load_der_x509_certificate(unb64(hello["cert"]))
    ok, why = verify_certificate(cert, CA)
    if not ok:
        raise ValueError(f"bad certificate: {why}")
    peer_pub = unb64(hello["eph"])
    cert.public_key().verify(unb64(hello["sig"]), peer_pub, PSS, hashes.SHA256())
    shared = eph.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    peer = cn(cert).lower()
    a, b = (me, peer) if initiator else (peer, me)
    key = HKDF(hashes.SHA256(), 32, None, f"tp1-session|{a}|{b}".encode()).derive(shared)
    return peer, AESGCM(key)


async def secure_send(w, aes, text):
    nonce = os.urandom(12)
    await send_msg(w, {"nonce": b64(nonce), "ct": b64(aes.encrypt(nonce, text.encode(), None))})


async def secure_recv(r, aes):
    m = await recv_msg(r)
    return aes.decrypt(unb64(m["nonce"]), unb64(m["ct"]), None).decode()


async def handle_incoming(r, w, me, my_cert):
    try:
        hello = await recv_msg(r)
        eph, mine = make_hello(me, my_cert)
        peer, aes = finish(eph, hello, False, me)
        await send_msg(w, mine)
        print(f"[{me}] secure session with {peer}")
        for _ in range(3):
            print(f"[{me}] decrypted from {peer}: {await secure_recv(r, aes)}")
    except Exception as e:
        print(f"[{me}] error: {e}")
    finally:
        w.close()


async def connect_to(me, my_cert, target, texts):
    host, port = PEERS[target]
    r, w = await asyncio.open_connection(host, port)
    try:
        eph, mine = make_hello(me, my_cert)
        await send_msg(w, mine)
        peer, aes = finish(eph, await recv_msg(r), True, me)
        print(f"[{me}] secure session with {peer}")
        for t in texts:
            await secure_send(w, aes, t)
            print(f"[{me}] sent (encrypted): {t}")
    finally:
        w.close()


async def main():
    me = sys.argv[1].lower()
    my_cert = load_cert(me)
    host, port = PEERS[me]
    server = await asyncio.start_server(
        lambda r, w: handle_incoming(r, w, me, my_cert), host, port
    )
    print(f"[{me}] listening on {host}:{port}")
    if len(sys.argv) >= 3:
        await asyncio.sleep(1)
        texts = ["hello bob", "block #1 proposal", "vote: yes"]
        await connect_to(me, my_cert, sys.argv[2].lower(), texts)
        await asyncio.sleep(1)
        return
    async with server:
        await server.serve_forever()


try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("\nnode stopped")