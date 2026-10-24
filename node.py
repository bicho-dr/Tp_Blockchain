import asyncio
import base64
import json
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from common import *

CA = load_ca_cert()


async def send_msg(writer, obj):
    data = json.dumps(obj).encode()
    writer.write(struct.pack(">I", len(data)) + data)  # 4 بايت للطول
    await writer.drain()


async def recv_msg(reader):
    header = await reader.readexactly(4)
    (length,) = struct.unpack(">I", header)
    return json.loads(await reader.readexactly(length))


def cert_to_b64(cert):
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def cert_from_b64(s):
    return x509.load_der_x509_certificate(base64.b64decode(s))


def common_name(cert):
    return cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value


async def handle_incoming(reader, writer, me, my_cert):
    """الطرف المستقبِل: يستلم شهادة الطالب، يتحقق، ثم يرد بشهادته."""
    try:
        hello = await recv_msg(reader)
        peer_cert = cert_from_b64(hello["cert"])
        ok, why = verify_certificate(peer_cert, CA)
        if not ok:
            print(f"[{me}] REJECTED connection: {why}")
            await send_msg(writer, {"type": "reject", "reason": why})
            return
        peer = common_name(peer_cert)
        print(f"[{me}] accepted certificate of {peer}")
        await send_msg(writer, {"type": "hello", "cert": cert_to_b64(my_cert)})
        msg = await recv_msg(reader)
        print(f"[{me}] received from {peer}: {msg['text']}")
    except Exception as e:
        print(f"[{me}] connection error: {e}")
    finally:
        writer.close()


async def connect_to(me, my_cert, target, text):
    """الطرف المبادِر: يرسل شهادته، يتحقق من رد الطرف الآخر، ثم يرسل الرسالة."""
    host, port = PEERS[target]
    reader, writer = await asyncio.open_connection(host, port)
    try:
        await send_msg(writer, {"type": "hello", "cert": cert_to_b64(my_cert)})
        reply = await recv_msg(reader)
        if reply["type"] == "reject":
            print(f"[{me}] {target} rejected me: {reply['reason']}")
            return
        peer_cert = cert_from_b64(reply["cert"])
        ok, why = verify_certificate(peer_cert, CA)
        if not ok:
            print(f"[{me}] I reject {target}: {why}")
            return
        print(f"[{me}] {target}'s certificate verified, sending message")
        await send_msg(writer, {"type": "plain", "text": text})
    finally:
        writer.close()


async def main():
    me = sys.argv[1].lower()
    my_cert = load_cert(me)
    host, port = PEERS[me]

    server = await asyncio.start_server(
        lambda r, w: handle_incoming(r, w, me, my_cert), host, port
    )
    print(f"[{me}] listening on {host}:{port}")

    # python node.py alice bob "hello"  -> alice ترسل إلى bob ثم تنتهي
    if len(sys.argv) >= 4:
        await asyncio.sleep(1)
        await connect_to(me, my_cert, sys.argv[2].lower(), sys.argv[3])
        await asyncio.sleep(1)
        return
    async with server:
        await server.serve_forever()


asyncio.run(main())