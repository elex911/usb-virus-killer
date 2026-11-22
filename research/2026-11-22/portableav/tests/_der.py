"""测试用的 DER / 证书构造工具（只给测试用，不进产品路径）。"""

from __future__ import annotations

import datetime as dt
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_CTL = "1.3.6.1.4.1.311.10.1"
OID_SPC_INDIRECT = "1.3.6.1.4.1.311.2.1.4"


def L(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def T(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + L(len(content)) + content


def seq(*parts: bytes) -> bytes:
    return T(0x30, b"".join(parts))


def set_(*parts: bytes) -> bytes:
    return T(0x31, b"".join(parts))


def integer(value: int) -> bytes:
    if value == 0:
        return T(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return T(0x02, raw)


def oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = bytearray([p & 0x7F])
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunk))
    return T(0x06, bytes(body))


def octets(data: bytes) -> bytes:
    return T(0x04, data)


def null() -> bytes:
    return T(0x05, b"")


def algid(dotted_oid: str) -> bytes:
    return seq(oid(dotted_oid), null())


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_cert(cn: str, issuer_cert=None, issuer_key=None, is_ca=False,
              code_signing=True, timestamping=False,
              not_before=None, not_after=None, serial=1001):
    key = make_key()
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
               .issuer_name(issuer_cert.subject if issuer_cert is not None else
                            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
               .public_key(key.public_key())
               .serial_number(serial)
               .not_valid_before(not_before or (now - dt.timedelta(days=1)))
               .not_valid_after(not_after or (now + dt.timedelta(days=365))))
    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                        critical=True)
    ekus = []
    if code_signing:
        ekus.append(ExtendedKeyUsageOID.CODE_SIGNING)
    if timestamping:
        ekus.append(ExtendedKeyUsageOID.TIME_STAMPING)
    if ekus:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
    cert = builder.sign(issuer_key if issuer_key is not None else key, hashes.SHA256())
    return key, cert


def cert_der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def build_pkcs7(econtent: bytes, econtent_type: str, signer_cert, signer_key,
                extra_certs=(), sign_bytes=None):
    """构造 PKCS#7 SignedData（CMS 形态：eContent 用 OCTET STRING 包裹）。"""
    body_to_sign = econtent if sign_bytes is None else sign_bytes
    attrs = set_(
        seq(oid("1.2.840.113549.1.9.3"), set_(oid(econtent_type))),
        seq(oid("1.2.840.113549.1.9.4"), set_(octets(hashlib.sha256(body_to_sign).digest()))),
    )
    signature = signer_key.sign(attrs, padding.PKCS1v15(), hashes.SHA256())
    signer_info = seq(
        integer(1),
        seq(signer_cert.issuer.public_bytes(), integer(signer_cert.serial_number)),
        algid(OID_SHA256),
        bytes([0xA0]) + attrs[1:],
        algid(OID_SHA256_RSA),
        octets(signature),
    )
    signed_data = seq(
        integer(1),
        set_(algid(OID_SHA256)),
        seq(oid(econtent_type), T(0xA0, octets(econtent))),
        T(0xA0, b"".join(cert_der(c) for c in (signer_cert,) + tuple(extra_certs))),
        set_(signer_info),
    )
    return seq(oid(OID_SIGNED_DATA), T(0xA0, signed_data))


def build_ctl(hashes) -> bytes:
    """构造 CTL：subjectIdentifier 直接是摘要字节（最常见形态）。"""
    entries = b"".join(seq(octets(h)) for h in hashes)
    return seq(
        integer(1),
        seq(oid("1.3.6.1.4.1.311.12.1.1")),          # subjectUsage
        algid("1.3.6.1.4.1.311.12.1.2"),             # subjectAlgorithm
        seq(entries),                                 # ctlEntries
    )


def build_name_ctl(name_hash_pairs) -> bytes:
    """构造名字型 CTL：subjectIdentifier 是名字，摘要在 SPC_INDIRECT_DATA 属性里。"""
    entries = b""
    for name, digest in name_hash_pairs:
        spc = seq(
            seq(oid("1.3.6.1.4.1.311.2.1.15")),
            seq(algid("1.3.14.3.2.26"), octets(digest)),
        ) if len(digest) == 20 else seq(
            seq(oid("1.3.6.1.4.1.311.2.1.15")),
            seq(algid(OID_SHA256), octets(digest)),
        )
        attr = seq(oid(OID_SPC_INDIRECT), set_(spc))
        entries += seq(octets(name.encode("utf-16-le")), set_(attr))
    return seq(
        integer(1),
        seq(oid("1.3.6.1.4.1.311.12.1.1")),
        algid("1.3.6.1.4.1.311.12.1.2"),
        seq(entries),
    )
