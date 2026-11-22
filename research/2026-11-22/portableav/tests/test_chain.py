"""chain.py 的验证：用合成 CA 链证明「伪造签名必须被拒」。

为什么不用真实 .cat 来测这条：真实文件只能证明"能通过"，
证明不了"该拒的会拒"。红线的证据必须来自对手视角——自己造一个假 CA、
造一张假编录，然后要求验证器说不。
"""

from __future__ import annotations

import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from portableav import chain

crypto = pytest.importorskip("cryptography", reason="需要 cryptography 生成测试证书")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# ------------------------------------------------------------------ DER

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _t(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _seq(*parts: bytes) -> bytes:
    return _t(0x30, b"".join(parts))


def _set(*parts: bytes) -> bytes:
    return _t(0x31, b"".join(parts))


def _int(value: int) -> bytes:
    if value == 0:
        return _t(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _t(0x02, raw)


def _oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = bytearray([p & 0x7F])
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunk))
    return _t(0x06, bytes(body))


def _octets(data: bytes) -> bytes:
    return _t(0x04, data)


def _seq_oid(dotted: str) -> bytes:
    return _seq(_oid(dotted), _t(0x05, b""))


# ------------------------------------------------------------ 造证书

def _make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_cert(subject_cn, issuer_cert=None, issuer_key=None, is_ca=False,
               code_signing=True, not_before=None, not_after=None, serial=1001):
    key = _make_key()
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
               .issuer_name(issuer_cert.subject if issuer_cert else
                            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
               .public_key(key.public_key())
               .serial_number(serial)
               .not_valid_before(not_before or (now - dt.timedelta(days=1)))
               .not_valid_after(not_after or (now + dt.timedelta(days=365))))
    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if code_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return key, cert


def _cert_der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _signer_info(cert, issuer_name_der, sig_algo_oid, digest_oid, econtent, econtent_type,
                 key, attrs_tag=0xA0):
    """构造 SignerInfo；attrs 先按 SET(0x31) 编码并据此验签，嵌入时改成 [0]。"""
    attrs_set = _set(
        _seq(_oid("1.2.840.113549.1.9.3"), _set(_oid(econtent_type))),
        _seq(_oid("1.2.840.113549.1.9.4"),
             _set(_octets(__import__("hashlib").sha256(econtent).digest()))),
    )
    signature = key.sign(attrs_set, padding.PKCS1v15(), hashes.SHA256())
    attrs_implicit = bytes([attrs_tag]) + attrs_set[1:]
    return _seq(
        _int(1),
        _seq(issuer_name_der, _int(cert.serial_number)),
        _seq_oid(digest_oid),
        attrs_implicit,
        _seq_oid(sig_algo_oid),
        _octets(signature),
    )


def _build_pkcs7(econtent, econtent_type, signer_cert, signer_key, extra_certs=(),
                 tamper=None):
    signed_data = _seq(
        _int(1),
        _set(_seq_oid("2.16.840.1.101.3.4.2.1")),
        _seq(_oid(econtent_type), _t(0xA0, _octets(econtent))),
        _t(0xA0, b"".join(_cert_der(c) for c in (signer_cert,) + tuple(extra_certs))),
        _set(_signer_info(signer_cert, signer_cert.issuer.public_bytes(),
                          "1.2.840.113549.1.1.11", "2.16.840.1.101.3.4.2.1",
                          econtent, econtent_type, signer_key)),
    )
    blob = _seq(_oid("1.2.840.113549.1.7.2"), _t(0xA0, signed_data))
    if tamper:
        blob = tamper(blob)
    return blob


CTL_OID = "1.3.6.1.4.1.311.10.1"
FAKE_CTL = _seq(_int(1), _octets(b"fake-catalog-payload-0123456789"))


def _roots(*certs):
    return [chain.parse_cert(_cert_der(c)) for c in certs]


# --------------------------------------------------------------- 用例

def test_valid_chain_accepted():
    root_key, root = _make_cert("Test Root CA", is_ca=True, code_signing=False, serial=1)
    leaf_key, leaf = _make_cert("Test Publisher", root, root_key, serial=2)
    blob = _build_pkcs7(FAKE_CTL, CTL_OID, leaf, leaf_key)
    res = chain.verify_pkcs7(blob, _roots(root))
    assert res.ok is True, res.reason
    assert res.econtent == FAKE_CTL
    assert len(res.chain.chain) == 2


def test_self_signed_forgery_rejected():
    """攻击者自建 CA + 自签证书冒充发布者：根集合里没有它 → 必须拒绝。"""
    fake_key, fake_root = _make_cert("Microsoft Windows", is_ca=True, code_signing=False, serial=9)
    evil_key, evil = _make_cert("Microsoft Windows", fake_root, fake_key, serial=10)
    blob = _build_pkcs7(FAKE_CTL, CTL_OID, evil, evil_key)
    res = chain.verify_pkcs7(blob, [])
    assert res.ok is False
    assert "找不到签发者" in res.reason or "自签名" in res.reason, res.reason


def test_tampered_content_rejected():
    root_key, root = _make_cert("Test Root CA", is_ca=True, code_signing=False, serial=1)
    leaf_key, leaf = _make_cert("Test Publisher", root, root_key, serial=2)
    blob = _build_pkcs7(FAKE_CTL, CTL_OID, leaf, leaf_key)
    # 在 eContent 里改一个字节（模拟"签名后往编录里塞哈希"）
    bad = blob.replace(b"fake-catalog-payload", b"fake-catalog-payloaX")
    assert bad != blob
    res = chain.verify_pkcs7(bad, _roots(root))
    assert res.ok is False, res.reason


def test_missing_code_signing_eku_rejected():
    root_key, root = _make_cert("Test Root CA", is_ca=True, code_signing=False, serial=1)
    leaf_key, leaf = _make_cert("Test Publisher", root, root_key, code_signing=False, serial=3)
    blob = _build_pkcs7(FAKE_CTL, CTL_OID, leaf, leaf_key)
    res = chain.verify_pkcs7(blob, _roots(root), require_eku=True)
    assert res.ok is False
    assert "EKU" in res.reason


def test_expired_leaf_rejected():
    root_key, root = _make_cert("Test Root CA", is_ca=True, code_signing=False, serial=1)
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=400)
    leaf_key, leaf = _make_cert("Test Publisher", root, root_key,
                                not_before=old, not_after=old + dt.timedelta(days=10), serial=4)
    blob = _build_pkcs7(FAKE_CTL, CTL_OID, leaf, leaf_key)
    res = chain.verify_pkcs7(blob, _roots(root))
    assert res.ok is False
    assert "有效期" in res.reason


def test_intermediate_chain_accepted():
    """根 → 中间 → 叶：中间证书必须来自 SignedData 自带的池子。"""
    root_key, root = _make_cert("Test Root CA", is_ca=True, code_signing=False, serial=1)
    mid_key, mid = _make_cert("Test Intermediate", root, root_key, is_ca=True,
                              code_signing=False, serial=5)
    leaf_key, leaf = _make_cert("Test Publisher", mid, mid_key, serial=6)
    blob = _build_pkcs7(FAKE_CTL, CTL_OID, leaf, leaf_key, extra_certs=(mid,))
    res = chain.verify_pkcs7(blob, _roots(root))
    assert res.ok is True, res.reason
    assert len(res.chain.chain) == 3


def test_no_roots_never_trusts():
    """没有离线根证书库时，任何签名都不得被当成"已验证"。"""
    root_key, root = _make_cert("Test Root CA", is_ca=True, code_signing=False, serial=1)
    leaf_key, leaf = _make_cert("Test Publisher", root, root_key, serial=2)
    blob = _build_pkcs7(FAKE_CTL, CTL_OID, leaf, leaf_key)
    res = chain.verify_pkcs7(blob, [])
    assert res.ok is False


def test_garbage_never_raises():
    for blob in (b"", b"\x00" * 10, b"\x30\x82\xff\xff" + b"A" * 20, os.urandom(64)):
        res = chain.verify_pkcs7(blob, [])
        assert res.ok is False
        assert res.reason
