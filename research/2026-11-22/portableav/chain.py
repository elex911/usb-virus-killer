"""X.509 / PKCS#7 验证（离线，不调用 CryptSvc、不联网查吊销）。

职责边界：
- 只做「结构解析 + 密码学验证 + 链到给定根集合」；
- 根集合由调用方提供（离线 PEM）。**没有根就一律不信任**，绝不因为"验不了"而放行；
- 返回三态：True / False / None（None = 算法不支持或依赖缺失，必须当成"未验证"）。

密码学运算交给 `cryptography`（绿包内自带，静态链 OpenSSL）。
若该依赖缺失，RSA/ECDSA 验签返回 None，链验证整体失败——不降级成"通过"。
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .authsig import SigError, TLV, children, decode_oid, read_tlv

# 摘要/签名算法 OID
OID_SHA1_RSA = "1.3.14.3.2.29"
OID_RSA_PKCS1 = {
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.3.14.3.2.29": "sha1",
}
OID_ECDSA = {
    "1.2.840.10045.4.1": "sha1",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}
OID_EKU = "2.5.29.37"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

MAX_CHAIN = 8


class ChainError(Exception):
    """证书/签名结构不可解析。"""""


@dataclass
class Cert:
    der: bytes
    subject: bytes            # Name 的 DER
    issuer: bytes
    serial: bytes
    not_before: Optional[_dt.datetime]
    not_after: Optional[_dt.datetime]
    spki_der: bytes
    sig_alg_oid: str
    signature: bytes
    tbs: bytes
    eku: Tuple[str, ...] = ()
    is_ca: bool = False
    subject_text: str = ""

    def valid_at(self, now: _dt.datetime) -> bool:
        if self.not_before and now < self.not_before:
            return False
        if self.not_after and now > self.not_after:
            return False
        return True

    def has_eku(self, oid: str) -> bool:
        """是否**显式**声明该用途。

        按 RFC 5280，缺 EKU 本应视为"不限用途"；但本引擎用 EKU 决定"能否放行"，
        宁可严：缺 EKU 的证书不参与白名单，只降级为待复核（不判恶意）。
        """
        return oid in self.eku

    @property
    def eku_state(self) -> str:
        if not self.eku:
            return "无 EKU 扩展"
        return "EKU=%s" % ",".join(self.eku)


def _time_value(data: bytes, tlv: TLV) -> Optional[_dt.datetime]:
    raw = data[tlv.value_off:tlv.value_off + tlv.value_len]
    txt = raw.decode("latin-1", "replace")
    try:
        if tlv.tag == 0x17:      # UTCTime YYMMDDHHMMSSZ
            yy = int(txt[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            return _dt.datetime(year, int(txt[2:4]), int(txt[4:6]),
                                int(txt[6:8]), int(txt[8:10]), int(txt[10:12]),
                                tzinfo=_dt.timezone.utc)
        if tlv.tag == 0x18:      # GeneralizedTime YYYYMMDDHHMMSSZ
            return _dt.datetime(int(txt[0:4]), int(txt[4:6]), int(txt[6:8]),
                                int(txt[8:10]), int(txt[10:12]), int(txt[12:14]),
                                tzinfo=_dt.timezone.utc)
    except Exception:
        return None
    return None


def _name_text(data: bytes, tlv: TLV) -> str:
    """粗粒度可读名（仅用于报告展示，不参与逻辑判断）。"""
    out = []
    for rdn in children(data, tlv):
        for atv in children(data, rdn):
            kids = children(data, atv)
            if len(kids) >= 2 and kids[0].tag == 0x06:
                oid = decode_oid(data, kids[0])
                val = data[kids[1].value_off:kids[1].value_off + kids[1].value_len]
                try:
                    text = val.decode("utf-16-be") if val[:1] == b"\x00" else val.decode("utf-8", "replace")
                except Exception:
                    text = val.decode("latin-1", "replace")
                out.append("%s=%s" % (oid, text))
    return ", ".join(out)


def parse_cert(der: bytes) -> Cert:
    top = read_tlv(der, 0)
    kids = children(der, top)
    if len(kids) < 3:
        raise ChainError("Certificate 子项不足")
    tbs = kids[0]
    sig_alg = children(der, kids[1])
    if not sig_alg:
        raise ChainError("缺少 signatureAlgorithm")
    sig_oid = decode_oid(der, sig_alg[0])
    if kids[2].tag != 0x03:
        raise ChainError("signatureValue 不是 BIT STRING")
    sig_raw = der[kids[2].value_off:kids[2].value_off + kids[2].value_len]
    if not sig_raw:
        raise ChainError("signatureValue 为空")
    signature = sig_raw[1:]          # 去掉 unused-bits 字节

    tkids = children(der, tbs)
    idx = 0
    if tkids and tkids[0].tag == 0xA0:
        idx = 1
    if len(tkids) < idx + 6:
        raise ChainError("tbsCertificate 子项不足")
    serial = der[tkids[idx].value_off:tkids[idx].value_off + tkids[idx].value_len]
    issuer_t = tkids[idx + 2]
    validity = tkids[idx + 3]
    subject_t = tkids[idx + 4]
    spki_t = tkids[idx + 5]

    vkids = children(der, validity)
    nb = _time_value(der, vkids[0]) if vkids else None
    na = _time_value(der, vkids[1]) if len(vkids) > 1 else None

    eku: List[str] = []
    is_ca = False
    for node in tkids[idx + 6:]:
        if node.tag != 0xA3:          # [3] extensions
            continue
        for ext in children(der, children(der, node)[0]):
            ekids = children(der, ext)
            if len(ekids) < 2:
                continue
            oid = decode_oid(der, ekids[0])
            value_t = ekids[-1]
            inner = der[value_t.value_off:value_t.value_off + value_t.value_len]
            if oid == OID_EKU:
                try:
                    seq = read_tlv(inner, 0)
                    for oid_t in children(inner, seq):
                        eku.append(decode_oid(inner, oid_t))
                except SigError:
                    pass
            elif oid == OID_BASIC_CONSTRAINTS:
                try:
                    seq = read_tlv(inner, 0)
                    bs = children(inner, seq)
                    if bs and bs[0].tag == 0x01:
                        is_ca = bool(inner[bs[0].value_off])
                except SigError:
                    pass

    return Cert(der=der,
                subject=der[subject_t.start:subject_t.end],
                issuer=der[issuer_t.start:issuer_t.end],
                serial=serial,
                not_before=nb, not_after=na,
                spki_der=der[spki_t.start:spki_t.end],
                sig_alg_oid=sig_oid, signature=signature,
                tbs=der[tbs.start:tbs.end],
                eku=tuple(eku), is_ca=is_ca,
                subject_text=_name_text(der, subject_t))


def _crypto_verify(spki_der: bytes, sig_alg_oid: str, data: bytes, signature: bytes,
                   hash_hint: Optional[str] = None) -> Optional[bool]:
    """True/False/None（None = 不支持或依赖缺失）。

    hash_hint：`rsaEncryption (1.2.840.113549.1.1.1)` 这类不带参数的老式算法
    本身不说明摘要，只能从 SignerInfo.digestAlgorithm 借（实测 .cat 正是这种）。
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding
    except Exception:
        return None

    if sig_alg_oid in OID_RSA_PKCS1:
        algo = OID_RSA_PKCS1[sig_alg_oid]
        is_rsa = True
    elif sig_alg_oid in OID_ECDSA:
        algo = OID_ECDSA[sig_alg_oid]
        is_rsa = False
    elif sig_alg_oid == "1.2.840.113549.1.1.1":
        algo = hash_hint or "sha256"
        is_rsa = True
    else:
        return None
    if algo not in ("sha1", "sha256", "sha384", "sha512"):
        return None
    try:
        pub = serialization.load_der_public_key(spki_der)
    except Exception:
        return None
    hash_obj = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(),
                "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}[algo]
    try:
        if is_rsa:
            pub.verify(signature, data, padding.PKCS1v15(), hash_obj)
        else:
            pub.verify(signature, data, ec.ECDSA(hash_obj))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return None


def verify_cert_signature(cert: Cert, issuer: Cert) -> Optional[bool]:
    return _crypto_verify(issuer.spki_der, cert.sig_alg_oid, cert.tbs, cert.signature)


def load_roots_from_pem(pem_text: str) -> List[Cert]:
    import base64

    roots: List[Cert] = []
    block: List[str] = []
    in_block = False
    for line in pem_text.splitlines():
        if line.startswith("-----BEGIN CERTIFICATE-----"):
            in_block, block = True, []
        elif line.startswith("-----END CERTIFICATE-----"):
            in_block = False
            try:
                roots.append(parse_cert(base64.b64decode("".join(block))))
            except Exception:
                pass
        elif in_block:
            block.append(line.strip())
    return roots


def load_roots_from_dir(path: str, suffixes=(".cer", ".crt", ".der", ".pem")) -> List[Cert]:
    import os

    out: List[Cert] = []
    try:
        names = os.listdir(path)
    except Exception:
        return out
    for name in names:
        if not name.lower().endswith(suffixes):
            continue
        p = os.path.join(path, name)
        try:
            if name.lower().endswith(".pem"):
                out.extend(load_roots_from_pem(open(p, encoding="utf-8", errors="ignore").read()))
            else:
                out.append(parse_cert(open(p, "rb").read()))
        except Exception:
            continue
    return out


@dataclass
class ChainResult:
    ok: bool
    reason: str
    chain: List[Cert] = field(default_factory=list)
    leaf_text: str = ""
    self_signed: bool = False


def build_chain_to_root(leaf: Cert, pool: Sequence[Cert], roots: Sequence[Cert],
                        now: _dt.datetime) -> ChainResult:
    """从叶证书走到受信根。任何一步失败都返回 ok=False 并写明原因。"""
    if not leaf.valid_at(now):
        return ChainResult(False, "叶证书不在有效期内", [leaf], leaf.subject_text)
    chain = [leaf]
    cur = leaf
    seen = set()
    for _ in range(MAX_CHAIN):
        if cur.subject in seen:
            return ChainResult(False, "证书链出现环", chain, leaf.subject_text)
        seen.add(cur.subject)
        # 命中受信根
        for root in roots:
            if root.subject == cur.issuer and root.subject == root.issuer:
                v = verify_cert_signature(cur, root)
                if v is True:
                    chain.append(root)
                    return ChainResult(True, "已链到受信根：%s" % root.subject_text, chain,
                                       leaf.subject_text)
        # 找中间证书
        nxt = None
        for cand in pool:
            if cand is cur or cand.subject != cur.issuer:
                continue
            if not cand.valid_at(now):
                return ChainResult(False, "中间证书不在有效期：%s" % cand.subject_text, chain,
                                   leaf.subject_text)
            if verify_cert_signature(cur, cand) is True:
                nxt = cand
                break
        if nxt is None:
            if cur.subject == cur.issuer:
                return ChainResult(False, "自签名证书，且不在受信根集合内",
                                   chain, leaf.subject_text, self_signed=True)
            return ChainResult(False, "找不到签发者：%s" % cur.issuer[:12].hex(), chain,
                               leaf.subject_text)
        chain.append(nxt)
        cur = nxt
    return ChainResult(False, "证书链超过 %d 层" % MAX_CHAIN, chain, leaf.subject_text)


def verify_cert_against_roots(cert: Cert, pool: Sequence[Cert], roots: Sequence[Cert],
                              now: _dt.datetime) -> ChainResult:
    return build_chain_to_root(cert, pool, roots, now)


# --------------------------------------------------------------- PKCS#7

@dataclass
class SignerInfo:
    digest_algo: str = ""
    signature_algo_oid: str = ""
    signature: bytes = b""
    unsigned_attrs: bool = False
    issuer_and_serial: Optional[Tuple[bytes, bytes]] = None
    message_digest_hex: str = ""
    content_type_hex: str = ""


@dataclass
class Pkcs7Result:
    ok: bool
    reason: str
    econtent_type: str = ""
    econtent: bytes = b""        # [0] 内元素的 value 八位组（摘要就用它，实测口径）
    econtent_tlv: bytes = b""    # 含 tag/len 的完整 TLV（要再解析结构时用）
    signer: Optional[Cert] = None
    chain: ChainResult = field(default_factory=lambda: ChainResult(False, "未验证"))
    certs: List[Cert] = field(default_factory=list)
    signer_count: int = 0


def _digest(name: str, data: bytes) -> Optional[bytes]:
    import hashlib

    try:
        return hashlib.new(name, data).digest()
    except Exception:
        return None


def _parse_signer(data: bytes, si: TLV) -> SignerInfo:
    out = SignerInfo()
    kids = children(data, si)
    if len(kids) < 5:
        raise ChainError("SignerInfo 子项不足")
    sid = kids[1]
    sid_kids = children(data, sid)
    # IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
    # 顺序是 issuer 在前、serial 在后；反了就会永远找不到签名者证书。
    if len(sid_kids) >= 2 and sid_kids[0].tag == 0x30 and sid_kids[1].tag == 0x02:
        out.issuer_and_serial = (data[sid_kids[0].start:sid_kids[0].end],
                                 data[sid_kids[1].value_off:
                                      sid_kids[1].value_off + sid_kids[1].value_len])
    da = children(data, kids[2])
    if da:
        oid = decode_oid(data, da[0])
        out.digest_algo = (OID_RSA_PKCS1.get(oid) or OID_ECDSA.get(oid) or
                           {"1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.1": "sha256",
                            "2.16.840.1.101.3.4.2.2": "sha384",
                            "2.16.840.1.101.3.4.2.3": "sha512"}.get(oid, ""))
    # 定位 [0] authAttrs / signatureAlgorithm / signature / [1] unauthAttrs
    rest = kids[3:]
    auth_attrs: Optional[TLV] = None
    sig_alg_oid = ""
    signature = b""
    for node in rest:
        if node.tag == 0xA0:
            auth_attrs = node
        elif node.tag == 0x30 and not sig_alg_oid:
            sub = children(data, node)
            if sub:
                sig_alg_oid = decode_oid(data, sub[0])
        elif node.tag == 0x04:
            signature = data[node.value_off:node.value_off + node.value_len]
        elif node.tag == 0xA1:
            out.unsigned_attrs = True
    out.signature_algo_oid = sig_alg_oid
    out.signature = signature
    if auth_attrs is not None:
        for attr in children(data, auth_attrs):
            akids = children(data, attr)
            if not akids or akids[0].tag != 0x06:
                continue
            oid = decode_oid(data, akids[0])
            if oid == OID_MESSAGE_DIGEST and len(akids) >= 2:
                vals = children(data, akids[1])
                if vals and vals[0].tag == 0x04:
                    v = vals[0]
                    out.message_digest_hex = data[v.value_off:v.value_off + v.value_len].hex()
            elif oid == "1.2.840.113549.1.9.3" and len(akids) >= 2:
                vals = children(data, akids[1])
                if vals and vals[0].tag == 0x06:
                    out.content_type_hex = decode_oid(data, vals[0])
    return out


def _auth_attrs_as_set(data: bytes, attrs: TLV) -> bytes:
    """authenticatedAttributes 是 [0] IMPLICIT；验签时须按 SET(0x31) 重新编码。"""
    raw = bytearray(data[attrs.start:attrs.end])
    raw[0] = 0x31
    return bytes(raw)


def verify_pkcs7(data: bytes, roots: Sequence[Cert], now: Optional[_dt.datetime] = None,
                 require_eku: bool = True, eku_oid: str = OID_CODE_SIGNING,
                 allow_timestamp: bool = True) -> Pkcs7Result:
    """验证一个 PKCS#7 SignedData：内容摘要 + 签名 + 链到受信根 + EKU。

    证书过期不算死路：若带有效时间戳且 genTime 落在有效期内，则按"签名当时有效"
    处理，并在原因里写明。时间戳本身也要验签（见 timestamp.py）。
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    try:
        ci = read_tlv(data, 0)
        ci_kids = children(data, ci)
        if len(ci_kids) < 2 or decode_oid(data, ci_kids[0]) != "1.2.840.113549.1.7.2":
            return Pkcs7Result(False, "不是 PKCS#7 signedData")
        inner = children(data, ci_kids[1])
        if not inner:
            return Pkcs7Result(False, "SignedData 缺失")
        sd = inner[0]
        sd_kids = children(data, sd)
        if len(sd_kids) < 4:
            return Pkcs7Result(False, "SignedData 子项不足")

        encap = sd_kids[2]
        encap_kids = children(data, encap)
        etype = decode_oid(data, encap_kids[0]) if encap_kids else ""
        # eContent 口径（实测 PE 内嵌签名与 .cat 一致）：
        # 摘要算的是 [0] EXPLICIT 内那个元素的 **value 八位组**，
        # 不含它自己的 tag/len。按"完整 DER"算会全盘不匹配。
        econtent = b""
        econtent_tlv = b""
        for node in encap_kids[1:]:
            if node.tag != 0xA0:
                continue
            inner_elems = children(data, node)
            if inner_elems:
                first = inner_elems[0]
                econtent = data[first.value_off:first.value_off + first.value_len]
                econtent_tlv = data[first.start:first.end]
            break
        if not econtent:
            return Pkcs7Result(False, "缺少 eContent", econtent_type=etype)

        certs: List[Cert] = []
        for node in sd_kids[3:-1]:
            if node.tag == 0xA0:            # [0] certificates
                for c in children(data, node):
                    if c.tag == 0x30:
                        try:
                            certs.append(parse_cert(data[c.start:c.end]))
                        except Exception:
                            pass

        signer_set = sd_kids[-1]
        if signer_set.tag != 0x31:
            return Pkcs7Result(False, "找不到 signerInfos", econtent_type=etype,
                               econtent=econtent, certs=certs)
        signers = children(data, signer_set)
        if not signers:
            return Pkcs7Result(False, "signerInfos 为空", econtent_type=etype,
                               econtent=econtent, certs=certs)

        try:
            si = _parse_signer(data, signers[0])
        except (ChainError, SigError) as exc:
            return Pkcs7Result(False, "SignerInfo 解析失败：%s" % exc, econtent_type=etype,
                               econtent=econtent, certs=certs)

        if not si.signature or not si.signature_algo_oid:
            return Pkcs7Result(False, "缺少签名值", econtent_type=etype, econtent=econtent,
                               certs=certs, signer_count=len(signers))

        # 1) 内容摘要
        algo = si.digest_algo or "sha256"
        mine = _digest(algo, econtent)
        if mine is None:
            return Pkcs7Result(False, "不支持的摘要算法 %s" % algo, econtent_type=etype,
                               econtent=econtent, certs=certs)
        if si.message_digest_hex and mine.hex() != si.message_digest_hex:
            return Pkcs7Result(False, "eContent 摘要与 messageDigest 不一致",
                               econtent_type=etype, econtent=econtent, certs=certs)

        # 2) 找签名者证书
        signer_cert = None
        if si.issuer_and_serial:
            issuer_der, serial = si.issuer_and_serial
            for c in certs:
                if c.serial == serial and c.issuer == issuer_der:
                    signer_cert = c
                    break
        if signer_cert is None:
            return Pkcs7Result(False, "找不到签名者证书", econtent_type=etype,
                               econtent=econtent, certs=certs, signer_count=len(signers))

        # 3) 验签（有 authAttrs 时签的是 attrs 的 SET 编码）
        attrs = None
        for node in children(data, signers[0])[3:]:
            if node.tag == 0xA0:
                attrs = node
                break
        signed_bytes = _auth_attrs_as_set(data, attrs) if attrs is not None else econtent
        v = _crypto_verify(signer_cert.spki_der, si.signature_algo_oid, signed_bytes,
                           si.signature, hash_hint=si.digest_algo)
        if v is None:
            return Pkcs7Result(False, "验签不可用（算法不支持或缺 cryptography）",
                               econtent_type=etype, econtent=econtent,
                               econtent_tlv=econtent_tlv, certs=certs,
                               signer=signer_cert, signer_count=len(signers))
        if v is False:
            return Pkcs7Result(False, "签名校验失败", econtent_type=etype, econtent=econtent,
                               econtent_tlv=econtent_tlv, certs=certs, signer=signer_cert,
                               signer_count=len(signers))

        # 4) EKU（缺省要求 Code Signing；验证时间戳令牌时改传时间戳 EKU）
        if require_eku and not signer_cert.has_eku(eku_oid):
            return Pkcs7Result(False,
                               "签名证书未声明所需用途（%s；%s）"
                               % (eku_oid, signer_cert.eku_state),
                               econtent_type=etype, econtent=econtent,
                               econtent_tlv=econtent_tlv, certs=certs,
                               signer=signer_cert, signer_count=len(signers))

        # 5) 链到受信根；过期时尝试用时间戳解释
        chain = build_chain_to_root(signer_cert, certs, roots, now)
        via_ts = ""
        if not chain.ok and allow_timestamp:
            from . import timestamp as tsmod

            for token in tsmod.extract_tokens(data):
                tr = tsmod.verify_token(token, roots, si.signature, now=now)
                if not tr.ok or tr.gen_time is None:
                    continue
                chain2 = build_chain_to_root(signer_cert, certs, roots, tr.gen_time)
                if chain2.ok:
                    chain = chain2
                    via_ts = "；时间戳证明签名时证书有效（%s）" % tr.gen_time.strftime(
                        "%Y-%m-%d %H:%M:%SZ")
                    break
        return Pkcs7Result(chain.ok,
                           ("签名有效，%s%s" % (chain.reason, via_ts)) if chain.ok else chain.reason,
                           econtent_type=etype, econtent=econtent, econtent_tlv=econtent_tlv,
                           certs=certs, signer=signer_cert, chain=chain,
                           signer_count=len(signers))
    except (SigError, ChainError) as exc:
        return Pkcs7Result(False, "结构解析失败：%s" % exc)
    except Exception as exc:  # 任何意外都不许静默当成有效
        return Pkcs7Result(False, "验证异常：%s: %s" % (type(exc).__name__, exc))
