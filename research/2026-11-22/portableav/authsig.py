"""Authenticode：自己算哈希、自己取签名里的摘要（不调用 WinVerifyTrust）。

本模块只做「可独立验证的那一半」：
1. 按规范计算文件的 Authenticode 摘要；
2. 从 PE 的 WIN_CERTIFICATE / PKCS#7 里取出签名者写入的摘要与算法。
   —— 这两者对得上，说明哈希实现正确（摘要是微软签名机算的，不是我算的）。

证书链、时间戳、吊销、CatRoot 属于后续阶段，本文件不假装已实现。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .pe import PEInfo, PEError, hash_ranges, parse_header

CHUNK = 1024 * 1024

# 摘要算法 OID -> hashlib 名称
OID_DIGEST = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
OID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1"
OID_CTL = "1.3.6.1.4.1.311.10.1"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"


class SigError(Exception):
    """签名结构不可解析。调用方必须计入「解析失败」，不得当作无签名。"""


# ---------------------------------------------------------------- 最小 DER

@dataclass(frozen=True)
class TLV:
    tag: int
    value_off: int
    value_len: int
    end: int          # 本 TLV 之后的下一个偏移
    start: int = 0    # 本 TLV 起始偏移（含 tag/len），取原始字节时要用

    @property
    def is_constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def raw_len(self) -> int:
        return self.end - self.start


def read_tlv(data: bytes, off: int, end: Optional[int] = None) -> TLV:
    limit = len(data) if end is None else min(end, len(data))
    if off < 0 or off + 2 > limit:
        raise SigError("TLV 越界 @%d" % off)
    tag = data[off]
    if tag & 0x1F == 0x1F:
        raise SigError("不支持多字节 tag @%d" % off)
    first = data[off + 1]
    pos = off + 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4:
            raise SigError("非法长度编码 @%d" % off)
        if pos + n > limit:
            raise SigError("长度字节越界 @%d" % off)
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > limit:
        raise SigError("TLV 内容越界 @%d len=%d" % (off, length))
    return TLV(tag=tag, value_off=pos, value_len=length, end=pos + length, start=off)


def children(data: bytes, tlv: TLV) -> List[TLV]:
    out: List[TLV] = []
    if not tlv.is_constructed:
        return out
    pos = tlv.value_off
    end = tlv.value_off + tlv.value_len
    while pos < end:
        child = read_tlv(data, pos, end)
        out.append(child)
        if child.end <= pos:  # 防御死循环
            raise SigError("TLV 长度为零导致死循环 @%d" % pos)
        pos = child.end
    return out


def tlv_bytes(data: bytes, off: int) -> bytes:
    """取从 off 开始的完整 TLV（含 tag/len），用于再解析嵌套结构。"""
    t = read_tlv(data, off)
    return data[off:t.end]


def decode_oid(data: bytes, tlv: TLV) -> str:
    if tlv.tag != 0x06:
        raise SigError("期望 OID，实得 tag=0x%02X" % tlv.tag)
    raw = data[tlv.value_off:tlv.value_off + tlv.value_len]
    if not raw:
        raise SigError("空 OID")
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


# ------------------------------------------------------- 摘要计算（规范实现）

def authenticode_digest(fp, pe: PEInfo, algo: str) -> Tuple[bytes, int]:
    """按 Authenticode 规范计算摘要，返回 (digest, 参与哈希的字节数)。"""
    h = hashlib.new(algo)
    total = 0
    for start, end in hash_ranges(pe):
        fp.seek(start)
        remaining = end - start
        while remaining > 0:
            chunk = fp.read(min(CHUNK, remaining))
            if not chunk:
                raise PEError("读取中止 @%d（文件可能被截断）" % (end - remaining))
            h.update(chunk)
            remaining -= len(chunk)
            total += len(chunk)
    return h.digest(), total


# ------------------------------------------------------- 签名结构解析

@dataclass
class EmbeddedSignature:
    revision: int
    cert_type: int
    total_len: int
    digest_algo: str = ""            # sha1 / sha256 / ...
    digest_hex: str = ""
    signer_digest_algo: str = ""     # SignerInfo.digestAlgorithm
    message_digest_hex: str = ""     # authenticatedAttributes.messageDigest
    has_nested: bool = False
    nested: List["EmbeddedSignature"] = field(default_factory=list)
    signer_serial: str = ""
    issuer_hint: str = ""
    error: str = ""


def _find_encap(data: bytes, signed_data: TLV) -> TLV:
    kids = children(data, signed_data)
    # SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo, ... }
    if len(kids) < 3:
        raise SigError("SignedData 子项不足：%d" % len(kids))
    return kids[2]


def parse_spc_indirect(der: bytes) -> Tuple[str, str]:
    """从 SpcIndirectDataContent 取 (digest_algo, digest_hex)。"""
    top = read_tlv(der, 0)
    kids = children(der, top)
    if len(kids) < 2:
        raise SigError("SpcIndirectDataContent 子项不足")
    digest_info = kids[1]
    di_kids = children(der, digest_info)
    if len(di_kids) < 2:
        raise SigError("DigestInfo 子项不足")
    alg_kids = children(der, di_kids[0])
    oid = decode_oid(der, alg_kids[0]) if alg_kids else ""
    algo = OID_DIGEST.get(oid, oid)
    octet = di_kids[1]
    if octet.tag != 0x04:
        raise SigError("DigestInfo 摘要不是 OCTET STRING")
    digest = der[octet.value_off:octet.value_off + octet.value_len]
    return algo, digest.hex()


def _attr_oid(data: bytes, attr: TLV) -> str:
    kids = children(data, attr)
    return decode_oid(data, kids[0]) if kids else ""


def parse_pkcs7(pkcs7: bytes) -> EmbeddedSignature:
    """解析一个 PKCS#7 SignedData，取摘要信息；失败抛 SigError。"""
    sig = EmbeddedSignature(revision=0, cert_type=0, total_len=len(pkcs7))
    ci = read_tlv(pkcs7, 0)
    ci_kids = children(pkcs7, ci)
    if len(ci_kids) < 2:
        raise SigError("ContentInfo 子项不足")
    if decode_oid(pkcs7, ci_kids[0]) != OID_SIGNED_DATA:
        raise SigError("ContentInfo 不是 signedData")
    inner = children(pkcs7, ci_kids[1])
    if not inner:
        raise SigError("[0] 内为空")
    signed_data = inner[0]
    encap = _find_encap(pkcs7, signed_data)
    encap_kids = children(pkcs7, encap)
    if not encap_kids:
        raise SigError("encapContentInfo 为空")
    etype = decode_oid(pkcs7, encap_kids[0])
    if etype != OID_SPC_INDIRECT_DATA:
        # .cat 是 CTL，摘要语义不同，本函数不处理
        raise SigError("非 SPC_INDIRECT_DATA（%s）" % etype)

    econtent_der = None
    econtent_note = ""
    for k in encap_kids[1:]:
        if k.tag != 0xA0:  # [0] EXPLICIT
            continue
        inner2 = children(pkcs7, k)
        for node in inner2:
            if node.tag == 0x04:                      # CMS 规范形态：OCTET STRING 包裹
                econtent_der = pkcs7[node.value_off:node.value_off + node.value_len]
                econtent_note = "octet-string"
                break
            if node.tag == 0x30:                      # Authenticode 实际形态：裸 SEQUENCE
                econtent_der = pkcs7[node.start:node.end]
                econtent_note = "bare-sequence"
                break
    if econtent_der is None:
        raise SigError("缺少 eContent")
    # 有的实现把 DER 再套一层 OCTET STRING：剥到 SEQUENCE 为止
    for _ in range(2):
        try:
            probe = read_tlv(econtent_der, 0)
        except SigError:
            break
        if probe.tag == 0x04:
            econtent_der = econtent_der[probe.value_off:probe.value_off + probe.value_len]
        else:
            break

    algo, digest = parse_spc_indirect(econtent_der)
    sig.digest_algo, sig.digest_hex = algo, digest

    # SignerInfo：取 digestAlgorithm 与 messageDigest，供后续验签使用
    sd_kids = children(pkcs7, signed_data)
    signer_set = sd_kids[-1]
    if signer_set.tag == 0x31:
        signers = children(pkcs7, signer_set)
        if signers:
            si = children(pkcs7, signers[0])
            if len(si) >= 3:
                sid = si[1]
                sid_kids = children(pkcs7, sid)
                if sid_kids and sid_kids[0].tag == 0x02:
                    sig.signer_serial = pkcs7[sid_kids[0].value_off:
                                              sid_kids[0].value_off + sid_kids[0].value_len].hex()
                da = children(pkcs7, si[2])
                if da:
                    oid = decode_oid(pkcs7, da[0])
                    sig.signer_digest_algo = OID_DIGEST.get(oid, oid)
                for k in si[3:]:
                    if k.tag == 0xA0:  # authenticatedAttributes
                        for attr in children(pkcs7, k):
                            if _attr_oid(pkcs7, attr) == OID_MESSAGE_DIGEST:
                                akids = children(pkcs7, attr)
                                if len(akids) >= 2:
                                    vals = children(pkcs7, akids[1])
                                    if vals and vals[0].tag == 0x04:
                                        v = vals[0]
                                        sig.message_digest_hex = pkcs7[
                                            v.value_off:v.value_off + v.value_len].hex()
                    elif k.tag == 0xA1:  # unauthenticatedAttributes
                        for attr in children(pkcs7, k):
                            if _attr_oid(pkcs7, attr) == OID_NESTED_SIGNATURE:
                                sig.has_nested = True
    return sig


def tail_slack(body: bytes) -> int:
    """WIN_CERTIFICATE 里 bCertificate 的尾部多余字节数。

    规范只要求 8 字节内对齐；超过 8 字节的残余是 CVE-2013-3900 类
    「签名表尾部塞载荷」的典型特征。返回 -1 表示无法解析。
    """
    try:
        ci = read_tlv(body, 0)
    except SigError:
        return -1
    return len(body) - ci.end


def iter_cert_entries(blob: bytes):
    """遍历 WIN_CERTIFICATE 链，产出 (body, revision, cert_type, dw_length)。

    body 就是 PKCS#7 SignedData 的原始字节，可直接交给 chain.verify_pkcs7。
    """
    pos = 0
    while pos + 8 <= len(blob):
        dw_len = int.from_bytes(blob[pos:pos + 4], "little")
        rev = int.from_bytes(blob[pos + 4:pos + 6], "little")
        ctype = int.from_bytes(blob[pos + 6:pos + 8], "little")
        if dw_len < 8 or pos + dw_len > len(blob):
            break
        yield blob[pos + 8:pos + dw_len], rev, ctype, dw_len
        pos += (dw_len + 7) & ~7


def embedded_signatures(fp, pe: PEInfo) -> List[EmbeddedSignature]:
    """枚举 WIN_CERTIFICATE 链里的所有签名（含双签名的第二条）。"""
    if not pe.has_signature:
        return []
    fp.seek(pe.cert_file_offset)
    blob = fp.read(pe.cert_size)
    out: List[EmbeddedSignature] = []
    for body, rev, ctype, dw_len in iter_cert_entries(blob):
        try:
            sig = parse_pkcs7(body)
        except SigError as exc:
            sig = EmbeddedSignature(revision=rev, cert_type=ctype,
                                    total_len=dw_len, error=str(exc))
        else:
            sig.revision = rev
            sig.cert_type = ctype
            sig.total_len = dw_len
            slack = tail_slack(body)
            if slack > 8:
                sig.error = "签名表尾部存在 %d 字节非 ASN.1 数据" % slack
        out.append(sig)
    return out


def check_digest_matches(fp, pe: PEInfo, sig: EmbeddedSignature) -> Tuple[Optional[bool], str]:
    """把签名里声明的摘要与自算摘要比对。None 表示无法比较（结构不全）。"""
    if not sig.digest_algo or not sig.digest_hex:
        return None, "签名未给出摘要（%s）" % (sig.error or "结构缺字段")
    algo = sig.digest_algo
    if algo not in hashlib.algorithms_available:
        return None, "本机不支持算法 %s" % algo
    try:
        mine, hashed_len = authenticode_digest(fp, pe, algo)
    except (PEError, OSError) as exc:
        return None, "计算摘要失败：%s" % exc
    if mine.hex().lower() == sig.digest_hex.lower():
        return True, "%s 摘要一致（已哈希 %d 字节）" % (algo, hashed_len)
    return False, "%s 摘要不一致（自算 %s… vs 签名 %s…）" % (
        algo, mine.hex()[:16], sig.digest_hex[:16])


def analyze(fp) -> Dict[str, object]:
    """一次性给出 PE 签名概览，供报告使用。任何异常都转成 error 字段。"""
    try:
        pe = parse_header(fp)
    except PEError as exc:
        return {"ok": False, "error": "PE 解析失败：%s" % exc}
    result: Dict[str, object] = {
        "ok": True,
        "is_64": pe.is_64,
        "file_size": pe.file_size,
        "sections": len(pe.sections),
        "has_signature": pe.has_signature,
        "signatures": [],
    }
    sigs = embedded_signatures(fp, pe)
    rows = []
    for s in sigs:
        ok, detail = check_digest_matches(fp, pe, s) if not s.error else (None, s.error)
        rows.append({"algo": s.digest_algo, "digest": s.digest_hex[:32],
                     "nested": s.has_nested, "match": ok, "detail": detail,
                     "error": s.error})
    result["signatures"] = rows
    return result


def is_trusted_by_digest(fp) -> Tuple[bool, str]:
    """仅凭「签名内摘要 == 自算摘要」判断文件未被篡改。

    注意：这只证明文件与签名时的内容一致，**不证明签名者可信**。
    证书链校验属于后续阶段，本函数不得单独用于放行。
    """
    a = analyze(fp)
    if not a.get("ok"):
        return False, str(a.get("error"))
    for row in a.get("signatures") or []:
        if row.get("match") is True:
            return True, "摘要一致（%s）" % row.get("algo")
    if not a.get("signatures"):
        return False, "无内嵌签名（可能仅存在于 .cat 编录）"
    return False, "摘要不一致或结构异常"
