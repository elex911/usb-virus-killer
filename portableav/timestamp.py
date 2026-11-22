"""RFC 3161 时间戳令牌验证（离线）。

为什么必须做：微软编录的签名证书会过期（本机实测叶证书 2026-06-17 到期、
中间证书 2026-10-19 到期，而系统时间是 2026-11）。没有时间戳，所有合法编录
都会被判"证书过期"，白名单直接归零——这正是"旧版合法文件大面积误报"的成因。

安全要求（不满足就绝不采信）：
1. 令牌自身的签名必须验得过，且 TSA 证书要链到受信根、带时间戳 EKU；
2. 令牌里的 messageImprint 必须等于**被签名的那段签名值**的摘要——
   否则可以把任意一张有效令牌贴到别的文件上；
3. genTime 必须落在签名证书的有效期内，才允许用"当时有效"来解释过期。
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass
from typing import Optional, Tuple

from . import chain as chainmod
from .authsig import SigError, children, decode_oid, read_tlv

OID_MS_TIMESTAMP = "1.3.6.1.4.1.311.3.3.1"
OID_COUNTER_SIGNATURE = "1.2.840.113549.1.9.6"
OID_EKU_TIMESTAMP = "1.3.6.1.5.5.7.3.8"

_HASH_BY_OID = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}


@dataclass
class TokenResult:
    ok: bool
    reason: str
    gen_time: Optional[_dt.datetime] = None
    imprint_algo: str = ""
    tsa: str = ""


def _gen_time(data: bytes, tlv) -> Optional[_dt.datetime]:
    raw = data[tlv.value_off:tlv.value_off + tlv.value_len].decode("latin-1", "replace")
    digits = raw.rstrip("Z")
    frac = 0.0
    if "." in digits:
        digits, _, tail = digits.partition(".")
        tail = tail.rstrip("Z")
        if tail.isdigit():
            frac = float("0." + tail)
    if len(digits) < 14 or not digits.isdigit():
        return None
    try:
        base = _dt.datetime(int(digits[0:4]), int(digits[4:6]), int(digits[6:8]),
                            int(digits[8:10]), int(digits[10:12]), int(digits[12:14]),
                            tzinfo=_dt.timezone.utc)
        return base + _dt.timedelta(seconds=frac)
    except ValueError:
        return None


def parse_tstinfo(der: bytes) -> Tuple[Optional[_dt.datetime], str, str, str]:
    """解析 TSTInfo，返回 (genTime, 摘要算法, messageImprint 十六进制, 错误)。"""
    try:
        top = read_tlv(der, 0)
        kids = children(der, top)
        if len(kids) < 5:
            return None, "", "", "TSTInfo 子项不足：%d" % len(kids)
        imprint = kids[2]
        ikids = children(der, imprint)
        if len(ikids) < 2:
            return None, "", "", "messageImprint 结构异常"
        alg_kids = children(der, ikids[0])
        alg = ""
        if alg_kids and alg_kids[0].tag == 0x06:
            alg = _HASH_BY_OID.get(decode_oid(der, alg_kids[0]), "")
        octet = ikids[1]
        if octet.tag != 0x04:
            return None, "", "", "messageImprint 不是 OCTET STRING"
        hexed = der[octet.value_off:octet.value_off + octet.value_len].hex()
        gen = _gen_time(der, kids[4])
        if gen is None:
            return None, alg, hexed, "genTime 解析失败"
        return gen, alg, hexed, ""
    except (SigError, IndexError) as exc:
        return None, "", "", "TSTInfo 解析异常：%s" % exc


def extract_tokens(pkcs7: bytes) -> list:
    """从 PKCS#7 的 unauthAttrs 里取出时间戳令牌（ContentInfo 的 DER）。"""
    from .authsig import children as _ch

    tokens = []
    try:
        ci = read_tlv(pkcs7, 0)
        sd = _ch(pkcs7, _ch(pkcs7, ci)[1])[0]
        sd_kids = _ch(pkcs7, sd)
        signer_set = sd_kids[-1]
        for si in _ch(pkcs7, signer_set):
            for node in _ch(pkcs7, si):
                if node.tag != 0xA1:
                    continue
                for attr in _ch(pkcs7, node):
                    ak = _ch(pkcs7, attr)
                    if not ak or ak[0].tag != 0x06:
                        continue
                    oid = decode_oid(pkcs7, ak[0])
                    if oid == OID_MS_TIMESTAMP and len(ak) > 1:
                        for val in _ch(pkcs7, ak[1]):
                            if val.tag == 0x30:
                                tokens.append(pkcs7[val.start:val.end])
    except (SigError, IndexError):
        return tokens
    return tokens


def verify_token(token_der: bytes, roots, signed_value: bytes,
                 now: Optional[_dt.datetime] = None) -> TokenResult:
    """验证令牌，并确认它绑定的正是 signed_value（即上一级签名值）。

    两段式验签：先用当前时间验；若因证书过期失败，则按令牌自己声明的 genTime
    再验一次——这是时间戳的本来语义（证明"在那一天这个签名是有效的"）。
    genTime 晚于当前时间（允许 1 天时钟偏差）视为伪造，直接拒。
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    res = chainmod.verify_pkcs7(token_der, roots, now=now, require_eku=True,
                                eku_oid=OID_EKU_TIMESTAMP, allow_timestamp=False)

    gen, alg, imprint, why = (None, "", "", "缺少 eContent")
    if res.econtent:
        gen, alg, imprint, why = parse_tstinfo(res.econtent)

    if not res.ok and gen is not None:
        res = chainmod.verify_pkcs7(token_der, roots, now=gen, require_eku=True,
                                    eku_oid=OID_EKU_TIMESTAMP, allow_timestamp=False)

    if not res.ok:
        return TokenResult(False, "时间戳令牌验签未通过：%s" % res.reason)

    if gen is None:
        return TokenResult(False, why or "genTime 缺失",
                           tsa=res.signer.subject_text if res.signer else "")
    if gen > now + _dt.timedelta(days=1):
        return TokenResult(False, "时间戳 genTime 晚于当前时间（%s），视为伪造" % gen.isoformat(),
                           gen, alg, res.signer.subject_text if res.signer else "")
    if not alg:
        return TokenResult(False, "时间戳摘要算法不支持",
                           gen, alg, res.signer.subject_text if res.signer else "")
    mine = hashlib.new(alg, signed_value).hexdigest()
    if mine != imprint:
        return TokenResult(False, "时间戳绑定的不是本次签名（imprint 不一致）",
                           gen, alg, res.signer.subject_text if res.signer else "")
    return TokenResult(True, "令牌有效，genTime=%s" % gen.isoformat(),
                       gen, alg, res.signer.subject_text if res.signer else "")
