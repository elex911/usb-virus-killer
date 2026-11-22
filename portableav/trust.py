"""判定层：把「证据」变成「白 / 灰 / 黑」，且只给依据不算分。

三条不可让步的规则（AGENTS.md PortableAV 红线 1/2/3）：
1. 白名单只放行**当前这个文件**——绝不因为某个文件可信就跳过同目录的其他文件；
2. "签名摘要一致"只证明文件未被篡改，**不证明签名者可信**；
   必须证书链走到受信根 + 代码签名 EKU，才算白；
3. 拿不准一律灰（进报告等人复核），绝不把"验不了"写成"干净"。
"""

from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from . import authsig, catroot, chain as chainmod
from . import pe as pemod

LEVEL_WHITE = "白"
LEVEL_GRAY = "灰"
LEVEL_BLACK = "黑"

WHITE_EMBEDDED = "内嵌签名"
WHITE_CATALOG = "编录签名"


@dataclass
class Verdict:
    level: str
    reasons: List[str] = field(default_factory=list)
    path: str = ""
    basis: str = ""                                  # 放行依据：内嵌签名 / 编录签名
    signer: str = ""
    digest_sha256: str = ""
    digest_sha1: str = ""
    catalog_file: str = ""
    has_embedded: bool = False
    parse_failed: bool = False                       # True → 必须进「解析失败」分区

    @property
    def is_white(self) -> bool:
        return self.level == LEVEL_WHITE

    def summary(self) -> str:
        return "%s｜%s｜%s" % (self.level, self.basis or "-", "；".join(self.reasons))


def _auth_digests(fp, info) -> tuple:
    d256 = authsig.authenticode_digest(fp, info, "sha256")[0]
    d1 = authsig.authenticode_digest(fp, info, "sha1")[0]
    return d1, d256


def judge_pe(path: str, roots: Sequence[chainmod.Cert],
             index: Optional[catroot.CatIndex] = None,
             now: Optional[_dt.datetime] = None,
             revocation=None) -> Verdict:
    """对一个 PE 文件给出判定。任何异常都落成灰，不抛。

    revocation：revoke.RevocationList；链上任意一级命中即判黑（防盗用签名）。
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    v = Verdict(level=LEVEL_GRAY, path=path)
    try:
        with open(path, "rb") as fp:
            try:
                info = pemod.parse_header(fp)
            except pemod.PEError as exc:
                v.reasons.append("PE 解析失败：%s" % exc)
                v.parse_failed = True
                return v
            except OSError as exc:
                v.reasons.append("读取失败：%s" % exc)
                return v

            try:
                d1, d256 = _auth_digests(fp, info)
                v.digest_sha1, v.digest_sha256 = d1.hex(), d256.hex()
            except Exception as exc:
                v.reasons.append("摘要计算失败：%s" % exc)

            if info.has_signature:
                v.has_embedded = True
                fp.seek(info.cert_file_offset)
                blob = fp.read(info.cert_size)
                tampered = False
                for body, _rev, _ctype, _len in authsig.iter_cert_entries(blob):
                    res = chainmod.verify_pkcs7(body, roots, now=now, require_eku=True)
                    if not res.ok:
                        v.reasons.append("内嵌签名未通过：%s" % res.reason)
                        continue
                    # 签名有效 ≠ 内容未被改：还要比对文件摘要
                    try:
                        parsed = authsig.parse_pkcs7(body)
                    except authsig.SigError as exc:
                        v.reasons.append("签名结构异常：%s" % exc)
                        continue
                    ok, detail = authsig.check_digest_matches(fp, info, parsed)
                    if ok is False:
                        tampered = True
                        v.reasons.append("签名有效但文件摘要不符：%s" % detail)
                        continue
                    if ok is None:
                        v.reasons.append("无法比对摘要：%s" % detail)
                        continue
                    # 被盗/被吊销的证书签出来的文件，链能走通也必须拦
                    if revocation is not None and getattr(revocation, "loaded", False):
                        hit = revocation.check_chain(res.chain.chain or [])
                        if hit:
                            v.level = LEVEL_BLACK
                            v.basis = "吊销/黑名单证书"
                            v.signer = res.signer.subject_text if res.signer else ""
                            v.reasons.append(hit)
                            return v
                    v.level = LEVEL_WHITE
                    v.basis = WHITE_EMBEDDED
                    v.signer = res.signer.subject_text if res.signer else ""
                    v.reasons.append("签名链到受信根，且文件摘要与签名一致（%s）"
                                     % parsed.digest_algo)
                    return v
                if tampered:
                    v.level = LEVEL_BLACK
                    v.basis = "签名与内容不符"
                    return v
            # 无内嵌签名（或内嵌签名不可用）→ 查编录
            if index is None:
                v.reasons.append("无内嵌签名，且未建立编录索引")
                return v
            if not index.usable:
                v.reasons.append("无内嵌签名；编录索引不可用（%s）" % (index.reason or "未验证"))
                return v
            hit = index.lookup(d256) if v.digest_sha256 else None
            if not hit and v.digest_sha1:
                hit = index.lookup(bytes.fromhex(v.digest_sha1))
            if hit:
                v.level = LEVEL_WHITE
                v.basis = WHITE_CATALOG
                digest = d256 if hit == "sha256" else bytes.fromhex(v.digest_sha1)
                v.catalog_file = index.source_of(digest)
                v.reasons.append("Authenticode 摘要命中已验证编录（%s）%s"
                                 % (hit, v.catalog_file))
                return v
            v.reasons.append("无内嵌签名，且摘要不在任何已验证编录中")
            return v
    except Exception as exc:  # 任何意外都不许变成"白"
        v.level = LEVEL_GRAY
        v.reasons.append("判定异常：%s: %s" % (type(exc).__name__, exc))
        return v


def judge_any(path: str, roots: Sequence[chainmod.Cert],
              index: Optional[catroot.CatIndex] = None,
              now: Optional[_dt.datetime] = None,
              revocation=None) -> Verdict:
    """非 PE 文件不做签名判定，直接灰（留给规则引擎），但会说明原因。"""
    try:
        with open(path, "rb") as fp:
            head = fp.read(2)
    except OSError as exc:
        return Verdict(LEVEL_GRAY, ["读取失败：%s" % exc], path=path)
    if head == b"MZ":
        return judge_pe(path, roots, index=index, now=now, revocation=revocation)
    return Verdict(LEVEL_GRAY, ["非 PE 文件，未做签名判定"], path=path)


def siblings_not_covered(directory: str) -> str:
    """给报告用的一句话：白名单不覆盖同目录其他文件（防白加黑）。"""
    return ("白名单仅对当前文件生效；%s 下的其他文件（尤其无签名 DLL）"
            "必须逐个判定，不得因其邻居可信而跳过。" % directory)
