"""目标盘 CatRoot 编录（.cat）索引。

三条硬规则（对应设计文档 §6 与 AGENTS.md PortableAV 红线 3）：
1. **先验 .cat 自身签名**：未通过验证的 .cat，其哈希一律不入索引——否则木马
   只要往 CatRoot 里丢一张自造编录，就能给任意文件洗白。
2. 只从**结构化的 ctlEntries** 里取哈希，不在文件里盲搜字节：
   盲搜可能把别处长 20/32 字节的数据当成哈希，造成"假放行"。
3. 拿不到任何可信编录时，索引状态标为 unusable，由调用方显示"白名单不可用"，
   而不是安静地让所有文件都变成"未编录"。

哈希口径（实测得出，非推测）：编录里存的是目标文件的 **Authenticode 摘要**，
不是整文件哈希。用 notepad.exe 验证过：整文件 SHA-1/SHA-256 在 1453 个 .cat 中
命中 0 次，而 Authenticode 摘要命中 1 次（T2）。
"""

from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import chain as chainmod
from .authsig import OID_CTL, SigError, children, decode_oid, read_tlv

CAT_ROOT_GUID = "{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"


@dataclass
class CatFile:
    path: str
    verified: bool = False
    reason: str = ""
    sha1: Set[bytes] = field(default_factory=set)
    sha256: Set[bytes] = field(default_factory=set)
    signer: str = ""


@dataclass
class CatIndex:
    sha1: Set[bytes] = field(default_factory=set)
    sha256: Set[bytes] = field(default_factory=set)
    owner: Dict[bytes, str] = field(default_factory=dict)   # 摘要 -> 来源 .cat 文件名
    files_total: int = 0
    files_verified: int = 0
    files_rejected: List[Tuple[str, str]] = field(default_factory=list)
    parse_failed: List[Tuple[str, str]] = field(default_factory=list)
    usable: bool = False
    reason: str = ""

    def lookup(self, digest: bytes) -> Optional[str]:
        """命中返回 'sha1'/'sha256'，未命中返回 None。"""
        if len(digest) == 20 and digest in self.sha1:
            return "sha1"
        if len(digest) == 32 and digest in self.sha256:
            return "sha256"
        return None

    def source_of(self, digest: bytes) -> str:
        return self.owner.get(digest, "")

    @property
    def hash_count(self) -> int:
        return len(self.sha1) + len(self.sha256)

    def summary(self) -> str:
        return ("编录 %d 个，验签通过 %d，拒绝 %d，解析失败 %d，哈希 %d 条（%s）"
                % (self.files_total, self.files_verified, len(self.files_rejected),
                   len(self.parse_failed), self.hash_count, self.reason or "可用"))


def cat_dir_for(windows_dir: str) -> str:
    return os.path.join(windows_dir, "System32", "CatRoot", CAT_ROOT_GUID)


def list_cat_files(directory: str, limit: Optional[int] = None) -> List[str]:
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    out = [os.path.join(directory, n) for n in names if n.lower().endswith(".cat")]
    out.sort()
    return out[:limit] if limit else out


def _digest_from_attrs(der: bytes, fields) -> Optional[bytes]:
    """从 CTL_ENTRY 的属性里取 SPC_INDIRECT_DATA 的摘要。

    名字型编录（如打印机驱动的 ntprint.cat）的 subjectIdentifier 是文件名，
    真正的文件摘要放在 `1.3.6.1.4.1.311.2.1.4` 属性里。
    """
    from .authsig import OID_SPC_INDIRECT_DATA, parse_spc_indirect

    for node in fields:
        if node.tag not in (0x30, 0x31):
            continue
        for attr in children(der, node):
            ak = children(der, attr)
            if not ak or ak[0].tag != 0x06:
                continue
            try:
                oid = decode_oid(der, ak[0])
            except SigError:
                continue
            if oid != OID_SPC_INDIRECT_DATA:
                continue
            for holder in ak[1:]:
                for val in children(der, holder):
                    try:
                        _algo, hexed = parse_spc_indirect(der[val.start:val.end])
                    except Exception:
                        continue
                    try:
                        raw = bytes.fromhex(hexed)
                    except ValueError:
                        continue
                    if len(raw) in (20, 32):
                        return raw
    return None


def _ident_as_hex(ident: bytes) -> Optional[bytes]:
    """部分编录把哈希写成 UTF-16LE 的十六进制字符串。"""
    try:
        text = ident.decode("utf-16-le")
    except Exception:
        return None
    text = text.strip("\x00").strip()
    if len(text) in (40, 64):
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            return None
        if len(raw) in (20, 32):
            return raw
    return None


def _looks_like_ascii_utf16(blob: bytes) -> bool:
    """判断这段字节是不是 ASCII 文件名的 UTF-16LE 编码（而不是摘要）。

    为什么不用"能否解码成可打印文本"：随机摘要按 UTF-16LE 解码后，
    有很大概率变成可打印的中日韩字符（实测 notepad 的两个 SHA-1 就被误判），
    那会把真摘要当成文件名丢掉。
    这里要求"每个高字节都是 0x00 且低字节是可打印 ASCII"——真摘要几乎不可能满足。
    """
    if len(blob) < 4 or len(blob) % 2:
        return False
    if any(b != 0 for b in blob[1::2]):
        return False
    if any(not (0x20 <= b < 0x7F) for b in blob[0::2]):
        return False
    return any(chr(b).isalnum() for b in blob[0::2])


def _find_ctl_entries(der: bytes, top_off: int = 0) -> Optional[Tuple[List[bytes], str]]:
    """在 CTL 里定位 ctlEntries 并取出哈希列表。

    取哈希的优先级（均有真实样本支撑）：
    1. 条目属性里的 SPC_INDIRECT_DATA 摘要——最权威，名字型编录靠它；
    2. subjectIdentifier 本身是 20/32 字节且不像 ASCII 文件名 → 就是摘要；
    3. subjectIdentifier 是 UTF-16LE 十六进制字符串 → 转成字节。
    都不匹配就返回失败原因，**绝不回退到盲搜**。
    """
    try:
        top = read_tlv(der, top_off)
        kids = children(der, top)
    except SigError as exc:
        return None, "CTL 结构不可解析：%s" % exc

    for node in kids:
        if node.tag != 0x30:
            continue
        entries = children(der, node)
        if not entries or any(e.tag != 0x30 for e in entries):
            continue
        hashes: List[bytes] = []
        shape_ok = True
        for entry in entries:
            fields = children(der, entry)
            if not fields or fields[0].tag != 0x04:
                shape_ok = False
                break
            ident = der[fields[0].value_off:fields[0].value_off + fields[0].value_len]
            # 快路径：20/32 字节且不像 ASCII 文件名 → 直接当摘要（性能关键，
            # 1453 个编录里有 9 万多条目，每个都去解析属性会把耗时推到 6 秒以上）
            if len(ident) in (20, 32) and not _looks_like_ascii_utf16(ident):
                hashes.append(ident)
                continue
            got = _digest_from_attrs(der, fields[1:]) or _ident_as_hex(ident)
            if got:
                hashes.append(got)
        if shape_ok and hashes:
            return hashes, ""
    return None, "未找到 ctlEntries 结构"


def parse_cat(data: bytes) -> Tuple[Set[bytes], Set[bytes], str]:
    """解析 .cat 的 eContent（CTL），返回 (sha1 集合, sha256 集合, 错误)。

    注意：本函数**不验签**，只做结构解析；验签由 inspect_cat 负责。
    """
    from .authsig import OID_SIGNED_DATA

    try:
        ci = read_tlv(data, 0)
        ci_kids = children(data, ci)
        if len(ci_kids) < 2 or decode_oid(data, ci_kids[0]) != OID_SIGNED_DATA:
            return set(), set(), "不是 PKCS#7"
        inner = children(data, ci_kids[1])
        if not inner:
            return set(), set(), "SignedData 缺失"
        sd_kids = children(data, inner[0])
        if len(sd_kids) < 3:
            return set(), set(), "SignedData 子项不足"
        encap = sd_kids[2]
        encap_kids = children(data, encap)
        etype = decode_oid(data, encap_kids[0]) if encap_kids else ""
        if etype != OID_CTL:
            return set(), set(), "eContentType 不是 CTL（%s）" % etype
        econtent = b""
        for node in encap_kids[1:]:
            if node.tag != 0xA0:
                continue
            for sub in children(data, node):
                econtent = (data[sub.value_off:sub.value_off + sub.value_len]
                            if sub.tag == 0x04 else data[sub.start:sub.end])
                break
        if not econtent:
            return set(), set(), "缺少 eContent"
        hashes, why = _find_ctl_entries(econtent)
        if hashes is None:
            return set(), set(), why
        s1 = {h for h in hashes if len(h) == 20}
        s256 = {h for h in hashes if len(h) == 32}
        return s1, s256, ""
    except (SigError, IndexError) as exc:
        return set(), set(), "解析异常：%s" % type(exc).__name__


def inspect_cat(path: str, roots: Sequence[chainmod.Cert],
                now: Optional[_dt.datetime] = None,
                revocation=None) -> CatFile:
    """验签 + 提哈希。验签不过或证书被吊销 → 哈希为空，绝不入索引。"""
    cf = CatFile(path=path)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        cf.reason = "读取失败：%s" % exc
        return cf

    res = chainmod.verify_pkcs7(data, roots, now=now, require_eku=True)
    if not res.ok:
        cf.verified = False
        cf.reason = "验签未通过：%s" % res.reason
        return cf

    if revocation is not None and getattr(revocation, "loaded", False):
        hit = revocation.check_chain(res.chain.chain or [])
        if hit:
            cf.verified = False
            cf.reason = "签名证书被吊销：%s" % hit
            return cf

    s1, s256, why = parse_cat(data)
    if why:
        cf.verified = False
        cf.reason = "验签通过但内容不可解析：%s" % why
        return cf
    cf.verified = True
    cf.sha1, cf.sha256 = s1, s256
    cf.signer = res.signer.subject_text if res.signer else ""
    cf.reason = "签名有效；%d 条哈希" % (len(s1) + len(s256))
    return cf


def build_index(cat_files: Iterable[str], roots: Sequence[chainmod.Cert],
                now: Optional[_dt.datetime] = None,
                max_reject_samples: int = 5,
                revocation=None) -> CatIndex:
    idx = CatIndex()
    files = list(cat_files)
    idx.files_total = len(files)
    if not roots:
        idx.usable = False
        idx.reason = "无离线根证书，编录无法验证（不当作可信）"
        return idx

    for p in files:
        cf = inspect_cat(p, roots, now=now, revocation=revocation)
        if cf.verified:
            idx.files_verified += 1
            idx.sha1 |= cf.sha1
            idx.sha256 |= cf.sha256
            name = os.path.basename(p)
            for h in cf.sha1:
                idx.owner.setdefault(h, name)
            for h in cf.sha256:
                idx.owner.setdefault(h, name)
        elif cf.reason.startswith("读取失败") or "解析" in cf.reason:
            idx.parse_failed.append((os.path.basename(p), cf.reason))
        else:
            if len(idx.files_rejected) < max_reject_samples:
                idx.files_rejected.append((os.path.basename(p), cf.reason))

    if idx.files_verified == 0:
        idx.usable = False
        idx.reason = "没有任何编录通过验签（%d 个全部失败）" % idx.files_total
    else:
        idx.usable = True
        idx.reason = ""
    return idx


def index_from_windows_dir(windows_dir: str, roots: Sequence[chainmod.Cert],
                           now: Optional[_dt.datetime] = None,
                           limit: Optional[int] = None) -> CatIndex:
    return build_index(list_cat_files(cat_dir_for(windows_dir), limit=limit),
                       roots, now=now)
