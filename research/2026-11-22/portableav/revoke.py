"""吊销/黑名单检查（离线）。

数据来源只能是离线包：Windows 的 `disallowedcert` 或自建 JSON。
拿不到黑名单时**不阻塞**，但报告里必须写"未启用吊销检查"——
不能让人误以为"已检查且通过"。

匹配维度：证书 SHA-1 指纹（Windows 的 Thumbprint 口径）、SHA-256 指纹、序列号。
链上任意一级命中即判该签名不可信（被盗证书签的马就是这个特征）。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Set

from .chain import Cert


@dataclass
class RevocationList:
    sha1: Set[str] = field(default_factory=set)        # 大写十六进制，无分隔
    sha256: Set[str] = field(default_factory=set)
    serials: Set[str] = field(default_factory=set)     # 大写十六进制
    source: str = ""
    loaded: bool = False

    def __len__(self) -> int:
        return len(self.sha1) + len(self.sha256) + len(self.serials)

    def check(self, cert: Cert) -> Optional[str]:
        """命中返回原因，未命中返回 None。"""
        thumb1 = hashlib.sha1(cert.der).hexdigest().upper()
        thumb256 = hashlib.sha256(cert.der).hexdigest().upper()
        serial = cert.serial.hex().upper().lstrip("0")
        if thumb1 in self.sha1:
            return "证书 SHA-1 指纹命中吊销黑名单"
        if thumb256 in self.sha256:
            return "证书 SHA-256 指纹命中吊销黑名单"
        if serial and serial in self.serials:
            return "证书序列号命中吊销黑名单"
        return None

    def check_chain(self, certs: Sequence[Cert]) -> Optional[str]:
        for c in certs:
            hit = self.check(c)
            if hit:
                return "%s（%s）" % (hit, c.subject_text[:60])
        return None

    def summary(self) -> str:
        if not self.loaded:
            return "吊销检查未启用（%s）" % (self.source or "无黑名单文件")
        return "吊销黑名单 %d 条（%s）" % (len(self), self.source)


def _norm_hex(value: str) -> str:
    return "".join(ch for ch in str(value) if ch in "0123456789abcdefABCDEF").upper()


def load_blacklist(path: str) -> RevocationList:
    """支持两种格式：
    - JSON：{"sha1": [...], "sha256": [...], "serials": [...]} 或 [{"sha1":...}, ...]
    - 纯文本：每行一个 SHA-1 指纹（可带空格/冒号），# 开头为注释
    """
    rl = RevocationList(source=os.path.basename(path))
    try:
        raw = open(path, "r", encoding="utf-8", errors="ignore").read()
    except OSError as exc:
        rl.source = "%s（读取失败：%s）" % (os.path.basename(path), exc)
        return rl

    text = raw.strip()
    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
        except ValueError:
            rl.source = "%s（JSON 解析失败）" % os.path.basename(path)
            return rl
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            for key in ("sha1", "thumbprint", "thumbprints"):
                for v in _as_list(item.get(key)):
                    h = _norm_hex(v)
                    if len(h) == 40:
                        rl.sha1.add(h)
            for key in ("sha256", "sha256_thumbprint"):
                for v in _as_list(item.get(key)):
                    h = _norm_hex(v)
                    if len(h) == 64:
                        rl.sha256.add(h)
            for v in _as_list(item.get("serial") or item.get("serials")):
                h = _norm_hex(v)
                if h:
                    rl.serials.add(h.lstrip("0"))
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            h = _norm_hex(line)
            if len(h) == 40:
                rl.sha1.add(h)
            elif len(h) == 64:
                rl.sha256.add(h)

    rl.loaded = len(rl) > 0
    if not rl.loaded:
        rl.source = "%s（内容为空，等于未启用）" % os.path.basename(path)
    return rl


def _as_list(value) -> List:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def load_blacklists(paths: Iterable[str]) -> RevocationList:
    """合并多个黑名单文件。"""
    merged = RevocationList()
    names = []
    for p in paths:
        rl = load_blacklist(p)
        merged.sha1 |= rl.sha1
        merged.sha256 |= rl.sha256
        merged.serials |= rl.serials
        names.append(os.path.basename(p))
    merged.loaded = len(merged) > 0
    merged.source = ", ".join(names) if names else ""
    return merged


def default_blacklist_dir(rules_dir: str) -> str:
    return os.path.join(rules_dir, "revoked")
