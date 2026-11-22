"""规则匹配器：内置 EICAR 冒烟规则 + 可选 yara-x 适配。

为什么内置一条而不是直接依赖 yara-x：本机没有 `yara-x`，把它设成硬依赖会让
整条链路跑不起来，也会让测试在缺包时"跳过一切"变成假绿。
这里的约定是：
- 内置匹配器永远可用（用于冒烟与回归）；
- yara-x 存在就用，不存在就在报告里写明"未启用"，**不伪装成已扫描**。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

MAX_MATCH_BYTES = 2 * 1024 * 1024   # 内置规则只看前 2MB，避免大文件拖死


@dataclass
class Match:
    rule: str
    detail: str = ""


@dataclass
class MatchReport:
    matches: List[Match] = field(default_factory=list)
    engine: str = "builtin"
    error: str = ""

    @property
    def hit(self) -> bool:
        return bool(self.matches)

    def names(self) -> str:
        return ",".join(m.rule for m in self.matches)


class EicarMatcher:
    """只认 EICAR 测试串。命中即"确证"——它本来就是测试样本。"""

    name = "builtin-eicar"

    def scan(self, path: str, size: int = 0) -> MatchReport:
        rep = MatchReport(engine=self.name)
        try:
            with open(path, "rb") as f:
                head = f.read(min(MAX_MATCH_BYTES, max(size, 4096)))
        except OSError as exc:
            rep.error = "读取失败：%s" % exc
            return rep
        if EICAR in head:
            rep.matches.append(Match("EICAR-Test-File", "内置特征命中"))
        return rep


class YaraXMatcher:
    """yara-x 适配层；不可用时构造即抛，由上层决定怎么记录。"""

    name = "yara-x"

    def __init__(self, rules_path: Optional[str] = None):
        import yara_x  # noqa: F401  (缺失时抛 ImportError，由上层捕获)

        self._yx = yara_x
        compiler = yara_x.Compiler()
        if rules_path and os.path.isfile(rules_path):
            compiler.add_source(open(rules_path, encoding="utf-8").read())
        else:
            compiler.add_source(
                'rule Builtin_EICAR_Test {\n'
                '  strings:\n'
                '    $e = "X5O!P%%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"\n'
                '  condition:\n'
                '    $e\n'
                '}\n'
            )
        self._rules = compiler.build()

    def scan(self, path: str, size: int = 0) -> MatchReport:
        rep = MatchReport(engine=self.name)
        try:
            scanner = self._yx.Scanner(self._rules)
            result = scanner.scan_file(path)
            for rule in result.matching_rules:
                rep.matches.append(Match(rule.identifier, "yara-x 命中"))
        except Exception as exc:
            rep.error = "%s: %s" % (type(exc).__name__, exc)
        return rep


def build_matcher(rules_path: Optional[str] = None) -> tuple:
    """返回 (matcher, 状态说明)。优先 yara-x，失败则退回内置。"""
    try:
        return YaraXMatcher(rules_path), "yara-x 已启用"
    except Exception as exc:
        return EicarMatcher(), "yara-x 未启用（%s），仅内置 EICAR 特征" % type(exc).__name__


@dataclass
class CompositeMatcher:
    parts: Sequence[object]

    def scan(self, path: str, size: int = 0) -> MatchReport:
        merged = MatchReport(engine="+".join(getattr(p, "name", "?") for p in self.parts))
        for p in self.parts:
            rep = p.scan(path, size)
            if rep.error:
                merged.error = rep.error
            merged.matches.extend(rep.matches)
        return merged
