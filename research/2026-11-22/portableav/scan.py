"""扫描调度：遍历 + 线程池 + 限额 + 失败记账。

两条硬规矩：
1. **跳过 ≠ 干净**：解析失败、读不了、超大文件一律单独计数并进报告，
   不许并入"已检查且正常"；
2. 系统关键路径只告警不处置（防误隔离后目标机起不来）。
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from . import catroot, chain as chainmod, matcher as matchmod, pe as pemod, trust

SKIP_DIR_NAMES = {"$recycle.bin", "system volume information", "recovery"}
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass
class Limits:
    max_file_bytes: int = 100 * 1024 * 1024
    max_depth: int = 12
    max_files: int = 0                 # 0 = 不限制
    follow_links: bool = False
    skip_dirs: Sequence[str] = tuple(SKIP_DIR_NAMES)
    include_exts: Sequence[str] = ()   # 空 = 全部


@dataclass
class FileResult:
    path: str
    size: int = 0
    level: str = trust.LEVEL_GRAY
    basis: str = ""
    reasons: List[str] = field(default_factory=list)
    digest_sha256: str = ""
    rules: List[str] = field(default_factory=list)
    action: str = ""                   # 隔离 / 仅告警 / 无
    quarantine_id: str = ""
    error: str = ""


@dataclass
class Summary:
    root: str
    started: str = ""
    elapsed: float = 0.0
    files_seen: int = 0
    files_scanned: int = 0
    skipped_big: int = 0
    skipped_link: int = 0
    skipped_ext: int = 0
    errors: List[FileResult] = field(default_factory=list)
    results: List[FileResult] = field(default_factory=list)
    by_level: Dict[str, int] = field(default_factory=dict)
    whitelist_status: str = ""
    matcher_status: str = ""
    quarantine_status: str = ""
    truncated: bool = False

    def count(self, level: str) -> int:
        return self.by_level.get(level, 0)

    def add(self, r: FileResult) -> None:
        if r.error:
            self.errors.append(r)
        else:
            self.results.append(r)
            self.by_level[r.level] = self.by_level.get(r.level, 0) + 1


def _is_reparse(entry: os.DirEntry) -> bool:
    try:
        st = entry.stat(follow_symlinks=False)
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT) or entry.is_symlink()


def _iter_files(root: str, limits: Limits, exclude_dirs: Sequence[str]):
    root = os.path.abspath(root)
    exclude = {os.path.normcase(os.path.abspath(d)) for d in exclude_dirs if d}
    stack = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > limits.max_depth:
            continue
        try:
            entries = list(os.scandir(cur))
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    if not limits.follow_links and _is_reparse(e):
                        yield ("link", e.path)
                        continue
                    if e.name.lower() in limits.skip_dirs:
                        continue
                    if os.path.normcase(os.path.abspath(e.path)) in exclude:
                        continue
                    stack.append((e.path, depth + 1))
                elif e.is_file(follow_symlinks=False):
                    if not limits.follow_links and _is_reparse(e):
                        yield ("link", e.path)
                        continue
                    yield ("file", e.path)
            except OSError:
                yield ("error", e.path)


def scan_tree(root: str,
              roots: Sequence[chainmod.Cert],
              index: Optional[catroot.CatIndex] = None,
              matcher=None,
              limits: Optional[Limits] = None,
              quarantine=None,
              dry_run: bool = True,
              protect: Optional[Callable[[str], bool]] = None,
              workers: int = 0,
              exclude_dirs: Sequence[str] = (),
              progress: Optional[Callable[[int, int], None]] = None,
              revocation=None) -> Summary:
    limits = limits or Limits()
    summ = Summary(root=os.path.abspath(root), started=time.strftime("%Y-%m-%d %H:%M:%S"))
    if index is not None:
        summ.whitelist_status = index.summary() if index else "未建立"
    if matcher is not None:
        summ.matcher_status = getattr(matcher, "name", "unknown")
    if quarantine is not None:
        st = quarantine.stats()
        summ.quarantine_status = ("%s（%s）" % (quarantine.root,
                                  ", ".join("%s=%d" % kv for kv in st.items()) or "空"))
    t0 = time.time()

    jobs: List[str] = []
    for kind, path in _iter_files(summ.root, limits, exclude_dirs):
        if kind == "link":
            summ.skipped_link += 1
            continue
        if kind == "error":
            summ.errors.append(FileResult(path, error="目录读取失败"))
            continue
        summ.files_seen += 1
        if limits.include_exts and not path.lower().endswith(tuple(limits.include_exts)):
            summ.skipped_ext += 1
            continue
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            summ.errors.append(FileResult(path, error="取大小失败：%s" % exc))
            continue
        if size > limits.max_file_bytes:
            summ.skipped_big += 1
            continue
        jobs.append(path)
        if limits.max_files and len(jobs) >= limits.max_files:
            summ.truncated = True
            break

    def work(path: str) -> FileResult:
        return _scan_one(path, roots, index, matcher, quarantine, dry_run, protect, revocation)

    if not jobs:
        summ.elapsed = time.time() - t0
        return summ

    n_workers = workers or max(4, min(32, (os.cpu_count() or 4) * 4))
    done = 0
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(work, p): p for p in jobs}
        for fut in as_completed(futures):
            path = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:
                res = FileResult(path, error="扫描异常：%s: %s" % (type(exc).__name__, exc))
            summ.add(res)
            if not res.error:
                summ.files_scanned += 1
            done += 1
            if progress:
                try:
                    progress(done, len(jobs))
                except Exception:
                    pass

    summ.elapsed = time.time() - t0
    return summ


def _scan_one(path: str, roots, index, matcher, quarantine, dry_run: bool,
              protect, revocation=None) -> FileResult:
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    res = FileResult(path=path, size=size)

    try:
        verdict = trust.judge_any(path, roots, index=index, revocation=revocation)
    except Exception as exc:
        return FileResult(path, size=size,
                          error="判定异常：%s: %s" % (type(exc).__name__, exc))
    res.level = verdict.level
    res.basis = verdict.basis
    res.reasons = list(verdict.reasons)
    res.digest_sha256 = verdict.digest_sha256
    if getattr(verdict, "parse_failed", False):
        # 解析失败必须进「没有被检查」分区，不能混进灰名单当成"看过但没结论"
        res.error = "；".join(verdict.reasons) or "PE 解析失败"
        return res

    if matcher is not None:
        try:
            rep = matcher.scan(path, size)
        except Exception as exc:
            rep = matchmod.MatchReport(error="%s: %s" % (type(exc).__name__, exc))
        if rep.matches:
            res.level = trust.LEVEL_BLACK
            res.rules = [m.rule for m in rep.matches]
            res.reasons.append("规则命中：%s" % ", ".join(res.rules))
        if rep.error:
            res.reasons.append("规则引擎异常：%s" % rep.error)

    if res.level != trust.LEVEL_BLACK:
        return res

    protected = bool(protect and protect(path))
    if protected:
        res.action = "仅告警（系统关键路径）"
        res.reasons.append("命中系统关键路径护栏：不隔离，仅告警")
        return res
    if dry_run or quarantine is None:
        res.action = "未处置（演练模式）"
        return res
    try:
        item = quarantine.quarantine_file(path, res.rules)
        res.quarantine_id = item.id
        if item.status == "stored":
            res.action = "已加密隔离"
        else:
            res.action = "隔离未完成：%s" % (item.error or item.status)
    except Exception as exc:
        res.action = "隔离失败：%s: %s" % (type(exc).__name__, exc)
    return res
