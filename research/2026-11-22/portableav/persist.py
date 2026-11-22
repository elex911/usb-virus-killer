"""离线持久化矩阵：注册表自启动/服务、计划任务 XML、启动目录。

为什么这三类而不是更多：它们覆盖 U 盘蠕虫与常见驻留手法的绝大多数，
且全部可以**只读文件**解析，不需要目标系统活着。

原则：
- 每类独立 try/except，单点失败只记错误不中断；
- 解析不出来就记"解析失败"，不猜；
- 只产出线索与"关联判定"，不在这里做处置。
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from . import paths as pathmod

MAX_TASK_FILES = 20000
MAX_STARTUP_ITEMS = 5000


@dataclass
class PersistenceItem:
    kind: str                  # registry / task / startup
    source: str                # 具体位置（如 SOFTWARE\\Run / Tasks\\Foo）
    name: str
    raw: str                   # 原始命令行或路径
    note: str = ""
    target: str = ""           # 翻译成当前挂载后的路径
    unresolved: bool = False
    exists: Optional[bool] = None
    # 与扫描结果的关联
    level: str = ""
    basis: str = ""
    scanned: bool = False


@dataclass
class PersistSummary:
    items: List[PersistenceItem] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    registry_rows: int = 0
    task_files: int = 0
    startup_items: int = 0

    def add(self, item: PersistenceItem) -> None:
        if len(self.items) < MAX_TASK_FILES:
            self.items.append(item)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


# ---------------------------------------------------------------- 注册表

def registry_items(windows_dir: str, summary: PersistSummary,
                   target_drive: str) -> None:
    """复用已验证的 core.offline_registry 做只读解析（不重复造轮子）。"""
    try:
        import sys

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from core.offline_registry import RegistryHive, read_persistence
    except Exception as exc:
        summary.errors.append("离线注册表模块不可用：%s" % exc)
        return

    cfg = os.path.join(windows_dir, "System32", "config")
    handles = {}
    user_hives = []

    def open_hive(path: str):
        try:
            return RegistryHive(path)
        except Exception as exc:
            summary.errors.append("打开 hive 失败 %s：%s" % (os.path.basename(path), exc))
            return None

    sys_hive = open_hive(os.path.join(cfg, "SYSTEM"))
    if sys_hive:
        handles["SYSTEM"] = sys_hive
    sw_hive = open_hive(os.path.join(cfg, "SOFTWARE"))
    if sw_hive:
        handles["SOFTWARE"] = sw_hive

    users_root = os.path.join(os.path.dirname(os.path.normpath(windows_dir)), "Users")
    if os.path.isdir(users_root):
        try:
            for name in sorted(os.listdir(users_root))[:200]:
                p = os.path.join(users_root, name, "NTUSER.DAT")
                if os.path.isfile(p):
                    h = open_hive(p)
                    if h:
                        user_hives.append(h)
        except OSError as exc:
            summary.errors.append("枚举用户 hive 失败：%s" % exc)

    if not handles and not user_hives:
        summary.errors.append("未找到任何可读 hive（%s）" % cfg)
        return

    try:
        rows, errors = read_persistence(sys_hive, sw_hive, tuple(user_hives))
    except Exception as exc:
        summary.errors.append("持久化汇总失败：%s" % exc)
        rows, errors = [], []
    for e in errors:
        summary.errors.append("注册表：%s" % e)

    summary.registry_rows = len(rows)
    for row in rows:
        raw = row.get("value") or ""
        res = pathmod.translate(raw, target_drive,
                                exists=lambda p: os.path.isfile(p))
        summary.add(PersistenceItem(
            kind="registry", source=row.get("source", ""), name=row.get("name", ""),
            raw=raw, note=row.get("note", ""), target=res.translated,
            unresolved=res.unresolved, exists=res.exists))

    for h in list(handles.values()) + user_hives:
        try:
            h.close()
        except Exception:
            pass


# ---------------------------------------------------------------- 计划任务

def task_items(windows_dir: str, summary: PersistSummary, target_drive: str) -> None:
    tasks_root = os.path.join(windows_dir, "System32", "Tasks")
    if not os.path.isdir(tasks_root):
        return
    count = 0
    for dirpath, _dirnames, filenames in os.walk(tasks_root):
        for fn in filenames:
            count += 1
            if count > MAX_TASK_FILES:
                summary.errors.append("计划任务数量超过 %d，已截断" % MAX_TASK_FILES)
                break
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, tasks_root)
            try:
                tree = ET.parse(full)
            except (ET.ParseError, OSError) as exc:
                summary.errors.append("任务 XML 解析失败 %s：%s" % (rel, exc))
                continue
            execs = 0
            for node in tree.getroot().iter():
                if _local(node.tag) != "exec":
                    continue
                cmd = args = ""
                for child in node:
                    tag = _local(child.tag)
                    if tag == "command":
                        cmd = (child.text or "").strip()
                    elif tag == "arguments":
                        args = (child.text or "").strip()
                if not cmd:
                    continue
                execs += 1
                raw = (cmd + " " + args).strip()
                res = pathmod.translate(cmd, target_drive,
                                        exists=lambda p: os.path.isfile(p))
                summary.add(PersistenceItem(
                    kind="task", source="Tasks\\" + rel, name=os.path.basename(rel),
                    raw=raw, note="计划任务；参数：%s" % args if args else "计划任务",
                    target=res.translated, unresolved=res.unresolved,
                    exists=res.exists))
            if execs == 0:
                summary.add(PersistenceItem(
                    kind="task", source="Tasks\\" + rel, name=os.path.basename(rel),
                    raw="", note="该任务没有 Exec 动作（可能是 COM 处理器或空任务）",
                    unresolved=True))
        if count > MAX_TASK_FILES:
            break
    summary.task_files = min(count, MAX_TASK_FILES)


# ---------------------------------------------------------------- 启动目录

def startup_items(windows_dir: str, summary: PersistSummary, target_drive: str) -> None:
    base = os.path.dirname(os.path.normpath(windows_dir))
    dirs = [os.path.join(base, "ProgramData", "Microsoft", "Windows",
                         "Start Menu", "Programs", "Startup")]
    users_root = os.path.join(base, "Users")
    if os.path.isdir(users_root):
        try:
            for name in sorted(os.listdir(users_root))[:200]:
                dirs.append(os.path.join(users_root, name, "AppData", "Roaming",
                                         "Microsoft", "Windows", "Start Menu",
                                         "Programs", "Startup"))
        except OSError:
            pass

    n = 0
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            entries = list(os.scandir(d))
        except OSError as exc:
            summary.errors.append("启动目录不可读 %s：%s" % (d, exc))
            continue
        for e in entries:
            n += 1
            if n > MAX_STARTUP_ITEMS:
                summary.errors.append("启动目录条目超过 %d，已截断" % MAX_STARTUP_ITEMS)
                break
            summary.add(PersistenceItem(
                kind="startup", source="Startup",
                name=e.name, raw=e.path, note="启动目录文件（需核对快捷方式目标）",
                target=e.path, unresolved=False, exists=True))
    summary.startup_items = n


# ---------------------------------------------------------------- 汇总与关联

def collect(windows_dir: str, target_drive: str = "",
            do_registry: bool = True, do_tasks: bool = True,
            do_startup: bool = True) -> PersistSummary:
    """收集三类持久化点。任一失败只记错误，不影响其他。"""
    drive = pathmod.norm_drive(target_drive) or _drive_of(windows_dir)
    s = PersistSummary()
    if do_registry:
        try:
            registry_items(windows_dir, s, drive)
        except Exception as exc:
            s.errors.append("注册表收集异常：%s: %s" % (type(exc).__name__, exc))
    if do_tasks:
        try:
            task_items(windows_dir, s, drive)
        except Exception as exc:
            s.errors.append("计划任务收集异常：%s: %s" % (type(exc).__name__, exc))
    if do_startup:
        try:
            startup_items(windows_dir, s, drive)
        except Exception as exc:
            s.errors.append("启动目录收集异常：%s: %s" % (type(exc).__name__, exc))
    return s


def _drive_of(path: str) -> str:
    return pathmod.norm_drive(os.path.splitdrive(os.path.abspath(path))[0])


def link(items: Sequence[PersistenceItem], results_by_norm: Dict[str, object]) -> int:
    """把扫描结果按规范化路径贴到持久化条目上；返回关联上的条数。"""
    hits = 0
    for it in items:
        if not it.target:
            continue
        key = os.path.normcase(os.path.abspath(it.target))
        r = results_by_norm.get(key)
        if r is None:
            continue
        it.scanned = True
        it.level = getattr(r, "level", "")
        it.basis = getattr(r, "basis", "") or ""
        if it.level:
            hits += 1
    return hits


def index_results(results) -> Dict[str, object]:
    out: Dict[str, object] = {}
    for r in results:
        try:
            out[os.path.normcase(os.path.abspath(r.path))] = r
        except Exception:
            continue
    return out


def by_level(items: Sequence[PersistenceItem]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for it in items:
        key = it.level or "未关联"
        out[key] = out.get(key, 0) + 1
    return out
