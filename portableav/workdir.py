"""运行位置决策：程序自己的临时目录、隔离区、报告写到哪里。

必须先分清两件事（混在一起会得出错误结论）：
1. **onefile 的解压位置**由 bootloader 在进程启动前决定，受 `TMP`/`TEMP`
   或构建期 `--runtime-tmpdir` 控制；Python 代码里改 `TEMP` 对"已经发生的解压"无效
   —— 这一步只能靠启动器（run_portableav.bat）或构建参数解决。
2. **本模块管的是第 2 件事**：程序运行期自己产生的临时文件、隔离区、日志、报告写哪。
   它管不了第 1 件事，代码里也不假装能管。

默认策略是"绝不写目标系统盘"：
- 优先程序所在目录（U 盘 / 已拷到本地的目录）；
- 只有显式 `--workdir` 指定目标盘路径，才允许写目标盘，并且报告里要标取证影响；
- 一律拒绝 WinPE 的内存盘（X:）。
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple


@dataclass
class WorkdirPlan:
    ok: bool
    path: str = ""
    reason: str = ""
    on_target_drive: bool = False
    tried: List[Tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        head = "工作目录：%s" % (self.path or "-")
        tail = "；写入目标系统盘（会改变目标盘内容，取证场景需自行评估）" if self.on_target_drive else ""
        return head + tail + ("；%s" % self.reason if self.reason else "")


def _default_probe(path: str) -> bool:
    """可写探测：真写一个临时文件再删掉（只读盘/权限不足都会在这里暴露）。"""
    try:
        fd, tmp = tempfile.mkstemp(prefix=".pav-probe-", dir=path)
        os.close(fd)
        os.unlink(tmp)
        return True
    except OSError:
        return False


def _default_free_mb(path: str) -> float:
    try:
        return shutil.disk_usage(path).free / (1024.0 * 1024.0)
    except OSError:
        return -1.0


def _drive_of(path: str) -> str:
    d = os.path.splitdrive(os.path.abspath(path))[0]
    return d.upper()


def plan_workdir(explicit: str = "",
                 app_dir: str = "",
                 target_drive: str = "",
                 system_drive: str = "X:",
                 allow_target: bool = False,
                 required_free_mb: float = 256.0,
                 probe: Optional[Callable[[str], bool]] = None,
                 free_mb: Optional[Callable[[str], float]] = None) -> WorkdirPlan:
    """按优先级挑一个可写、非内存盘、空间够的工作目录。

    候选顺序：显式指定 → 程序目录下 _work → （可选）目标盘的独立目录。
    """
    do_probe = probe or _default_probe
    do_free = free_mb or _default_free_mb
    sys_drive = (system_drive or "X:").upper()
    tgt_drive = (target_drive or "").upper()

    candidates: List[Tuple[str, str]] = []      # (路径, 类型 explicit/app/target)
    if explicit:
        candidates.append((os.path.abspath(explicit), "explicit"))
    if app_dir:
        candidates.append((os.path.join(os.path.abspath(app_dir), "_work"), "app"))
    if allow_target and tgt_drive:
        candidates.append((tgt_drive + "\\PortableAV_Work", "target"))

    plan = WorkdirPlan(ok=False)
    if not candidates:
        plan.reason = "没有可用候选目录"
        return plan

    for path, kind in candidates:
        drive = _drive_of(path)
        # 内存盘：哪怕是显式指定也拒绝（断电即失 + 空间极小）
        if drive == sys_drive:
            plan.tried.append((path, "拒绝：位于 %s（WinPE 内存盘）" % sys_drive))
            continue
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as exc:
            plan.tried.append((path, "拒绝：无法创建（%s）" % exc))
            continue
        if not os.path.isdir(path):
            plan.tried.append((path, "拒绝：不是目录"))
            continue
        if not do_probe(path):
            plan.tried.append((path, "拒绝：不可写"))
            continue
        free = do_free(path)
        if 0 <= free < required_free_mb:
            plan.tried.append((path, "拒绝：剩余空间 %.0fMB < 需要 %.0fMB" % (free, required_free_mb)))
            continue
        plan.ok = True
        plan.path = path
        plan.on_target_drive = bool(tgt_drive) and drive == tgt_drive
        plan.tried.append((path, "可用%s" % ("" if free < 0 else "（剩余 %.0fMB）" % free)))
        if kind == "explicit":
            plan.reason = "由 --workdir 显式指定，写入目标盘" if plan.on_target_drive \
                else "由 --workdir 显式指定"
        elif kind == "app":
            plan.reason = ("程序位于目标盘：工作目录随之落在被检盘上" if plan.on_target_drive
                           else "位于程序目录，不改变被检系统")
        else:
            plan.reason = "已授权写入目标盘的独立目录"
        return plan

    plan.reason = "，".join("%s：%s" % (p, r) for p, r in plan.tried) or "无可用目录"
    return plan


def apply_env(workdir: str) -> dict:
    """把临时目录指向工作目录，并关掉 __pycache__ 生成。

    坑：Windows 上 `tempfile` 的候选顺序是 **TMPDIR → TEMP → TMP**，
    只设 TEMP/TMP 而环境里已有 TMPDIR 时，会继续用旧目录（实测踩到）。
    所以三个都设，并把 `tempfile.tempdir` 直接钉死。

    仍然要强调：这只影响**本进程及其子进程**；onefile 的解压发生在进程启动前，
    必须由启动器设置，或构建时用 --runtime-tmpdir。
    """
    tmp = os.path.join(workdir, "tmp")
    os.makedirs(tmp, exist_ok=True)
    for name in ("TMPDIR", "TEMP", "TMP"):
        os.environ[name] = tmp
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    tempfile.tempdir = tmp
    return {"TMPDIR": tmp, "TEMP": tmp, "TMP": tmp, "PYTHONDONTWRITEBYTECODE": "1"}


def evidence_note(plan: WorkdirPlan) -> str:
    """写进报告的一句话，说明本次运行是否改动过目标盘。"""
    if not plan.ok:
        return "工作目录不可用：%s" % plan.reason
    if plan.on_target_drive:
        return ("本次运行的工作目录位于目标系统盘（%s）：隔离区/临时文件会写入被检系统，"
                "属于处置行为，不是纯取证。纯取证应在被检盘之外运行。" % plan.path)
    return "工作目录位于被检盘之外（%s），未改动被检系统。" % plan.path
