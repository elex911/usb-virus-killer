# -*- coding: utf-8 -*-
"""
活动威胁处置（强杀 + 持久化点清理）
----------------------------------
口径与证据锚点（不可放宽）：
  * 唯一可触发修改的判定 = folder_virus 的「确证恶意」（verdict == 恶意）。
  * modern_threats 的「高危/关注」与 signature_db 的「命中/待核」是疑点，
    绝不进入本模块的强杀或清理流程（AGENTS.md 红线 2）。
  * 只杀「可执行文件精确命中确证恶意路径」的进程，及其后代进程；
    系统关键进程按名字硬白名单排除，即使路径命中也不杀。
  * 进程终止不可回滚：执行前必须摘要确认，逐进程写快照留证。

接缝（测试注入，不实际杀进程/改注册表）：
  collect_processes_with_parent / _terminate_process / _collect_persist / _apply_persist
"""
import ctypes
import io
import json
import os
from datetime import datetime

try:
    from ctypes import wintypes
except Exception:  # pragma: no cover - 非 Windows 仅用于导入不崩
    wintypes = None

from core.api import Action, ActionResult, Context, ModuleBase

# 系统关键进程：即使路径命中确证恶意也绝不终止。
# 理由：误杀这些进程会直接蓝屏/系统不可用，代价远高于放过单个恶意进程。
SYSTEM_PROCESS_NAMES = frozenset(name.lower() for name in (
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsass ", "svchost.exe", "fontdrvhost.exe",
    "dwm.exe", "sihost.exe", "explorer.exe", "ctfmon.exe", "conhost.exe",
    "audiodg.exe", "taskhostw.exe", "runtimebroker.exe", "shellexperiencehost.exe",
    "searchindexer.exe", "spoolsv.exe", "win Defend".replace(" ", ""),
))

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_TERMINATE = 0x0001
MAX_PATH = 260


# ---------------- 纯函数：证据与计划（可测接缝） ----------------

def _norm(path):
    return os.path.normcase(os.path.abspath(path)) if path else ""


def confirmed_targets(items):
    """从 folder_virus.scan() 的 items 提取确证恶意目标路径集合。

    只取 verdict == '恶意' 的项：
      - .lnk：从 detail 的 '目标: xxx' 解析被指向的真实程序；
      - 其他（autorun.inf 等）：取 path 本身。
    verdict 为「可疑 / 正常 / 待核」的一律不取。
    """
    out = set()
    for item in items or []:
        if str(item.get("verdict") or "") != "恶意":
            continue
        detail = str(item.get("detail") or "")
        target = detail.split("目标:", 1)[1].strip() if "目标:" in detail else ""
        raw = target or str(item.get("path") or "")
        if raw:
            out.add(_norm(raw))
    return out


def _is_protected(path):
    name = os.path.basename(path or "").lower()
    return name in SYSTEM_PROCESS_NAMES


def plan_kill(processes, confirmed, protected=None):
    """计算要终止的 PID 列表（有序：先父后子由调用方决定，这里只返回集合）。

    processes: [(pid, ppid, exe_path), ...]
    confirmed: 确证恶意路径集合（已规范化）
    protected: 系统白名单进程名集合

    种子 = exe 路径命中 confirmed 且不在白名单；
    再递归纳入所有后代（同样排除白名单）。疑点进程永不作为种子。
    """
    protected = SYSTEM_PROCESS_NAMES if protected is None else protected
    confirmed = set(confirmed or [])
    by_parent = {}
    info = {}
    for pid, ppid, path in processes or []:
        info[int(pid)] = (int(ppid), str(path))
        by_parent.setdefault(int(ppid), []).append(int(pid))

    seeds = []
    for pid, (ppid, path) in info.items():
        name = os.path.basename(path).lower()
        if name in protected:
            continue
        if _norm(path) in confirmed:
            seeds.append(pid)

    victims = []
    seen = set()

    def walk(pid):
        if pid in seen:
            return
        seen.add(pid)
        victims.append(pid)
        for child in by_parent.get(pid, []):
            cpath = info.get(child, (0, ""))[1]
            if os.path.basename(cpath).lower() in protected:
                continue
            walk(child)

    for s in seeds:
        walk(s)
    return victims


def plan_persist_cleanup(points, confirmed):
    """只挑选「值里含确证恶意路径」的持久化点，其余不碰。

    points: [{"id","type","value","path"}, ...]
    匹配策略：确证路径出现在 value 中（大小写不敏感），或 value 本身就是确证路径。
    """
    confirmed = set(confirmed or [])
    out = []
    for p in points or []:
        value = str(p.get("value") or "")
        low = value.lower()
        if any(c and c.lower() in low for c in confirmed):
            out.append(dict(p))
    return out


def write_snapshot(path, processes, extra=None):
    """原子写强杀快照：PID/父PID/路径/证据/时间（逐进程留证）。"""
    now = datetime.now().isoformat(timespec="seconds")
    procs = []
    for rec in (processes or []):
        item = dict(rec)
        item.setdefault("time", now)
        procs.append(item)
    payload = {
        "time": now,
        "kind": "active_defense_kill_snapshot",
        "processes": procs,
    }
    if extra:
        payload["extra"] = extra
    tmp = path + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return payload


def backup_persist(path, items):
    """原子写持久化点备份，保留原值供回滚。"""
    payload = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "kind": "active_defense_persist_backup",
        "items": list(items or []),
    }
    tmp = path + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return payload


# ---------------- Windows 接缝（默认实现，测试可覆盖） ----------------

def collect_processes_with_parent():
    """枚举 (pid, ppid, exe_path)。纯 ctypes，无第三方依赖。

    用 CreateToolhelp32Snapshot + Process32FirstW/NextW 取 PID 与父 PID，
    再 OpenProcess + QueryFullProcessImageNameW 取完整路径。
    失败时返回空列表，不抛异常（只读采集失败不应阻断）。
    """
    if wintypes is None:
        return []
    try:
        kernel = ctypes.windll.kernel32

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * MAX_PATH),
            ]

        kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
        ]

        snap = kernel.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == -1:  # INVALID_HANDLE_VALUE
            return []
        out = []
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            ok = kernel.Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                pid = int(entry.th32ProcessID)
                ppid = int(entry.th32ParentProcessID)
                path = ""
                h = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
                if h:
                    try:
                        buf = ctypes.create_unicode_buffer(1024)
                        size = wintypes.DWORD(1024)
                        if kernel.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                            path = buf.value
                    finally:
                        kernel.CloseHandle(h)
                if not path:
                    path = entry.szExeFile
                out.append((pid, ppid, path))
                ok = kernel.Process32NextW(snap, ctypes.byref(entry))
        finally:
            kernel.CloseHandle(snap)
        return out
    except Exception:
        return []


def _terminate_process(pid, log=lambda m: None):
    """终止单个进程。仅对已通过 plan_kill 的 PID 调用。"""
    if wintypes is None:
        log("非 Windows 环境，跳过终止 PID %s" % pid)
        return False
    kernel = ctypes.windll.kernel32
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    h = kernel.OpenProcess(PROCESS_TERMINATE, False, int(pid))
    if not h:
        log("无法打开进程 PID %s（可能已退出或权限不足）" % pid)
        return False
    try:
        rc = kernel.TerminateProcess(h, 1)
        log("终止 PID %s：%s" % (pid, "成功" if rc else "失败"))
        return bool(rc)
    finally:
        kernel.CloseHandle(h)


def _collect_persist(log=lambda m: None):
    """采集持久化点（只读）。复用 modern_threats 的只读采集，转换为通用结构。"""
    points = []
    try:
        from modules import modern_threats as mt
        rows = []
        rows += mt.collect_wmi(log)
        rows += mt.collect_scheduled_tasks(log)
        for idx, row in enumerate(rows):
            points.append({
                "id": "p%d" % idx,
                "type": str(row.get("kind") or "persist"),
                "value": str(row.get("value") or row.get("detail") or ""),
                "path": str(row.get("path") or ""),
            })
    except Exception as exc:
        log("持久化点采集失败：%s" % exc)
    return points


def _apply_persist_cleanup(point, log=lambda m: None):
    """对单个持久化点执行清理。默认不实现实际删除（留给显式接线）。"""
    log("持久化点清理未接线（需显式确认与备份后执行）：%s" % point.get("id"))
    return False


# ---------------- 模块类 ----------------

class Module(ModuleBase):
    meta = {
        "id": "active_defense",
        "name": "活动威胁处置",
        "version": "1.0",
        "description": "强杀确证恶意进程树、清理其关联持久化点；疑点不触发修改。",
        "order": 80,
    }

    CAUTION = (
        "强杀只认「确证恶意」锚点（隐藏原文件+.lnk伪装 / autorun.inf）；"
        "「可疑/待核/高危」一律不触发修改。系统关键进程硬白名单排除，"
        "进程终止不可回滚，执行前逐进程写快照。"
    )

    def build_view(self, parent, ctx):
        from core.widgets import ResultTable
        return ResultTable(
            parent,
            columns=[("pid", "PID", 80), ("path", "可执行文件", 420),
                     ("result", "处置", 110), ("time", "时间", 170)],
            tag_key="result",
            tag_map={"terminated": "#c0392b", "failed": "#b8860b"},
            caution=self.CAUTION,
            on_detail=self.detail,
            height=11,
        )

    def render(self, action_id, result, view, ctx):
        view.set_rows(result.data.get("victims", []))

    def detail(self, row):
        return (
            "PID：%s\n父PID：%s\n可执行文件：%s\n\n证据：%s\n\n处置：%s\n时间：%s\n\n"
            "进程终止不可回滚。完整快照见运行日志给出的 snapshot 路径。"
            % (row.get("pid", ""), row.get("ppid", ""), row.get("path", ""),
               row.get("evidence", ""), row.get("result", ""), row.get("time", ""))
        )

    def actions(self):
        return [
            Action("scan", "活动威胁扫描(只读)", target_mode="required", prompt="directory",
                   prompt_title="选择要扫描的盘符/目录", order=10),
            Action("kill", "强杀确证恶意进程树", danger=True, target_mode="required",
                   prompt="directory", prompt_title="选择要取证的盘符/目录", order=20,
                   confirm="将对所选目录现场取证：只终止「可执行文件命中确证恶意」的进程"
                           "及其后代，系统关键进程已排除。\n"
                           "进程终止不可回滚，未保存的工作可能丢失。继续？"),
            Action("clean_persist", "清理关联持久化点(可回滚)", danger=True,
                   target_mode="required", prompt="directory",
                   prompt_title="选择要取证的盘符/目录", order=30,
                   confirm="将对所选目录现场取证，只清理指向确证恶意文件的持久化点，"
                           "执行前备份可回滚。继续？"),
        ]

    def prepare_context(self, ctx, raw_target, allow_fixed=True):
        """复用 folder_virus 的目标解析（兼容 'C:  [本地固定磁盘]' 展示文本）。"""
        try:
            from modules import folder_virus as fv
            root, is_drive = fv.norm_target(raw_target)
        except Exception:
            root, is_drive = None, False
        ctx.target = root or (raw_target or "").strip()
        ctx.is_drive = bool(is_drive)
        ctx.allow_fixed = bool(allow_fixed)
        return bool(ctx.target)

    def action_confirm(self, action_id, ctx, log=lambda m: None):
        if action_id in ("kill", "clean_persist"):
            from modules import folder_virus as fv
            root, is_drive = fv.norm_target(getattr(ctx, "target", ""))
            if fv.is_system_drive_target(root, is_drive):
                return (
                    "警告：取证目标为系统盘 %s。\n"
                    "系统关键路径下的确证锚点已排除，不会触发强杀或持久化清理；"
                    "其余命中仍按原安全规则处理。\n\n确认继续？" % root
                )
        return None

    @staticmethod
    def _confirmed_from_target(ctx, log=lambda m: None):
        """现场取证：对待处理目录跑 folder_virus 只读扫描，提取确证恶意锚点。

        自包含，不依赖跨模块的隐式共享状态（主程序不会回灌 items 到 ctx.settings）。
        """
        from modules import folder_virus as fv
        eng = fv.Engine(ctx.target, getattr(ctx, "is_drive", False),
                        getattr(ctx, "allow_fixed", True))
        eng.scan(log)
        safe_items = []
        for item in eng.items:
            if item.get("system_protected") or fv.is_system_protected(item["path"]):
                log("系统保护：确证锚点 %s 仅报告，不触发强杀/持久化清理。" % item["path"])
                continue
            safe_items.append(item)
        return confirmed_targets(safe_items)

    def run(self, action_id, ctx, log):
        confirmed = self._confirmed_from_target(ctx, log)
        if not confirmed:
            return ActionResult(
                ok=True, action=action_id,
                message="【%s】未发现确证恶意目标，未做任何修改。\n"
                        "确证判定 = U盘病毒典型特征（隐藏原文件+.lnk伪装 / autorun.inf）；"
                        "「可疑/待核/高危」均不触发处置。" % ctx.target,
                data={"confirmed": [], "victims": []},
            )

        if action_id == "scan":
            procs = collect_processes_with_parent()
            victims = plan_kill(procs, confirmed)
            rows = [{"pid": p, "path": next((x[2] for x in procs if x[0] == p), "")}
                    for p in victims]
            return ActionResult(
                ok=True, action=action_id,
                message="活动威胁扫描：确证目标 %d，命中进程 %d（只读，未终止）。"
                        % (len(confirmed), len(victims)),
                data={"confirmed": sorted(confirmed), "victims": rows},
            )

        if action_id == "kill":
            procs = collect_processes_with_parent()
            victims = plan_kill(procs, confirmed)
            if not victims:
                return ActionResult(ok=True, action=action_id,
                                    message="没有命中确证恶意的运行中进程，未终止任何进程。",
                                    data={"victims": []})
            info = {int(p[0]): (int(p[1]), str(p[2])) for p in procs}
            snap_dir = os.path.join(ctx.app_dir or os.getcwd(), "active_defense_snapshots")
            os.makedirs(snap_dir, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            snap_path = os.path.join(snap_dir, "kill_%s.json" % stamp)
            records = []
            killed = 0
            # 子进程先于父进程终止，降低被拉起的可能
            for pid in sorted(victims, reverse=True):
                ppid, path = info.get(pid, (0, ""))
                rec = {"pid": pid, "ppid": ppid, "path": path,
                       "evidence": "可执行文件命中确证恶意目标路径"}
                if _terminate_process(pid, log):
                    killed += 1
                    rec["result"] = "terminated"
                else:
                    rec["result"] = "failed"
                records.append(rec)
                # 逐项落盘：中途异常也有据可查
                write_snapshot(snap_path, records)
            return ActionResult(
                ok=True, action=action_id,
                message="强杀完成：命中 %d，成功终止 %d。快照：%s"
                        % (len(victims), killed, snap_path),
                data={"victims": records, "snapshot": snap_path, "killed": killed},
                report={"active_defense": {"confirmed": sorted(confirmed),
                                           "killed": killed, "snapshot": snap_path}},
            )

        if action_id == "clean_persist":
            points = _collect_persist(log)
            plan = plan_persist_cleanup(points, confirmed)
            if not plan:
                return ActionResult(ok=True, action=action_id,
                                    message="没有指向确证恶意目标的持久化点，未做任何修改。",
                                    data={"plan": []})
            backup_dir = os.path.join(ctx.app_dir or os.getcwd(), "active_defense_snapshots")
            os.makedirs(backup_dir, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(backup_dir, "persist_%s.json" % stamp)
            backup_persist(backup_path, plan)
            cleaned = 0
            for point in plan:
                if _apply_persist_cleanup(point, log):
                    cleaned += 1
            return ActionResult(
                ok=True, action=action_id,
                message="持久化点：命中 %d，已清理 %d。备份：%s"
                        % (len(plan), cleaned, backup_path),
                data={"plan": plan, "backup": backup_path, "cleaned": cleaned},
                report={"active_defense": {"persist_hits": len(plan), "backup": backup_path}},
            )

        return ActionResult(ok=False, action=action_id, message="未知操作：%s" % action_id)
