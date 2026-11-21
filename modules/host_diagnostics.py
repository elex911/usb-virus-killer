# -*- coding: utf-8 -*-
"""
主机只读诊断模块
----------------
借鉴 QQKav「闪电扫描启动项/服务/注册表加载项 + IFEO 映像劫修复」的检测思路，
但只做读取与标注，不做任何修改、删除、修复动作。

红线：
  - 只读：全程 winreg.Query*，无 SetValue/DeleteValue/CreateKey。
  - 口径分离：结论用「高危 / 关注 / 信息」，绝不输出「恶意」，不进入隔离流程。
  - 降噪：默认只报异常项；Run 键全列为「信息」，仅可疑路径升为「关注」。
  - 证据可核：每条结论附完整注册表路径 + 值名 + 值数据，可人工复核。
"""
import os
import re

from core.api import Action, ActionResult, ModuleBase
from core.widgets import ResultTable

try:
    import winreg
except ImportError:
    winreg = None

APP_VER = "2.0"

LEVEL_HIGH = "高危"
LEVEL_WARN = "关注"
LEVEL_INFO = "信息"

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER if winreg else None,
     r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (winreg.HKEY_CURRENT_USER if winreg else None,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
]

IFEO_BASE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
WINDOWS_BASE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
WINLOGON_BASE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
SERVICES_BASE = r"SYSTEM\CurrentControlSet\Services"

TEMP_HINT_RE = re.compile(
    r"(\\|/)(temp|tmp|recycled|appdata(\\|/)local(\\|/)temp)(\\|/|[\"']|$)", re.I
)
RANDOM_NAME_RE = re.compile(r"[a-z0-9]{12,}\.(exe|dll|vbs|js|bat)$", re.I)
SCRIPT_HOST_RE = re.compile(r"(wscript|cscript|mshta|rundll32|regsvr32)\.exe", re.I)
SAFE_SHELL_RE = re.compile(r"^explorer\.exe$", re.I)
SAFE_SYS_PATH_RE = re.compile(
    r"(%systemroot%|%windir%|\\windows\\|\\program files|\\programdata\\microsoft\\|\\system32\\|\\syswow64\\)",
    re.I,
)

CAUTION = (
    "只读取证：不修改、不删除、不修复。「高危/关注」是待核疑点，"
    "不属于「恶意」，不会进入隔离流程。"
)


def _reg_path(hive_name, subkey, value_name=""):
    label = "HKCU" if str(hive_name).upper() in ("HKCU", "HKEY_CURRENT_USER") else "HKLM"
    return "%s\\%s%s" % (label, subkey, ("\\" + value_name) if value_name else "")


def _hive_label(hive):
    return "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"


def _level_for_command(cmd):
    c = (cmd or "").lower()
    if TEMP_HINT_RE.search(cmd or "") or RANDOM_NAME_RE.search(cmd or ""):
        return LEVEL_WARN, "路径位于临时目录或随机命名（待核，可能为正常安装程序）"
    if SCRIPT_HOST_RE.search(c) and ("http" in c or ".vbs" in c or ".js" in c):
        return LEVEL_WARN, "脚本宿主启动且带脚本/网络参数（待核）"
    return LEVEL_INFO, "常规自启动项（仅登记，非风险结论）"


def _make_row(kind, level, path, value, detail):
    return {"kind": kind, "level": level, "path": path, "value": value, "detail": detail}


def collect(log=lambda m: None):
    """只读采集。返回 rows 列表；异常转成「信息」行，不中断。"""
    rows = []
    if winreg is None:
        return [_make_row("诊断", LEVEL_INFO, "-", "-", "winreg 不可用（非 Windows 环境）")]

    for hive, subkey, _label in RUN_KEYS:
        if hive is None:
            continue
        try:
            key = winreg.OpenKey(hive, subkey)
        except OSError as e:
            rows.append(_make_row(
                "自启动", LEVEL_INFO, _reg_path(_hive_label(hive), subkey), "-",
                "读取失败（%s）；HKLM 项通常需管理员权限" % e.strerror,
            ))
            continue
        try:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                level, detail = _level_for_command(str(val))
                rows.append(_make_row(
                    "自启动", level, _reg_path(_hive_label(hive), subkey, name),
                    str(val)[:300], detail,
                ))
        finally:
            winreg.CloseKey(key)
    log("自启动项采集完成。")

    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            base = winreg.OpenKey(hive, IFEO_BASE)
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    exe = winreg.EnumKey(base, i)
                except OSError:
                    break
                i += 1
                try:
                    sub = winreg.OpenKey(hive, IFEO_BASE + "\\" + exe)
                except OSError:
                    continue
                try:
                    try:
                        dbg, _dtype = winreg.QueryValueEx(sub, "Debugger")
                    except OSError:
                        continue
                    dbg = str(dbg)
                    level = LEVEL_HIGH if (
                        TEMP_HINT_RE.search(dbg) or SCRIPT_HOST_RE.search(dbg)
                    ) else LEVEL_WARN
                    rows.append(_make_row(
                        "IFEO", level,
                        _reg_path(_hive_label(hive), IFEO_BASE + "\\" + exe, "Debugger"),
                        dbg[:300],
                        "映像劫持：运行 %s 时实际执行 Debugger 指定程序（高危指标，需人工确认是否为调试工具）" % exe,
                    ))
                finally:
                    winreg.CloseKey(sub)
        finally:
            winreg.CloseKey(base)
    log("IFEO 映像劫持检查完成。")

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINDOWS_BASE)
        try:
            val, _dtype = winreg.QueryValueEx(key, "AppInit_DLLs")
            val = str(val).strip()
            if val and val.strip(','):
                rows.append(_make_row(
                    "AppInit", LEVEL_WARN, _reg_path("HKLM", WINDOWS_BASE, "AppInit_DLLs"),
                    val[:300],
                    "全局注入 DLL 到所有进程（Win8+ 需签名，非空即需人工确认）",
                ))
        finally:
            winreg.CloseKey(key)
    except OSError:
        pass

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINLOGON_BASE)
        try:
            val, _dtype = winreg.QueryValueEx(key, "Shell")
            val = str(val).strip()
            if val and not SAFE_SHELL_RE.match(val):
                rows.append(_make_row(
                    "Winlogon", LEVEL_WARN, _reg_path("HKLM", WINLOGON_BASE, "Shell"),
                    val[:300],
                    "登录 Shell 非 explorer.exe（需人工确认是否为正常定制）",
                ))
        finally:
            winreg.CloseKey(key)
    except OSError:
        pass

    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICES_BASE)
    except OSError:
        rows.append(_make_row(
            "服务", LEVEL_INFO, _reg_path("HKLM", SERVICES_BASE), "-",
            "读取失败；服务枚举通常需管理员权限",
        ))
    else:
        try:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(base, i)
                except OSError:
                    break
                i += 1
                try:
                    sub = winreg.OpenKey(base, name + "\\Parameters")
                except OSError:
                    continue
                try:
                    try:
                        val, _dtype = winreg.QueryValueEx(sub, "ServiceDll")
                    except OSError:
                        continue
                    val = str(val)
                    if SAFE_SYS_PATH_RE.search(val):
                        continue
                    if TEMP_HINT_RE.search(val) or RANDOM_NAME_RE.search(val):
                        rows.append(_make_row(
                            "服务", LEVEL_WARN,
                            _reg_path("HKLM", SERVICES_BASE + "\\" + name + "\\Parameters", "ServiceDll"),
                            val[:300],
                            "服务 DLL 位于临时目录或随机命名（待核，非系统路径）",
                        ))
                finally:
                    winreg.CloseKey(sub)
        finally:
            winreg.CloseKey(base)
    log("服务检查完成。")

    n_high = sum(1 for r in rows if r["level"] == LEVEL_HIGH)
    n_warn = sum(1 for r in rows if r["level"] == LEVEL_WARN)
    log("只读诊断完成：共 %d 条（高危 %d / 关注 %d / 信息 %d）。"
        % (len(rows), n_high, n_warn, len(rows) - n_high - n_warn))
    return rows


class Module(ModuleBase):
    meta = {
        "id": "host_diagnostics",
        "name": "主机诊断（只读）",
        "version": "2.0",
        "description": "启动项/IFEO/AppInit/Winlogon/服务 DLL，只读取证不修改。",
        "order": 20,
    }

    def actions(self):
        return [
            Action(
                "collect", "主机诊断(只读)",
                confirm="将只读取以下位置，不修改、不删除任何内容：\n"
                        "  · 自启动项（Run / RunOnce）\n"
                        "  · IFEO 映像劫持（Debugger 值）\n"
                        "  · AppInit_DLLs / Winlogon Shell\n"
                        "  · 可疑服务 DLL 路径\n\n"
                        "结果中的「高危/关注」仅为待核疑点，不代表已确认病毒。\n继续？",
                target_mode="none", order=10,
            ),
        ]

    def build_view(self, parent, ctx):
        return ResultTable(
            parent,
            columns=[("kind", "类别", 80), ("level", "等级", 60),
                     ("path", "注册表位置", 340), ("value", "值数据", 230),
                     ("detail", "说明", 300)],
            tag_key="level",
            tag_map={"高危": "#c0392b", "关注": "#b8860b", "信息": "#666"},
            caution=CAUTION,
            on_detail=self.detail,
            height=11,
        )

    def render(self, action_id, result, view, ctx):
        view.set_rows(result.data.get("rows", []))

    def detail(self, row):
        return (
            "类别：%s\n等级：%s\n\n注册表位置：%s\n\n值数据：%s\n\n说明：%s\n\n"
            "本项仅作取证登记，未做任何修改。请人工核实后再决定是否处理。"
            % (row.get("kind", ""), row.get("level", ""), row.get("path", ""),
               row.get("value", ""), row.get("detail", ""))
        )

    def run(self, action_id, ctx, log):
        rows = collect(log)
        n_high = sum(1 for r in rows if r["level"] == LEVEL_HIGH)
        n_warn = sum(1 for r in rows if r["level"] == LEVEL_WARN)
        return ActionResult(
            action=action_id,
            message="共 %d 条：高危 %d / 关注 %d / 信息 %d。\n\n"
                    "「高危/关注」是待核疑点，未做任何修改。\n"
                    "如需处理，请人工核实后自行操作，或交由正规杀毒软件。"
                    % (len(rows), n_high, n_warn, len(rows) - n_high - n_warn),
            title="只读诊断完成", show_dialog=True,
            data={"rows": rows},
            report={
                "host_diagnostics_readonly": rows,
                "caution": "只读疑点登记（高危/关注/信息），非病毒确认，未做任何修改。",
            },
        )
