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
from datetime import datetime

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


def _fix_command_for(row):
    """把一条诊断发现映射为 (类型, 正文)。

    类型：command=可注释掉的 PowerShell 命令；note=仅人工处理建议。
    解析失败或信息级行一律给 note。所有命令默认注释，由用户复核后自行执行。
    """
    kind = str(row.get("kind", ""))
    path = str(row.get("path", "") or "")
    if not path or path in ("-", "(AMSI)"):
        return "note", "项无法解析出注册表路径，请人工处理。"
    if kind in ("Winlogon", "服务"):
        return "note", ("涉及登录 Shell / 服务 DLL，误改可能导致系统无法启动，"
                        "请人工确认后手动处理（services.msc / 注册表编辑器）。")
    parts = path.split("\\")
    if len(parts) < 3:
        return "note", "注册表路径不完整，请人工处理。"
    label = parts[0]
    hive = {"HKCU": "HKCU:", "HKLM": "HKLM:"}.get(label.upper())
    if hive is None:
        return "note", "未知注册表配置单元 %s，请人工处理。" % label
    value_name = parts[-1]
    key_path = hive + "\\" + "\\".join(parts[1:-1])
    if kind == "AppInit":
        cmd = ("Set-ItemProperty -Path '%s' -Name '%s' -Value ''"
               % (key_path, value_name.replace("'", "''")))
        note = "清空 AppInit_DLLs（会立即影响所有进程加载行为，请先确认无误）"
        return "command", (cmd, note)
    cmd = ("Remove-ItemProperty -Path '%s' -Name '%s'"
           % (key_path, value_name.replace("'", "''")))
    return "command", (cmd, None)


def build_fix_script(rows, out_path, generated_at):
    """生成默认全注释的修复脚本；返回 (命令数, 建议数)。"""
    lines = [
        "# 主机诊断修复脚本（由 usb-virus-killer 生成）",
        "# 生成时间：%s" % generated_at,
        "#",
        "# 使用说明（务必先读）：",
        "#   1. 本脚本所有命令默认注释，本工具不会替你执行任何修改。",
        "#   2. 逐条复核后，把确认要执行的行去掉行首 \"# \" 再运行。",
        "#   3. 执行前请自行备份对应注册表项（reg export）或创建系统还原点。",
        "#   4. 高危/关注是待核疑点，不是病毒确认；不确定的项宁可跳过。",
        "#",
    ]
    n_cmd = n_note = 0
    for i, row in enumerate(rows, 1):
        if row.get("level") not in (LEVEL_HIGH, LEVEL_WARN):
            continue
        kind = str(row.get("kind", ""))
        lines.append("# ---- 第 %d 项 [%s] %s ----" % (i, row.get("level"), kind))
        lines.append("# 位置：%s" % row.get("path", ""))
        lines.append("# 值数据：%s" % str(row.get("value", ""))[:200])
        lines.append("# 说明：%s" % str(row.get("detail", ""))[:200])
        typ, body = _fix_command_for(row)
        if typ == "command":
            cmd, extra = body
            if extra:
                lines.append("# 注意：%s" % extra)
            lines.append("# " + cmd)
            n_cmd += 1
        else:
            lines.append("# 建议：%s" % body)
            n_note += 1
        lines.append("")
    lines.append("# 本脚本未包含任何未注释的命令。")
    with open(out_path, "w", encoding="utf-8-sig", newline="\r\n") as f:
        f.write("\n".join(lines) + "\n")
    return n_cmd, n_note


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
            Action(
                "fixscript", "导出修复脚本",
                confirm="将把最近一次「主机诊断(只读)」的高危/关注项生成 PowerShell 修复脚本。\n"
                        "脚本内所有命令默认注释，本工具不会替你执行；\n"
                        "逐条复核、备份注册表后再自行取消注释执行。\n继续？",
                target_mode="none", order=20,
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
        if action_id == "fixscript":
            return self._fixscript(action_id, ctx, log)

        rows = collect(log)
        self._last_rows = rows
        self._last_time = datetime.now().isoformat()
        n_high = sum(1 for r in rows if r["level"] == LEVEL_HIGH)
        n_warn = sum(1 for r in rows if r["level"] == LEVEL_WARN)
        return ActionResult(
            action=action_id,
            message="共 %d 条：高危 %d / 关注 %d / 信息 %d。\n\n"
                    "「高危/关注」是待核疑点，未做任何修改。\n"
                    "如需处理，请人工核实后自行操作，或用「导出修复脚本」生成待审脚本。"
                    % (len(rows), n_high, n_warn, len(rows) - n_high - n_warn),
            title="只读诊断完成", show_dialog=True,
            data={"rows": rows},
            report={
                "host_diagnostics_readonly": rows,
                "caution": "只读疑点登记（高危/关注/信息），非病毒确认，未做任何修改。",
            },
        )

    def _fixscript(self, action_id, ctx, log):
        rows = getattr(self, "_last_rows", None)
        if not rows:
            return ActionResult(
                action=action_id, ok=False, show_dialog=True, title="导出修复脚本",
                message="还没有诊断结果。请先点「主机诊断(只读)」，再导出修复脚本。",
                data={"rows": []}, report={"written": 0},
            )
        targets = [r for r in rows if r.get("level") in (LEVEL_HIGH, LEVEL_WARN)]
        if not targets:
            return ActionResult(
                action=action_id, message="最近一次诊断没有高危/关注项，无需修复脚本。",
                title="导出修复脚本", show_dialog=True,
                data={"rows": [{"kind": "脚本", "level": "信息", "path": "(修复脚本)",
                                "value": "无可处理项", "detail": "诊断结果均为信息级"}]},
                report={"written": 0, "commands": 0, "notes": 0},
            )
        app_dir = ctx.app_dir or os.getcwd()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(app_dir, "修复脚本_主机诊断_%s.ps1" % stamp)
        generated_at = getattr(self, "_last_time", "") or datetime.now().isoformat()
        n_cmd, n_note = build_fix_script(rows, out_path, generated_at)
        log("修复脚本已生成：%s（命令 %d 条，人工建议 %d 条）" % (out_path, n_cmd, n_note))
        msg = ("修复脚本已生成（默认全部注释，未执行任何命令）：\n%s\n\n"
               "可注释命令 %d 条 / 人工处理建议 %d 条。\n"
               "请逐条复核、备份注册表后再自行取消注释执行。"
               % (out_path, n_cmd, n_note))
        return ActionResult(
            action_id, message=msg, title="导出修复脚本", show_dialog=True,
            data={"rows": [{"kind": "脚本", "level": "信息", "path": out_path,
                            "value": "可注释命令 %d 条 / 人工建议 %d 条"
                                     % (n_cmd, n_note),
                            "detail": "全部命令默认注释；复核后自行执行"}]},
            report={"written": 1, "fixscript": out_path,
                    "commands": n_cmd, "notes": n_note,
                    "high_or_warn": len(targets)},
        )
