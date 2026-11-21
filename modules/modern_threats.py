# -*- coding: utf-8 -*-
r"""
现代威胁只读检测模块
--------------------
补上主机诊断未覆盖的 6 类持久化/痕迹位置，全部只读：

  1. WMI 事件订阅（CommandLineEventConsumer）
  2. 计划任务（TaskCache\Tasks 的 Actions 二进制中提取路径）
  3. 浏览器加载项 BHO（CLSID -> InprocServer32）
  4. 脚本文件关联劫持（.js/.vbs/.hta/.ps1 open command）
  5. 可疑进程路径（枚举进程 + QueryFullProcessImageNameW）
  6. 勒索痕迹（赎金笔记文件名 + 陌生扩展名批量出现）

红线（与 host_diagnostics 一致）：
  - 只读：全程 winreg.Query*/ctypes 查询/os.scandir，无写入、无删除、无终止进程。
  - 口径分离：只用「高危 / 关注 / 信息」，绝不写「恶意」，不进隔离流程。
  - 降噪：系统目录/官方路径一律跳过；键不存在视为「无此类项」，不当异常。
  - 证据可核：每条都附注册表路径或文件路径 + 原始值，可人工复核。
  - 不创建诱饵文件：勒索检测只读扫描已有文件。
"""
import os
import re

from core.api import Action, ActionResult, ModuleBase
from core.widgets import ResultTable

try:
    import winreg
    from ctypes import wintypes
    import ctypes
except ImportError:
    winreg = None
    wintypes = None
    ctypes = None

APP_VER = "2.0"

LEVEL_HIGH = "高危"
LEVEL_WARN = "关注"
LEVEL_INFO = "信息"

CAUTION = (
    "只读取证：不写注册表、不创建/删除文件、不终止进程。"
    "「高危/关注」是待核疑点，不等于「恶意」，不会进入隔离流程。"
)

# ---- 降噪白名单：系统/官方目录一律不报 ----
SAFE_PATH_RE = re.compile(
    r"(%systemroot%|%windir%|\\windows\\|\\program files|\\programdata\\microsoft\\|"
    r"\\system32\\|\\syswow64\\)", re.I
)
OFFICE_PATH_RE = re.compile(r"\\programdata\\microsoft\\office", re.I)

# 临时/可疑路径
TEMP_HINT_RE = re.compile(
    r"(\\|/)(temp|tmp|recycled|appdata(\\|/)local(\\|/)temp)(\\|/|[\"']|$)", re.I
)
RANDOM_NAME_RE = re.compile(r"[a-z0-9]{12,}\.(exe|dll|vbs|js|ps1|bat)$", re.I)
SCRIPT_HOST_RE = re.compile(r"(wscript|cscript|mshta|rundll32|regsvr32|powershell)\.exe", re.I)

# 勒索笔记常见文件名（只读匹配，不创建）
RANSOM_NOTE_RE = re.compile(
    r"(^|_|-)(readme|recover|restore|decrypt|how[-_ ]?to[-_ ]?decrypt|"
    r"decryption|ransom|notice|warning|help)(_|-|$|\.)",
    re.I,
)
# 常见勒索扩展名（出现 ≥3 个同类才报，避免单个文件误报）
RANSOM_EXT_RE = re.compile(
    r"\.(lockbit|blackcat|akira|wannacry|wncry|crypt|encrypted|locked|"
    r"cerber|dharma|phobos|stop|djvu|mallox|rhysida|8base)$", re.I
)

WMI_SUBSCRIPTIONS = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\WBEM\EventSubscriptions"
TASK_CACHE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
BHO_BASE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
CLSID_BASE = r"SOFTWARE\Classes\CLSID"
FILE_ASSOC_EXTS = (".js", ".jse", ".vbs", ".vbe", ".hta", ".ps1")


def _row(kind, level, path, value, detail):
    return {"kind": kind, "level": level, "path": path, "value": value, "detail": detail}


def _level_for_executable(text):
    """判断一个命令行/路径的可疑等级。"""
    if not text:
        return LEVEL_INFO, "空值"
    if SAFE_PATH_RE.search(text):
        return LEVEL_INFO, "系统/官方路径，已降噪跳过"
    if TEMP_HINT_RE.search(text) or RANDOM_NAME_RE.search(text):
        return LEVEL_WARN, "位于临时目录或随机命名（待核，可能为正常安装程序）"
    if SCRIPT_HOST_RE.search(text) and ("http" in text.lower() or "-e" in text.lower()):
        return LEVEL_WARN, "脚本宿主带脚本/网络参数（待核）"
    return LEVEL_INFO, "非系统路径但未命中可疑特征（仅登记）"


def _reg_subkeys(hive, subkey):
    """返回子键名列表；键不存在返回空列表。"""
    try:
        key = winreg.OpenKey(hive, subkey)
    except OSError:
        return []
    try:
        return [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]
    finally:
        winreg.CloseKey(key)


def _reg_values(hive, subkey):
    """返回 (name, value) 列表；键不存在返回空列表。"""
    try:
        key = winreg.OpenKey(hive, subkey)
    except OSError:
        return []
    try:
        out = []
        for i in range(winreg.QueryInfoKey(key)[1]):
            try:
                out.append(winreg.EnumValue(key, i)[:2])
            except OSError:
                pass
        return out
    finally:
        winreg.CloseKey(key)


def _reg_value(hive, subkey, name=""):
    try:
        key = winreg.OpenKey(hive, subkey)
    except OSError:
        return None
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None
    finally:
        winreg.CloseKey(key)


def collect_wmi(log=lambda m: None):
    """只读：WMI 事件订阅的命令行消费者。键不存在=无订阅，不报异常。"""
    rows = []
    if winreg is None:
        return rows
    for hive, label in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
        names = _reg_subkeys(hive, WMI_SUBSCRIPTIONS)
        for name in names:
            consumer = _reg_value(
                hive, WMI_SUBSCRIPTIONS + chr(92) + name + chr(92) + "CommandLineEventConsumer"
            )
            if consumer is None:
                continue
            consumer = str(consumer)
            level, detail = _level_for_executable(consumer)
            if SAFE_PATH_RE.search(consumer):
                continue
            level = LEVEL_HIGH if level != LEVEL_INFO else LEVEL_WARN
            detail = "WMI 事件订阅可在事件触发时执行命令（高危持久化点，需人工确认）"
            rows.append(_row(
                "WMI订阅", level,
                label + chr(92) + WMI_SUBSCRIPTIONS + chr(92) + name + chr(92) + "CommandLineTemplate",
                consumer[:300], detail,
            ))
    log("WMI 事件订阅检查完成：%d 条。" % len(rows))
    return rows


def _strings_from_binary(data):
    """从 REG_BINARY 的 Actions 中抽取 UTF-16LE 与 ASCII 可打印串。"""
    if not isinstance(data, (bytes, bytearray)):
        return []
    found = []
    # 解码后文本中的路径是单反斜杠，正则需匹配两个字面反斜杠字符
    path_re = "[A-Za-z]:" + chr(92) + chr(92) + "[^" + "\x00-\x1f" + "]{2,200}"
    try:
        text = bytes(data).decode("utf-16-le", errors="ignore")
        found += re.findall(path_re, text)
    except Exception:
        pass
    try:
        text2 = bytes(data).decode("latin-1", errors="ignore")
        found += re.findall(path_re, text2)
    except Exception:
        pass
    return list(dict.fromkeys(found))[:5]


def collect_scheduled_tasks(log=lambda m: None):
    r"""只读：从 TaskCache\Tasks 的 Actions 二进制提取可执行路径。"""
    rows = []
    if winreg is None:
        return rows
    for name in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, TASK_CACHE):
        actions = _reg_value(winreg.HKEY_LOCAL_MACHINE, TASK_CACHE + chr(92) + name, "Actions")
        if not isinstance(actions, (bytes, bytearray)):
            continue
        for exe in _strings_from_binary(actions):
            level, detail = _level_for_executable(exe)
            if level == LEVEL_INFO and SAFE_PATH_RE.search(exe):
                continue
            rows.append(_row(
                "计划任务", level,
                "HKLM" + chr(92) + TASK_CACHE + chr(92) + name + chr(92) + "Actions",
                exe[:300], detail,
            ))
    log("计划任务检查完成：%d 条。" % len(rows))
    return rows


def collect_bho(log=lambda m: None):
    """只读：浏览器 Helper Object 的 CLSID 指向 DLL 路径。"""
    rows = []
    if winreg is None:
        return rows
    for clsid in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, BHO_BASE):
        server = _reg_value(
            winreg.HKEY_LOCAL_MACHINE, CLSID_BASE + chr(92) + clsid + chr(92) + "InprocServer32"
        )
        if server is None:
            continue
        server = str(server).strip().strip('"')
        level, detail = _level_for_executable(server)
        if level == LEVEL_INFO and SAFE_PATH_RE.search(server):
            continue
        rows.append(_row(
            "浏览器加载项", level,
            "HKLM" + chr(92) + BHO_BASE + chr(92) + clsid + chr(92) + "InprocServer32",
            server[:300], detail,
        ))
    log("浏览器加载项检查完成：%d 条。" % len(rows))
    return rows


def collect_file_associations(log=lambda m: None):
    """只读：脚本扩展名的 open command 是否被改为非标准脚本宿主。"""
    rows = []
    if winreg is None:
        return rows
    for ext in FILE_ASSOC_EXTS:
        cmd = _reg_value(
            winreg.HKEY_CLASSES_ROOT, ext + chr(92) + "shell" + chr(92) + "open" + chr(92) + "command"
        )
        if cmd is None:
            continue
        cmd = str(cmd)
        if SCRIPT_HOST_RE.search(cmd) or SAFE_PATH_RE.search(cmd):
            continue
        rows.append(_row(
            "文件关联", LEVEL_HIGH,
            "HKCR" + chr(92) + ext + chr(92) + "shell" + chr(92) + "open" + chr(92) + "command",
            cmd[:300],
            "脚本文件默认打开程序不是已知脚本宿主（劫持指标，需人工确认）",
        ))
    log("脚本文件关联检查完成：%d 条。" % len(rows))
    return rows


def _process_paths():
    """只读：枚举进程并取可执行路径。必须声明 ctypes 原型，否则 64 位句柄被截断。"""
    if ctypes is None:
        return []
    kernel = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
    ]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    psapi.EnumProcesses.argtypes = [
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
    ]

    arr = (wintypes.DWORD * 1024)()
    needed = wintypes.DWORD()
    if not psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
        return []
    count = needed.value // ctypes.sizeof(wintypes.DWORD)
    paths = []
    for pid in list(arr)[:count]:
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            continue
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            if kernel.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)) and buf.value:
                paths.append((pid, buf.value))
        finally:
            kernel.CloseHandle(handle)
    return paths


def collect_processes(log=lambda m: None):
    """只读：进程路径位于临时目录或随机命名的疑点。不终止进程。"""
    rows = []
    for pid, path in _process_paths():
        if SAFE_PATH_RE.search(path):
            continue
        level, detail = _level_for_executable(path)
        if level == LEVEL_INFO and not (TEMP_HINT_RE.search(path) or RANDOM_NAME_RE.search(path)):
            continue
        rows.append(_row("进程", level, "PID %s" % pid, path[:300], detail))
    log("进程路径检查完成：%d 条疑点。" % len(rows))
    return rows


def collect_ransom_traces(log=lambda m: None):
    """只读：用户文档目录中的赎金笔记文件名与批量勒索扩展名。不创建任何诱饵。"""
    rows = []
    profile = os.environ.get("USERPROFILE", "")
    if not profile or not os.path.isdir(profile):
        return rows
    folders = [os.path.join(profile, name) for name in ("Desktop", "Documents", "Downloads")]
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        notes = []
        ext_count = {}
        try:
            with os.scandir(folder) as it:
                for entry in it:
                    if not entry.is_file():
                        continue
                    if RANSOM_NOTE_RE.search(entry.name):
                        notes.append(entry.name)
                    m = RANSOM_EXT_RE.search(entry.name)
                    if m:
                        ext_count[m.group(0).lower()] = ext_count.get(m.group(0).lower(), 0) + 1
        except OSError:
            continue
        for name in notes[:5]:
            rows.append(_row(
                "勒索痕迹", LEVEL_HIGH, os.path.join(folder, name), name,
                "文件名命中赎金笔记常见命名（待核，正常文件也可能同名）",
            ))
        for ext, count in ext_count.items():
            if count >= 3:
                rows.append(_row(
                    "勒索痕迹", LEVEL_WARN, folder, "%s × %d" % (ext, count),
                    "同一可疑扩展名批量出现（待核，需人工确认是否为正常工作产物）",
                ))
    log("勒索痕迹检查完成：%d 条。" % len(rows))
    return rows


class Module(ModuleBase):
    meta = {
        "id": "modern_threats",
        "name": "现代威胁检测（只读）",
        "version": APP_VER,
        "description": "WMI订阅/计划任务/BHO/脚本关联/进程路径/勒索痕迹，只读取证不修改。",
        "order": 30,
    }

    COLLECTORS = (
        ("WMI 事件订阅", collect_wmi),
        ("计划任务", collect_scheduled_tasks),
        ("浏览器加载项", collect_bho),
        ("脚本文件关联", collect_file_associations),
        ("进程路径", collect_processes),
        ("勒索痕迹", collect_ransom_traces),
    )

    def actions(self):
        return [
            Action(
                "collect", "现代威胁检测(只读)",
                confirm="将只读取以下位置，不写注册表、不创建/删除文件、不终止进程：\n"
                        "  · WMI 事件订阅 / 计划任务 / 浏览器加载项\n"
                        "  · 脚本文件关联 / 进程路径 / 勒索痕迹\n\n"
                        "「高危/关注」仅为待核疑点，不代表已确认恶意软件。\n继续？",
                target_mode="none", order=10,
            ),
        ]

    def build_view(self, parent, ctx):
        return ResultTable(
            parent,
            columns=[("kind", "类别", 90), ("level", "等级", 60),
                     ("path", "位置", 330), ("value", "值/路径", 240),
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
            "类别：%s\n等级：%s\n\n位置：%s\n\n值/路径：%s\n\n说明：%s\n\n"
            "本项仅作取证登记，未做任何修改。请人工核实后再决定是否处理。"
            % (row.get("kind", ""), row.get("level", ""), row.get("path", ""),
               row.get("value", ""), row.get("detail", ""))
        )

    def run(self, action_id, ctx, log):
        if action_id != "collect":
            raise RuntimeError("模块 %s 不支持操作：%s" % (self.meta["id"], action_id))
        rows = []
        for label, collector in self.COLLECTORS:
            try:
                rows.extend(collector(log))
            except Exception as exc:
                rows.append(_row(label, LEVEL_INFO, "-", "-", "采集异常：%s" % exc))
                log("%s 采集异常：%s" % (label, exc))
        n_high = sum(1 for r in rows if r["level"] == LEVEL_HIGH)
        n_warn = sum(1 for r in rows if r["level"] == LEVEL_WARN)
        return ActionResult(
            action=action_id,
            message="共 %d 条：高危 %d / 关注 %d / 信息 %d。\n\n"
                    "「高危/关注」是待核疑点，未做任何修改。\n"
                    "如需处理，请人工核实后交由正规杀毒软件。"
                    % (len(rows), n_high, n_warn, len(rows) - n_high - n_warn),
            title="现代威胁检测完成", show_dialog=True,
            data={"rows": rows},
            report={
                "modern_threats_readonly": rows,
                "caution": "只读疑点登记（高危/关注/信息），非恶意确认，未做任何修改。",
            },
        )
