"""离线路径翻译：把目标系统里写的 C:\\... / %SystemRoot% / \\SystemRoot\\ 等
翻译成当前（WinPE 或本机）真实的挂载路径。

设计原则（与附件 Demo 的差异，逐条都是踩过的坑）：
1. 只在字符串**开头**匹配盘符 `^[A-Za-z]:`，不用 `p[1] == ':'` 这种盲判，
   否则 `\\\\?\\C:\\`、`\\\\server\\share` 会被误改。
2. UNC（`\\\\` 开头）一律不重映射——它指向网络，不是本地离线系统。
3. 只有「盘符与目标盘不同」才重映射；已经指向目标盘的不动，保证幂等。
4. `\\Device\\HarddiskVolumeN\\` 这种内核路径必须靠调用方提供卷映射表，
   查不到就原样返回并标记 unresolved，绝不猜。
5. 环境变量按 token 精确替换（大小写不敏感），未知 token 保留原文，
   不做「猜它是啥」的补全。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Callable, Dict, Mapping, Optional, Tuple

# %VAR% 形式的 token；只认字母数字和括号（覆盖 %ProgramFiles(x86)%）
_ENV_TOKEN = re.compile(r"%([A-Za-z0-9_()#]+)%")

# 命令里可执行文件后缀，按长度降序，避免 .exe 抢在 .sys 前面
_EXE_SUFFIXES = (".exe", ".sys", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js")

# 驱动类路径可能带这些前缀（长的在前，避免短前缀先吃掉）
_STRIPPABLE_PREFIXES = ("\\\\?\\", "\\??\\", "\\\\.\\")

_DRIVE_RE = re.compile(r"^([A-Za-z]):(.*)$", re.DOTALL)
_DEVICE_RE = re.compile(r"^\\Device\\HarddiskVolume(\d+)(.*)$", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class Resolution:
    """一条注册表/任务值的翻译结果。"""

    raw: str                 # 原始字符串
    executable: str          # 从命令行里抽出的可执行文件部分（未翻译）
    translated: str          # 翻译后的路径（可能仍不可解析）
    kind: str                # quoted / extension / first_token / empty
    remapped: bool           # 是否发生过盘符重映射
    unresolved: bool         # 是否是完全没法定位的路径（UNC/未知 Device/无字母）
    exists: Optional[bool]   # None 表示未做存在性检查


def norm_drive(drive: str) -> str:
    """'d:' / 'd:\\' / 'D:/' -> 'D:'。空或非法返回 ''。"""
    if not drive:
        return ""
    d = drive.strip().strip('"').rstrip("\\/")
    if len(d) == 1 and d.isalpha():
        return d.upper() + ":"
    if len(d) == 2 and d[1] == ":" and d[0].isalpha():
        return d[0].upper() + ":"
    return ""


def env_map(target_drive: str) -> Dict[str, str]:
    """目标系统视角的环境变量展开表（值均为当前挂载下的绝对路径）。"""
    d = norm_drive(target_drive)
    win = d + "\\Windows"
    return {
        "systemroot": win,
        "windir": win,
        "systemdrive": d,
        "system32": win + "\\System32",
        "programdata": d + "\\ProgramData",
        "programfiles": d + "\\Program Files",
        "programfiles(x86)": d + "\\Program Files (x86)",
        "commonprogramfiles": d + "\\Common Files",
        "commonprogramfiles(x86)": d + "\\Common Files (x86)",
    }


def expand_env(text: str, target_drive: str) -> str:
    """把 %SystemRoot% 之类替换成当前挂载路径；未知 token 原样保留。"""
    table = env_map(target_drive)

    def _sub(match: "re.Match[str]") -> str:
        key = match.group(1).lower()
        return table.get(key, match.group(0))

    return _ENV_TOKEN.sub(_sub, text)


def extract_executable(raw: str) -> Tuple[str, str]:
    """从命令行里抽出可执行文件部分。

    返回 (executable, kind)；kind 用于报告里说明「凭什么这么切」：
    - quoted：引号包裹，最可靠
    - extension：按已知后缀切，是启发式
    - first_token：只取第一个空白分隔 token
    - empty：空值
    """
    if raw is None:
        return "", "empty"
    s = str(raw).strip()
    if not s:
        return "", "empty"
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 1:
            return s[1:end], "quoted"
        # 引号没闭合——按后缀继续尝试，不直接放弃
        s = s[1:]
    lower = s.lower()
    best = -1
    for suf in _EXE_SUFFIXES:
        idx = lower.find(suf)
        while idx != -1:
            # 后缀后面必须是结尾/空白/逗号，避免 a.exe.bak 被切成 a.exe
            after = lower[idx + len(suf): idx + len(suf) + 1]
            if after == "" or after in " \t,;":
                best = max(best, idx + len(suf))
                break
            idx = lower.find(suf, idx + 1)
    if best > 0:
        return s[:best], "extension"
    first = s.split()[0] if s.split() else ""
    return first, "first_token"


def translate(
    raw: str,
    target_drive: str,
    device_map: Optional[Mapping[int, str]] = None,
    exists: Optional[Callable[[str], bool]] = None,
) -> Resolution:
    """把一条原始值翻译成当前挂载路径。

    device_map: {3: 'D:'} 形式的 卷号 -> 盘符，用于 \\Device\\HarddiskVolumeN\\；
    exists: 传入 os.path.isfile 可顺带探测文件是否真实存在（只读）。
    """
    drive = norm_drive(target_drive)
    exe, kind = extract_executable(raw)
    if not exe:
        return Resolution(str(raw or ""), "", "", "empty", False, True, None)

    work = exe
    for pref in _STRIPPABLE_PREFIXES:
        if work.lower().startswith(pref.lower()):
            work = work[len(pref):]
            break

    unresolved = False

    # 内核卷路径：只有给了映射表才敢翻译
    mapped_device = False
    m = _DEVICE_RE.match(work)
    if m:
        vol = int(m.group(1))
        if device_map and vol in device_map:
            work = norm_drive(device_map[vol]) + m.group(2)
            mapped_device = True
        else:
            unresolved = True

    if not unresolved:
        work = expand_env(work, drive)

        low = work.lower()
        if low.startswith("\\\\systemroot\\"):
            work = drive + "\\Windows" + work[len("\\\\systemroot"):]
        elif low.startswith("\\systemroot\\"):
            work = drive + "\\Windows" + work[len("\\systemroot"):]
        elif low.startswith("systemroot\\"):
            work = drive + "\\Windows\\" + work[len("systemroot\\"):]

    remapped = False
    if not unresolved:
        if work.startswith("\\\\"):
            # UNC 指向网络共享，不属于离线系统
            unresolved = True
        else:
            m = _DRIVE_RE.match(work)
            if m:
                letter = m.group(1).upper()
                if mapped_device:
                    # 已由 \\Device\\HarddiskVolumeN 映射到真实盘，不再二次改写
                    pass
                elif drive and letter != drive[0]:
                    work = drive + m.group(2)
                    remapped = True
            elif work.startswith("\\"):
                # 无盘符但绝对：相对目标盘根
                work = drive + work
            elif work.lower().startswith("system32\\"):
                work = drive + "\\Windows\\" + work
            else:
                # 裸文件名（如 svchost.exe）：搜索路径语义，无法离线定位
                unresolved = True

    ok: Optional[bool] = None
    if exists is not None and not unresolved and work:
        try:
            ok = bool(exists(work))
        except Exception:
            ok = None

    return Resolution(str(raw or ""), exe, work, kind, remapped, unresolved, ok)


def is_system_critical(path: str, target_drive: str) -> bool:
    """目标系统关键路径判定（处置前护栏；只报告不处置）。

    与主项目 modules/folder_virus.is_system_protected 的口径保持一致：
    宁可多护，不可误动——误隔离 bootmgr / ntoskrnl 会导致目标机无法启动。
    """
    if not path:
        return False
    p = path.replace("/", "\\").rstrip("\\").lower()
    d = norm_drive(target_drive)
    win = (d + "\\windows").lower()
    guards = (
        win + "\\system32\\config",
        win + "\\system32\\drivers",
        win + "\\system32\\catroot",
        win + "\\winsxs",
        win + "\\boot",
        win + "\\system32\\ntoskrnl.exe",
        win + "\\system32\\winload.exe",
        win + "\\system32\\winlogon.exe",
        win + "\\system32\\services.exe",
        win + "\\system32\\lsass.exe",
        win + "\\system32\\csrss.exe",
        win + "\\system32\\smss.exe",
        win + "\\explorer.exe",
        win + "\\system32\\svchost.exe",
        win + "\\system32\\userinit.exe",
        d.lower() + "\\bootmgr",
        d.lower() + "\\boot\\bcd",
        d.lower() + "\\pagefile.sys",
        d.lower() + "\\hiberfil.sys",
        d.lower() + "\\swapfile.sys",
        d.lower() + "\\efi",
    )
    return any(p == g or p.startswith(g + "\\") for g in guards)


def resolve_relative_to(value: str, base_dir: str) -> str:
    """把不含盘符的相对路径（如 System32\\a.sys）补到给定基目录下。仅用于展示。"""
    if not value:
        return value
    if _DRIVE_RE.match(value) or value.startswith("\\\\"):
        return value
    return os.path.join(base_dir, value.lstrip("\\"))
