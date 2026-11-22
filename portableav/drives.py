"""磁盘与离线系统盘定位。

原则：
- 只把 DRIVE_FIXED 当作候选（U 盘是自己所在的介质，不当作扫描目标）；
- WinPE 下排除自身所在的 X:；
- 判定一个目录是不是「离线系统」必须同时满足
  `Windows\\System32\\ntoskrnl.exe` 与 `Windows\\System32\\config\\SYSTEM`，
  少一个就标 incomplete 并写明缺哪个，不猜；
- 支持一台机器多个 Windows 目录（Windows、Windows.old、Windows10 等）。
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

DRIVE_TYPE_NAMES = {
    DRIVE_UNKNOWN: "未知",
    DRIVE_NO_ROOT_DIR: "无效",
    DRIVE_REMOVABLE: "可移动",
    DRIVE_FIXED: "本地固定",
    DRIVE_REMOTE: "网络",
    DRIVE_CDROM: "光驱",
    DRIVE_RAMDISK: "内存盘",
}


@dataclass(frozen=True)
class Drive:
    letter: str          # 'C:'
    type_code: int
    ready: bool = True

    @property
    def type_name(self) -> str:
        return DRIVE_TYPE_NAMES.get(self.type_code, "未知(%d)" % self.type_code)


@dataclass(frozen=True)
class OfflineSystem:
    drive: str           # 'D:'
    windows_dir: str     # 'D:\\Windows'
    complete: bool       # ntoskrnl + SYSTEM hive 都在
    missing: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()

    @property
    def label(self) -> str:
        state = "完整" if self.complete else "不完整(缺 %s)" % ",".join(self.missing)
        return "%s\\Windows  [%s]" % (self.drive, state)


def _win32_list_drives() -> List[Drive]:
    """枚举本机盘符与类型。非 Windows 平台返回空。"""
    if os.name != "nt":
        return []
    k32 = ctypes.windll.kernel32
    buf_len = k32.GetLogicalDriveStringsW(0, None)
    if not buf_len:
        return []
    buf = ctypes.create_unicode_buffer(buf_len)
    k32.GetLogicalDriveStringsW(buf_len, buf)
    out: List[Drive] = []
    for part in buf[:].split("\x00"):
        if not part:
            continue
        letter = part.rstrip("\\")
        if len(letter) != 2:
            continue
        code = int(k32.GetDriveTypeW(part))
        out.append(Drive(letter=letter.upper(), type_code=code, ready=os.path.isdir(part)))
    return out


def list_drives(api: Optional[Callable[[], Sequence[Drive]]] = None) -> List[Drive]:
    return list(api() if api else _win32_list_drives())


def _list_subdirs(path: str) -> List[str]:
    try:
        return [e.name for e in os.scandir(path) if e.is_dir(follow_symlinks=False)]
    except Exception:
        return []


def candidate_windows_dirs(
    drive: str,
    subdirs: Optional[Callable[[str], List[str]]] = None,
) -> List[str]:
    """列出该盘下所有可能的 Windows 目录（含 Windows.old / Windows10 等）。"""
    lister = subdirs or _list_subdirs
    root = drive.rstrip("\\") + "\\"
    names = lister(root)
    picked = [n for n in names if n.lower() == "windows" or n.lower().startswith("windows")]
    # 稳定顺序：Windows 优先，其余按名称
    picked.sort(key=lambda n: (n.lower() != "windows", n.lower()))
    return [os.path.join(root, n) for n in picked]


def find_offline_systems(
    drives: Optional[Iterable[Drive]] = None,
    exists: Optional[Callable[[str], bool]] = None,
    in_pe: bool = False,
    pe_drive: str = "X:",
    include_removable: bool = False,
    subdirs: Optional[Callable[[str], List[str]]] = None,
) -> List[OfflineSystem]:
    """定位离线系统盘。返回可能为空，调用方必须处理空结果（不许自动猜）。"""
    is_file = exists or (lambda p: os.path.isfile(p))
    pool = list(drives) if drives is not None else list_drives()
    wanted = {DRIVE_FIXED}
    if include_removable:
        wanted.add(DRIVE_REMOVABLE)

    out: List[OfflineSystem] = []
    pe = pe_drive.rstrip("\\").upper()
    for d in pool:
        if d.type_code not in wanted:
            continue
        if in_pe and d.letter.upper() == pe:
            continue
        for win in candidate_windows_dirs(d.letter, subdirs):
            kernel = os.path.join(win, "System32", "ntoskrnl.exe")
            hive = os.path.join(win, "System32", "config", "SYSTEM")
            has_k = is_file(kernel)
            has_h = is_file(hive)
            if not has_k and not has_h:
                continue  # 连特征都没有，不当作候选
            missing = []
            if not has_k:
                missing.append("ntoskrnl.exe")
            if not has_h:
                missing.append("SYSTEM")
            notes = []
            if os.path.basename(win).lower() != "windows":
                notes.append("非默认目录名")
            out.append(OfflineSystem(drive=d.letter, windows_dir=win,
                                     complete=not missing, missing=tuple(missing),
                                     notes=tuple(notes)))
    # 完整的排前面
    out.sort(key=lambda s: (not s.complete, s.drive, s.windows_dir.lower()))
    return out


def describe_drives(drives: Iterable[Drive]) -> List[str]:
    return ["%s  %s%s" % (d.letter, d.type_name, "" if d.ready else " (未就绪)") for d in drives]
