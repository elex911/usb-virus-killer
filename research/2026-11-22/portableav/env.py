"""WinPE 环境识别（复合判据）。

为什么不用单一 MiniNT 键：已有实测记录显示，普通 Windows 上残留
`HKLM\\SYSTEM\\CurrentControlSet\\Control\\MiniNT` 会让 DISM 误判为 PE。
本模块要求「硬信号」至少命中 2 条才判 winpe，只命中 1 条判 suspected_pe，
并在报告里原样列出命中了哪些信号——不把推测说成结论。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, Dict, Mapping, Optional, Tuple

MODE_WINPE = "winpe"
MODE_SUSPECTED = "suspected_pe"
MODE_WINDOWS = "windows"

_HINT_WINPE = "离线取证模式（WinPE：目标系统进程休眠，禁用活体 API）"
_HINT_SUSPECTED = "疑似 WinPE：仅命中 1 条硬信号，按离线模式运行但需人工确认"
_HINT_WINDOWS = "常规 Windows 模式（可做活体检查）"


@dataclass(frozen=True)
class Environment:
    mode: str
    signals: Tuple[str, ...] = ()
    detail: Dict[str, str] = field(default_factory=dict)
    system_drive: str = ""
    windows_dir: str = ""

    @property
    def is_offline(self) -> bool:
        """离线语义：不碰目标系统的活体服务。疑似也按离线跑（宁可少做）。"""
        return self.mode in (MODE_WINPE, MODE_SUSPECTED)

    @property
    def hint(self) -> str:
        return {MODE_WINPE: _HINT_WINPE,
                MODE_SUSPECTED: _HINT_SUSPECTED}.get(self.mode, _HINT_WINDOWS)


def _default_minint_probe() -> bool:
    """只读探测 MiniNT 键。失败一律返回 False（不因权限问题误判为 PE）。"""
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\MiniNT",
            0,
            winreg.KEY_READ,
        )
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False
    except Exception:
        return False


def detect(
    environ: Optional[Mapping[str, str]] = None,
    minint_probe: Optional[Callable[[], bool]] = None,
    explorer_exists: Optional[Callable[[str], bool]] = None,
) -> Environment:
    """识别当前运行环境。

    environ / minint_probe / explorer_exists 全部可注入，便于在
    没有真实 PE 的机器上做确定性测试。
    """
    env = dict(os.environ if environ is None else environ)
    probe = minint_probe or _default_minint_probe

    system_drive = (env.get("SystemDrive") or "").strip().rstrip("\\")
    windows_dir = (env.get("windir") or env.get("SystemRoot") or "").strip().rstrip("\\")

    hard = []
    detail: Dict[str, str] = {}

    try:
        if probe():
            hard.append("minint_key")
            detail["minint_key"] = "存在 MiniNT 键"
        else:
            detail["minint_key"] = "不存在"
    except Exception as exc:  # 探测函数自己炸了也不能中断
        detail["minint_key"] = "探测异常：%s" % type(exc).__name__

    sd_upper = system_drive.upper()
    if sd_upper == "X:":
        hard.append("systemdrive_x")
    detail["system_drive"] = system_drive or "(未设置)"

    if windows_dir.upper().startswith("X:\\") or windows_dir.upper() == "X:":
        hard.append("windir_x")
    detail["windows_dir"] = windows_dir or "(未设置)"

    soft = []
    if windows_dir:
        checker = explorer_exists or (lambda p: os.path.isfile(p))
        try:
            if not checker(os.path.join(windows_dir, "explorer.exe")):
                soft.append("no_explorer")
                detail["explorer"] = "目标 %s 下无 explorer.exe（PE 常见）" % windows_dir
            else:
                detail["explorer"] = "存在 explorer.exe"
        except Exception:
            detail["explorer"] = "检查异常"

    # 去重但保持顺序（systemdrive_x 与 windir_x 常常同时命中，是同一件事的两面，
    # 因此把它们算作一条独立证据来源：MiniNT / X: 盘 / 无 explorer）
    uniq = tuple(dict.fromkeys(hard))
    if "systemdrive_x" in uniq and "windir_x" in uniq:
        # 两者同源（都在 X:），只算 1 条硬证据，避免自我加权
        uniq = tuple(s for s in uniq if s != "windir_x")
        detail["note"] = "systemdrive 与 windir 同在 X:，按同一证据计"

    if len(uniq) >= 2:
        mode = MODE_WINPE
    elif len(uniq) == 1:
        mode = MODE_SUSPECTED
    else:
        mode = MODE_WINDOWS

    if soft and mode == MODE_SUSPECTED:
        detail["soft"] = ",".join(soft)

    return Environment(mode=mode, signals=uniq, detail=detail,
                       system_drive=system_drive, windows_dir=windows_dir)
