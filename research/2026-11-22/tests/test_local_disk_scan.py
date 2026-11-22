# -*- coding: utf-8 -*-
"""本地磁盘（含系统盘）扫描能力验收。

背景：用户反馈「扫描 C:\\ 被安全拦截：目标是系统盘」。经查旧话术只存在于
`.backup-modular-20261121/FolderVirusKiller.py`，当前源码已在 7be5585
改为「默认放行固定盘，系统关键路径只报告不隔离」。本文件把这条口径钉死，
防止以后又被改回整体拒绝。

口径：
- 固定盘（DRIVE_FIXED=3）默认可扫可查杀；只有显式取消「允许本地固定磁盘」才拒。
- 系统盘根不整体拒绝，但 `is_system_protected()` 命中的项只报告、不隔离。
- 光驱/网络盘等非可处理类型仍拒绝。
"""
import os
import sys
import tempfile

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, ROOT)

from modules import folder_virus as fv

WINDOWS = os.name == "nt"


def _system_root():
    return os.path.splitdrive(os.environ.get("SystemDrive", "C:"))[0] + "\\"


def test_system_drive_root_allowed_when_allow_fixed():
    """系统盘根必须能通过 precheck（这正是用户被拦的那一步）。"""
    if not WINDOWS:
        pytest.skip("仅 Windows")
    eng = fv.Engine(_system_root(), is_drive=True, allow_fixed=True)
    eng.precheck()                                  # 不抛异常即为通过
    assert eng.meta["is_system_drive"] is True
    assert eng.meta["drive_type"] == "本地固定磁盘"
    assert "warning" not in eng.meta


def test_system_drive_allowed_via_mock_without_touching_real_disk(monkeypatch):
    """不依赖真实盘符类型：把 drive_type 钉成 3，验证门禁逻辑本身。"""
    monkeypatch.setattr(fv, "drive_type", lambda p: 3)
    monkeypatch.setenv("SystemDrive", "C:")
    eng = fv.Engine("C:\\", is_drive=True, allow_fixed=True)
    eng.precheck()
    assert eng.meta["is_system_drive"] is True


def test_fixed_drive_refused_only_when_checkbox_off(monkeypatch):
    monkeypatch.setattr(fv, "drive_type", lambda p: 3)
    monkeypatch.setenv("SystemDrive", "C:")
    eng = fv.Engine("C:\\", is_drive=True, allow_fixed=False)
    with pytest.raises(RuntimeError) as ei:
        eng.precheck()
    assert "勾选" in str(ei.value)


def test_unsupported_drive_type_still_refused(monkeypatch):
    """光驱(5)/网络盘(4) 不是可处理目标，仍应拒绝——放行固定盘不等于放行一切。"""
    monkeypatch.setattr(fv, "drive_type", lambda p: 5)
    eng = fv.Engine("E:\\", is_drive=True, allow_fixed=True)
    with pytest.raises(RuntimeError) as ei:
        eng.precheck()
    assert "不支持" in str(ei.value)


def test_system_protected_paths_marked():
    for p in (r"C:\Windows\System32\evil.exe",
              r"C:\Program Files\app\evil.exe",
              r"C:\ProgramData\evil.exe"):
        assert fv.is_system_protected(p) is True, p
    for p in (r"C:\Users\Public\evil.exe", r"C:\Temp\evil.exe"):
        assert fv.is_system_protected(p) is False, p


def test_scan_local_directory_detects_disguise():
    """在本地磁盘的目录上真跑一次扫描，确认枚举/判定链路可用（不是只看门禁）。"""
    base = tempfile.mkdtemp(prefix="pav_local_", dir=ROOT)   # ROOT 位于 C: 本地盘
    try:
        # 1) 隐藏+系统属性的原文件 + 同名 .lnk 伪装 → 恶意
        hidden = os.path.join(base, "照片.jpg")
        with open(hidden, "wb") as f:
            f.write(b"\xff\xd8\xff" + b"0" * 64)
        if WINDOWS:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
            k32.SetFileAttributesW(hidden, 0x02 | 0x04)     # HIDDEN | SYSTEM
        lnk = os.path.join(base, "照片.jpg.lnk")
        with open(lnk, "wb") as f:
            f.write(os.path.join(base, "照片.jpg").encode("utf-16-le"))

        # 2) autorun.inf → 恶意
        with open(os.path.join(base, "autorun.inf"), "w", encoding="utf-8") as f:
            f.write("[autorun]\nopen=run.exe\n")

        eng = fv.Engine(base, is_drive=False, allow_fixed=True)
        logs = []
        eng.precheck()                     # 目录模式：标 warning，但不拒绝
        stats = eng.scan(logs.append)

        assert stats["malicious"] >= 2, (stats, logs)
        kinds = {i["kind"] for i in eng.items if i["verdict"] == "恶意"}
        assert "autorun.inf" in kinds
        assert "快捷方式" in kinds
        # 这个临时目录不在系统关键路径，因此不被打保护标
        assert all(i["system_protected"] is False for i in eng.items)
        assert eng.meta["scan_stats"]["scanned"] >= 3
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)


def test_directory_mode_bypasses_drive_type_but_warns(monkeypatch):
    """目录模式不做盘符类型校验，但必须留下 warning（避免被当成"没有风险"）。"""
    eng = fv.Engine(ROOT, is_drive=False, allow_fixed=True)
    eng.precheck()
    assert eng.meta["drive_type"].startswith("目录")
    assert "warning" in eng.meta
