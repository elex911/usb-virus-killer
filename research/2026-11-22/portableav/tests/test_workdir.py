"""运行位置决策测试。

核心断言：**默认绝不写目标系统盘、绝不写 X:**。
因为"写到哪"直接决定这件事是取证还是处置，不能靠使用者记得加参数。
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from portableav import workdir


def _ok_probe(_path):
    return True


def _no_probe(_path):
    return False


def _plenty(_path):
    return 10_000.0


def _drive(path) -> str:
    d = os.path.splitdrive(os.path.abspath(str(path)))[0]
    return (d or "C:") + ":" if not d.endswith(":") else d


def test_default_uses_app_dir_and_not_target(tmp_path):
    app = str(tmp_path / "app")
    os.makedirs(app, exist_ok=True)
    # 目标盘设成另一个盘符，确保 app 目录不在目标盘上
    other = "Z:" if _drive(tmp_path).upper() != "Z:" else "Y:"
    plan = workdir.plan_workdir(app_dir=app, target_drive=other,
                                system_drive="X:", probe=_ok_probe, free_mb=_plenty)
    assert plan.ok
    assert plan.path.endswith("_work")
    assert plan.on_target_drive is False
    assert "不改变被检系统" in plan.reason


def test_target_drive_not_used_without_permission(tmp_path):
    """没给 --allow-target-write 时，目标盘候选根本不出现。"""
    app = str(tmp_path / "app")
    os.makedirs(app, exist_ok=True)
    plan = workdir.plan_workdir(app_dir=app, target_drive="D:",
                                system_drive="X:", allow_target=False,
                                probe=_ok_probe, free_mb=_plenty)
    assert all("PortableAV_Work" not in p for p, _ in plan.tried)


def test_target_drive_used_when_allowed(tmp_path):
    """程序就放在目标盘上（把绿包拷到被检系统的情形）→ 必须标出这一点。"""
    app = str(tmp_path / "app")
    os.makedirs(app, exist_ok=True)
    plan = workdir.plan_workdir(app_dir=app, target_drive=_drive(tmp_path),
                                system_drive="X:", allow_target=True,
                                probe=_ok_probe, free_mb=_plenty)
    assert plan.ok
    assert plan.on_target_drive is True
    assert "目标盘" in plan.reason


def test_x_drive_always_rejected(tmp_path):
    """X: 是内存盘：显式指定也拒绝（断电即失，空间极小）。"""
    plan = workdir.plan_workdir(explicit="X:\\PortableAV_Work", system_drive="X:",
                                probe=_ok_probe, free_mb=_plenty)
    assert plan.ok is False
    assert any("内存盘" in r for _p, r in plan.tried)


def test_unwritable_falls_through_to_next(tmp_path):
    app = str(tmp_path / "app")
    os.makedirs(app, exist_ok=True)
    explicit = str(tmp_path / "explicit")

    def probe(path):
        return not path.startswith(explicit)      # 显式目录不可写

    plan = workdir.plan_workdir(explicit=explicit, app_dir=app, system_drive="X:",
                                probe=probe, free_mb=_plenty)
    assert plan.ok
    assert plan.path == os.path.join(os.path.abspath(app), "_work")
    assert any("不可写" in r for _p, r in plan.tried)


def test_low_space_rejected(tmp_path):
    app = str(tmp_path / "app")
    os.makedirs(app, exist_ok=True)
    plan = workdir.plan_workdir(app_dir=app, system_drive="X:",
                                required_free_mb=999_999, probe=_ok_probe,
                                free_mb=lambda p: 10.0)
    assert plan.ok is False
    assert any("剩余空间" in r for _p, r in plan.tried)


def test_no_candidate_reports_reason(tmp_path):
    plan = workdir.plan_workdir(system_drive="X:", probe=_ok_probe, free_mb=_plenty)
    assert plan.ok is False
    assert plan.reason


def test_apply_env_sets_temp_and_no_pycache(tmp_path):
    wd = str(tmp_path / "w")
    os.makedirs(wd, exist_ok=True)
    backup = {k: os.environ.get(k) for k in ("TMPDIR", "TEMP", "TMP", "PYTHONDONTWRITEBYTECODE")}
    backup_tempdir = tempfile.tempdir
    try:
        envs = workdir.apply_env(wd)
        for name in ("TMPDIR", "TEMP", "TMP"):
            assert os.environ[name] == envs[name]
        assert os.environ["PYTHONDONTWRITEBYTECODE"] == "1"
        assert os.path.isdir(envs["TEMP"])
        # 关键：tempfile 必须真的跟着走（Windows 上 TMPDIR 优先级最高，曾经踩过）
        assert os.path.normcase(tempfile.gettempdir()) == os.path.normcase(envs["TEMP"])
        with tempfile.NamedTemporaryFile(delete=True) as f:
            assert os.path.normcase(os.path.dirname(f.name)) == os.path.normcase(envs["TEMP"])
    finally:
        for k, v in backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        tempfile.tempdir = backup_tempdir


def test_evidence_note_wording(tmp_path):
    app = str(tmp_path / "app")
    os.makedirs(app, exist_ok=True)
    other = "Z:" if _drive(tmp_path).upper() != "Z:" else "Y:"
    safe = workdir.plan_workdir(app_dir=app, target_drive=other, system_drive="X:",
                                probe=_ok_probe, free_mb=_plenty)
    assert "未改动被检系统" in workdir.evidence_note(safe)

    on_target = workdir.plan_workdir(app_dir=app, target_drive=_drive(tmp_path),
                                     allow_target=True, system_drive="X:",
                                     probe=_ok_probe, free_mb=_plenty)
    note = workdir.evidence_note(on_target)
    assert "不是纯取证" in note
