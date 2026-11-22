"""构建护栏用例：--force 不得连带删掉已隔离的样本。

背景：绿包默认工作目录是 <包目录>\\_work，加密隔离区就在里面。
      build_portable.py --force 原先是直接 rmtree(out)，会把隔离样本一起删掉，
      而且删掉后无法还原——这不是"重建"，是"销毁证据"。
"""

import importlib.util
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load_builder():
    path = os.path.join(ROOT, "tools", "build_portable.py")
    spec = importlib.util.spec_from_file_location("pav_build_portable", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def builder():
    return _load_builder()


def _mk(tmp_path, items):
    qdir = tmp_path / "_work" / "quarantine"
    (qdir / "items").mkdir(parents=True)
    with open(qdir / "manifest.json", "w", encoding="utf-8") as f:
        json.dump({"items": items}, f)
    return qdir


def test_pending_zero_without_dir(builder, tmp_path):
    assert builder._quarantine_pending(str(tmp_path / "nope")) == 0


def test_pending_counts_stored(builder, tmp_path):
    qdir = _mk(tmp_path, [{"id": "a", "status": "stored"},
                          {"id": "b", "status": "restored"},
                          {"id": "c", "status": "failed"}])
    assert builder._quarantine_pending(str(qdir)) == 1


def test_pending_falls_back_to_cipher_files(builder, tmp_path):
    """清单坏了也得拦住：此时没有证据证明"没东西"，只能按密文数量保守处理。"""
    qdir = tmp_path / "_work" / "quarantine"
    (qdir / "items").mkdir(parents=True)
    (qdir / "manifest.json").write_text("{broken", encoding="utf-8")
    (qdir / "items" / "a.qbin").write_bytes(b"x")
    (qdir / "items" / "b.qbin").write_bytes(b"y")
    assert builder._quarantine_pending(str(qdir)) == 2


def test_force_refused_when_quarantine_has_items(builder, tmp_path):
    out = tmp_path / "PortableAV"
    out.mkdir()
    qdir = _mk(out, [{"id": "a", "status": "stored"}])
    assert builder._guard_overwrite(str(out), True, False) == 3

    # 走一次 main 也要真的被拦住（不进入下载/解压阶段）
    rc = builder.main(["--out", str(out), "--force", "--skip-download"])
    assert rc == 3
    assert os.path.isdir(out)
    assert (qdir / "items").is_dir()
    assert (qdir / "manifest.json").is_file()


def test_force_allowed_with_discard_work(builder, tmp_path):
    out = tmp_path / "PortableAV"
    out.mkdir()
    _mk(out, [{"id": "a", "status": "stored"}])
    assert builder._guard_overwrite(str(out), True, True) is None


def test_force_allowed_when_quarantine_empty(builder, tmp_path):
    out = tmp_path / "PortableAV"
    out.mkdir()
    _mk(out, [{"id": "a", "status": "restored"}])
    assert builder._guard_overwrite(str(out), True, False) is None


def test_no_force_requires_confirmation(builder, tmp_path):
    out = tmp_path / "PortableAV"
    out.mkdir()
    assert builder._guard_overwrite(str(out), False, False) == 2
    assert builder.main(["--out", str(out), "--skip-download"]) == 2


def test_fresh_dir_needs_no_confirmation(builder, tmp_path):
    assert builder._guard_overwrite(str(tmp_path / "new"), True, False) is None
