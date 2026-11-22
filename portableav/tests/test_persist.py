"""持久化矩阵测试：计划任务 XML、启动目录、关联判定、失败记账。

计划任务夹具刻意混入三种：正常（两个 Exec）、无动作、坏 XML——
后者必须进"解析失败"，不能静默跳过。
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from portableav import persist

NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"

TASK_TWO_EXECS = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="%s">
  <Actions Context="Author">
    <Exec><Command>C:\\Users\\Public\\evil.exe</Command><Arguments>--silent</Arguments></Exec>
    <Exec><Command>%%SystemRoot%%\\System32\\cmd.exe</Command><Arguments>/c calc</Arguments></Exec>
  </Actions>
</Task>""" % NS

TASK_NO_ACTION = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="%s"><Actions/></Task>""" % NS


def _make_win(tmp_path) -> str:
    win = os.path.join(str(tmp_path), "Windows")
    tasks = os.path.join(win, "System32", "Tasks")
    os.makedirs(tasks, exist_ok=True)
    os.makedirs(os.path.join(win, "System32", "config"), exist_ok=True)
    return win


def _write_task(win: str, rel: str, xml: str) -> None:
    p = os.path.join(win, "System32", "Tasks", rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-16") as f:      # 真实任务文件就是 UTF-16
        f.write(xml)


def test_task_xml_two_execs_and_translation(tmp_path):
    win = _make_win(tmp_path)
    _write_task(win, "EvilTask", TASK_TWO_EXECS)
    s = persist.PersistSummary()
    persist.task_items(win, s, "D:")
    assert s.task_files == 1
    assert len(s.items) == 2
    targets = sorted(i.target for i in s.items)
    assert r"D:\Users\Public\evil.exe" in targets, targets
    assert r"D:\Windows\System32\cmd.exe" in targets, targets
    assert all(i.kind == "task" for i in s.items)
    assert not s.errors


def test_task_without_action_is_recorded_not_dropped(tmp_path):
    win = _make_win(tmp_path)
    _write_task(win, "Empty", TASK_NO_ACTION)
    s = persist.PersistSummary()
    persist.task_items(win, s, "D:")
    assert len(s.items) == 1
    assert "Exec" in s.items[0].note
    assert s.items[0].unresolved is True


def test_broken_task_xml_goes_to_errors(tmp_path):
    win = _make_win(tmp_path)
    _write_task(win, "Broken", "<Task><Actions><Exec>")
    s = persist.PersistSummary()
    persist.task_items(win, s, "D:")
    assert s.items == []
    assert len(s.errors) == 1
    assert "Broken" in s.errors[0] and "XML" in s.errors[0]


def test_task_namespace_is_ignored(tmp_path):
    """不同命名空间/无命名空间都该解析（用 localname 匹配）。"""
    win = _make_win(tmp_path)
    _write_task(win, "NoNs", '<Task><Actions><Exec><Command>C:\\a.exe</Command></Exec></Actions></Task>')
    s = persist.PersistSummary()
    persist.task_items(win, s, "D:")
    assert len(s.items) == 1
    assert s.items[0].target == r"D:\a.exe"


def test_startup_items_per_user_and_programdata(tmp_path):
    base = str(tmp_path)
    win = os.path.join(base, "Windows")
    os.makedirs(win, exist_ok=True)
    pd = os.path.join(base, "ProgramData", "Microsoft", "Windows",
                      "Start Menu", "Programs", "Startup")
    os.makedirs(pd, exist_ok=True)
    open(os.path.join(pd, "all.lnk"), "wb").write(b"x")
    ua = os.path.join(base, "Users", "Alice", "AppData", "Roaming", "Microsoft",
                      "Windows", "Start Menu", "Programs", "Startup")
    os.makedirs(ua, exist_ok=True)
    open(os.path.join(ua, "alice.lnk"), "wb").write(b"x")

    s = persist.PersistSummary()
    persist.startup_items(win, s, "D:")
    names = sorted(i.name for i in s.items)
    assert names == ["alice.lnk", "all.lnk"]
    assert s.startup_items == 2


def test_registry_missing_hives_reports_error_not_crash(tmp_path):
    win = _make_win(tmp_path)
    s = persist.PersistSummary()
    persist.registry_items(win, s, "D:")
    assert s.items == []
    assert any("hive" in e for e in s.errors)


def test_collect_is_resilient(tmp_path):
    """三类里两类缺失也不该整体失败。"""
    base = os.path.join(str(tmp_path), "Empty")
    os.makedirs(base, exist_ok=True)
    s = persist.collect(base, "D:")
    assert isinstance(s.items, list)
    assert s.errors, "至少应如实报告找不到证据"

def test_link_matches_scan_results():
    items = [
        persist.PersistenceItem(kind="task", source="Tasks\\A", name="A",
                                raw="x", target=r"D:\Users\Public\evil.exe"),
        persist.PersistenceItem(kind="task", source="Tasks\\B", name="B",
                                raw="y", target=r"D:\Windows\System32\cmd.exe"),
    ]

    class R:
        def __init__(self, path, level, basis="规则命中"):
            self.path, self.level, self.basis = path, level, basis

    results = [R(r"D:\Users\Public\evil.exe", "黑")]
    n = persist.link(items, persist.index_results(results))
    assert n == 1
    assert items[0].level == "黑" and items[0].scanned
    assert items[1].level == "" and not items[1].scanned


def test_by_level_counts_unlinked():
    items = [
        persist.PersistenceItem(kind="task", source="a", name="a", raw="", target="", level="黑"),
        persist.PersistenceItem(kind="task", source="b", name="b", raw="", target="", level=""),
    ]
    stats = persist.by_level(items)
    assert stats["黑"] == 1 and stats["未关联"] == 1
