"""交互模式（双击启动）用例。

背景：双击 .bat 等于零参数运行。若程序打印 usage 就退出，控制台窗口会立即关闭，
用户看到的就是「一闪而过」。所以这里钉死三条：
1. 无参数 + 真实终端 → 进菜单，循环到用户选 0；
2. 无参数 + 非终端   → 打印用法并非零退出（脚本误用不能被静默吞掉）；
3. 常规 Windows 下不让「自动定位」直接扫正在运行的系统。
"""

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from portableav import cli


class FakeEnv:
    def __init__(self, offline=False, system_drive="X:"):
        self.mode = "winpe" if offline else "windows"
        self.hint = "离线" if offline else "在线"
        self.is_offline = offline
        self.system_drive = system_drive
        self.signals = ["fake"]
        self.detail = {}


class FakeSystem:
    def __init__(self, windows_dir):
        self.windows_dir = windows_dir
        self.complete = True
        self.label = windows_dir


def _script(lines):
    """把一串输入变成 input 替身；用尽后抛 EOFError（模拟窗口被关掉）。

    真实运行时提示语由内置 input() 写到控制台，这里替换了 input，
    所以提示语只能从 prompts 里核对，不能从输出流里找。
    """
    it = iter(lines)
    prompts = []

    def _in(prompt=""):
        prompts.append(prompt)
        try:
            return next(it)
        except StopIteration:
            raise EOFError
    _in.prompts = prompts
    return _in


def _run(lines, env=None, tmp=None, monkeypatch=None):
    out = io.StringIO()
    if tmp is not None and monkeypatch is not None:
        monkeypatch.setattr(cli, "APP_DIR", str(tmp))
    rc = cli.interactive(input_fn=_script(lines), out=out,
                         env_obj=env if env is not None else FakeEnv())
    return rc, out.getvalue()


def test_no_args_without_tty_prints_usage_and_fails():
    """非终端下不能挂住等输入，也不能返回 0（否则脚本误用查不出）。"""
    assert cli.main([]) == 2


def test_menu_lists_all_actions(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "APP_DIR", str(tmp_path))
    out = io.StringIO()
    script = _script(["0"])
    rc = cli.interactive(input_fn=script, out=out, env_obj=FakeEnv())
    text = out.getvalue()
    assert rc == 0
    for token in ("环境信息", "演练", "隔离", "退出", "工作目录"):
        assert token in text
    assert any("请选择" in p for p in script.prompts)


def test_eof_exits_cleanly(tmp_path, monkeypatch):
    """窗口被关掉 / 输入读尽时返回 0，不抛异常。"""
    rc, text = _run([], tmp=tmp_path, monkeypatch=monkeypatch)
    assert rc == 0
    assert "PortableAV" in text


def test_unknown_option_then_exit(tmp_path, monkeypatch):
    rc, text = _run(["zzz", "0"], tmp=tmp_path, monkeypatch=monkeypatch)
    assert rc == 0
    assert "未知选项" in text


def test_auto_target_refused_on_live_windows():
    """常规系统下自动定位到的是正在运行的系统，必须拒绝而不是照扫。"""
    e = FakeEnv(offline=False)
    target, why = cli._auto_target(e, [FakeSystem(r"C:\Windows")])
    assert target == ""
    assert "正在运行" in why


def test_auto_target_used_in_pe():
    e = FakeEnv(offline=True)
    target, why = cli._auto_target(e, [FakeSystem(r"D:\Windows")])
    assert target == r"D:\Windows"
    assert why == ""


def test_auto_target_without_system():
    target, why = cli._auto_target(FakeEnv(offline=True), [])
    assert target == ""
    assert "未定位" in why


def test_prompt_target_returns_abs_path(tmp_path):
    out = io.StringIO()
    real = tmp_path / "tree"
    real.mkdir()
    say = lambda m="": print(m, file=out)
    got = cli._prompt_target(FakeEnv(offline=True), say,
                             _script([str(real)]), [FakeSystem(r"D:\Windows")])
    assert got == os.path.normpath(os.path.abspath(str(real)))


def test_prompt_target_rejects_missing_dir(tmp_path):
    out = io.StringIO()
    say = lambda m="": print(m, file=out)
    got = cli._prompt_target(FakeEnv(offline=True), say,
                             _script([str(tmp_path / "nope")]), [FakeSystem(r"D:\Windows")])
    assert got is None
    assert "目录不存在" in out.getvalue()


def test_prompt_target_quote_stripped(tmp_path):
    """从资源管理器复制路径常带引号，不能因此判「不存在」。"""
    out = io.StringIO()
    real = tmp_path / "with space"
    real.mkdir()
    say = lambda m="": print(m, file=out)
    got = cli._prompt_target(FakeEnv(offline=True), say,
                             _script(['"%s"' % real]), [FakeSystem(r"D:\Windows")])
    assert got == os.path.normpath(os.path.abspath(str(real)))


def test_scan_choice_refused_when_auto_unavailable(tmp_path, monkeypatch):
    """常规系统下选「扫描」并回车走自动 → 拒绝，且不进入 cmd_scan。"""
    called = []
    monkeypatch.setattr(cli, "cmd_scan", lambda a: called.append(a) or 0)
    # systems 由 find_offline_systems 提供，这里替换成"正在运行的系统"
    monkeypatch.setattr(cli.drives, "find_offline_systems",
                        lambda **kw: [FakeSystem(r"C:\Windows")])
    rc, text = _run(["2", "", "0"], env=FakeEnv(offline=False),
                    tmp=tmp_path, monkeypatch=monkeypatch)
    assert rc == 0
    assert "正在运行" in text
    assert called == []


def test_scan_choice_runs_dry_run(tmp_path, monkeypatch):
    seen = []

    def fake_scan(args):
        seen.append((args.target, args.apply, args.quarantine, args.workdir))
        return 0

    monkeypatch.setattr(cli, "cmd_scan", fake_scan)
    target = tmp_path / "tree"
    target.mkdir()
    rc, _ = _run(["2", str(target), "0"], env=FakeEnv(offline=False),
                 tmp=tmp_path, monkeypatch=monkeypatch)
    assert rc == 0
    assert seen and seen[0][0] == os.path.normpath(os.path.abspath(str(target)))
    assert seen[0][1] is False           # 演练：不处置
    assert seen[0][2] == ""              # 演练不带隔离区


def test_quarantine_requires_explicit_yes(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "cmd_scan", lambda a: seen.append((a.apply, a.quarantine)) or 0)
    target = tmp_path / "tree"
    target.mkdir()
    rc, text = _run(["3", str(target), "no", "0"], env=FakeEnv(offline=False),
                    tmp=tmp_path, monkeypatch=monkeypatch)
    assert rc == 0
    assert "已取消" in text
    assert seen == []

    rc, text = _run(["3", str(target), "yes", "0"], env=FakeEnv(offline=False),
                    tmp=tmp_path, monkeypatch=monkeypatch)
    assert rc == 0
    assert seen and seen[0][0] is True
    assert seen[0][1].endswith("quarantine")


def test_quarantine_menu_without_dir(tmp_path, monkeypatch):
    rc, text = _run(["4", "0"], env=FakeEnv(offline=False),
                    tmp=tmp_path, monkeypatch=monkeypatch)
    assert rc == 0
    assert "还没有隔离过" in text


def test_want_interactive_env_flag(monkeypatch):
    monkeypatch.setenv("PAV_INTERACTIVE", "1")
    assert cli._want_interactive() is True
    monkeypatch.delenv("PAV_INTERACTIVE", raising=False)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))
    assert cli._want_interactive() is False


def test_header_states_missing_roots(tmp_path, monkeypatch):
    """没有根证书时必须明说「一律不判白」，否则「白 0」会被误读成校验坏了。"""
    monkeypatch.setattr(cli, "APP_DIR", str(tmp_path))
    monkeypatch.setattr(cli, "_load_roots", lambda arg: [])
    monkeypatch.setattr(cli, "_load_blacklist", lambda arg: None)
    out = io.StringIO()
    cli.interactive(input_fn=_script(["0"]), out=out, env_obj=FakeEnv())
    text = out.getvalue()
    assert "根证书 0 张" in text
    assert "一律不判白" in text


def test_header_states_loaded_roots(tmp_path, monkeypatch):
    class _RL:
        def summary(self):
            return "1 条指纹"

    monkeypatch.setattr(cli, "APP_DIR", str(tmp_path))
    monkeypatch.setattr(cli, "_load_roots", lambda arg: [object(), object()])
    monkeypatch.setattr(cli, "_load_blacklist", lambda arg: _RL())
    out = io.StringIO()
    cli.interactive(input_fn=_script(["0"]), out=out, env_obj=FakeEnv())
    text = out.getvalue()
    assert "根证书 2 张" in text
    assert "1 条指纹" in text
