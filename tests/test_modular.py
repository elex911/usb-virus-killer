# -*- coding: utf-8 -*-
"""模块化重构回归测试。运行：python tests/test_modular.py"""
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, ROOT)

from core.registry import load_modules
from core.api import Context, ModuleBase
from modules import folder_virus as fv
from modules import signature_db as sig
from modules import clamav_bridge as cb
from modules import modern_threats as mt


def make_lnk(path, target):
    """构造最小可读 Shell Link：只放目标路径，不依赖 COM。"""
    with open(path, "wb") as f:
        f.write(target.encode("utf-16-le"))


def test_discovery():
    mods, errors = load_modules()
    ids = [m.meta.get("id") for m in mods]
    assert "folder_virus" in ids, ids
    assert "host_diagnostics" in ids, ids
    assert "signature_db" in ids, ids
    assert "clamav_bridge" in ids, ids
    assert "modern_threats" in ids, ids
    assert not errors, errors
    print("[OK] 内置模块发现:", ids)


def test_plugin_hot_discovery():
    plugin = os.path.join(ROOT, "plugins", "zz_selftest_plugin.py")
    code = (
        "# -*- coding: utf-8 -*-\n"
        "from core.api import Action, ActionResult, ModuleBase\n"
        "class Module(ModuleBase):\n"
        "    meta = {'id': 'selftest_plugin', 'name': '自测插件', 'order': 999}\n"
        "    def actions(self): return [Action('ping', '自测', target_mode='none')]\n"
        "    def run(self, action_id, ctx, log): return ActionResult(message='ok')\n"
    )
    try:
        with open(plugin, "w", encoding="utf-8") as f:
            f.write(code)
        mods, errors = load_modules()
        ids = [m.meta.get("id") for m in mods]
        assert "selftest_plugin" in ids, (ids, errors)
        assert not errors, errors
        print("[OK] 外部插件自动发现: selftest_plugin")
    finally:
        if os.path.exists(plugin):
            os.remove(plugin)
        pyc = os.path.join(ROOT, "plugins", "__pycache__")
        if os.path.isdir(pyc):
            for fn in os.listdir(pyc):
                if fn.startswith("zz_selftest_plugin"):
                    os.remove(os.path.join(pyc, fn))


def test_engine_and_rollback():
    tmp = tempfile.mkdtemp(prefix="fk_modular_test_", dir=ROOT)
    try:
        original = os.path.join(tmp, "假期照片.jpg")
        with open(original, "wb") as f:
            f.write(b"fake image")
        fv.set_attr(original, fv.FILE_ATTRIBUTE_HIDDEN | fv.FILE_ATTRIBUTE_SYSTEM)

        fake_lnk = os.path.join(tmp, "假期照片.lnk")
        make_lnk(fake_lnk, os.path.join(tmp, "假期照片.jpg"))
        legit_lnk = os.path.join(tmp, "我的文档.lnk")
        make_lnk(legit_lnk, r"D:\Docs\我的文档.docx")
        auto = os.path.join(tmp, "autorun.inf")
        with open(auto, "w", encoding="utf-8") as f:
            f.write("[autorun]\nopen=bad.exe\n")

        eng = fv.Engine(tmp, False)
        eng.precheck()
        stats = eng.scan(lambda m: None)
        assert stats["malicious"] >= 2, stats
        assert stats["normal"] >= 1, stats
        assert any(i["verdict"] == "恶意" and i["path"] == fake_lnk for i in eng.items)
        assert any(i["verdict"] == "恶意" and i["path"] == auto for i in eng.items)
        assert any(i["verdict"] == "正常" and i["path"] == legit_lnk for i in eng.items)
        print("[OK] 引擎判定:", stats)

        r = eng.clean(lambda m: None)
        assert r["moved"] >= 2, r
        assert not os.path.exists(fake_lnk)
        assert not os.path.exists(auto)
        assert os.path.exists(legit_lnk)
        attr = fv.get_attr(original)
        assert attr is not None and not (attr & fv.FILE_ATTRIBUTE_HIDDEN), attr
        print("[OK] 查杀隔离 + 解除隐藏:", r)

        manifest = os.path.join(r["quarantine"], "manifest.json")
        with open(manifest, encoding="utf-8") as f:
            mf = json.load(f)
        assert mf["root"] == tmp
        assert sum(1 for i in mf["items"] if i["action"] == "quarantine") >= 2

        ok, fail = fv.Engine.restore(r["quarantine"], lambda m: None)
        assert ok >= 2 and fail == 0, (ok, fail)
        assert os.path.exists(fake_lnk) and os.path.exists(auto)
        print("[OK] 回滚:", ok, fail)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_host_diagnostics():
    import HostDiagnostics
    rows = HostDiagnostics.collect(lambda m: None)
    assert isinstance(rows, list)
    assert all(r["level"] in ("高危", "关注", "信息") for r in rows)
    assert all(r["level"] != "恶意" for r in rows)
    print("[OK] 主机诊断只读口径: %d 行" % len(rows))


def test_signature_db_empty_and_rules():
    import hashlib

    tmp = tempfile.mkdtemp(prefix="fk_sig_test_", dir=ROOT)
    try:
        db_path = os.path.join(tmp, "signature_db.json")
        ctx = Context(app_dir=tmp, settings={"signature_db_path": db_path})
        mod = sig.Module()

        r1 = mod.run("init", ctx, lambda m: None)
        assert r1.report["created"] is True
        r2 = mod.run("init", ctx, lambda m: None)
        assert r2.report["created"] is False

        db = sig.load_db(db_path)
        assert db["rules"] == []
        errors, statuses, enabled = sig.validate_db(db)
        assert errors == [] and statuses == [] and enabled == []

        sample = os.path.join(tmp, "bad_sample.txt")
        with open(sample, "wb") as f:
            f.write(b"test sample")
        digest = hashlib.sha256(b"test sample").hexdigest()

        db["rules"] = [
            {"id": "r_hash", "type": "sha256", "value": digest,
             "source": "本地自测样本 SAMPLE-001", "evidence": "T1",
             "first_seen": "2026-11-21", "enabled": False},
            {"id": "r_name", "type": "filename_regex", "value": "^bad_sample",
             "source": "本地自测样本 SAMPLE-001", "evidence": "T1",
             "first_seen": "2026-11-21", "enabled": True},
            {"id": "r_t3", "type": "filename_regex", "value": "x",
             "source": "据他人转述", "evidence": "T3",
             "first_seen": "2026-11-21", "enabled": True},
            {"id": "r_placeholder", "type": "filename_regex", "value": "y",
             "source": "未知", "evidence": "T1",
             "first_seen": "2026-11-21", "enabled": False},
            {"id": "r_bad_regex", "type": "filename_regex", "value": "[",
             "source": "本地自测样本 SAMPLE-001", "evidence": "T1",
             "first_seen": "2026-11-21", "enabled": True},
        ]
        with open(db_path, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)

        errors, statuses, enabled = sig.validate_db(db)
        joined = "；".join(errors)
        assert "T3" in joined, joined
        assert "占位符" in joined, joined
        assert "正则无效" in joined, joined
        assert len(enabled) == 1 and enabled[0]["id"] == "r_name", enabled
        assert len(statuses) == 5
        print("[OK] 特征库校验: T3/占位符/坏正则均被拒绝，仅 1 条启用规则生效")

        ctx.target = tmp
        ctx.is_drive = False
        res = mod.run("scan", ctx, lambda m: None)
        assert res.report["matched"] == 1, res.report
        assert res.report["matches"][0]["path"] == sample
        assert "quarantine" not in res.report
        print("[OK] 特征库按库扫描: 命中 1 条，未触发隔离")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_clamav_bridge_parse_and_mock():
    sample_out = (
        "C:\\fake\\sample.exe: Win.Test.EICAR_HDB-1 FOUND\n"
        "----------- SCAN SUMMARY -----------\n"
        "Infected files: 1\n"
    )
    found = cb.parse_found(sample_out)
    assert len(found) == 1, found
    assert found[0]["path"] == "C:\\fake\\sample.exe", found
    assert found[0]["signature"] == "Win.Test.EICAR_HDB-1", found

    tmp = tempfile.mkdtemp(prefix="fk_clamav_test_", dir=ROOT)
    fake_exe = os.path.join(tmp, "clamscan.exe")
    with open(fake_exe, "wb"):
        pass
    original = cb._run_process
    calls = []

    def fake_run(cmd, timeout):
        calls.append((list(cmd), timeout))
        if "--version" in cmd:
            return 0, "ClamAV 1.5.5", ""
        return 1, sample_out, ""

    cb._run_process = fake_run
    try:
        ctx = Context(app_dir=tmp, settings={"clamscan_path": fake_exe})
        ctx.target = tmp
        ctx.is_drive = False
        res = cb.Module().run("scan", ctx, lambda m: None)
        assert res.report["infected"] == 1, res.report
        assert res.report["summary_infected"] == 1, res.report
        assert "quarantine" not in res.report
        assert all("--remove" not in c for c, _ in calls), calls
        assert all("--move" not in c for c, _ in calls), calls
        print("[OK] ClamAV 桥接: 外部命中解析 / 无删除参数 / 只报告")
    finally:
        cb._run_process = original
        shutil.rmtree(tmp, ignore_errors=True)


def test_modern_threats():
    """现代威胁只读检测：真实环境低噪音 + 注入检出 + 假零命中反查。"""
    B = chr(92)
    temp_exe = "C:" + B + "Users" + B + "x" + B + "AppData" + B + "Local" + B + "Temp" + B + "evil.exe"
    sys_exe = "C:" + B + "Windows" + B + "System32" + B + "svchost.exe"

    # 真实环境：只允许高危/关注/信息，不得出现「恶意」
    real = mt.Module().run("collect", Context(), lambda m: None)
    assert "modern_threats_readonly" in real.report
    assert all(r["level"] in ("高危", "关注", "信息") for r in real.data["rows"])
    assert all("恶意" not in r["level"] for r in real.data["rows"])
    assert all(set(r.keys()) == {"kind", "level", "path", "value", "detail"}
               for r in real.data["rows"])

    # 注入 WMI：临时路径应报高危，系统路径应被降噪跳过
    orig_sub, orig_val = mt._reg_subkeys, mt._reg_value
    mt._reg_subkeys = lambda hive, subkey: (["EvilConsumer", "SafeConsumer"]
                                            if subkey == mt.WMI_SUBSCRIPTIONS else [])
    mt._reg_value = lambda hive, subkey, name="": (
        temp_exe if "EvilConsumer" in subkey else sys_exe
    ) if "CommandLineEventConsumer" in subkey else None
    try:
        wmi = mt.collect_wmi()
    finally:
        mt._reg_subkeys, mt._reg_value = orig_sub, orig_val
    assert len(wmi) == 2 and all(r["level"] == "高危" for r in wmi), wmi

    # 反查假零命中：UTF-16LE 路径抽取必须命中
    extracted = mt._strings_from_binary(temp_exe.encode("utf-16-le"))
    assert extracted and extracted[0] == temp_exe, extracted

    # 注入进程路径：临时路径命中，系统路径跳过
    orig_paths = mt._process_paths
    mt._process_paths = lambda: [(1234, temp_exe), (5678, sys_exe)]
    try:
        procs = mt.collect_processes()
    finally:
        mt._process_paths = orig_paths
    assert len(procs) == 1 and procs[0]["path"] == "PID 1234", procs

    # 勒索痕迹：临时目录造笔记 + 3 个同类扩展名，不碰真实用户目录
    tmp = tempfile.mkdtemp(prefix="fk_modern_test_", dir=ROOT)
    folder = os.path.join(tmp, "Documents")
    os.makedirs(folder)
    for name in ("RECOVER-FILES.txt", "a.doc.lockbit", "b.doc.lockbit", "c.doc.lockbit"):
        with open(os.path.join(folder, name), "w"):
            pass
    orig_env = os.environ.get("USERPROFILE")
    os.environ["USERPROFILE"] = tmp
    try:
        ransom = mt.collect_ransom_traces()
    finally:
        if orig_env is None:
            del os.environ["USERPROFILE"]
        else:
            os.environ["USERPROFILE"] = orig_env
        shutil.rmtree(tmp, ignore_errors=True)
    assert any(r["level"] == "高危" for r in ransom), ransom
    assert any(r["level"] == "关注" for r in ransom), ransom
    print("[OK] 现代威胁检测: 真实环境 %d 行(0 恶意) / 注入 WMI+进程+勒索均检出 / 假零命中反查通过"
          % len(real.data["rows"]))


def test_gui_assembly():
    import tkinter as tk
    from core.app import App
    root = tk.Tk()
    root.withdraw()
    try:
        app = App(root)
        root.update()
        assert len(app.views) >= 2, list(app.views)
        assert len(app.all_buttons) >= 5, len(app.all_buttons)
        texts = []

        def walk(widget):
            try:
                texts.append(str(widget.cget("text")))
            except Exception:
                pass
            for child in widget.winfo_children():
                walk(child)

        walk(root)
        assert any("军不见" in t and "180******66" in t for t in texts), "界面未找到作者信息"
        print("[OK] GUI 装配: %d 视图 / %d 按钮；作者信息已显示"
              % (len(app.views), len(app.all_buttons)))
    finally:
        root.destroy()


if __name__ == "__main__":
    test_discovery()
    test_plugin_hot_discovery()
    test_engine_and_rollback()
    test_host_diagnostics()
    test_signature_db_empty_and_rules()
    test_clamav_bridge_parse_and_mock()
    test_modern_threats()
    test_gui_assembly()
    print("ALL PASS")
