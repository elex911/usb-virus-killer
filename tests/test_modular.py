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
from core.api import ActionResult, Context, ModuleBase
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
    assert "classic_trojans" in ids, ids
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

        # P2 回归：重扫不得把自身隔离区 __WORM_QUARANTINE_* 里的对象再判为目标
        qdir = r["quarantine"]
        eng2 = fv.Engine(tmp, False)
        eng2.precheck()
        eng2.scan(lambda m: None)
        qn = os.path.normcase(os.path.abspath(qdir)) + os.sep
        leaked = [i for i in eng2.items
                  if os.path.normcase(os.path.abspath(i["path"])).startswith(qn)]
        assert not leaked, "隔离区对象被重扫判级: %r" % leaked[:3]
        leaked_hidden = [p for p in eng2.hidden_items
                         if os.path.normcase(os.path.abspath(p)).startswith(qn)]
        assert not leaked_hidden, "隔离区对象被重扫记为隐藏项: %r" % leaked_hidden[:3]
        print("[OK] 重扫排除自身隔离区: 隔离对象 0 复报")

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


def test_restore_safety():
    """危险路径复审回归：回滚拒绝路径穿越、拒绝覆盖已存在文件；clean 中途崩溃 manifest 不丢。"""
    import unittest.mock as um

    # ---- 场景一：正常隔离后，验证 restore 的两道防线 ----
    tmp = tempfile.mkdtemp(prefix="fk_restore_", dir=ROOT)
    try:
        usb = os.path.join(tmp, "usb")
        original = os.path.join(usb, "照片.jpg")
        os.makedirs(usb)
        with open(original, "wb") as f:
            f.write(b"img")
        fv.set_attr(original, fv.FILE_ATTRIBUTE_HIDDEN | fv.FILE_ATTRIBUTE_SYSTEM)
        fake_lnk = os.path.join(usb, "照片.lnk")
        make_lnk(fake_lnk, original)
        eng = fv.Engine(usb, False)
        eng.precheck()
        eng.scan(lambda m: None)
        r = eng.clean(lambda m: None)
        qdir = r["quarantine"]
        mf_path = os.path.join(qdir, "manifest.json")
        with open(mf_path, encoding="utf-8") as f:
            mf = json.load(f)
        assert any(i.get("action") == "quarantine" for i in mf["items"]), mf

        # B) 目标位置已存在同名文件 → 该项失败、原文件内容不变、隔离区文件不丢
        with open(fake_lnk, "wb") as f:
            f.write(b"IMPORTANT-DO-NOT-OVERWRITE")
        okc, fail = fv.Engine.restore(qdir, lambda m: None)
        assert okc == 0 and fail >= 1, (okc, fail)
        with open(fake_lnk, "rb") as f:
            assert f.read() == b"IMPORTANT-DO-NOT-OVERWRITE"
        assert os.path.exists(os.path.join(qdir, "照片.lnk")), "隔离区源文件不得被消费掉"
        print("[OK] 回滚拒绝覆盖已存在目标")

        # A) 篡改 manifest 的 rel 为路径穿越 → 必须拒绝且不写出隔离区
        mf2 = json.loads(json.dumps(mf))
        outside = os.path.join(tmp, "outside_evil.txt")
        for it in mf2["items"]:
            if it.get("action") == "quarantine":
                it["rel"] = os.path.join("..", "..", "outside_evil.txt")
                break
        with open(mf_path, "w", encoding="utf-8") as f:
            json.dump(mf2, f)
        okc, fail = fv.Engine.restore(qdir, lambda m: None)
        assert okc == 0 and fail >= 1, (okc, fail)
        assert not os.path.exists(outside), "路径穿越被成功执行（严重漏洞）"
        # 绝对路径同样拒绝
        mf3 = json.loads(json.dumps(mf))
        for it in mf3["items"]:
            if it.get("action") == "quarantine":
                it["rel"] = os.path.abspath(outside)
                break
        with open(mf_path, "w", encoding="utf-8") as f:
            json.dump(mf3, f)
        okc, fail = fv.Engine.restore(qdir, lambda m: None)
        assert okc == 0 and fail >= 1 and not os.path.exists(outside), (okc, fail)
        print("[OK] 回滚拒绝路径穿越/绝对路径")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- 场景二：clean 中途被 Ctrl+C 打断，manifest 必须已逐项落盘 ----
    tmp2 = tempfile.mkdtemp(prefix="fk_crash_", dir=ROOT)
    try:
        usb2 = os.path.join(tmp2, "usb")
        os.makedirs(usb2)
        targets = []
        for name in ("照片.jpg", "账单.pdf"):
            orig = os.path.join(usb2, name)
            with open(orig, "wb") as f:
                f.write(b"data")
            fv.set_attr(orig, fv.FILE_ATTRIBUTE_HIDDEN | fv.FILE_ATTRIBUTE_SYSTEM)
            lnk = os.path.join(usb2, name.rsplit(".", 1)[0] + ".lnk")
            make_lnk(lnk, orig)
            targets.append(lnk)
        eng3 = fv.Engine(usb2, False)
        eng3.precheck()
        eng3.scan(lambda m: None)
        real_move = shutil.move
        calls = {"n": 0}

        def flaky_move(src, dst, *a, **kw):
            calls["n"] += 1
            if calls["n"] >= 2:
                raise KeyboardInterrupt  # 模拟用户中途 Ctrl+C
            return real_move(src, dst, *a, **kw)

        raised = False
        with um.patch("shutil.move", flaky_move):
            try:
                eng3.clean(lambda m: None)
            except KeyboardInterrupt:
                raised = True
        assert raised, "中断必须向上传播（不得被吞掉伪装成功）"
        import glob as _g
        qdirs = _g.glob(os.path.join(usb2, "__WORM_QUARANTINE_*"))
        assert len(qdirs) == 1, qdirs
        mf2p = os.path.join(qdirs[0], "manifest.json")
        assert os.path.isfile(mf2p), "中断后 manifest 丢失＝隔离项不可回滚"
        with open(mf2p, encoding="utf-8") as f:
            mf2 = json.load(f)
        done = [i for i in mf2["items"] if i.get("action") == "quarantine"]
        assert len(done) == 1, "第 1 项已搬入隔离区但清单未记录: %r" % mf2
        assert all(i.get("status") == "compensated" for i in done), "中断后应补偿回滚，不留孤儿项: %r" % mf2
        assert os.path.exists(targets[0]), "第 1 项补偿后应回到原路径"
        assert not os.path.exists(os.path.join(qdirs[0], os.path.basename(targets[0]))), "隔离区不应残留孤儿"
        print("[OK] clean 中途中断：逐项落盘 + 补偿回滚，无孤儿")
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)


def test_quarantine_metadata_and_summary():
    """补强1：隔离元数据显示证据级、回滚摘要确认、SHA-256 篡改拒绝。"""
    import unittest.mock as um
    tmp = tempfile.mkdtemp(prefix="fk_meta_", dir=ROOT)
    try:
        usb = os.path.join(tmp, "usb")
        os.makedirs(usb)
        orig = os.path.join(usb, "证据.jpg")
        with open(orig, "wb") as f:
            f.write(b"original-evidence")
        fv.set_attr(orig, fv.FILE_ATTRIBUTE_HIDDEN | fv.FILE_ATTRIBUTE_SYSTEM)
        lnk = os.path.join(usb, "证据.lnk")
        make_lnk(lnk, orig)
        eng = fv.Engine(usb, False)
        eng.precheck()
        eng.scan(lambda m: None)
        r = eng.clean(lambda m: None)
        qdir = r["quarantine"]
        mf_path = os.path.join(qdir, "manifest.json")
        with open(mf_path, encoding="utf-8") as f:
            mf = json.load(f)
        assert mf.get("schema_version") == 2, mf
        item = next(i for i in mf["items"] if i.get("action") == "quarantine")
        assert len(item.get("sha256", "")) == 64, item
        assert item.get("size") == os.path.getsize(os.path.join(qdir, item["rel"])), item
        assert item.get("mtime_ns") and item.get("attrs") is not None, item
        assert item.get("detection") and "确证特征" in item["detection"], item
        assert os.path.isabs(item.get("original_path", "")), item

        s = fv.Engine.restore_summary(qdir)
        assert s["count"] >= 1 and s["time"] and s["root"] == usb, s
        mod = fv.Module()
        ctx = Context()
        ctx.pick = qdir
        text = mod.action_confirm("restore", ctx)
        assert "SHA-256" in text and "原路径" in text and "项" in text, text

        # 篡改隔离区文件 → SHA-256 不匹配必须拒绝回滚
        qfile = os.path.join(qdir, item["rel"])
        with open(qfile, "wb") as f:
            f.write(b"tampered!")
        okc, fail = fv.Engine.restore(qdir, lambda m: None)
        assert okc == 0 and fail >= 1, (okc, fail)
        assert not os.path.exists(lnk), "篡改文件不得被还原到原路径"
        print("[OK] 隔离元数据/摘要确认/SHA-256 篡改拒绝")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_host_diagnostics():
    import HostDiagnostics
    rows = HostDiagnostics.collect(lambda m: None)
    assert isinstance(rows, list)
    assert all(r["level"] in ("高危", "关注", "信息") for r in rows)
    assert all(r["level"] != "恶意" for r in rows)
    print("[OK] 主机诊断只读口径: %d 行" % len(rows))


def test_classic_rollback_tampered_item():
    """危险路径复审：回滚 manifest 含坏项（未知 hive）不得中断剩余项的还原。"""
    from modules import classic_trojans as ct
    app_dir = tempfile.mkdtemp(prefix="fk_rbt_", dir=ROOT)
    try:
        ct._reset_seams()
        bdir = os.path.join(app_dir, "legacy_fix_backups", "20260101_000000_000000")
        os.makedirs(bdir)
        mf = {"time": "2026-01-01T00:00:00", "applied": [
            {"kind": "启动项", "hive": "HKXX", "subkey": "X", "name": "Bad",
             "action": "delete_value", "old_value": "v", "old_type": 1},
            {"kind": "启动项", "hive": "HKLM", "subkey": "Software\\TestApp",
             "name": "KV2004", "action": "delete_value",
             "old_value": "C:\\evil.exe", "old_type": 1},
        ]}
        with open(os.path.join(bdir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(mf, f)
        sets_ = []
        ct._reg_set = lambda hive, sk, n, v, t: sets_.append((hive, sk, n, v, t))
        mod = ct.Module()
        mod.collect = lambda log: ([], [])  # 回滚后的复核用空数据，隔离真实注册表
        ctx = Context(app_dir=app_dir)
        res = mod.run("rollback", ctx, lambda m: None)
        assert res.report["restored"] == 1, "坏项之后的好项被中断: %r" % res.report
        assert len(sets_) == 1 and sets_[0][1] == "Software\\TestApp", sets_
        ct._reset_seams()
        print("[OK] 经典木马回滚: 坏 manifest 项跳过不中断，好项照常还原")
    finally:
        shutil.rmtree(app_dir, ignore_errors=True)


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

    # 注入 WMI：三层键结构（订阅 GUID -> Consumer 类 -> Consumer GUID），
    # 临时路径应报高危，系统路径应被降噪跳过
    sub_guid = "{11111111-1111-1111-1111-111111111111}"
    evil_guid, safe_guid = "{22222222-2222-2222-2222-222222222222}", "{33333333-3333-3333-3333-333333333333}"
    consumer_cls = "CommandLineEventConsumer"
    cls_base = mt.WMI_SUBSCRIPTIONS + B + sub_guid + B + consumer_cls

    def fake_subkeys(hive, subkey):
        if subkey == mt.WMI_SUBSCRIPTIONS:
            return [sub_guid]
        if subkey == mt.WMI_SUBSCRIPTIONS + B + sub_guid:
            return [consumer_cls]
        if subkey == cls_base:
            return [evil_guid, safe_guid]
        return []

    def fake_value(hive, subkey, name=""):
        if name == "CommandLineTemplate":
            if subkey == cls_base + B + evil_guid:
                return temp_exe
            if subkey == cls_base + B + safe_guid:
                return sys_exe
        return None

    orig_sub, orig_val = mt._reg_subkeys, mt._reg_value
    mt._reg_subkeys, mt._reg_value = fake_subkeys, fake_value
    try:
        wmi = mt.collect_wmi()
    finally:
        mt._reg_subkeys, mt._reg_value = orig_sub, orig_val
    assert len(wmi) == 2 and all(r["level"] == "高危" for r in wmi), wmi  # HKLM/HKCU 各 1 条（SAFE 降噪）
    assert all(r["path"].endswith(B + evil_guid + B + "CommandLineTemplate") for r in wmi), wmi

    # 注入文件关联：ProgID 间接劫持应检出（.js 默认值指向自定义 ProgID），
    # 标准脚本宿主（VBSFile -> wscript.exe）应跳过，直挂键缺失不报错
    assoc_table = {
        ".js": "evilprog",
        ".js" + B + "shell" + B + "open" + B + "command": None,
        "evilprog" + B + "shell" + B + "open" + B + "command": temp_exe,
        ".vbs": "VBSFile",
        "VBSFile" + B + "shell" + B + "open" + B + "command": sys_exe + B + "wscript.exe " + chr(34) + "%1" + chr(34) + " %*",
    }
    orig_val2 = mt._reg_value

    def fake_assoc_value(hive, subkey, name=""):
        return assoc_table.get(subkey)

    mt._reg_value = fake_assoc_value
    try:
        assoc = mt.collect_file_associations()
    finally:
        mt._reg_value = orig_val2
    assert len(assoc) == 1 and assoc[0]["level"] == "高危", assoc
    assert "evilprog" in assoc[0]["path"], assoc

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


def test_classic_trojans():
    """QQKav 移植模块：接缝注入验证 检出→修复→回滚 三链路 + 真实主机低噪音。"""
    from modules import classic_trojans as ct

    # 真实主机：只读体检不得报任何高危（本机干净）
    ct._reset_seams()
    real = ct.Module().run("detect", Context(), lambda m: None)
    assert all(r["level"] != "高危" for r in real.data["rows"]), real.data["rows"]

    # 注入世界：已知 QQ 尾巴特征 + 关联劫持 + IFEO + 正常项
    fake = {}
    hklm_run = ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    hkcu_run = ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    fake[hklm_run] = {"KV2004": (r"C:\Windows\microsoft.exe", 1),
                      "Good": (r"C:\Program Files (x86)\App\App.exe", 1)}
    fake[hkcu_run] = {"WebAuto": (r"C:\Windows\System32\WebAuto.exe", 2)}  # 2=REG_EXPAND_SZ，验证回滚保类型
    assoc = ("HKCR", ct.TXTFILE_ASSOC)
    fake[assoc] = {"": (r'c:\windows\winsoft "%1"', 1)}
    ifeo = ("HKLM", ct.IFEOSUB + "\\evil.exe")
    fake[ifeo] = {"Debugger": (r"C:\Windows\evil.dll", 1)}

    deleted, sets_ = [], []

    def hive_name(hive):
        for n, h in ct.HIVE_NAMES.items():
            if h == hive:
                return n
        return "?"

    ct._reg_enum_values = lambda h, sk: [(n, v, t) for n, (v, t) in fake.get((hive_name(h), sk), {}).items()]
    ct._reg_get = lambda h, sk, n: fake.get((hive_name(h), sk), {}).get(n, (None,))[0]
    ct._reg_get_ex = lambda h, sk, n: fake.get((hive_name(h), sk), {}).get(n)
    ct._reg_delete_value = lambda h, sk, n: (deleted.append((hive_name(h), sk, n)),
                                             fake.get((hive_name(h), sk), {}).pop(n, None))
    def _set(h, sk, n, v, t):
        sets_.append((hive_name(h), sk, n, v))
        fake.setdefault((hive_name(h), sk), {})[n or ""] = (v, t)
    ct._reg_set = _set
    ct._reg_enum_keys = lambda h, sk: (["evil.exe"]
                                       if (hive_name(h), sk) == ("HKLM", ct.IFEOSUB) else [])
    ct._read_hosts = lambda p: "127.0.0.1 localhost\n"
    ct._list_shares = lambda: []

    mod = ct.Module()
    app_tmp = tempfile.mkdtemp(prefix="fk_ct_", dir=ROOT)
    try:
        ctx = Context(app_dir=app_tmp)
        det = mod.run("detect", ctx, lambda m: None)
        hi = [r for r in det.data["rows"] if r["level"] == "高危"]
        assert len(hi) == 4, [(r["kind"], r["value"]) for r in hi]
        assert len(det.report["fixable"]) == 4
        assert all("Good" not in r["value"] or r["level"] == "信息"
                   for r in det.data["rows"] if r["kind"] == "启动项")

        # 中途异常：第 2 次删除时抛错 → manifest 已逐项落盘，已改的第 1 项仍可回滚
        orig_del = ct._reg_delete_value
        calls = {"n": 0}

        def flaky_del(h, sk, n):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("模拟修复中途失败")
            return orig_del(h, sk, n)

        ct._reg_delete_value = flaky_del
        raised = False
        try:
            mod._do_fix(ctx, lambda m: None)
        except OSError:
            raised = True
        assert raised, "注入的失败未触发"
        assert len(deleted) == 1, deleted  # 第 1 项已改、第 2 项失败
        backup_root = os.path.join(app_tmp, "legacy_fix_backups")
        latest = sorted(os.listdir(backup_root))[-1]
        mf = json.load(open(os.path.join(backup_root, latest, "manifest.json"), encoding="utf-8"))
        assert len(mf["applied"]) == 1 and mf["applied"][0]["name"] == "KV2004", mf
        msg, n_rb = mod._do_rollback(ctx, lambda m: None)
        assert n_rb == 1 and fake[hklm_run].get("KV2004"), (msg, fake[hklm_run])
        ct._reg_delete_value = orig_del  # 还原正常删除接缝，进入完整链路

        deleted.clear()
        sets_.clear()
        fixed = mod.run("fix", ctx, lambda m: None)
        assert not [r for r in fixed.data["rows"] if r["level"] == "高危"], "修复后不得残留高危"
        assert len(deleted) == 3 and len(sets_) == 1 and "NOTEPAD" in sets_[0][3].upper()
        mf = json.load(open(os.path.join(fixed.report["fixed_backup_dir"], "manifest.json"),
                            encoding="utf-8"))
        assert len(mf["applied"]) == 4

        rb = mod.run("rollback", ctx, lambda m: None)
        assert rb.report["restored"] == 4, rb.report
        assert fake[hklm_run].get("KV2004") and fake[assoc][""][0].startswith("c:")
        assert fake[hkcu_run]["WebAuto"][1] == 2, "回滚必须保留 REG_EXPAND_SZ 原类型"
        print("[OK] 经典木马查杀: 检出4高危 / 中途异常逐项备份+回滚 / 完整修复回滚4 / REG_EXPAND_SZ 保类型")
    finally:
        shutil.rmtree(app_tmp, ignore_errors=True)


def test_signature_db_pack():
    """特征库 v2：版本化规则包 导入/降级拒绝/重复拒绝/坏规则整包拒绝/回滚。"""
    tmp = tempfile.mkdtemp(prefix="fk_pack_", dir=ROOT)
    try:
        db_path = os.path.join(tmp, "signature_db.json")
        ctx = Context(app_dir=tmp, settings={"signature_db_path": db_path})
        mod = sig.Module()
        mod.run("init", ctx, lambda m: None)

        rule = {"id": "t_rule_a", "type": "filename_regex", "value": r"(?i)^microsoft\.exe$",
                "source": "百度百科 Trojan/QQMsg.FakeUpdt（T3 登记，禁用）",
                "evidence": "T3", "first_seen": "2004-06-01", "enabled": False}

        def write_pack(name, obj):
            p = os.path.join(tmp, name)
            with open(p, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False)
            return p

        ctx.pick = write_pack("p1.json", {"name": "testpack", "version": 1,
                                          "source": "example.org/pack-v1 (T3 出处)",
                                          "rules": [rule]})
        r1 = mod.run("import_pack", ctx, lambda m: None)
        assert r1.ok and sig.load_db(db_path)["db_version"] == 1, r1.message

        r2 = mod.run("import_pack", ctx, lambda m: None)
        assert not r2.ok, "同版本重复导入必须被拒绝"

        ctx.pick = write_pack("p0.json", {"name": "testpack", "version": 0,
                                          "source": "s", "rules": [rule]})
        r0 = mod.run("import_pack", ctx, lambda m: None)
        assert not r0.ok, "降级必须被拒绝"
        assert sig.load_db(db_path)["db_version"] == 1

        bad = dict(rule, id="t_bad", evidence="T4")
        ctx.pick = write_pack("pb.json", {"name": "testpack", "version": 2,
                                          "source": "example.org/pack-v2", "rules": [bad]})
        rb = mod.run("import_pack", ctx, lambda m: None)
        assert not rb.ok and sig.load_db(db_path)["db_version"] == 1, "坏规则整包拒绝后版本不变"

        ctx.pick = write_pack("p2.json", {"name": "testpack", "version": 2,
                                          "source": "example.org/pack-v2", "rules": [rule]})
        r3 = mod.run("import_pack", ctx, lambda m: None)
        assert r3.ok and sig.load_db(db_path)["db_version"] == 2
        assert r3.report["replaced"] == 1 and r3.report["backup"], r3.report

        # 补强3：带 sha256 的完整包；篡改后整包拒绝且旧库不变；缺哈希给出警告
        good = {"name": "testpack", "version": 3, "source": "example.org/pack-v3",
                "rules": [rule]}
        good["sha256"] = sig.rules_sha256(good["rules"])
        ctx.pick = write_pack("p3.json", good)
        r4 = mod.run("import_pack", ctx, lambda m: None)
        assert r4.ok and r4.report.get("integrity") == "sha256-verified", r4.report
        tampered = dict(good, version=4)
        tampered["rules"] = [dict(rule, value=r"(?i)^evil\.exe$")]
        ctx.pick = write_pack("p4-tampered.json", tampered)
        r5 = mod.run("import_pack", ctx, lambda m: None)
        assert not r5.ok and "完整性" in r5.message, r5.message
        assert sig.load_db(db_path)["db_version"] == 3, "拒绝后旧库必须保留"
        ctx.pick = write_pack("p5-legacy.json", {"name": "testpack", "version": 5,
                                                  "source": "example.org/pack-v5", "rules": [rule]})
        r6 = mod.run("import_pack", ctx, lambda m: None)
        assert r6.ok and r6.report.get("integrity") == "not-provided", r6.report
        print("[OK] 规则包 sha256 完整性/篡改拒绝/旧格式警告")

        rr = mod.run("rollback_db", ctx, lambda m: None)
        assert rr.ok and sig.load_db(db_path)["db_version"] == 3, rr.message
        print("[OK] 特征库 v2: 导入/重复拒/降级拒/坏包拒/替换计数/回滚 全链路")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_clamav_log_not_contaminated():
    """clamscan --log 是追加写：上次扫描的命中不得混入本次统计（回归）。"""
    tmp = tempfile.mkdtemp(prefix="fk_clam_log_", dir=ROOT)
    try:
        log_file = os.path.join(tmp, "clamav_last_scan.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("D:\\old\\eicar.com: Eicar-Test-Signature FOUND\n"
                    "----------- SCAN SUMMARY -----------\nInfected files: 1\n")

        original = cb._run_process
        original_find = cb.find_clamscan
        cb.find_clamscan = lambda c: os.path.join(tmp, "clamscan.exe")  # CI 无真实引擎时仍可测桥接逻辑
        cb._run_process = lambda cmd, timeout: (0, "", "")  # 本次扫描无输出无命中
        try:
            ctx = Context(app_dir=tmp)
            ctx.target = tmp
            ctx.is_drive = False
            res = cb.Module().run("scan", ctx, lambda m: None)
            assert res.report["infected"] == 0, res.report
            assert res.report["summary_infected"] == 0, res.report
            assert not os.path.exists(log_file) or "FOUND" not in open(
                log_file, encoding="utf-8", errors="replace").read(), "旧日志未清理"
            print("[OK] ClamAV 日志隔离: 旧扫描命中不再污染本次统计")
        finally:
            cb._run_process = original
            cb.find_clamscan = original_find
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_clamav_partial_error():
    """rc=2 且有命中：结果仍给出，但必须明示「扫描部分出错」，不静默吞错。"""
    tmp = tempfile.mkdtemp(prefix="fk_clam_perr_", dir=ROOT)
    try:
        original = cb._run_process
        original_find = cb.find_clamscan
        cb.find_clamscan = lambda c: os.path.join(tmp, "clamscan.exe")  # CI 无真实引擎时仍可测 rc=2 分支

        def fake_run(cmd, timeout):
            if not any("--recursive" in c for c in cmd):
                return (0, "ClamAV 1.5.5", "")  # 版本探测等前置调用
            log_path = cmd[2].split("=", 1)[1]
            with open(log_path, "w", encoding="utf-8", errors="replace") as f:
                f.write("X:\\target\\bad.exe: Eicar-Test-Signature FOUND\n"
                        "----------- SCAN SUMMARY -----------\nInfected files: 1\n")
            return (2, "", "LibClamAV Error: some files could not be scanned")

        cb._run_process = fake_run
        try:
            ctx = Context(app_dir=tmp)
            ctx.target = tmp
            ctx.is_drive = False
            res = cb.Module().run("scan", ctx, lambda m: None)
            assert res.ok and res.report["partial_error"] is True, res.report
            assert "部分出错" in res.message, res.message
            assert res.report["summary_infected"] == 1, res.report
            assert any(r.get("type") == "partial_error" for r in res.data["rows"]), res.data["rows"]
            print("[OK] ClamAV rc=2: 保留命中结果并明示扫描不完整")
        finally:
            cb._run_process = original
            cb.find_clamscan = original_find
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_freshclam_summary():
    """更新结果必须给中文结论，不把原始英文输出与返回码糊到弹窗里。"""
    upstream = (
        "ClamAV update process started at Sat Nov 21 10:24:46 2026\n"
        "daily.cvd database is up-to-date (version: 28189, sigs: 355874, f-level: 90)\n"
        "main.cvd database is up-to-date (version: 63, sigs: 3287027, f-level: 90)\n"
        "bytecode.cvd database is up-to-date (version: 339, sigs: 80, f-level: 90)"
    )
    updated = (
        "ClamAV update process started at Sat Nov 21 10:30:00 2026\n"
        "daily.cvd updated (version: 28190, sigs: 355900, f-level: 90)"
    )
    failed = (
        "ClamAV update process started at Sat Nov 21 10:31:00 2026\n"
        "ERROR: Can't download daily.cvd from database.clamav.net"
    )
    up = cb.summarize_freshclam(0, upstream)
    new = cb.summarize_freshclam(0, updated)
    bad = cb.summarize_freshclam(1, failed)

    assert "返回码" not in up and "返回码" not in new, (up, new)
    assert "已是最新" in up and "28189" in up and "63" in up, up
    assert "已更新" in new and "daily.cvd 28190" in new, new
    assert "更新失败" in bad and "Can't download" in bad, bad
    print("[OK] freshclam 摘要: 最新 / 已更新 / 失败 三种输出均中文结论")


def test_amsi_scan():
    """AMSI 模块：不可用时优雅降级；注入 provider 分级判定；隔离目录与非脚本跳过。"""
    from modules import amsi_scan as am
    am._reset_seams()
    mod = am.Module()

    tmp = tempfile.mkdtemp(prefix="fk_amsi_a_", dir=ROOT)
    app_dir = tempfile.mkdtemp(prefix="fk_amsi_b_", dir=ROOT)
    tmp2 = None
    try:
        with open(os.path.join(tmp, "a.ps1"), "w", encoding="utf-8") as f:
            f.write("Write-Host hello\n")
        ctx = Context(app_dir=app_dir)
        ctx.target = tmp
        am._load_amsi = lambda: None
        res = mod.run("scan", ctx, lambda m: None)
        assert res.ok and res.report["amsi"]["available"] is False
        assert "跳过" in res.message

        am._reset_seams()

        def fake_scan(api, data, name):
            if name.endswith(".vbs"):
                return (0, 1)
            if name.endswith(".js"):
                return (0, 2000)
            return (0, 0)

        am._amsi_scan = fake_scan
        tmp2 = tempfile.mkdtemp(prefix="fk_amsi_c_", dir=ROOT)
        with open(os.path.join(tmp2, "evil.vbs"), "w") as f:
            f.write("x=1\n")
        with open(os.path.join(tmp2, "sus.js"), "w") as f:
            f.write("y=2\n")
        with open(os.path.join(tmp2, "note.txt"), "w") as f:
            f.write("z=3\n")
        os.makedirs(os.path.join(tmp2, "sub__WORM_QUARANTINE_x"))
        with open(os.path.join(tmp2, "sub__WORM_QUARANTINE_x", "q.vbs"), "w") as f:
            f.write("skip\n")
        ctx2 = Context(); ctx2.target = tmp2
        res2 = mod.run("scan", ctx2, lambda m: None)
        rows = res2.data["rows"]
        hi = [r for r in rows if r["level"] == "高危"]
        wa = [r for r in rows if r["level"] == "关注"]
        assert len(hi) == 1 and hi[0]["path"].endswith("evil.vbs"), hi
        assert len(wa) == 1 and wa[0]["path"].endswith("sus.js"), wa
        assert not any("q.vbs" in r["path"] or "note.txt" in r["path"] for r in rows)
        assert res2.report["amsi"]["detected"] == 1 and res2.report["amsi"]["suspicious"] == 1
        print("[OK] AMSI 扫描: 降级跳过 + 注入检出 高危1/关注1，隔离目录与非脚本不扫")
    finally:
        am._reset_seams()
        for d in (tmp, app_dir, tmp2):
            if d:
                shutil.rmtree(d, ignore_errors=True)


def test_fp_feedback():
    """误报候选登记：报告解析 / 去重 / 查看 / 校验提示。"""
    from modules import signature_db as sig
    app_dir = tempfile.mkdtemp(prefix="fk_fp_", dir=ROOT)
    try:
        _fp_feedback_body(app_dir)
    finally:
        shutil.rmtree(app_dir, ignore_errors=True)


def _fp_feedback_body(app_dir):
    matches = [
        {"id": "R1", "type": "filename_regex", "level": "命中",
         "path": "C:/x/evil.exe", "value": "evil.*",
         "source": "T1来源", "evidence": "T1", "first_seen": "2026-01-01"},
    ]
    exported = {"module_results": {"signature_db": {
        "module": "本地特征库", "action": "scan",
        "report": {"matches": matches, "matched": 1}}}}
    rf = os.path.join(app_dir, "report.json")
    with open(rf, "w", encoding="utf-8") as f:
        json.dump(exported, f, ensure_ascii=False)
    ctx = Context(app_dir=app_dir)
    ctx.pick = rf
    mod = sig.Module()
    r1 = mod.run("fp_mark", ctx, lambda m: None)
    assert r1.ok and r1.report["logged"] == 1, r1.report
    r2 = mod.run("fp_mark", ctx, lambda m: None)
    assert r2.ok and r2.report["logged"] == 0 and r2.report["duplicates"] == 1
    r3 = mod.run("fp_view", ctx, lambda m: None)
    assert r3.report["pending"] == 1
    empty = os.path.join(app_dir, "empty.json")
    with open(empty, "w", encoding="utf-8") as f:
        json.dump({"module_results": {}}, f)
    ctx2 = Context(app_dir=app_dir)
    ctx2.pick = empty
    r4 = mod.run("fp_mark", ctx2, lambda m: None)
    assert not r4.ok and "没有找到" in r4.message
    print("[OK] 误报反馈: 登记1条 / 重复去重 / 查看 / 空报告拒绝")


def test_fixscript():
    """修复脚本导出：默认全注释、命令映射正确、信息级排除、未诊断拒绝。"""
    from modules import host_diagnostics as hd
    app_dir = tempfile.mkdtemp(prefix="fk_fx_", dir=ROOT)
    try:
        _fixscript_body(hd, app_dir)
    finally:
        shutil.rmtree(app_dir, ignore_errors=True)


def _fixscript_body(hd, app_dir):
    rows = [
        {"kind": "自启动", "level": "高危",
         "path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KV2004",
         "value": "microsoft.exe", "detail": "QQ 尾巴"},
        {"kind": "IFEO", "level": "高危",
         "path": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe\Debugger",
         "value": r"C:\tmp\evil.exe", "detail": "映像劫持"},
        {"kind": "Winlogon", "level": "关注",
         "path": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
         "value": "explorer.exe x.exe", "detail": "Shell 异常"},
        {"kind": "自启动", "level": "信息",
         "path": r"HKCU\...\Run\Good", "value": "good.exe", "detail": "常规"},
    ]
    mod = hd.Module()
    mod._last_rows = rows
    mod._last_time = "2026-11-21T12:00:00"
    r1 = mod.run("fixscript", Context(app_dir=app_dir), lambda m: None)
    assert r1.ok and r1.report["written"] == 1, r1.report
    raw = open(r1.report["fixscript"], "rb").read().decode("utf-8-sig")
    uncommented = [l for l in raw.splitlines()
                   if l.strip() and not l.strip().startswith("#")]
    assert not uncommented, uncommented
    assert "-Name 'KV2004'" in raw and "-Name 'Debugger'" in raw
    assert "误改可能导致系统无法启动" in raw
    assert "Good" not in raw
    m2 = hd.Module()
    r2 = m2.run("fixscript", Context(app_dir=app_dir), lambda m: None)
    assert not r2.ok
    print("[OK] 修复脚本: 全注释输出 3 命令映射 / 1 人工建议 / 信息级排除 / 未诊断拒绝")


def test_report_export_contract():
    """报告导出契约：模块经 report_export 自声明顶层字段，主程序不硬编码。"""
    from modules import host_diagnostics as hd

    # 默认实现不贡献字段
    assert ModuleBase().report_export(ActionResult()) == {}

    # folder_virus：v1.x 兼容字段由模块自己声明
    fvm = fv.Module()
    fake = ActionResult(report={"root": "E:\\x", "meta": {"a": 1},
                                "items": [1], "hidden_items": [2], "other": 3})
    exported = fvm.report_export(fake)
    assert exported == {"root": "E:\\x", "meta": {"a": 1}, "items": [1], "hidden_items": [2]}, exported
    assert "other" not in exported

    # host_diagnostics：只读字段由模块自己声明；无 report 时给空列表
    hdm = hd.Module()
    assert hdm.report_export(ActionResult(report={"host_diagnostics_readonly": [1]})) == \
        {"host_diagnostics_readonly": [1]}
    assert hdm.report_export(ActionResult()) == {"host_diagnostics_readonly": []}

    # 模拟主程序合并：仅这两个模块贡献顶层字段，其余模块必须返回空
    instances, _errs = load_modules()
    mods = {m.meta["id"]: m for m in instances}
    data = {}
    for mid, m in mods.items():
        res = ActionResult(report={})
        extra = m.report_export(res)
        if mid == "folder_virus":
            assert extra == {"root": None, "meta": None, "items": None, "hidden_items": None}, extra
        elif mid == "host_diagnostics":
            assert extra == {"host_diagnostics_readonly": []}, extra
        else:
            assert extra == {}, (mid, extra)
        if isinstance(extra, dict):
            data.update(extra)
    print("[OK] 报告导出契约: 7 模块自声明字段 / 默认空 / app.py 无硬编码依赖")


def test_report_iso():
    """补强6：报告 ISO 生成、读回校验、容量上限拒绝；明确非引导盘。"""
    from core import iso_writer as iw
    tmp = tempfile.mkdtemp(prefix="fk_iso_", dir=ROOT)
    try:
        with open(os.path.join(tmp, "report.json"), "w", encoding="utf-8") as f:
            f.write('{"scan": 1}')
        with open(os.path.join(tmp, "摘要.TXT"), "w", encoding="utf-8") as f:
            f.write("report\n")
        out = os.path.join(tmp, "reports.iso")
        r = iw.build_iso(tmp, out)
        assert r["size"] % iw.SECTOR == 0 and r["size"] > iw.DATA_START * iw.SECTOR, r
        assert r["sha256"] == iw._sha256_file(out)
        vol, names = iw.read_back_check(out)
        assert vol == "REPORT_ISO" and any(n == "REPORT.JSON;1" for n, _s in names), names
        assert any(n == "SHA256SUMS.TXT;1" for n, _s in names), names
        try:
            iw.build_iso(tmp, os.path.join(tmp, "too_big.iso"), max_bytes=1024)
            assert False, "超限必须拒绝"
        except ValueError as e:
            assert "上限" in str(e)
        assert not os.path.exists(os.path.join(tmp, "too_big.iso"))
        print("[OK] 报告 ISO: 生成/读回/清单/上限拒绝（内容刻录，非引导）")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_scan_edge_cases():
    """补强5：只读文件、权限失败、压缩包不当容器展开、内容读取失败不崩。"""
    import builtins
    import stat as _stat
    import zipfile
    from core import scan_guard as sg
    tmp = tempfile.mkdtemp(prefix="fk_edge_", dir=ROOT)
    try:
        # 只读文件：正常扫描且不改动内容
        ro = os.path.join(tmp, "readonly.txt")
        with open(ro, "wb") as f:
            f.write(b"readonly-content")
        os.chmod(ro, _stat.S_IREAD)
        rule = {"id": "r_ro", "type": "sha256",
                "value": sig.rules_sha256([{"x": 1}])[:0] + sig._hash_file(ro),
                "source": "unit-test", "evidence": "T3", "first_seen": "2026-01-01"}
        m, scanned, skipped, errors, _g = sig._scan_target(tmp, [rule], lambda x: None)
        assert scanned >= 1 and any(x["id"] == "r_ro" for x in m), (m, errors)
        with open(ro, "rb") as f:
            assert f.read() == b"readonly-content"

        # 权限失败/不可读：接缝注入 OSError，计数而不是崩溃
        orig_lstat, orig_size = sg._lstat, os.path.getsize
        def deny(p):
            raise OSError("permission denied")
        sg._lstat = deny
        os.path.getsize = deny
        try:
            st = sg.new_stats()
            rows = list(sg.walk_entries(tmp, st))
            assert rows == [] and st["unreadable"] >= 1, st
        finally:
            sg._lstat, os.path.getsize = orig_lstat, orig_size
            sg._reset_seams()

        # 压缩包：作为单文件处理，不展开内部成员
        arc = os.path.join(tmp, "sample.zip")
        with zipfile.ZipFile(arc, "w") as z:
            z.writestr("inner.lnk", "fake")
        st2 = sg.new_stats()
        paths = [p for p, _s, _d in sg.walk_entries(tmp, st2)]
        assert arc in paths and not any(p.endswith("inner.lnk") for p in paths), paths

        # 内容正则读取失败：记 errors，不抛出
        cr = {"id": "r_cr", "type": "content_regex", "value": "x",
              "source": "unit-test", "evidence": "T3", "first_seen": "2026-01-01"}
        orig_open = builtins.open
        def bad_open(p, *a, **kw):
            if str(p) == ro:
                raise OSError("disk.full simulated")
            return orig_open(p, *a, **kw)
        builtins.open = bad_open
        try:
            m2, _sc, _sk, errs2, _g2 = sig._scan_target(tmp, [cr], lambda x: None)
        finally:
            builtins.open = orig_open
        assert any("disk.full" in e for e in errs2), errs2
        print("[OK] 边界用例: 只读/权限失败/压缩包不展开/读取失败记错不崩")
    finally:
        os.chmod(os.path.join(tmp, "readonly.txt"), _stat.S_IWRITE | _stat.S_IREAD)
        shutil.rmtree(tmp, ignore_errors=True)


def test_report_tools_export_and_audit():
    """补强4：三格式导出、脱敏、引擎/库状态泛化提取、审计日志追加。"""
    import csv as _csv
    from core import report_tools as rt
    tmp = tempfile.mkdtemp(prefix="fk_report_", dir=ROOT)
    try:
        full = "180" + "7090" + "7766"
        data = {
            "time": "2026-11-22T00:00:00",
            "meta": {"version": "v2.0", "target": "C:" + chr(92) + "Users" + chr(92) + "zhangsan" + chr(92) + "usb"},
            "module_results": {
                "signature_db": {"module": "本地特征库", "action": "scan", "ok": True,
                                 "report": {"db_version": 3, "rule_count": 2, "updated_at": "2026-11-20",
                                            "matches": [{"type": "sha256", "level": "命中",
                                                         "path": r"C:\Users\zhangsan\usb\a.exe",
                                                         "value": full}]}},
                "clamav_bridge": {"module": "ClamAV", "action": "scan", "ok": True,
                                  "report": {"version": "1.0", "arch": "x64", "matches": []}},
            },
        }
        assert rt.anonymize(full) == "<手机号>"
        assert r"C:\Users\zhangsan" not in rt.anonymize(data["meta"]["target"])
        built = rt.build_report([], data["module_results"], data["meta"])
        assert len(built["status"]["engines"]) == 1 and built["status"]["engines"][0]["name"] == "ClamAV"
        assert built["status"]["databases"][0]["version"] == 3

        pj = rt.export(built, "json", os.path.join(tmp, "r.json"))
        with open(pj, encoding="utf-8") as f:
            txt = f.read()
        assert full not in txt and "<手机号>" in txt
        pc = rt.export(built, "csv", os.path.join(tmp, "r.csv"))
        with open(pc, encoding="utf-8-sig", newline="") as f:
            rows = list(_csv.DictReader(f))
        assert len(rows) == 1 and rows[0]["等级"] == "命中"
        pt = rt.export(built, "txt", os.path.join(tmp, "r.txt"))
        with open(pt, encoding="utf-8") as f:
            t = f.read()
        assert "引擎状态" in t and "数据库状态" in t and full not in t

        rt.append_audit(tmp, {"module": "U盘文件查杀", "action": "clean", "ok": True,
                              "target": r"C:\Users\zhangsan\usb"})
        rt.append_audit(tmp, {"module": "经典木马", "action": "fix", "ok": False})
        with open(os.path.join(tmp, "audit.log"), encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 2 and "zhangsan" not in lines[0]["target"], lines
        print("[OK] 审计报告: 三格式/脱敏/状态聚合/审计追加")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_scan_guard_boundaries():
    """补强2：重解析点剪枝 / 体积上限 / 深度上限 / 不可读计数 / 接缝可注入。"""
    from core import scan_guard as sg
    B = chr(92)

    class S:
        def __init__(self, mode=0, attrs=0):
            self.st_mode = mode
            self.st_file_attributes = attrs

    root = "C:" + B + "scan_root"
    reparse_dir = os.path.join(root, "junction")
    reparse_file = os.path.join(root, "link.lnk")
    big = os.path.join(root, "big.bin")
    normal = os.path.join(root, "ok.txt")
    trees = [(root, ["junction", "sub"], ["link.lnk", "big.bin", "ok.txt"]),
             (os.path.join(root, "sub"), [], ["deep.txt"])]
    sizes = {big: 500, normal: 3, os.path.join(root, "sub", "deep.txt"): 4}

    orig = (sg._lstat, sg._walk)
    sg._lstat = lambda p: S(attrs=sg.FILE_ATTRIBUTE_REPARSE_POINT) if p in (reparse_dir, reparse_file) else S()
    sg._walk = lambda r: iter(trees)
    orig_size = os.path.getsize
    os.path.getsize = lambda p: sizes[p]
    try:
        st = sg.new_stats()
        rows = [p for p, _sz, _isdir in sg.walk_entries(root, st, max_file_bytes=100, max_depth=4)]
        assert normal in rows and os.path.join(root, "sub", "deep.txt") in rows, rows
        assert reparse_file not in rows and big not in rows, rows
        assert st["skipped_reparse"] == 2 and st["skipped_large"] == 1, st
        assert st["scanned"] == 2, st

        st2 = sg.new_stats()
        list(sg.walk_entries(root, st2, max_depth=1))
        assert st2["skipped_depth"] >= 1, st2
    finally:
        sg._lstat, sg._walk, os.path.getsize = orig[0], orig[1], orig_size
        sg._reset_seams()
    print("[OK] 扫描边界: 重解析点剪枝/体积与深度上限/统计口径")


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

        # 多个模块都提供同一批盘符：下拉框不得出现重复项，提示不得重复叠加
        values = [str(v) for v in app.cb["values"]]
        drives = fv.list_drives()
        assert len(values) == len(dict.fromkeys(values)) == len(drives), values
        hint = app.info.cget("text")
        assert hint.count("共 ") == 1 and "；共" not in hint, hint
        assert ("共 %d 个可处理盘符。" % len(drives)) in hint, hint
        print("[OK] GUI 装配: %d 视图 / %d 按钮；作者信息已显示；盘符 %d 项无重复，提示单一"
              % (len(app.views), len(app.all_buttons), len(values)))
    finally:
        root.destroy()


if __name__ == "__main__":
    test_discovery()
    test_plugin_hot_discovery()
    test_engine_and_rollback()
    test_host_diagnostics()
    test_signature_db_empty_and_rules()
    test_clamav_bridge_parse_and_mock()
    test_clamav_log_not_contaminated()
    test_clamav_partial_error()
    test_classic_trojans()
    test_signature_db_pack()
    test_modern_threats()
    test_freshclam_summary()
    test_amsi_scan()
    test_fp_feedback()
    test_fixscript()
    test_gui_assembly()
    print("ALL PASS")
