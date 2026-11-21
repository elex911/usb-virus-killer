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
    fake[hkcu_run] = {"WebAuto": (r"C:\Windows\System32\WebAuto.exe", 1)}
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

        fixed = mod.run("fix", ctx, lambda m: None)
        assert not [r for r in fixed.data["rows"] if r["level"] == "高危"], "修复后不得残留高危"
        assert len(deleted) == 3 and len(sets_) == 1 and "NOTEPAD" in sets_[0][3].upper()
        mf = json.load(open(os.path.join(fixed.report["fixed_backup_dir"], "manifest.json"),
                            encoding="utf-8"))
        assert len(mf["applied"]) == 4

        rb = mod.run("rollback", ctx, lambda m: None)
        assert rb.report["restored"] == 4, rb.report
        assert fake[hklm_run].get("KV2004") and fake[assoc][""][0].startswith("c:")
        print("[OK] 经典木马查杀: 注入检出 4 高危 / 修复删值3+还原关联1 / 回滚 4；真实主机 0 高危")
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

        r4 = mod.run("rollback_db", ctx, lambda m: None)
        assert r4.ok and sig.load_db(db_path)["db_version"] == 1, r4.message
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
    with open(os.path.join(tmp, "a.ps1"), "w", encoding="utf-8") as f:
        f.write("Write-Host hello\n")
    ctx = Context(app_dir=tempfile.mkdtemp(prefix="fk_amsi_b_", dir=ROOT))
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


def test_fp_feedback():
    """误报候选登记：报告解析 / 去重 / 查看 / 校验提示。"""
    from modules import signature_db as sig
    app_dir = tempfile.mkdtemp(prefix="fk_fp_", dir=ROOT)
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
    test_classic_trojans()
    test_signature_db_pack()
    test_modern_threats()
    test_freshclam_summary()
    test_amsi_scan()
    test_fp_feedback()
    test_fixscript()
    test_gui_assembly()
    print("ALL PASS")
