# -*- coding: utf-8 -*-
"""测试台执行器：对查杀工具跑全场景测试，收集数据出报告。

用法：
  python testbed/run_testbed.py            # 跑全部场景
  python testbed/run_testbed.py --list     # 只列场景

产物：
  testbed/results/<run_id>/report.json     机器可读全量数据
  控制台摘要（通过/失败/检出率/误报/耗时）
退出码：全部通过 0，任何失败 1。
"""
import io
import json
import os
import shutil
import sys
import tempfile
import time
import traceback
import platform

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.api import Context                      # noqa: E402
from modules import folder_virus as fv            # noqa: E402
from modules import signature_db as sig           # noqa: E402
from modules import clamav_bridge as cb           # noqa: E402
from modules import modern_threats as mt          # noqa: E402
from modules import host_diagnostics as hd        # noqa: E402
from modules import classic_trojans as ct         # noqa: E402
import fixtures                                   # noqa: E402

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


class Case:
    def __init__(self, name, func):
        self.name = name
        self.func = func


def case(name):
    def deco(func):
        return Case(name, func)
    return deco


# ---------------- 场景 ----------------

@case("01 合成感染样本构建")
def s_build_infected(log):
    tmp = tempfile.mkdtemp(prefix="tb_infected_", dir=RESULTS_DIR)
    truth = fixtures.build_infected_usb(os.path.join(tmp, "usb"))
    hidden_ok = all(
        (fv.get_attr(p) or 0) & fv.FILE_ATTRIBUTE_HIDDEN for p in truth["hidden_originals"]
    )
    checks = {
        "hidden_dirs": len(truth["hidden_originals"]),
        "mimic_lnks": len(truth["mimic_lnks"]),
        "autorun_exists": os.path.isfile(truth["autorun"]),
        "attrs_ok": hidden_ok,
    }
    ok = checks["attrs_ok"] and checks["autorun_exists"] and checks["mimic_lnks"] == 4
    return ok, checks, tmp


@case("02 感染盘扫描（判定准确率）")
def s_scan_infected(log):
    tmp = tempfile.mkdtemp(prefix="tb_scan_", dir=RESULTS_DIR)
    usb = os.path.join(tmp, "usb")
    truth = fixtures.build_infected_usb(usb)
    eng = fv.Engine(usb, False)
    eng.precheck()
    stats = eng.scan(log)
    mal = [i for i in eng.items if i["verdict"] == "恶意"]
    sus = [i for i in eng.items if i["verdict"] == "可疑"]
    mal_paths = {os.path.normcase(i["path"]) for i in mal}
    expected = {os.path.normcase(p) for p in truth["mimic_lnks"] + [truth["autorun"]]}
    clean_paths = {os.path.normcase(p) for p in truth["clean_paths"]}
    tp = len(expected & mal_paths)
    fp = len(clean_paths & (mal_paths | {os.path.normcase(i["path"]) for i in sus}))
    fn = len(expected - mal_paths)
    checks = {
        "expected_malicious": len(expected),
        "true_positive": tp,
        "false_negative": fn,
        "false_positive": fp,
        "stats": stats,
    }
    ok = tp == len(expected) and fn == 0 and fp == 0
    return ok, checks, tmp


@case("03 干净盘扫描（误报基准）")
def s_scan_clean(log):
    tmp = tempfile.mkdtemp(prefix="tb_clean_", dir=RESULTS_DIR)
    usb = os.path.join(tmp, "usb")
    truth = fixtures.build_clean_usb(usb)
    eng = fv.Engine(usb, False)
    eng.precheck()
    stats = eng.scan(log)
    bad = [i for i in eng.items if i["verdict"] in ("恶意", "可疑")]
    checks = {"stats": stats, "flagged": [i["path"] for i in bad]}
    ok = stats["malicious"] == 0 and stats["suspicious"] == 0 and len(bad) == 0
    return ok, checks, tmp


@case("04 查杀隔离（含 quarantine 清单）")
def s_clean(log):
    tmp = tempfile.mkdtemp(prefix="tb_kill_", dir=RESULTS_DIR)
    usb = os.path.join(tmp, "usb")
    truth = fixtures.build_infected_usb(usb)
    eng = fv.Engine(usb, False)
    eng.precheck()
    eng.scan(log)
    r = eng.clean(log)
    gone = all(not os.path.exists(p) for p in truth["mimic_lnks"]) and not os.path.exists(truth["autorun"])
    kept = all(os.path.exists(p) for p in truth["clean_paths"])
    unhidden = all(
        not ((fv.get_attr(p) or 0) & fv.FILE_ATTRIBUTE_HIDDEN)
        for p in truth["hidden_originals"] if os.path.exists(p)
    )
    mf_path = os.path.join(r["quarantine"], "manifest.json")
    with io.open(mf_path, encoding="utf-8") as f:
        mf = json.load(f)
    q_count = sum(1 for i in mf["items"] if i["action"] == "quarantine")
    checks = {"moved": r["moved"], "quarantined_in_manifest": q_count,
              "mimics_gone": gone, "clean_kept": kept, "originals_unhidden": unhidden,
              "quarantine": r["quarantine"]}
    ok = r["moved"] == 5 and q_count == 5 and gone and kept and unhidden
    return ok, checks, tmp


@case("05 回滚还原")
def s_restore(log):
    tmp = tempfile.mkdtemp(prefix="tb_restore_", dir=RESULTS_DIR)
    usb = os.path.join(tmp, "usb")
    truth = fixtures.build_infected_usb(usb)
    eng = fv.Engine(usb, False)
    eng.precheck()
    eng.scan(log)
    r = eng.clean(log)
    ok_n, fail_n = fv.Engine.restore(r["quarantine"], log)
    back = all(os.path.exists(p) for p in truth["mimic_lnks"]) and os.path.exists(truth["autorun"])
    checks = {"restored_ok": ok_n, "restored_fail": fail_n, "files_back": back}
    ok = ok_n == 5 and fail_n == 0 and back
    return ok, checks, tmp


@case("06 免疫 autorun.inf")
def s_immunize(log):
    tmp = tempfile.mkdtemp(prefix="tb_immune_", dir=RESULTS_DIR)
    usb = os.path.join(tmp, "usb")
    fixtures.build_clean_usb(usb)
    guard = fv.Engine.immunize(usb, log)
    is_dir = os.path.isdir(guard)
    again_ok = False
    try:
        fv.Engine.immunize(usb, log)
        again_ok = False  # 第二次应当报错而不是静默成功
    except RuntimeError:
        again_ok = True
    checks = {"guard_is_dir": is_dir, "second_rejected": again_ok}
    ok = bool(guard) and is_dir and again_ok
    return ok, checks, tmp


@case("07 本地特征库按库扫描（空库零命中）")
def s_sigdb(log):
    tmp = tempfile.mkdtemp(prefix="tb_sig_", dir=RESULTS_DIR)
    usb = os.path.join(tmp, "usb")
    fixtures.build_infected_usb(usb)
    db_path = os.path.join(tmp, "signature_db.json")
    ctx = Context(app_dir=tmp, settings={"signature_db_path": db_path})
    mod = sig.Module()
    mod.run("init", ctx, log)
    ctx.target = usb
    ctx.is_drive = False
    res = mod.run("scan", ctx, log)
    rows = res.data.get("rows", [])
    # 空库允许一条「(空库)」信息行；绝不允许命中/待核/规则错误
    hits = [r for r in rows if r.get("level") in ("命中", "待核", "规则错误")]
    checks = {"rows": len(rows), "hits": len(hits),
              "row_levels": [r.get("level") for r in rows]}
    ok = res.ok and len(hits) == 0
    return ok, checks, tmp


@case("08 ClamAV 连续两扫（跨次污染回归）")
def s_clamav_infected(log):
    tmp = tempfile.mkdtemp(prefix="tb_clam_", dir=RESULTS_DIR)
    usb = os.path.join(tmp, "usb")
    fixtures.build_infected_usb(usb)
    ctx = Context()
    ctx.is_drive = False
    eicar_dir = r"D:\ClamAV\eicar-test"
    if not os.path.isdir(eicar_dir):
        ctx.target = usb
        res = cb.Module().run("scan", ctx, log)
        checks = {"clamscan_found": bool(res.report.get("clamscan")),
                  "first_infected": res.report.get("infected"),
                  "skipped": "无 EICAR 基准目录，退化为单扫"}
        return checks["clamscan_found"] and res.report.get("infected") == 0, checks, tmp
    # 第一次：扫 EICAR（必命中）；第二次：扫合成样本（必须 0，不得带走上次结果）
    ctx.target = eicar_dir
    r1 = cb.Module().run("scan", ctx, log)
    ctx.target = usb
    r2 = cb.Module().run("scan", ctx, log)
    n1, n2 = r1.report.get("infected"), r2.report.get("infected")
    checks = {"first_eicar_hits": n1, "second_usb_hits": n2, "ok": r2.ok}
    ok = r1.ok and r2.ok and (n1 or 0) >= 1 and n2 == 0
    return ok, checks, tmp


@case("09 ClamAV 扫 EICAR 基准（检出能力）")
def s_clamav_eicar(log):
    eicar_dir = r"D:\ClamAV\eicar-test"
    if not os.path.isdir(eicar_dir):
        return True, {"skipped": "未找到 EICAR 基准目录 %s" % eicar_dir}, None
    ctx = Context()
    ctx.target = eicar_dir
    ctx.is_drive = False
    res = cb.Module().run("scan", ctx, log)
    infected = res.report.get("infected", 0)
    matches = res.report.get("matches", [])
    sigs = sorted({m.get("signature", "") for m in matches})
    checks = {"infected": infected, "signatures": sigs, "ok": res.ok}
    ok = res.ok and infected >= 1
    return ok, checks, None


@case("10 现代威胁检测（真实主机低噪音）")
def s_modern(log):
    res = mt.Module().run("collect", Context(), log)
    rows = res.data.get("rows", [])
    levels = [r["level"] for r in rows]
    hi = levels.count("高危")
    checks = {"rows": len(rows), "high": hi, "watch": levels.count("关注"),
              "levels_valid": all(l in ("高危", "关注", "信息") for l in levels),
              "no_malicious_label": all(l != "恶意" for l in levels)}
    ok = checks["levels_valid"] and checks["no_malicious_label"] and len(rows) < 120
    return ok, checks, None


@case("11 主机诊断（真实主机低噪音）")
def s_hostdiag(log):
    res = hd.Module().run("collect", Context(), log)
    rows = res.data.get("rows", [])
    levels = [r["level"] for r in rows]
    checks = {"rows": len(rows), "high": levels.count("高危"), "watch": levels.count("关注"),
              "levels_valid": all(l in ("高危", "关注", "信息") for l in levels)}
    ok = checks["levels_valid"]
    return ok, checks, None


@case("13 经典木马体检（真实主机低噪音）")
def s_classic(log):
    ct._reset_seams()
    res = ct.Module().run("detect", Context(), log)
    rows = res.data.get("rows", [])
    levels = [r["level"] for r in rows]
    kinds = {r["kind"] for r in rows}
    checks = {"rows": len(rows), "high": levels.count("高危"),
              "watch": levels.count("关注"), "kinds": sorted(kinds),
              "levels_valid": all(l in ("高危", "关注", "信息") for l in levels)}
    # 真实主机干净：不得有高危；核心四类必须完成采集
    # （IFEO 类仅在有 Debugger 时输出，缺省不算失败）
    core = {"启动项", "文件关联", "hosts", "共享"}
    ok = checks["levels_valid"] and checks["high"] == 0 and core <= kinds
    return ok, checks, None


@case("14 特征库规则包全链路")
def s_sigpack(log):
    tmp = tempfile.mkdtemp(prefix="tb_pack_", dir=RESULTS_DIR)
    try:
        db_path = os.path.join(tmp, "signature_db.json")
        ctx = Context(app_dir=tmp, settings={"signature_db_path": db_path})
        mod = sig.Module()
        mod.run("init", ctx, log)
        rule = {"id": "tb_rule", "type": "filename_regex", "value": r"(?i)^microsoft\.exe$",
                "source": "百度百科 Trojan/QQMsg.FakeUpdt（T3 登记）",
                "evidence": "T3", "first_seen": "2004-06-01", "enabled": False}
        pack = os.path.join(tmp, "pack_v1.json")
        with io.open(pack, "w", encoding="utf-8") as f:
            json.dump({"name": "tb-pack", "version": 1, "source": "testbed.local/v1",
                       "rules": [rule]}, f, ensure_ascii=False)
        ctx.pick = pack
        r1 = mod.run("import_pack", ctx, log)
        ver_after_import = sig.load_db(db_path)["db_version"]
        ctx.pick = pack
        r_dup = mod.run("import_pack", ctx, log)
        r_rb = mod.run("rollback_db", ctx, log)
        ver_after_rollback = sig.load_db(db_path)["db_version"]
        checks = {"import_ok": r1.ok, "db_version_after": ver_after_import,
                  "duplicate_rejected": not r_dup.ok, "rollback_ok": r_rb.ok,
                  "rollback_version": ver_after_rollback,
                  "backup_exists": bool(r1.report.get("backup"))}
        ok = (checks["import_ok"] and checks["db_version_after"] == 1
              and checks["duplicate_rejected"] and checks["rollback_ok"]
              and checks["rollback_version"] == 0 and checks["backup_exists"])
        return ok, checks, tmp
    finally:
        pass
@case("15 GUI 装配烟测（源码级）")
def s_gui(log):
    import tkinter as tk
    from core.app import App
    root = tk.Tk()
    root.withdraw()
    try:
        app = App(root)
        root.update()
        values = [str(v) for v in app.cb["values"]]
        hint = app.info.cget("text")
        texts = []

        def walk(w):
            try:
                texts.append(str(w.cget("text")))
            except Exception:
                pass
            for ch in w.winfo_children():
                walk(ch)
        walk(root)
        author_ok = any("军不见" in t and "180******66" in t for t in texts)
        drives = fv.list_drives()
        checks = {
            "views": len(app.views), "buttons": len(app.all_buttons),
            "author_ok": author_ok, "combobox_unique": len(values) == len(set(values)),
            "combobox_count_matches_drives": len(values) == len(drives),
            "hint": hint,
        }
        ok = (len(app.views) == 6 and author_ok
              and len(values) == len(set(values)) == len(drives)
              and hint.count("；") == 0)
        return ok, checks, None
    finally:
        root.destroy()


# ---------------- 执行器 ----------------

def exe_info():
    dist = os.path.join(ROOT, "dist")
    out = {"exe_built": None, "exe_bytes": None}
    if os.path.isdir(dist):
        exes = [os.path.join(dist, f) for f in os.listdir(dist) if f.lower().endswith(".exe")]
        if exes:
            p = max(exes, key=os.path.getmtime)
            out["exe_built"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(p)))
            out["exe_bytes"] = os.path.getsize(p)
    return out


def cleanup(tmp):
    if tmp and os.path.isdir(tmp) and tmp.startswith(RESULTS_DIR):
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    cases = [v for v in globals().values() if isinstance(v, Case)]
    cases.sort(key=lambda c: c.name)
    if "--list" in argv:
        for c in cases:
            print(c.name)
        return 0
    os.makedirs(RESULTS_DIR, exist_ok=True)
    run_id = time.strftime("%Y%m%d_%H%M%S")
    rundir = os.path.join(RESULTS_DIR, run_id)
    os.makedirs(rundir, exist_ok=True)

    report = {
        "run_id": run_id,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "exe": exe_info(),
        "scenarios": [],
    }
    print("=" * 72)
    print("测试台 run_id=%s" % run_id)
    print("=" * 72)
    failed = 0
    for c in cases:
        t0 = time.time()
        entry = {"name": c.name, "ok": False, "duration_ms": None, "checks": None, "error": None}
        tmpdir = None
        print("\n[ RUN ] %s" % c.name)
        try:
            ok, checks, tmpdir = c.func(lambda m: print("       · %s" % m) if len(str(m)) < 100 else None)
            entry["ok"] = bool(ok)
            entry["checks"] = checks
        except Exception as exc:
            entry["error"] = "%s\n%s" % (exc, traceback.format_exc())
        finally:
            cleanup(tmpdir)
        entry["duration_ms"] = int((time.time() - t0) * 1000)
        report["scenarios"].append(entry)
        mark = "PASS" if entry["ok"] else "FAIL"
        if not entry["ok"]:
            failed += 1
        print("[ %s ] %s  (%d ms)" % (mark, c.name, entry["duration_ms"]))
        if entry["error"]:
            print("       错误: %s" % entry["error"].splitlines()[0])
        if entry["checks"]:
            print("       数据: %s" % json.dumps(entry["checks"], ensure_ascii=False, default=str))

    passed = len(cases) - failed
    report["passed"] = passed
    report["failed"] = failed
    out = os.path.join(rundir, "report.json")
    with io.open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)
    print("\n" + "=" * 72)
    print("结果: %d/%d 通过；报告: %s" % (passed, len(cases), out))
    print("=" * 72)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
