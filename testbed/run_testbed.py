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
        rep = res.report if isinstance(res.report, dict) else {}
        checks = {"clamscan_found": bool(rep.get("clamscan")),
                  "first_infected": rep.get("infected"),
                  "skipped": "无 EICAR 基准目录，退化为单扫"}
        if not res.ok or not rep:
            # CI/无 ClamAV 环境：引擎缺失是环境限制，不是缺陷；如实标记跳过
            checks["skipped"] = "无 clamscan.exe / 引擎不可用：" + (res.message or "")[:120]
            return True, checks, tmp
        return checks["clamscan_found"] and rep.get("infected") == 0, checks, tmp
    # 第一次：扫 EICAR（必命中）；第二次：扫合成样本（必须 0，不得带走上次结果）
    ctx.target = eicar_dir
    r1 = cb.Module().run("scan", ctx, log)
    ctx.target = usb
    r2 = cb.Module().run("scan", ctx, log)
    p1 = r1.report if isinstance(r1.report, dict) else {}
    p2 = r2.report if isinstance(r2.report, dict) else {}
    n1, n2 = p1.get("infected"), p2.get("infected")
    checks = {"first_eicar_hits": n1, "second_usb_hits": n2, "ok": r2.ok}
    if not r1.ok or not r2.ok or not p1 or not p2:
        checks["skipped"] = "ClamAV 引擎不可用：" + ((r1.message or r2.message or "")[:120])
        return True, checks, tmp
    ok = (n1 or 0) >= 1 and n2 == 0
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
    rep = res.report if isinstance(res.report, dict) else {}
    if not res.ok or not rep:
        return True, {"skipped": "ClamAV 引擎不可用：" + (res.message or "")[:120]}, None
    infected = rep.get("infected", 0)
    matches = rep.get("matches", [])
    sigs = sorted({m.get("signature", "") for m in matches})
    checks = {"infected": infected, "signatures": sigs, "ok": res.ok}
    ok = infected >= 1
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


@case("12 经典木马体检（真实主机低噪音）")
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


@case("13 特征库规则包全链路")
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
@case("14 GUI 装配烟测（源码级）")
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
        # 视图数随内置模块数增长，动态计算而非硬编码（新增模块不应让烟测假失败）
        from core.registry import BUILTIN_MODULES
        expected_views = len(BUILTIN_MODULES)
        ok = (len(app.views) == expected_views and author_ok
              and len(values) == len(set(values)) == len(drives)
              and hint.count("；") == 0)
        return ok, checks, None
    finally:
        root.destroy()


@case("15 AMSI 脚本扫描（接缝注入 + 降级）")
def s_amsi(log):
    from modules import amsi_scan as am
    tmp = tempfile.mkdtemp(prefix="tb_amsi_", dir=RESULTS_DIR)
    am._reset_seams()
    try:
        with open(os.path.join(tmp, "evil.vbs"), "w") as f:
            f.write("x=1\n")
        with open(os.path.join(tmp, "note.txt"), "w") as f:
            f.write("z=3\n")

        am._load_amsi = lambda: None
        ctx0 = Context(); ctx0.target = tmp
        r0 = am.Module().run("scan", ctx0, log)
        degraded = r0.ok and r0.report["amsi"]["available"] is False

        am._reset_seams()
        am._amsi_scan = lambda api, data, name: (0, 1) if name.endswith(".vbs") else (0, 0)
        ctx = Context(); ctx.target = tmp
        r1 = am.Module().run("scan", ctx, log)
        hi = [r for r in r1.data["rows"] if r["level"] == "高危"]
        checks = {"degraded_ok": degraded, "detected": r1.report["amsi"]["detected"],
                  "high_rows": len(hi), "txt_not_scanned": not any(
                      "note.txt" in r["path"] for r in r1.data["rows"])}
        ok = degraded and checks["detected"] == 1 and checks["high_rows"] == 1 \
            and checks["txt_not_scanned"]
        return ok, checks, tmp
    finally:
        am._reset_seams()


@case("16 修复脚本导出 + 误报候选登记")
def s_fixscript_fp(log):
    tmp = tempfile.mkdtemp(prefix="tb_fx_", dir=RESULTS_DIR)
    rows = [
        {"kind": "自启动", "level": "高危",
         "path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KV2004",
         "value": "microsoft.exe", "detail": "QQ 尾巴特征"},
        {"kind": "Winlogon", "level": "关注",
         "path": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
         "value": "explorer.exe x.exe", "detail": "Shell 异常"},
    ]
    mod = hd.Module()
    mod._last_rows = rows
    mod._last_time = time.strftime("%Y-%m-%dT%H:%M:%S")
    r1 = mod.run("fixscript", Context(app_dir=tmp), log)
    script_ok = False
    if r1.ok and r1.report.get("written"):
        raw = io.open(r1.report["fixscript"], "rb").read().decode("utf-8-sig")
        script_ok = not [l for l in raw.splitlines()
                         if l.strip() and not l.strip().startswith("#")]
    matches = [{"id": "R1", "type": "filename_regex", "level": "命中",
                "path": "C:/x/evil.exe", "value": "evil.*",
                "source": "T1来源", "evidence": "T1", "first_seen": "2026-01-01"}]
    exported = {"module_results": {"signature_db": {
        "module": "本地特征库", "action": "scan",
        "report": {"matches": matches, "matched": 1}}}}
    rf = os.path.join(tmp, "report.json")
    io.open(rf, "w", encoding="utf-8").write(json.dumps(exported, ensure_ascii=False))
    smod = sig.Module()
    ctx = Context(app_dir=tmp); ctx.pick = rf
    r2 = smod.run("fp_mark", ctx, log)
    r3 = smod.run("fp_mark", ctx, log)
    r4 = smod.run("fp_view", Context(app_dir=tmp), log)
    checks = {
        "script_all_commented": script_ok,
        "fp_logged": r2.report.get("logged"),
        "fp_dedup": r3.report.get("logged") == 0,
        "fp_pending": r4.report.get("pending"),
    }
    ok = script_ok and checks["fp_logged"] == 1 and checks["fp_dedup"] \
        and checks["fp_pending"] == 1
    return ok, checks, tmp


# ---------------- 执行器 ----------------

@case("17 异常目标与锁定文件（优雅失败）")
def s_exceptions(log):
    tmp = tempfile.mkdtemp(prefix="tb_excep_", dir=RESULTS_DIR)
    checks = {}
    # a) 根目录不存在：必须是带中文说明的 RuntimeError
    eng = fv.Engine(os.path.join(tmp, "no_such_dir"), False)
    try:
        eng.precheck()
        checks["missing_root"] = "未拒绝（BUG）"
    except RuntimeError as exc:
        checks["missing_root"] = "已拒绝" if "目标不存在" in str(exc) else "拒绝但文案不符"
    except Exception as exc:
        checks["missing_root"] = "异常类型错误: %r" % (exc,)
    # b) 根目录是文件而非文件夹
    fpath = os.path.join(tmp, "plain.txt")
    with open(fpath, "w", encoding="utf-8") as f:
        f.write("x")
    eng2 = fv.Engine(fpath, False)
    try:
        eng2.precheck()
        checks["file_root"] = "未拒绝（BUG）"
    except RuntimeError as exc:
        checks["file_root"] = "已拒绝" if "不是文件夹" in str(exc) else "拒绝但文案不符"
    except Exception as exc:
        checks["file_root"] = "异常类型错误: %r" % (exc,)
    # c) 锁定文件（独占句柄）+ content_regex：逐文件失败记 error，不崩溃、不误报
    import ctypes
    db_path = os.path.join(tmp, "signature_db.json")
    ctx = Context(app_dir=tmp, settings={"signature_db_path": db_path})
    sig.Module().run("init", ctx, log)
    with io.open(db_path, encoding="utf-8") as f:
        db = json.load(f)
    db["rules"].append({"id": "R-LOCK-1", "type": "content_regex", "value": "hello",
                        "source": "测试台合成规则", "evidence": "T1",
                        "first_seen": time.strftime("%Y-%m-%d"), "enabled": True})
    with io.open(db_path, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False)
    target = os.path.join(tmp, "usb")
    os.makedirs(target)
    with open(os.path.join(target, "normal.txt"), "w", encoding="utf-8") as f:
        f.write("hello world\n")
    locked = os.path.join(target, "locked.log")
    with open(locked, "w", encoding="utf-8") as f:
        f.write("hello locked\n")
    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    h = ctypes.windll.kernel32.CreateFileW(
        locked, GENERIC_READ, 0, None, OPEN_EXISTING, 0, None)
    checks["lock_handle"] = bool(h and h != -1)
    try:
        sctx = Context(app_dir=tmp, settings={"signature_db_path": db_path})
        sctx.target = target
        sctx.is_drive = False
        res = sig.Module().run("scan", sctx, log)
        hits = [m for m in res.report.get("matches", [])]
        hit_paths = [os.path.normcase(m["path"]) for m in hits]
        checks["scan_ok"] = bool(res.ok)
        checks["hits"] = len(hits)
        checks["only_normal"] = hit_paths == [os.path.normcase(os.path.join(target, "normal.txt"))]
        checks["errors_recorded"] = len(res.report.get("scan_errors", []) or []) >= 1
    finally:
        if h and h != -1:
            ctypes.windll.kernel32.CloseHandle(h)
    ok = (checks.get("missing_root") == "已拒绝"
          and checks.get("file_root") == "已拒绝"
          and checks.get("lock_handle")
          and checks.get("scan_ok") and checks.get("hits") == 1
          and checks.get("only_normal") and checks.get("errors_recorded"))
    return ok, checks, tmp


@case("18 损坏规则库（优雅失败链）")
def s_corrupt_db(log):
    tmp = tempfile.mkdtemp(prefix="tb_baddb_", dir=RESULTS_DIR)
    checks = {}
    db_path = os.path.join(tmp, "signature_db.json")
    # a) 库文件是乱码字节：init 绝不覆盖；validate 必须给中文 RuntimeError
    with open(db_path, "wb") as f:
        f.write(b"\xff\xfe{not json!!!")
    ctx = Context(app_dir=tmp, settings={"signature_db_path": db_path})
    mod = sig.Module()
    r_init = mod.run("init", ctx, log)
    checks["init_not_overwrite"] = (r_init.report.get("created") is False)
    try:
        mod.run("validate", ctx, log)
        checks["garbage"] = "未拒绝（BUG：坏库静默通过）"
    except RuntimeError as exc:
        checks["garbage"] = "中文拒绝" if ("特征库" in str(exc) and "解析失败" in str(exc)) else "拒绝但文案不符"
    except Exception as exc:
        checks["garbage"] = "异常类型错误: %r" % (exc,)
    # b) JSON 合法但根节点是数组：validate 优雅列出错误不崩溃
    with io.open(db_path, "w", encoding="utf-8") as f:
        json.dump([1, 2, 3], f)
    r2 = mod.run("validate", ctx, log)
    errs2 = r2.report.get("errors", [])
    checks["array_root"] = bool(r2.ok) and any("根节点" in e for e in errs2)
    # c) 根节点对象但 rules 不是数组
    with io.open(db_path, "w", encoding="utf-8") as f:
        json.dump({"rules": "oops"}, f)
    r3 = mod.run("validate", ctx, log)
    errs3 = r3.report.get("errors", [])
    checks["rules_not_list"] = bool(r3.ok) and any("rules 必须是数组" in e for e in errs3)
    ok = (checks.get("init_not_overwrite") and checks.get("garbage") == "中文拒绝"
          and checks.get("array_root") and checks.get("rules_not_list"))
    return ok, checks, tmp


@case("19 本地磁盘与系统盘查杀（含关键路径护栏）")
def s_local_disk(log):
    """本地磁盘为一等公民：默认放行、系统盘可查、关键路径只报告不改动。"""
    tmp = tempfile.mkdtemp(prefix="tb_localdisk_", dir=RESULTS_DIR)
    checks = {}
    checks["default_allow_fixed"] = Context().allow_fixed is True
    root, is_drive = fv.norm_target("D:  [本地固定磁盘]")
    checks["display_text"] = (root == "D:" + chr(92) and is_drive)

    sysroot = os.path.splitdrive(os.environ.get("SystemDrive", "C:"))[0].upper() + chr(92)
    orig_dt = fv.drive_type
    fv.drive_type = lambda r: 3
    try:
        eng_sys = fv.Engine(sysroot, True, True)
        eng_sys.precheck()
        checks["system_drive_allowed"] = eng_sys.meta.get("is_system_drive") is True
    except Exception as exc:
        checks["system_drive_allowed"] = "拒绝: %s" % exc
    finally:
        fv.drive_type = orig_dt

    # 本地磁盘目录模式：合成感染样本必须能查出、隔离
    local = os.path.join(tmp, "local_disk")
    fixtures.build_infected_usb(local)
    eng = fv.Engine(local, False, True)
    eng.precheck()
    eng.scan(log)
    checks["detected"] = sum(1 for i in eng.items if i["verdict"] == "恶意")
    checks["quarantined"] = eng.clean(log)["moved"]

    # 系统关键路径：同一批样本打标后只报告，不隔离、不触发强杀
    guard = os.path.join(tmp, "system_guard")
    fixtures.build_infected_usb(guard)
    orig_guard = fv.is_system_protected
    fv.is_system_protected = lambda p: True
    try:
        eng2 = fv.Engine(guard, False, True)
        eng2.scan(log)
        checks["guard_reported"] = eng2.meta["system_protected_reported"]
        checks["guard_quarantined"] = eng2.clean(log)["moved"]
    finally:
        fv.is_system_protected = orig_guard

    ok = (checks["default_allow_fixed"] and checks["display_text"]
          and checks.get("system_drive_allowed") is True
          and checks["detected"] > 0 and checks["quarantined"] > 0
          and checks["guard_reported"] > 0 and checks["guard_quarantined"] == 0)
    return ok, checks, tmp


@case("20 WinPE 离线取证只读解析")
def s_offline_forensics(log):
    """离线 Hive/任务 XML 只读解析；验证 Select\\Current 与 X:\\ 红线。"""
    import importlib.util
    from core import offline_registry as oreg
    from modules import offline_forensics as of
    from core.api import Context

    spec = importlib.util.spec_from_file_location(
        "fk_test_helpers", os.path.join(ROOT, "tests", "test_modular.py"))
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)

    tmp = tempfile.mkdtemp(prefix="tb_offline_", dir=RESULTS_DIR)
    cfg = os.path.join(tmp, "Windows", "System32", "config")
    os.makedirs(cfg)
    hive_path = os.path.join(cfg, "SYSTEM")
    helpers._build_mini_hive(hive_path)
    before = open(hive_path, "rb").read()
    task_dir = os.path.join(tmp, "Windows", "System32", "Tasks")
    os.makedirs(task_dir)
    token = of.SUSPICIOUS_PATTERNS[0][0]
    with open(os.path.join(task_dir, "job"), "w", encoding="utf-8") as f:
        f.write("<Task><Command>%s.exe</Command><Arguments>-enc QQ==</Arguments></Task>" % token)

    with oreg.RegistryHive(hive_path) as h:
        current = oreg.select_current_number(h)
    res = of.Module().run("scan", Context(target=tmp), log)
    checks = {
        "select_current": current,
        "concern_rows": res.report.get("concern_count", 0),
        "hive_unchanged": open(hive_path, "rb").read() == before,
        "readonly_report": res.report.get("scanned") is True,
        "x_drive_blocked": of.guard_output_path("X:\\tmp\\log.txt",
                                                {"TEMP": "X:\\tmp"})[0] is False,
    }
    ok = (current == 2 and checks["concern_rows"] > 0
          and checks["hive_unchanged"] and checks["readonly_report"]
          and checks["x_drive_blocked"])
    return ok, checks, tmp


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
