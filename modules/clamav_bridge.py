# -*- coding: utf-8 -*-
"""
ClamAV 外部引擎桥接模块
-----------------------
调用本机已安装的 ClamAV（官方 Windows x64 版）做二次扫描。

红线：
  - 不捆绑 ClamAV 引擎/特征库到本工具，避免把 GPLv2 代码和 200+MB 库塞进单文件 exe。
  - 只调用 clamscan 的扫描能力；绝不使用 --remove / --move 等删除或移动选项。
  - 命中口径为「外部命中」，不等于本工具确认的「恶意」；不隔离、不删除。
  - 特征库更新由用户显式点击「更新ClamAV库」后调用 freshclam，不自动联网。
"""
import glob
import os
import re
import shutil
import struct
import subprocess
from datetime import datetime

from . import folder_virus as fv
from core.api import Action, ActionResult, ModuleBase
from core.widgets import ResultTable

CAUTION = (
    "ClamAV 是本机外部 GPLv2 引擎；命中仅表示其公开特征库匹配，"
    "需人工复核。本模块只报告，不隔离、不删除。"
)

FOUND_RE = re.compile(r"^(.+):\s*(.+?)\s+FOUND$")
MACHINE_MAP = {0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}
TIMEOUT_SCAN = 900
TIMEOUT_UPDATE = 600


def _run_process(cmd, timeout):
    kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "timeout": timeout,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        p = subprocess.run(cmd, **kwargs)
        return (
            p.returncode,
            p.stdout.decode("utf-8", errors="replace"),
            p.stderr.decode("utf-8", errors="replace"),
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
        err = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
        return -99, out, (err + "\n超时：%d 秒" % timeout).strip()
    except Exception as exc:
        return -98, "", str(exc)


def _pe_arch(path):
    try:
        with open(path, "rb") as f:
            head = f.read(0x400)
        if head[:2] != b"MZ":
            return "未知"
        off = struct.unpack_from("<I", head, 0x3C)[0]
        if off + 24 > len(head) or head[off:off + 4] != b"PE\0\0":
            return "未知"
        machine = struct.unpack_from("<H", head, off + 4)[0]
        return MACHINE_MAP.get(machine, "0x%04X" % machine)
    except Exception:
        return "未知"


def _candidate_paths(ctx, exe_name):
    custom = (ctx.settings or {}).get(exe_name[:-4].lower() + "_path")
    if custom and os.path.isfile(custom):
        return [custom]
    found = shutil.which(exe_name) or shutil.which(exe_name[:-4])
    paths = [found] if found else []
    # 候选根目录：标准环境变量位置 + 常见安装盘符根（便携版常装在 D:\ClamAV 等）。
    roots = []
    for env in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "ProgramData"):
        base = os.environ.get(env)
        if base:
            roots.append(os.path.join(base, "ClamAV"))
    if os.name == "nt":
        for drive in ("C:", "D:", "E:"):
            roots.append(os.path.join(drive + os.sep, "ClamAV"))
    for root in roots:
        paths.append(os.path.join(root, exe_name))
        paths.extend(glob.glob(os.path.join(root, "**", exe_name), recursive=True)[:5])
    return [p for p in paths if p and os.path.isfile(p)]


def find_clamscan(ctx):
    return _candidate_paths(ctx, "clamscan.exe")


def find_freshclam(ctx):
    return _candidate_paths(ctx, "freshclam.exe")


def _db_files(exe_path):
    bases = []
    if exe_path:
        bases.append(os.path.join(os.path.dirname(exe_path), "db"))
    for env in ("ProgramData", "LOCALAPPDATA", "APPDATA"):
        base = os.environ.get(env)
        if base:
            bases.append(os.path.join(base, "ClamAV", "db"))
            bases.append(os.path.join(base, ".clamav", "db"))
    names = ("daily.cvd", "daily.cld", "main.cvd", "main.cld", "bytecode.cvd")
    files = []
    for base in bases:
        for name in names:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                files.append(p)
    return sorted(set(files))


def _version(exe_path):
    rc, out, err = _run_process([exe_path, "--version"], 30)
    text = (out or err or "").strip().splitlines()
    return text[0].strip() if text else "(未取得)"


def parse_found(output):
    rows = []
    seen = set()
    for line in (output or "").splitlines():
        m = FOUND_RE.match(line.strip())
        if not m:
            continue
        path, sig = m.group(1).strip(), m.group(2).strip()
        key = (path, sig)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"path": path, "signature": sig})
    return rows


DB_LINE_RE = re.compile(
    r"([a-z0-9_.]+\.c[vd]l?d?)\s+(?:database\s+)?(updated|is up-to-date)",
    re.I,
)
DB_VERSION_RE = re.compile(r"version:\s*(\d+)", re.I)
ERROR_LINE_RE = re.compile(r"^(error|warning)\b|failed|can't|cannot", re.I)


def summarize_freshclam(rc, text):
    """把 freshclam 英文输出压成中文结论；失败时保留原始末段便于排查。"""
    updated, current, errors = [], [], []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = DB_LINE_RE.search(line)
        if m:
            name = m.group(1).lower()
            state = m.group(2).lower()
            ver = DB_VERSION_RE.search(line)
            ver = ver.group(1) if ver else ""
            item = "%s %s" % (name, ver) if ver else name
            (updated if state == "updated" else current).append(item)
            continue
        if ERROR_LINE_RE.search(line):
            errors.append(line)

    if rc == 0:
        if updated:
            head = "特征库已更新：%s。" % "、".join(updated)
        else:
            head = "特征库已是最新，无需更新。"
        if current:
            head += "\n当前版本：%s。" % "、".join(current)
        if errors:
            head += "\n提示：%s" % errors[-1][:200]
        return head

    reason = errors[-1] if errors else "（无错误行输出）"
    tail = (text or "").strip()
    msg = "特征库更新失败（返回码 %d）。\n原因：%s" % (rc, reason[:300])
    if tail:
        msg += "\n\n原始输出末段：\n%s" % tail[-1200:]
    return msg


class Module(ModuleBase):
    meta = {
        "id": "clamav_bridge",
        "name": "ClamAV外部引擎",
        "version": "1.0",
        "description": "调用本机 ClamAV x64 官方引擎做只读二次扫描；不捆绑引擎与病毒库。",
        "order": 40,
    }

    def actions(self):
        return [
            Action("check", "检查引擎", target_mode="none", order=10),
            Action("update", "更新ClamAV库",
                   confirm="将调用本机 freshclam.exe 联网更新 ClamAV 官方特征库。\n"
                           "只更新 ClamAV 自己的库，不修改本工具文件。\n继续？",
                   target_mode="none", order=20),
            Action("scan", "ClamAV扫描(只读)",
                   confirm="将调用本机 ClamAV 扫描目标，只输出报告。\n"
                           "不会删除、移动或隔离任何文件。\n继续？",
                   target_mode="required", order=30),
        ]

    def prepare_context(self, ctx, raw_target, allow_fixed=False):
        path, is_drive = fv.norm_target(raw_target)
        if not path:
            return False
        ctx.target = path
        ctx.is_drive = is_drive
        ctx.allow_fixed = bool(allow_fixed)
        return True

    def suggest_targets(self):
        return fv.list_drives()

    def target_hint(self, count):
        return "共 %d 个可处理盘符。" % count

    def build_view(self, parent, ctx):
        return ResultTable(
            parent,
            columns=[("id", "来源", 100), ("type", "类型", 110),
                     ("level", "结论", 90), ("path", "路径", 440),
                     ("value", "签名/说明", 240)],
            tag_key="level",
            tag_map={"外部命中": "#b8860b", "信息": "#666", "错误": "#c0392b"},
            caution=CAUTION,
            on_detail=self.detail,
            height=11,
        )

    def render(self, action_id, result, view, ctx):
        view.set_rows(result.data.get("rows", []))

    def detail(self, row):
        return (
            "来源：%s\n类型：%s\n结论：%s\n\n路径：%s\n签名/说明：%s\n\n"
            "本项为外部引擎输出，需人工复核；本工具未做任何修改。"
            % (row.get("id", ""), row.get("type", ""), row.get("level", ""),
               row.get("path", ""), row.get("value", ""))
        )

    def run(self, action_id, ctx, log):
        scans = find_clamscan(ctx)
        exe = scans[0] if scans else ""
        fresh = find_freshclam(ctx)
        fresh_exe = fresh[0] if fresh else ""

        if action_id == "check":
            rows = [{
                "id": "clamav", "type": "engine", "level": "信息",
                "path": exe or "(未找到 clamscan.exe)",
                "value": _version(exe) if exe else "请安装官方 Windows x64 版",
            }, {
                "id": "clamav", "type": "arch", "level": "信息",
                "path": exe or "-", "value": _pe_arch(exe) if exe else "-",
            }, {
                "id": "clamav", "type": "freshclam", "level": "信息",
                "path": fresh_exe or "(未找到 freshclam.exe)",
                "value": "用于更新官方特征库",
            }]
            dbs = _db_files(exe)
            rows.append({
                "id": "clamav", "type": "signature_db", "level": "信息",
                "path": exe or "-",
                "value": ("%d 个库文件：%s" % (len(dbs), ", ".join(os.path.basename(x) for x in dbs)))
                         if dbs else "未找到 daily.cvd/main.cvd",
            })
            msg = (
                "clamscan：%s\n版本：%s\n架构：%s\nfreshclam：%s\n特征库文件：%d 个\n\n"
                "官方 Windows x64 安装包约 214 MB，从 clamav.net/downloads 获取；GPLv2。"
                % (exe or "未找到", _version(exe) if exe else "-",
                   _pe_arch(exe) if exe else "-", fresh_exe or "未找到", len(dbs))
            )
            return ActionResult(
                action=action_id, ok=bool(exe), message=msg, title="ClamAV 引擎检查",
                show_dialog=bool(exe), data={"rows": rows},
                report={"clamscan": exe, "freshclam": fresh_exe,
                        "version": _version(exe) if exe else "",
                        "arch": _pe_arch(exe) if exe else "", "db_files": dbs},
            )

        if action_id == "update":
            if not fresh_exe:
                return ActionResult(
                    action=action_id, ok=False,
                    message="未找到 freshclam.exe，无法更新特征库。",
                    show_dialog=False,
                )
            log("调用 freshclam 联网更新 ClamAV 特征库…")
            rc, out, err = _run_process([fresh_exe], TIMEOUT_UPDATE)
            text = ((out or "") + "\n" + (err or "")).strip()
            ok = rc == 0
            msg = summarize_freshclam(rc, text)
            return ActionResult(
                action=action_id, ok=ok, message=msg, title="更新ClamAV库",
                show_dialog=True, report={"freshclam": fresh_exe, "returncode": rc,
                                           "output_tail": text[-4000:]},
            )

        if action_id == "scan":
            if not exe:
                return ActionResult(
                    action=action_id, ok=False,
                    message="未找到 clamscan.exe。请安装 ClamAV 官方 Windows x64 版，"
                            "或在模块设置中指定 clamscan_path。",
                    show_dialog=False,
                )
            # ClamAV 是只读外部引擎，clamscan 原生支持单文件与目录。
            # 不套用 U 盘查杀的 Engine.precheck()（那是文件夹/盘符专用门禁）。
            if not os.path.exists(ctx.target):
                return ActionResult(
                    action=action_id, ok=False,
                    message="扫描目标不存在：" + str(ctx.target),
                    show_dialog=False,
                )

            version = _version(exe)
            arch = _pe_arch(exe)
            log_file = os.path.join(ctx.app_dir or os.getcwd(), "clamav_last_scan.log")
            # clamscan --log 为追加写：残留旧结果会污染本次命中统计，先清空
            try:
                if os.path.isfile(log_file):
                    os.remove(log_file)
            except Exception as exc:
                log("清理旧扫描日志失败：%s" % exc)
            cmd = [exe, "--recursive", "--log=" + log_file, ctx.target]
            log("调用外部引擎扫描：%s" % exe)
            rc, out, err = _run_process(cmd, TIMEOUT_SCAN)

            log_text = ""
            if os.path.isfile(log_file):
                try:
                    with open(log_file, encoding="utf-8", errors="replace") as f:
                        log_text = f.read()
                except Exception as exc:
                    log("读取 ClamAV 日志失败：%s" % exc)
            combined = (out or "") + "\n" + log_text
            found = parse_found(combined)
            m = re.search(r"Infected files:\s*(\d+)", combined)
            summary_infected = int(m.group(1)) if m else len(found)

            rows = [{
                "id": "clamav", "type": "external_signature",
                "level": "外部命中", "path": item["path"], "value": item["signature"],
            } for item in found]
            rows.append({
                "id": "clamav", "type": "summary", "level": "信息",
                "path": "(汇总)",
                "value": "外部引擎报告感染 %s 项；返回码 %d；日志 %s"
                         % (summary_infected, rc, log_file),
            })

            if rc not in (0, 1) and not found:
                tail = ((out or "") + "\n" + (err or "")).strip()[-1200:]
                return ActionResult(
                    action=action_id, ok=False,
                    message="ClamAV 扫描异常（返回码 %d）：\n%s" % (rc, tail or "无输出"),
                    show_dialog=False, data={"rows": rows},
                    report={"returncode": rc, "log_file": log_file},
                )

            msg = (
                "ClamAV 外部扫描完成：感染报告 %s 项，返回码 %d。\n"
                "引擎：%s（%s）\n日志：%s\n\n"
                "命中需人工复核；本工具未隔离、未删除任何文件。"
                % (summary_infected, rc, version, arch, log_file)
            )
            return ActionResult(
                action=action_id, ok=True, message=msg, title="ClamAV 扫描",
                show_dialog=True, data={"rows": rows},
                report={
                    "clamscan": exe, "version": version, "arch": arch,
                    "target": ctx.target, "returncode": rc,
                    "log_file": log_file,
                    "infected": len(found),
                    "summary_infected": summary_infected,
                    "matches": found,
                    "output_tail": combined[-4000:],
                    "caution": CAUTION,
                },
            )

        raise RuntimeError("模块 %s 不支持操作：%s" % (self.meta["id"], action_id))
