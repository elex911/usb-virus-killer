# -*- coding: utf-8 -*-
"""
离线取证模块（WinPE / 离线目标盘，只读）
----------------------------------------
目标：在 WinPE（或正常 Windows 下挂载的离线盘）排查持久化点，不依赖目标系统
活体服务（API / COM / WMI / Task Scheduler / CryptSvc）。

红线：
  - 本模块全程只读：不删除、不隔离、不挂载 hive、不改注册表、不改文件属性。
  - 不判"恶意"：只输出"关注/信息"级线索，必须人工复核。
  - 不往 X:\\（WinPE 内存盘）写任何东西；临时/日志/隔离区一律重定向到目标盘
    或外置 U 盘（本模块自身不落盘，仅提供 guard_output_path 供后续模块使用）。
  - 修复（挂载写 hive / 删除持久化点）是后续独立动作，必须先备份，不在本模块。

证据分级：T1=磁盘原始文件/解析结果；T3=启发式规则（明确写进 detail）。
"""
import glob
import os
import re
import struct
import xml.etree.ElementTree as ET

from core.api import Action, ActionResult, ModuleBase
from core import offline_registry as oreg
from core.widgets import ResultTable

CAUTION = (
    "只读取证：不删除、不隔离、不挂载注册表、不修改任何文件。\n"
    "结果为待复核线索，不是恶意判定；无内嵌签名 ≠ 恶意（系统文件可能靠 CatRoot 编录签名）。"
)

# 可注入接缝（测试用；生产走真实文件系统）
_exists = None
_walk = None


def _default_exists(path):
    return os.path.exists(path)


def _default_walk(path):
    for root, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if d.lower() not in ("$recycle.bin", "system volume information")]
        yield root, dirs, files


def _reset_seams():
    global _exists, _walk
    _exists = _default_exists
    _walk = _default_walk


_reset_seams()


# ---------------- 环境识别与盘符映射 ----------------

def detect_environment(environ=None, key_exists=None):
    """复合识别 WinPE：MiniNT 可被伪造，单信号只算"疑似"。"""
    environ = os.environ if environ is None else environ
    if key_exists is None:
        key_exists = _mini_nt_exists
    signals = []
    if key_exists():
        signals.append("MiniNT 键存在")
    sysdrive = str(environ.get("SystemDrive", "") or "").strip().rstrip("\\").upper()
    windir = str(environ.get("windir", "") or "").strip().lower().replace("/", "\\")
    if sysdrive == "X:":
        signals.append("SystemDrive=X:")
    if windir.startswith("x:\\windows"):
        signals.append("windir 指向 X:\\Windows")
    mini = "MiniNT 键存在" in signals
    xsignal = any(s != "MiniNT 键存在" for s in signals)
    if mini and xsignal:
        level = "确认"
    elif signals:
        level = "疑似"
    else:
        level = "否"
    return {"level": level, "is_winpe": level == "确认", "signals": signals}


def _mini_nt_exists():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\MiniNT"):
            return True
    except Exception:
        return False


def find_target_systems(letters=None, exists=None, skip="X:"):
    """通过 \\Windows\\System32\\config\\SYSTEM 定位离线系统盘（支持多系统）。"""
    exists = _exists if exists is None else exists
    letters = letters or [c + ":" for c in "CDEFGHIJKLMNOPQRSTUVWXYZ"]
    found = []
    for drive in letters:
        if drive.upper() == skip.upper():
            continue
        root = drive + "\\"
        hive_path = root + r"Windows\System32\config\SYSTEM"
        kernel_path = root + r"Windows\System32\ntoskrnl.exe"
        has_hive = bool(exists(hive_path))
        has_kernel = bool(exists(kernel_path))
        if has_hive or has_kernel:
            found.append({"drive": drive, "root": root,
                          "has_system_hive": has_hive,
                          "has_kernel": has_kernel,
                          "strength": "强" if has_hive else "弱"})
    return found


def build_path_map(drive):
    """把目标系统里的 C:\\ 等逻辑路径翻译为 PE 下的真实挂载盘符。"""
    d = drive.rstrip("\\")
    return {
        "%SystemDrive%": d,
        "%SystemRoot%": d + "\\Windows",
        "%ProgramData%": d + "\\ProgramData",
        "%ProgramFiles%": d + "\\Program Files",
        "%ProgramFiles(x86)%": d + "\\Program Files (x86)",
        "C:\\Windows": d + "\\Windows",
        "C:\\ProgramData": d + "\\ProgramData",
        "C:\\Program Files": d + "\\Program Files",
        "C:\\Users": d + "\\Users",
    }


def translate_offline_path(value, mapping):
    """大小写不敏感地替换映射键；未命中的原样返回。"""
    text = str(value or "")
    hits = []
    for key in sorted(mapping, key=len, reverse=True):
        pattern = re.compile(re.escape(key), re.IGNORECASE)
        # 用回调替换，避免映射值里的反斜杠被 re 当成转义模板。
        text, n = pattern.subn(lambda _m, v=mapping[key]: v, text)
        if n:
            hits.append(key)
    return text, hits


# ---------------- 计划任务 / 签名（只读） ----------------

SUSPICIOUS_PATTERNS = (
    ("powershell", "PowerShell 执行"),
    ("-enc", "疑似编码命令"),
    ("rundll32", "rundll32 加载"),
    ("mshta", "mshta 执行脚本"),
    ("regsvr32", "regsvr32 注册组件"),
    ("wscript", "脚本宿主执行"),
    ("cscript", "脚本宿主执行"),
    ("frombase64string", "Base64 解码执行"),
)


def classify_value(value, note=""):
    """T3 启发式：返回 (level, detail)。只提示关注，绝不判恶意。"""
    text = str(value or "")
    low = text.lower()
    reasons = [desc for token, desc in SUSPICIOUS_PATTERNS if token in low]
    if "\\temp\\" in low or "appdata\\local\\temp" in low or "\\users\\public\\" in low:
        reasons.append("指向用户可写临时目录")
    if reasons:
        return "关注", "启发式命中：" + "、".join(reasons) + ("；" + note if note else "")
    return "信息", ("仅枚举，未命中启发式规则；" + note if note else "仅枚举，未命中启发式规则")


def scan_task_xml(root, max_files=1000):
    """直接解析 <Target>\\Windows\\System32\\Tasks 的 XML，不调 COM。"""
    task_dir = os.path.join(root, "Windows", "System32", "Tasks")
    rows, errors, count = [], [], 0
    if not _exists(task_dir):
        return rows, ["未找到任务目录：%s（不算异常，可能为空）" % task_dir]
    try:
        for base, _dirs, files in _walk(task_dir):
            for name in files:
                if count >= max_files:
                    errors.append("任务文件超过 %d 个，已截断（未扫描部分不算排除）" % max_files)
                    return rows, errors
                path = os.path.join(base, name)
                try:
                    if os.path.getsize(path) > 2 * 1024 * 1024:
                        continue
                    tree = ET.parse(path)
                    commands, arguments = [], []
                    for elem in tree.iter():
                        tag = elem.tag.split("}")[-1].lower()
                        if tag == "command" and elem.text:
                            commands.append(elem.text.strip())
                        elif tag == "arguments" and elem.text:
                            arguments.append(elem.text.strip())
                    if not commands and not arguments:
                        continue
                    count += 1
                    value = " | ".join(commands + arguments)
                    level, detail = classify_value(value, "来源：计划任务 XML")
                    rows.append({"level": level, "source": "计划任务",
                                 "name": os.path.relpath(path, task_dir),
                                 "value": value[:500], "detail": detail})
                except Exception as exc:
                    errors.append("任务文件解析失败 %s：%s" % (name, str(exc)[:120]))
    except Exception as exc:
        errors.append("任务目录遍历失败：%s" % exc)
    return rows, errors


def pe_has_embedded_signature(path):
    """只读检查 PE 的 IMAGE_DIRECTORY_ENTRY_SECURITY；不验签、不判恶意。"""
    try:
        with open(path, "rb") as f:
            dos = f.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return None
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            f.seek(e_lfanew)
            head = f.read(24)
            if len(head) < 24 or head[:4] != b"PE\x00\x00":
                return None
            opt_size = struct.unpack_from("<H", head, 20)[0]
            opt = f.read(min(opt_size, 512))
            if len(opt) < 112:
                return None
            magic = struct.unpack_from("<H", opt, 0)[0]
            dd = 112 if magic == 0x20B else 96
            if len(opt) < dd + 5 * 8:
                return None
            size = struct.unpack_from("<I", opt, dd + 4 * 8)[0]
            return size > 0
    except Exception:
        return None


def list_catalogs(root, limit=20000):
    """列出目标盘 CatRoot 中的 .cat 数量；不解析内容，不据此判定签名状态。"""
    pattern = os.path.join(root, "Windows", "System32", "CatRoot", "*", "*.cat")
    try:
        return len(glob.glob(pattern)[:limit])
    except Exception:
        return 0


def guard_output_path(path, environ=None):
    """WinPE 内存盘红线：禁止把大文件/日志/隔离区写到 X:\\。"""
    environ = os.environ if environ is None else environ
    p = str(path or "").strip().replace("/", "\\")
    if not p:
        return False, "空路径"
    norm = os.path.normcase(os.path.abspath(p))
    if norm.startswith("x:\\") or p.upper().startswith("X:"):
        return False, "目标位于 X:\\ 内存盘（Scratch Space 有限），必须改到目标盘或外置 U 盘"
    tmp = str(environ.get("TEMP", "") or "").replace("/", "\\")
    if tmp.upper().startswith("X:") and norm.startswith(os.path.normcase(os.path.abspath(tmp))):
        return False, "目标位于 %TEMP%（WinPE 下指向 X:\\），必须重定向"
    return True, "允许"


# ---------------- 模块 ----------------

class Module(ModuleBase):
    meta = {
        "id": "offline_forensics",
        "name": "离线取证查杀",
        "version": "1.0",
        "description": "WinPE/离线盘只读排查持久化点、计划任务与盘符漂移；不依赖目标系统活体服务。",
        "order": 40,
        "tab": "离线取证",
    }

    def actions(self):
        return [
            Action("detect", "环境识别(只读)", target_mode="none",
                   confirm=None, order=10),
            Action("scan", "离线取证扫描(只读)", target_mode="required",
                   prompt="directory",
                   confirm="将以只读方式解析所选目标盘的注册表 Hive、计划任务与 PE 签名目录。\n"
                           "不删除、不隔离、不挂载注册表、不修改任何文件。\n继续？",
                   order=20),
        ]

    def prepare_context(self, ctx, raw_target, allow_fixed=True):
        from . import folder_virus as fv
        path, is_drive = fv.norm_target(raw_target)
        ctx.target = path or (raw_target or "").strip().strip('"')
        ctx.is_drive = bool(is_drive)
        ctx.allow_fixed = bool(allow_fixed)
        return bool(ctx.target)

    def suggest_targets(self):
        # 下拉框契约要求字符串候选；离线盘识别结果走「环境识别」动作展示。
        # 复用统一盘符列表，避免给 GUI 增加重复/异形候选。
        from . import folder_virus as fv
        return fv.list_drives()

    def target_hint(self, count):
        # 主程序只保留一条盘符提示，额外模块提示会引入「；」导致 GUI 烟测失败。
        # 目标盘识别结果改由「环境识别」动作展示。
        return ""

    def build_view(self, parent, ctx):
        return ResultTable(
            parent,
            columns=[("level", "结论", 70), ("source", "来源", 180),
                     ("name", "项目", 200), ("value", "值/命令", 420),
                     ("detail", "判定依据", 320)],
            tag_key="level",
            tag_map={"关注": "#b8860b", "信息": "#666", "高危": "#c0392b"},
            caution=CAUTION,
            on_detail=self.detail,
            height=13,
        )

    def render(self, action_id, result, view, ctx):
        view.set_rows(result.data.get("rows", []))

    def detail(self, row):
        return (
            "结论：%s\n来源：%s\n项目：%s\n\n值：%s\n\n依据：%s\n\n"
            "这是待人工复核的线索，不是恶意判定；本模块未做任何修改。"
            % (row.get("level", ""), row.get("source", ""), row.get("name", ""),
               row.get("value", ""), row.get("detail", ""))
        )

    def report_export(self, result):
        return {"offline_forensics": result.data.get("report", {})}

    def _detect_rows(self):
        env = detect_environment()
        rows = [{"level": "信息", "source": "运行环境",
                 "name": "WinPE 识别", "value": env["level"],
                 "detail": "信号：" + ("、".join(env["signals"]) if env["signals"] else "无")
                           + "；MiniNT 键可被伪造，单信号只算疑似"}]
        targets = find_target_systems()
        if not targets:
            rows.append({"level": "信息", "source": "运行环境", "name": "离线系统盘",
                         "value": "未自动定位", "detail": "请用「选择目录」指定离线 Windows 根目录"})
        for t in targets:
            rows.append({"level": "信息", "source": "运行环境",
                         "name": "离线系统盘 " + t["drive"],
                         "value": t["root"],
                         "detail": "SYSTEM Hive=%s；ntoskrnl=%s；证据强度=%s"
                                   % (t["has_system_hive"], t["has_kernel"], t["strength"])})
        return env, targets, rows

    def run(self, action_id, ctx, log):
        if action_id not in ("detect", "scan"):
            raise RuntimeError("模块 %s 不支持操作：%s" % (self.meta["id"], action_id))
        env, targets, rows = self._detect_rows()

        if action_id == "detect":
            return ActionResult(
                action=action_id, ok=True, title="离线取证 · 环境识别",
                message="WinPE 判定：%s；自动定位目标盘 %d 个。\n注意：MiniNT 单信号可伪造。"
                        % (env["level"], len(targets)),
                show_dialog=True, data={"rows": rows},
                report={"environment": env, "targets": targets, "scanned": False},
            )

        root = ctx.target
        if not root or not _exists(root):
            return ActionResult(action=action_id, ok=False, show_dialog=True,
                                title="离线取证扫描",
                                message="目标不存在：%s" % root,
                                data={"rows": rows},
                                report={"environment": env, "targets": targets,
                                        "error": "target not found"})

        winroot = os.path.join(root, "Windows")
        mapd = build_path_map(os.path.splitdrive(os.path.abspath(root))[0] or "C:")
        errors = []

        hives = {
            "SYSTEM": os.path.join(winroot, "System32", "config", "SYSTEM"),
            "SOFTWARE": os.path.join(winroot, "System32", "config", "SOFTWARE"),
        }
        handles = {}
        for label, path in hives.items():
            if _exists(path):
                try:
                    handles[label] = oreg.RegistryHive(path)
                except Exception as exc:
                    errors.append("%s Hive 只读解析失败：%s" % (label, exc))
            else:
                errors.append("未找到 %s Hive（可能不是完整离线系统）" % label)

        user_hives = []
        users_dir = os.path.join(root, "Users")
        if _exists(users_dir):
            for user in sorted(os.listdir(users_dir))[:20]:
                p = os.path.join(users_dir, user, "NTUSER.DAT")
                if _exists(p):
                    try:
                        user_hives.append(oreg.RegistryHive(p))
                    except Exception as exc:
                        errors.append("用户 %s NTUSER.DAT 解析失败：%s" % (user, exc))

        try:
            p_rows, p_errors = oreg.read_persistence(
                handles.get("SYSTEM"), handles.get("SOFTWARE"), tuple(user_hives))
            errors.extend(p_errors)
            for r in p_rows:
                value, hits = translate_offline_path(r["value"], mapd)
                level, detail = classify_value(value, r["note"] or "离线注册表")
                if hits:
                    detail += "；盘符映射：" + "、".join(hits)
                rows.append({"level": level, "source": r["source"], "name": r["name"],
                             "value": value[:500], "detail": detail})
        except Exception as exc:
            errors.append("持久化点汇总失败：%s" % exc)

        t_rows, t_errors = scan_task_xml(root)
        rows.extend(t_rows)
        errors.extend(t_errors)

        catalogs = list_catalogs(root)
        rows.append({"level": "信息", "source": "签名目录",
                     "name": "CatRoot 编录", "value": "%d 个 .cat" % catalogs,
                     "detail": "仅计数；系统文件可能靠编录签名，无内嵌签名不能判恶意"})
        sample = os.path.join(winroot, "System32", "notepad.exe")
        if _exists(sample):
            embedded = pe_has_embedded_signature(sample)
            rows.append({"level": "信息", "source": "签名目录",
                         "name": "notepad.exe 内嵌签名",
                         "value": "有" if embedded else ("无" if embedded is False else "不可读"),
                         "detail": "只读检查 PE 安全目录；无内嵌签名需查 CatRoot，不能据此判恶意"})

        for h in list(handles.values()) + user_hives:
            try:
                h.close()
            except Exception:
                pass

        for e in errors[:30]:
            rows.append({"level": "信息", "source": "解析提示", "name": "限制",
                         "value": e[:300], "detail": "解析失败不算排除；该文件未被判定"})

        n_concern = sum(1 for r in rows if r["level"] == "关注")
        report = {
            "environment": env, "targets": targets, "scanned": True,
            "target": root, "path_map": mapd,
            "concern_count": n_concern, "row_count": len(rows),
            "catalog_count": catalogs, "errors": errors[:30],
            "caution": CAUTION,
            "limits": ["本模块只读取证，不做删除/隔离/回滚",
                       "离线 hive 反映最后一次落盘状态，不含未落盘的易失键",
                       "不解析 WMI OBJECTS.DATA 结构（仅任务/XML 与注册表/文件层）",
                       "修复需另行授权：先备份 Hive，再挂载写入"],
        }
        return ActionResult(
            action=action_id, ok=True, title="离线取证扫描",
            message=("完成：线索 %d 条（关注 %d），解析提示 %d 条。\n"
                     "全部为只读结果，未修改目标盘任何文件。\n%s")
                    % (len(rows), n_concern, len(errors), CAUTION),
            show_dialog=True, data={"rows": rows, "report": report}, report=report,
        )
