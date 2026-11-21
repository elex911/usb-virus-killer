# -*- coding: utf-8 -*-
"""
U 盘文件夹病毒查杀模块
----------------------
判定原则（避免误杀）：
  高置信 = 同目录存在「被隐藏的同名原文件」+ 同名 .lnk 伪装 —— 该类病毒的确证特征。
  中置信 = .lnk 内容含 wscript/cmd/.vbs 等可疑串 且 快捷方式自身被隐藏。
  仅中置信的项默认只报告、不隔离；只有高置信项与 autorun.inf 会被隔离。
所有删除动作改为「移入隔离区」（保留相对路径），可一键回滚，绝不直接删除。
"""
import ctypes
import glob
import json
import os
import re
import shutil
from datetime import datetime

from core.api import Action, ActionResult, Context, ModuleBase
from core.widgets import ResultTable

FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_DIRECTORY = 0x10
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

DRIVE_TYPES = {
    0: "未知", 1: "无根目录", 2: "可移动磁盘(U盘)",
    3: "本地固定磁盘", 4: "网络驱动器", 5: "光驱", 6: "内存盘",
}

try:
    k32 = ctypes.windll.kernel32
    k32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    k32.GetFileAttributesW.restype = ctypes.c_uint32
    k32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    k32.SetFileAttributesW.restype = ctypes.c_bool
    k32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    k32.GetDriveTypeW.restype = ctypes.c_uint
except Exception:
    k32 = None

SUSPECT_TOKENS = [
    "wscript.exe", "cscript.exe", "cmd.exe", "powershell.exe",
    "rundll32.exe", "mshta.exe", "regsvr32.exe",
    ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".hta", ".scr", ".pif",
    "autorun", "windows\\system32", "recycled",
]
VIRUS_NAME_RE = re.compile(
    r"^(autorun|desktop|folder|新文件夹|回收站|recycled|thumbs|system|windows|update|run|start|open|readme|说明|文件夹)",
    re.I,
)
SCRIPT_EXTS = (".vbs", ".vbe", ".js", ".jse", ".hta", ".scr", ".pif", ".bat", ".cmd")


def get_attr(path):
    if k32 is None:
        return None
    a = k32.GetFileAttributesW(str(path))
    return None if a == INVALID_FILE_ATTRIBUTES else a


def set_attr(path, attrs):
    if k32 is None:
        return False
    return bool(k32.SetFileAttributesW(str(path), attrs))


def clear_hidden_system(path):
    a = get_attr(path)
    if a is None:
        return False, "属性读取失败"
    new = a & ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
    if new == a:
        return True, "无需修改"
    return set_attr(path, new), "已解除"


def drive_type(root):
    if k32 is None:
        return -1
    return int(k32.GetDriveTypeW(root.rstrip("\\") + "\\"))


def list_drives():
    out = []
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = c + ":\\"
        if os.path.exists(root):
            t = drive_type(root)
            if t in (2, 3):
                out.append("%s:  [%s]" % (c, DRIVE_TYPES.get(t, t)))
    return out


def norm_target(s):
    s = (s or "").strip().strip('"')
    if not s:
        return None, False
    # 兼容下拉框里的 "E:  [可移动磁盘(U盘)]" 这种展示文本
    m = re.match(r"^([A-Za-z]:)\s+\[", s)
    if m:
        s = m.group(1)
    if re.fullmatch(r"[A-Za-z]:", s):
        return s.upper() + "\\", True
    if re.fullmatch(r"[A-Za-z]:\\", s):
        return s.upper(), True
    return os.path.normpath(s), False


def lnk_target_and_suspect(path):
    """从 .lnk 二进制中提取目标并判定可疑，不依赖 COM/pywin32。"""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception:
        return "", False
    t16 = raw.decode("utf-16-le", errors="ignore")
    t8 = raw.decode("latin-1", errors="ignore")
    combined = (t16 + "\n" + t8).lower()
    paths = re.findall(r"[a-z]:\\[^\x00-\x1f]{1,180}", t16)
    target = paths[0] if paths else ""
    suspect = any(tok in combined for tok in SUSPECT_TOKENS)
    return target, suspect


class Engine:
    """查杀引擎：与原版判定/隔离/回滚口径一致。"""

    def __init__(self, root, is_drive, allow_fixed=False):
        self.root = root
        self.is_drive = is_drive
        self.allow_fixed = allow_fixed
        self.items = []
        self.hidden_items = []
        self.meta = {}

    def precheck(self):
        if not os.path.isdir(self.root):
            raise RuntimeError("目标不存在或不是文件夹：" + self.root)
        if self.is_drive:
            dt = drive_type(self.root)
            self.meta["drive_type"] = DRIVE_TYPES.get(dt, str(dt))
            sysdrive = os.path.splitdrive(os.environ.get("SystemDrive", "C:"))[0].upper() + "\\"
            if self.root.upper() == sysdrive.upper():
                raise RuntimeError("安全拦截：目标是系统盘 " + self.root + "，拒绝处理。")
            if dt not in (2, 3):
                raise RuntimeError(
                    "安全拦截：目标类型「%s」不支持（仅可移动盘/本地盘）。" % DRIVE_TYPES.get(dt, dt)
                )
            if dt == 3 and not self.allow_fixed:
                raise RuntimeError(
                    "安全拦截：%s 被识别为本地固定磁盘。\n若确为移动硬盘，请勾选「允许固定磁盘」后重试。" % self.root
                )
        else:
            self.meta["drive_type"] = "目录(高级模式)"
            self.meta["warning"] = "目录模式：请确认路径无误，本模式绕过盘符类型校验。"

    def scan(self, log):
        log("开始枚举文件（只读）…")
        all_items = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            for d in dirnames:
                try:
                    all_items.append(os.path.join(dirpath, d))
                except Exception:
                    pass
            for fn in filenames:
                try:
                    all_items.append(os.path.join(dirpath, fn))
                except Exception:
                    pass
        log("共枚举 %d 个对象。" % len(all_items))

        hidden = []
        for p in all_items:
            a = get_attr(p)
            if a is not None and (a & FILE_ATTRIBUTE_HIDDEN) and (a & FILE_ATTRIBUTE_SYSTEM):
                hidden.append(p)
        self.hidden_items = hidden
        log("发现隐藏+系统属性对象 %d 个（疑似被藏的原文件）。" % len(hidden))
        hidden_set = set(os.path.normcase(os.path.abspath(p)) for p in hidden)

        lnks = [p for p in all_items if p.lower().endswith(".lnk") and not os.path.isdir(p)]
        log("发现 .lnk 快捷方式 %d 个，开始逐个解析…" % len(lnks))
        referenced = set()
        for p in lnks:
            name = os.path.basename(p)
            stem = name[:-4] if name.lower().endswith(".lnk") else name
            parent = os.path.dirname(p)
            origins = [os.path.join(parent, stem)] + glob.glob(os.path.join(parent, stem + ".*"))
            has_hidden_origin = any(
                os.path.normcase(os.path.abspath(o)) in hidden_set for o in origins
            )
            target, suspect_content = lnk_target_and_suspect(p)
            own_attr = get_attr(p) or 0
            own_hidden = bool(own_attr & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))

            if has_hidden_origin:
                verdict, reason = "恶意", "同名原文件被隐藏 + .lnk 伪装（确证特征）"
            elif suspect_content and own_hidden:
                verdict, reason = "恶意", "快捷方式内容可疑且自身被隐藏"
            elif suspect_content:
                verdict, reason = "可疑", "内容含可疑特征（默认不隔离）"
            else:
                verdict, reason = "正常", "未发现可疑特征"

            self.items.append({
                "kind": "快捷方式", "verdict": verdict, "path": p,
                "detail": ("目标: %s" % target) if target else "无目标信息", "reason": reason,
            })
            if verdict == "恶意":
                referenced.add(target.lower())

        for p in all_items:
            if os.path.basename(p).lower() == "autorun.inf" and not os.path.isdir(p):
                self.items.append({
                    "kind": "autorun.inf", "verdict": "恶意", "path": p,
                    "detail": "自动运行脚本", "reason": "U 盘病毒典型自启动文件",
                })

        scripts = []
        for p in all_items:
            low = p.lower()
            if os.path.isdir(p) or not low.endswith(SCRIPT_EXTS):
                continue
            rel = os.path.relpath(p, self.root)
            depth = len(rel.split(os.sep))
            a = get_attr(p) or 0
            hidden_self = bool(a & FILE_ATTRIBUTE_HIDDEN)
            virus_name = bool(VIRUS_NAME_RE.match(os.path.basename(p)))
            referenced_here = any(r and r in p.lower() for r in referenced)
            if depth <= 2 and (hidden_self or virus_name or referenced_here):
                scripts.append(p)
        for p in scripts:
            self.items.append({
                "kind": "可疑脚本", "verdict": "可疑", "path": p,
                "detail": os.path.basename(p), "reason": "浅层目录的可疑脚本（默认不隔离）",
            })

        mal = sum(1 for i in self.items if i["verdict"] == "恶意")
        sus = sum(1 for i in self.items if i["verdict"] == "可疑")
        ok = sum(1 for i in self.items if i["verdict"] == "正常")
        log("扫描完成：恶意 %d / 可疑 %d / 正常 %d；隐藏原文件 %d。" % (mal, sus, ok, len(hidden)))
        stats = {"malicious": mal, "suspicious": sus, "normal": ok, "hidden": len(hidden)}
        self.meta["stats"] = stats
        return stats

    def clean(self, log, do_restore_attrs=True):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        qdir = os.path.join(self.root, "__WORM_QUARANTINE_" + stamp)
        os.makedirs(qdir, exist_ok=True)
        targets = [i for i in self.items if i["verdict"] == "恶意"]
        manifest = {"time": datetime.now().isoformat(), "root": self.root, "items": []}

        moved = 0
        for it in targets:
            p = it["path"]
            if not os.path.exists(p):
                continue
            rel = os.path.relpath(p, self.root)
            dest = os.path.join(qdir, rel)
            try:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.move(p, dest)
                manifest["items"].append({"action": "quarantine", "rel": rel})
                moved += 1
            except Exception as e:
                log("隔离失败 %s : %s" % (p, e))
        log("已隔离 %d 项 → %s" % (moved, qdir))

        restored = 0
        if do_restore_attrs:
            for p in self.hidden_items:
                if not os.path.exists(p):
                    continue
                if os.path.normcase(os.path.abspath(p)).startswith(os.path.normcase(os.path.abspath(qdir))):
                    continue
                ok, msg = clear_hidden_system(p)
                if ok and msg == "已解除":
                    restored += 1
                    manifest["items"].append({"action": "unhide", "rel": os.path.relpath(p, self.root)})
        log("已解除隐藏属性 %d 项。" % restored)

        with open(os.path.join(qdir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        with open(os.path.join(qdir, "README_回滚说明.txt"), "w", encoding="utf-8") as f:
            f.write("隔离时间: %s\n目标位置: %s\n\n" % (manifest["time"], self.root))
            f.write("本目录保存被隔离的病毒伪装文件，按原相对路径存放。\n")
            f.write("回滚：在软件中点击「回滚」并选择本目录，或运行：\n")
            f.write("  python FolderVirusKiller.py --restore \"%s\"\n\n" % qdir)
            f.write("确认无误后再删除本目录。不要双击目录内的快捷方式。\n")
        return {"moved": moved, "restored": restored, "quarantine": qdir}

    @staticmethod
    def restore(qdir, log):
        mf = os.path.join(qdir, "manifest.json")
        if not os.path.isfile(mf):
            raise RuntimeError("未找到 manifest.json，无法回滚：" + qdir)
        with open(mf, encoding="utf-8") as f:
            manifest = json.load(f)
        root = manifest.get("root") or os.path.dirname(os.path.dirname(qdir))
        okc = fail = 0
        for it in manifest.get("items", []):
            if it.get("action") != "quarantine":
                continue
            rel = it["rel"]
            src = os.path.join(qdir, rel)
            dst = os.path.join(root, rel)
            if not os.path.exists(src):
                fail += 1
                continue
            try:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.move(src, dst)
                okc += 1
            except Exception as e:
                log("回滚失败 %s : %s" % (rel, e))
                fail += 1
        log("回滚完成：成功 %d，失败 %d。" % (okc, fail))
        return okc, fail

    @staticmethod
    def immunize(root, log):
        p = os.path.join(root, "autorun.inf")
        if os.path.exists(p):
            raise RuntimeError("已存在 autorun.inf，请先清理后再免疫。")
        os.mkdir(p)
        with open(os.path.join(p, "此文件夹用于免疫U盘病毒.txt"), "w", encoding="utf-8") as f:
            f.write("此文件夹名为 autorun.inf，用于阻止病毒创建同名自动运行文件。\n请勿删除。\n")
        set_attr(p, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY)
        log("已创建 autorun.inf 免疫目录。")
        return p


class Module(ModuleBase):
    meta = {
        "id": "folder_virus",
        "name": "U盘文件查杀",
        "version": "2.0",
        "description": "隐藏原文件 + .lnk 伪装 + autorun.inf；隔离可回滚。",
        "order": 10,
    }

    def __init__(self):
        self.engine = None

    def actions(self):
        return [
            Action("scan", "扫描", target_mode="required", order=10),
            Action("clean", "查杀（隔离+恢复）",
                   confirm="查杀会把识别为恶意的项移入隔离区，并解除原文件隐藏属性。\n"
                           "不会直接删除任何文件，可回滚。\n\n继续？",
                   target_mode="required", danger=True, order=20),
            Action("immunize", "免疫",
                   confirm="将在目标根目录创建名为 autorun.inf 的只读文件夹以阻止病毒自启动。\n继续？",
                   target_mode="required", danger=True, order=30),
            Action("restore", "回滚",
                   confirm="将把所选隔离目录内的隔离项移回原路径，继续？",
                   target_mode="none", prompt="directory",
                   prompt_title="选择隔离目录（__WORM_QUARANTINE_...）", order=40),
        ]

    def prepare_context(self, ctx, raw_target, allow_fixed=False):
        path, is_drive = norm_target(raw_target)
        if not path:
            return False
        ctx.target = path
        ctx.is_drive = is_drive
        ctx.allow_fixed = bool(allow_fixed)
        return True

    def suggest_targets(self):
        return list_drives()

    def target_hint(self, count):
        return "共 %d 个可处理盘符。" % count

    def build_view(self, parent, ctx):
        return ResultTable(
            parent,
            columns=[("kind", "类别", 90), ("verdict", "判定", 70),
                     ("path", "路径", 460), ("detail", "说明", 250)],
            tag_key="verdict",
            tag_map={"恶意": "#c0392b", "可疑": "#b8860b", "正常": "#444"},
            on_detail=self.detail,
        )

    def render(self, action_id, result, view, ctx):
        view.set_rows(result.data.get("rows", []))

    def detail(self, row):
        return (
            "类别：%s\n判定：%s\n\n路径：%s\n\n说明：%s\n\n依据：%s"
            % (row.get("kind", ""), row.get("verdict", ""), row.get("path", ""),
               row.get("detail", ""), row.get("reason", ""))
        )

    def _new_engine(self, ctx):
        eng = Engine(ctx.target, ctx.is_drive, ctx.allow_fixed)
        eng.precheck()
        self.engine = eng
        return eng

    def _base_report(self, eng):
        return {
            "root": eng.root,
            "meta": dict(eng.meta),
            "items": list(eng.items),
            "hidden_items": list(eng.hidden_items),
        }

    def run(self, action_id, ctx, log):
        if action_id == "restore":
            qdir = ctx.pick
            if not qdir:
                return ActionResult(ok=False, message="未选择隔离目录，已取消。", show_dialog=False)
            ok, fail = Engine.restore(qdir, log)
            return ActionResult(
                action=action_id,
                message="回滚完成：成功 %d 项，失败 %d 项。" % (ok, fail),
                title="回滚完成", show_dialog=True,
                report={"ok": ok, "fail": fail, "quarantine": qdir},
            )

        eng = self._new_engine(ctx)

        if action_id == "immunize":
            path = Engine.immunize(ctx.target, log)
            return ActionResult(
                action=action_id,
                message="已创建免疫目录：" + path,
                title="免疫完成", show_dialog=True,
                report={"immunize_dir": path},
            )

        stats = eng.scan(log)
        report = self._base_report(eng)
        report["stats"] = stats

        if action_id == "scan":
            return ActionResult(
                action=action_id,
                data={"rows": list(eng.items)},
                report=report,
                show_dialog=False,
            )

        if action_id == "clean":
            if not any(i["verdict"] == "恶意" for i in eng.items):
                log("未发现恶意项，无需查杀。")
                return ActionResult(
                    action=action_id,
                    message="未发现恶意项，无需查杀。",
                    title="查杀结果", show_dialog=True,
                    data={"rows": list(eng.items)},
                    report=report,
                )
            result = eng.clean(log)
            report.update(result)
            return ActionResult(
                action=action_id,
                message="已隔离 %d 项，解除隐藏 %d 项。\n隔离区：%s\n\n请再用杀毒软件全盘扫描主机。"
                        % (result["moved"], result["restored"], result["quarantine"]),
                title="查杀完成", show_dialog=True,
                data={"rows": list(eng.items)},
                report=report,
            )

        raise RuntimeError("模块 %s 不支持操作：%s" % (self.meta["id"], action_id))
