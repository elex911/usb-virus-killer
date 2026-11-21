# -*- coding: utf-8 -*-
"""
AMSI 脚本扫描模块（只读）
--------------------------
借鉴火绒 6.0「AMSI 高级扫描」的思路：Windows 10+ 自带反恶意软件扫描接口
(Antimalware Scan Interface, amsi.dll)，已安装的杀毒软件（如 Defender）会
注册 AMSI provider 对脚本内容做评估。本模块把目标目录下的脚本文件内容
逐个交给 AMSI 评估，把 provider 的判定结果带回界面。

边界与红线（T3 来源为厂商公开文档，机制描述有官方文档交叉印证）：
  - 只读：不删除、不隔离、不修改任何文件；判定结果仅供人工复核。
  - 依赖 provider：AMSI 本身只是通道，判定来自已注册的 provider；
    本机若只有 Defender 则由 Defender 判定；0 检出 ≠ 无威胁。
  - 优雅降级：Win7/Server 2008 或 amsi.dll 缺失/初始化失败时，
    本模块输出「信息」级说明并跳过，不报错、不中断。
  - 判定分级：result=1（AMSI_RESULT_DETECTED）→ 高危；
    1600<=result（AMSI_RESULT 渐进区间）→ 关注；其余 → 信息。
"""
import ctypes
import os

from core.api import Action, ActionResult, ModuleBase
from core.widgets import ResultTable

try:
    import winreg  # noqa: F401  仅用于确认 Windows 环境
    _IS_WINDOWS = True
except ImportError:
    _IS_WINDOWS = False

SCRIPT_EXTS = (".ps1", ".psm1", ".psd1", ".bat", ".cmd",
               ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta")
MAX_FILE_BYTES = 2 * 1024 * 1024          # 脚本文件通常很小，2MB 足够
SCAN_CHARDIR_SKIP = "__WORM_QUARANTINE_"

AMSI_DETECTED = 1                          # AMSI_RESULT_DETECTED
AMSI_SUSPICIOUS_MIN = 1600                 # 官方渐进可疑区间下界

CAUTION = (
    "AMSI 检出表示「本机已注册的杀软 provider 判定恶意」，仍需人工复核；"
    "0 检出 ≠ 无威胁（provider 缺失或绕过都可能漏报）。只读，不删除。"
)

# ---- 可注入接缝（测试用；生产直接走 amsi.dll / 文件系统） ----
_load_amsi = None          # () -> (dll, ctx_handle, session) or None
_amsi_scan = None          # (api, data_bytes, content_name) -> (hr, result)
_script_files = None       # (root) -> [paths]


def _default_load_amsi():
    if not _IS_WINDOWS:
        return None
    try:
        dll = ctypes.WinDLL("amsi")
    except OSError:
        return None
    try:
        handle = ctypes.c_void_p()
        hr = dll.AmsiInitialize("usb-virus-killer", ctypes.byref(handle))
        if hr != 0 or not handle.value:
            return None
        session = ctypes.c_void_p()
        hr = dll.AmsiOpenSession(handle, ctypes.byref(session))
        if hr != 0 or not session.value:
            dll.AmsiUninitialize(handle)
            return None
        return (dll, handle, session)
    except Exception:
        return None


def _default_amsi_scan(api, data, content_name):
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    result = ctypes.c_uint(0)
    hr = api[0].AmsiScanBuffer(
        api[1], buf, ctypes.c_uint(len(data)), content_name,
        api[2], ctypes.byref(result),
    )
    return hr, result.value


def _default_script_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if SCAN_CHARDIR_SKIP not in d]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in SCRIPT_EXTS:
                p = os.path.join(dirpath, fn)
                if SCAN_CHARDIR_SKIP not in p:
                    out.append(p)
    return out


def _reset_seams():
    global _load_amsi, _amsi_scan, _script_files
    _load_amsi = _default_load_amsi
    _amsi_scan = _default_amsi_scan
    _script_files = _default_script_files


_reset_seams()


def _verdict(result):
    if result == AMSI_DETECTED:
        return "高危", "AMSI provider 判定为恶意（AMSI_RESULT_DETECTED）"
    if AMSI_SUSPICIOUS_MIN <= result <= 32767:
        return "关注", "AMSI provider 给出渐进可疑评分 %d（待人工复核）" % result
    return "信息", "AMSI provider 未判定恶意（评分 %d）" % result


class Module(ModuleBase):
    meta = {
        "id": "amsi_scan",
        "name": "AMSI 脚本扫描",
        "version": "1.0",
        "description": "Win10+ 把脚本内容交给系统 AMSI provider 评估；只读不删除。",
        "order": 35,
        "tab": "AMSI 脚本扫描",
    }

    def actions(self):
        return [
            Action("scan", "AMSI 扫描(只读)", target_mode="required",
                   confirm="将读取目标目录下脚本文件（ps1/bat/cmd/js/vbs/wsf/hta 等）的内容，\n"
                           "交给本机已注册的 AMSI provider（通常是 Defender）评估。\n"
                           "只读，不删除、不隔离；检出项需人工复核。\n继续？",
                   order=10),
        ]

    def prepare_context(self, ctx, raw_target, allow_fixed=False):
        path = (raw_target or "").strip().strip('"')
        if not path:
            return False
        ctx.target = path
        ctx.is_drive = len(path) == 2 and path[1] == ":"
        ctx.allow_fixed = bool(allow_fixed)
        return True

    def suggest_targets(self):
        from . import folder_virus as fv
        return fv.list_drives()

    def target_hint(self, count):
        return "共 %d 个可处理盘符。" % count

    def build_view(self, parent, ctx):
        return ResultTable(
            parent,
            columns=[("level", "结论", 70), ("path", "脚本文件", 430),
                     ("value", "评分/说明", 300), ("detail", "判定依据", 260)],
            tag_key="level",
            tag_map={"高危": "#c0392b", "关注": "#b8860b", "信息": "#666"},
            caution=CAUTION,
            on_detail=self.detail,
            height=11,
        )

    def render(self, action_id, result, view, ctx):
        view.set_rows(result.data.get("rows", []))

    def detail(self, row):
        return (
            "结论：%s\n脚本文件：%s\n\nAMSI 评分：%s\n判定依据：%s\n\n"
            "检出 = 本机杀软 provider 的判定，不是本工具的独立结论；\n"
            "请人工复核或交由正规杀毒软件处理。本模块未做任何修改。"
            % (row.get("level", ""), row.get("path", ""),
               row.get("value", ""), row.get("detail", ""))
        )

    def run(self, action_id, ctx, log):
        if action_id != "scan":
            raise RuntimeError("模块 %s 不支持操作：%s" % (self.meta["id"], action_id))

        api = None
        try:
            api = _load_amsi()
        except Exception as exc:
            log("AMSI 初始化异常：%s" % exc)
            api = None
        if api is None:
            msg = ("本机不支持 AMSI（需 Windows 10+ 且 amsi.dll 可用；"
                   "安全模式下部分服务不可用也可能导致）。\n本模块跳过，未扫描任何文件。")
            return ActionResult(
                action=action_id, ok=True, message=msg, title="AMSI 脚本扫描",
                show_dialog=True,
                data={"rows": [{"level": "信息", "path": "(AMSI)", "value": "不可用",
                                "detail": msg}]},
                report={"amsi": {"available": False, "scanned": 0, "detected": 0,
                                 "suspicious": 0, "skipped": 0}, "caution": CAUTION},
            )

        root = ctx.target
        if not root or not os.path.exists(root):
            return ActionResult(
                action=action_id, ok=False, show_dialog=True, title="AMSI 脚本扫描",
                message="目标不存在：%s" % root,
                data={"rows": []}, report={"amsi": {"available": True, "scanned": 0}},
            )

        try:
            files = _script_files(root)
        except Exception as exc:
            return ActionResult(
                action=action_id, ok=False, show_dialog=True, title="AMSI 脚本扫描",
                message="枚举脚本文件失败：%s" % exc, data={"rows": []},
                report={"amsi": {"available": True, "scanned": 0, "error": str(exc)}},
            )

        rows = []
        skipped = 0
        n_high = n_warn = 0
        for p in files:
            try:
                size = os.path.getsize(p)
                if size > MAX_FILE_BYTES or size == 0:
                    skipped += 1
                    continue
                with open(p, "rb") as f:
                    data = f.read()
                hr, result = _amsi_scan(api, data, p)
                if hr != 0:
                    rows.append({"level": "信息", "path": p,
                                 "value": "AMSI 调用失败 hr=0x%08X" % hr,
                                 "detail": "provider 未评估该内容；不算检出也不算排除"})
                    continue
                level, detail = _verdict(result)
                rows.append({"level": level, "path": p,
                             "value": "评分 %d" % result, "detail": detail})
                if level == "高危":
                    n_high += 1
                elif level == "关注":
                    n_warn += 1
            except Exception as exc:
                skipped += 1
                rows.append({"level": "信息", "path": p,
                             "value": "读取/评估失败（已跳过）", "detail": str(exc)[:200]})

        rows.append({"level": "信息", "path": "(汇总)",
                     "value": "脚本 %d 个（跳过 %d）；高危 %d / 关注 %d。"
                              % (len(files), skipped, n_high, n_warn),
                     "detail": CAUTION})
        msg = ("AMSI 扫描完成：脚本 %d 个（跳过 %d），高危 %d / 关注 %d。\n\n"
               "检出 = 本机杀软 provider 的判定，仍需人工复核；0 检出 ≠ 无威胁。\n"
               "本模块只读，未删除任何文件。"
               % (len(files), skipped, n_high, n_warn))
        return ActionResult(
            action=action_id, message=msg, title="AMSI 脚本扫描", show_dialog=True,
            data={"rows": rows},
            report={
                "amsi": {"available": True, "script_count": len(files),
                         "scanned": len(files) - skipped, "skipped": skipped,
                         "detected": n_high, "suspicious": n_warn},
                "caution": CAUTION,
            },
        )
