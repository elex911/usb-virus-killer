# -*- coding: utf-8 -*-
"""
经典木马查杀模块（QQKav 功能移植）
----------------------------------
调研出处（均为二手 T3 资料，功能口径以本模块实现为准）：
  - 百度百科「qqkav」、搜狗百科「qq病毒专杀工具」：功能清单
  - IT168《新QQ尾巴病毒分析报告及其手工清除方法》：Run/RunServices/autorun 痕迹
  - 百度百科Trojan/QQMsg.FakeUpdt、太原师范学院信息化中心：KV2004/winsoft/microsoft.exe、
    txtfile 关联劫持
  - 360百科「qq病毒」：WebAuto.exe、IE 首页劫持

移植决策（与项目既有红线一致）：
  ✅ 启动项/服务/注册表加载项扫描 → detect（只读，可核 file:line 级明细）
  ✅ QQ 尾巴典型痕迹（KV2004/WebAuto/Akica/cacom/winsoft/EKS）→ detect 高危
  ✅ txtfile 文件关联劫持、IFEO 映像劫持 → detect 高危 + fix 可回滚
  ✅ hosts 劫持检测、本机共享清点 → detect 只读
  ✅ 修复必须先备份、可回滚（等价隔离思想；不提供文件粉碎/开机删）
  ❌ 文件粉碎（不可逆，违背隔离回滚原则）→ 拒绝，用隔离/备份替代
  ❌ 网马拦截（注入 IE，现代浏览器无效且高风险）→ 拒绝
  ❌ Winsock 重置（会断网）→ 拒绝
  ❌ 开机删毒（绕过所有确认，不可逆）→ 拒绝
"""
import json
import os
import re
import subprocess
from datetime import datetime

import winreg

from core.api import Action, ActionResult, ModuleBase
from core.widgets import ResultTable

# ---- 可注入接缝（测试用；生产直接走 winreg/系统调用） ----
_reg_enum_values = None      # (hive_int, subkey) -> [(name, value, type)]
_reg_get = None              # (hive_int, subkey, name) -> value or None
_reg_get_ex = None           # (hive_int, subkey, name) -> (value, type) or None
_reg_delete_value = None     # (hive_int, subkey, name) -> None
_reg_set = None              # (hive_int, subkey, name, value, type) -> None
_reg_enum_keys = None        # (hive_int, subkey) -> [subkey_name]
_read_hosts = None           # (path) -> str
_list_shares = None          # () -> [(name, path)]


def _default_reg_enum_values(hive, subkey):
    out = []
    try:
        k = winreg.OpenKey(hive, subkey)
    except OSError:
        return out
    try:
        i = 0
        while True:
            try:
                name, val, typ = winreg.EnumValue(k, i)
                out.append((name, val, typ))
                i += 1
            except OSError:
                break
    finally:
        k.Close()
    return out


def _default_reg_get(hive, subkey, name):
    try:
        k = winreg.OpenKey(hive, subkey)
    except OSError:
        return None
    try:
        val, _typ = winreg.QueryValueEx(k, name)
        return val
    except OSError:
        return None
    finally:
        k.Close()


def _default_reg_get_ex(hive, subkey, name):
    """同 _reg_get，但连同值类型一起返回 (value, type)；键/值不存在返回 None。"""
    try:
        k = winreg.OpenKey(hive, subkey)
    except OSError:
        return None
    try:
        return winreg.QueryValueEx(k, name)
    except OSError:
        return None
    finally:
        k.Close()


def _default_reg_delete_value(hive, subkey, name):
    k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE)
    try:
        winreg.DeleteValue(k, name)
    finally:
        k.Close()


def _default_reg_set(hive, subkey, name, value, typ):
    k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE)
    try:
        winreg.SetValueEx(k, name, 0, typ, value)
    finally:
        k.Close()


def _default_reg_enum_keys(hive, subkey):
    try:
        k = winreg.OpenKey(hive, subkey)
    except OSError:
        return []
    out = []
    try:
        i = 0
        while True:
            try:
                out.append(winreg.EnumKey(k, i))
                i += 1
            except OSError:
                break
    finally:
        k.Close()
    return out


def _default_read_hosts(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _default_list_shares():
    kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        p = subprocess.run(["net", "share"], timeout=15, **kwargs)
        text = p.stdout.decode("gbk", errors="replace")
    except Exception:
        return []
    shares = []
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s{2,}([A-Za-z]:\\.+)$", line.strip())
        if m:
            shares.append((m.group(1), m.group(2).strip()))
    return shares


def _reset_seams():
    global _reg_enum_values, _reg_get, _reg_get_ex, _reg_delete_value, _reg_set
    global _reg_enum_keys, _read_hosts, _list_shares
    _reg_enum_values = _default_reg_enum_values
    _reg_get = _default_reg_get
    _reg_get_ex = _default_reg_get_ex
    _reg_delete_value = _default_reg_delete_value
    _reg_set = _default_reg_set
    _reg_enum_keys = _default_reg_enum_keys
    _read_hosts = _default_read_hosts
    _list_shares = _default_list_shares


_reset_seams()

# ---- 判据（出处见模块 docstring） ----
HIVE_NAMES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
}
RUN_LOCATIONS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
]
RUN_ONCE_SUBKEYS = {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}

KNOWN_RUN_NAMES = {"kv2004", "webauto", "akica", "cacom", "sycacom", "vm1", "eks"}
KNOWN_FILE_TOKENS = {"winsoft", "eks.exe", "webauto.exe", "akica.exe", "cacom.exe"}
WINDIR_ROOT_FILES = {"microsoft.exe", "winsoft"}

SAFE_DIRS = ("system32", "syswow64", "program files", "program files (x86)",
             "windowsapps", "microsoft", "windows defender")

TXTFILE_ASSOC = r"txtfile\shell\open\command"
TXT_DEFAULTS = {
    "%systemroot%\\system32\\notepad.exe %1",
    "%systemroot%\\system32\\notepad.exe \"%1\"",
}
DEFAULT_TXT_VALUE = "%SystemRoot%\\system32\\NOTEPAD.EXE %1"
DEFAULT_TXT_TYPE = winreg.REG_EXPAND_SZ

IFEOSUB = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
HOSTS_BASELINE = ("localhost", "127.0.0.1", "::1")

CAUTION = (
    "本模块等级口径：高危=强特征待修；关注=待核疑点；信息=登记。"
    "「修复」只处理高危项且先备份、可回滚；文件本体不做粉碎或删除，"
    "建议交给 ClamAV 外部引擎或隔离流程处理。"
)


def _norm(s):
    return str(s or "").strip().lower().replace("/", "\\")


def _first_exe(data):
    """从启动项命令行里取第一个 exe 路径（支持带空格的无引号路径）。"""
    s = str(data or "").strip()
    if not s:
        return ""
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[1:end] if end > 0 else s.strip('"')
    m = re.match(r"^([a-z]:\\[^\"*?<>|]*?\.exe)", s, re.I)
    return m.group(1) if m else s.split()[0]


def _classify_startup(name, data):
    """返回 (level, reason, fixable)。"""
    base_name = _norm(name)
    exe = _first_exe(data)
    low_data = _norm(data)
    exe_base = _norm(os.path.basename(exe.replace('"', "")))

    if base_name in KNOWN_RUN_NAMES or exe_base in KNOWN_FILE_TOKENS:
        return "高危", "命中 QQ 尾巴已知启动项特征（docstring 出处）", True
    if exe_base in WINDIR_ROOT_FILES and re.match(r"^[a-z]:\\windows\\[^\\]+$", _norm(os.path.dirname(exe))):
        return "高危", "Windows 根目录可疑主程序（winsoft/microsoft.exe 模式）", True

    d = _norm(exe)
    if d.startswith("c:\\windows\\") and "system32" not in d and "syswow64" not in d:
        return "关注", "启动项指向 Windows 根目录（非 system32），待核", False
    if "temp\\" in d or "appdata\\local\\temp" in d:
        return "关注", "启动项指向临时目录", False
    if d and not any(s in d for s in SAFE_DIRS) and "program files" not in d:
        return "关注", "启动项指向非系统标准目录，待核", False
    return "信息", "位于系统标准目录", False


class Module(ModuleBase):
    meta = {
        "id": "classic_trojans",
        "name": "经典木马查杀",
        "version": "1.0",
        "description": "QQKav 功能移植：QQ尾巴/启动项/关联劫持/IFEO/hosts/共享只读体检；高危项可备份修复并回滚。",
        "order": 15,
    }

    def actions(self):
        return [
            Action("detect", "经典体检(只读)", target_mode="none", order=10),
            Action("fix", "修复高危项(可回滚)",
                   confirm="将对「高危」项执行可回滚修复：先备份注册表原值，再删除病毒启动项/IFEO Debugger、还原 txtfile 关联。\n"
                           "不粉碎、不删除任何文件。继续？",
                   target_mode="none", order=20),
            Action("rollback", "回滚上次修复", target_mode="none", order=30),
        ]

    def suggest_targets(self):
        return []

    def build_view(self, parent, ctx):
        return ResultTable(
            parent,
            columns=[("kind", "类别", 120), ("level", "结论", 80),
                     ("path", "位置", 420), ("value", "键值/说明", 300)],
            tag_key="level",
            tag_map={"高危": "#c0392b", "关注": "#b8860b", "信息": "#666",
                     "已修复": "#2c7", "已回滚": "#666"},
            caution=CAUTION,
            on_detail=self.detail,
            height=11,
        )

    def render(self, action_id, result, view, ctx):
        view.set_rows(result.data.get("rows", []))

    def detail(self, row):
        return (
            "类别：%s\n结论：%s\n位置：%s\n键值/说明：%s\n\n依据：%s\n\n%s"
            % (row.get("kind", ""), row.get("level", ""), row.get("path", ""),
               row.get("value", ""), row.get("reason", ""), CAUTION)
        )

    # ---------- 只读体检 ----------
    def collect(self, log):
        rows = []
        fixables = []

        for hive_name, subkey in RUN_LOCATIONS:
            hive = HIVE_NAMES[hive_name]
            for name, val, vtype in _reg_enum_values(hive, subkey):
                level, reason, fixable = _classify_startup(name, val)
                row = {
                    "kind": "启动项", "level": level,
                    "path": "%s\\%s" % (hive_name, subkey),
                    "value": "%s = %s" % (name, str(val)[:160]),
                    "reason": reason,
                }
                rows.append(row)
                if level == "高危":
                    fixables.append({
                        "kind": "启动项", "hive": hive_name, "subkey": subkey,
                        "name": name, "old_value": val, "old_type": vtype,
                    })

        got = _reg_get_ex(HIVE_NAMES["HKCR"], TXTFILE_ASSOC, "")
        assoc_val = "" if got is None else str(got[0])
        assoc_norm = _norm(assoc_val).strip()
        known_ok = any(assoc_norm == _norm(t).strip() for t in TXT_DEFAULTS)
        if not assoc_val:
            rows.append({"kind": "文件关联", "level": "信息", "path": "HKCR\\" + TXTFILE_ASSOC,
                         "value": "(默认值不存在)", "reason": "未发现关联劫持特征"})
        elif known_ok:
            rows.append({"kind": "文件关联", "level": "信息", "path": "HKCR\\" + TXTFILE_ASSOC,
                         "value": assoc_val, "reason": "txtfile 关联为系统默认记事本，正常"})
        else:
            rows.append({"kind": "文件关联", "level": "高危", "path": "HKCR\\" + TXTFILE_ASSOC,
                         "value": assoc_val, "reason": "txtfile 被改向非记事本程序（QQ尾巴典型手法）"})
            fixables.append({
                "kind": "文件关联", "hive": "HKCR", "subkey": TXTFILE_ASSOC,
                "name": "", "old_value": assoc_val,
                "old_type": got[1] if got else winreg.REG_SZ,
                "new_value": DEFAULT_TXT_VALUE, "new_type": DEFAULT_TXT_TYPE,
            })

        try:
            subkeys = list(_reg_enum_keys(HIVE_NAMES["HKLM"], IFEOSUB))
        except Exception:
            subkeys = []
        for sk in subkeys:
            got = _reg_get_ex(HIVE_NAMES["HKLM"], IFEOSUB + "\\" + sk, "Debugger")
            dbg = got[0] if got else None
            if dbg:
                rows.append({
                    "kind": "IFEO劫持", "level": "高危",
                    "path": "HKLM\\%s\\%s" % (IFEOSUB, sk),
                    "value": "Debugger = %s" % str(dbg)[:160],
                    "reason": "映像劫持：目标程序启动前会被 Debugger 接管（QQKav 修复项）",
                })
                fixables.append({
                    "kind": "IFEO劫持", "hive": "HKLM",
                    "subkey": IFEOSUB + "\\" + sk, "name": "Debugger", "old_value": dbg,
                    "old_type": got[1],
                })

        homepage = _reg_get(HIVE_NAMES["HKCU"],
                            r"SOFTWARE\Microsoft\Internet Explorer\Main", "Start Page")
        if homepage and _norm(homepage) not in ("about:blank", "http://go.microsoft.com/fwlink/?linkid=69157"):
            rows.append({
                "kind": "IE首页", "level": "关注",
                "path": "HKCU\\SOFTWARE\\Microsoft\\Internet Explorer\\Main",
                "value": str(homepage)[:160],
                "reason": "IE 默认页非空；是否为用户自设需人工确认（QQ尾巴常改首页）",
            })

        try:
            hosts_text = _read_hosts(HOSTS_PATH)
        except Exception as exc:
            hosts_text = ""
            rows.append({"kind": "hosts", "level": "信息", "path": HOSTS_PATH,
                         "value": "读取失败：%s" % exc, "reason": "无法检查 hosts"})
        extra = []
        for line in (hosts_text or "").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            if len(parts) >= 2 and all(p.lower() in HOSTS_BASELINE for p in parts[:2]):
                continue
            if parts:
                extra.append(s[:160])
        if extra:
            rows.append({
                "kind": "hosts", "level": "关注", "path": HOSTS_PATH,
                "value": "%d 条非默认映射；示例：%s" % (len(extra), extra[0]),
                "reason": "hosts 被追加映射（屏蔽/劫持网站常用手法），是否合法需人工确认",
            })
        else:
            rows.append({"kind": "hosts", "level": "信息", "path": HOSTS_PATH,
                         "value": "无非默认映射", "reason": "hosts 干净"})

        try:
            shares = _list_shares()
        except Exception:
            shares = []
        if shares:
            names = ", ".join(n for n, _p in shares[:8])
            rows.append({
                "kind": "共享", "level": "关注", "path": "(本机共享)",
                "value": "%d 个共享：%s%s" % (len(shares), names, "…" if len(shares) > 8 else ""),
                "reason": "存在目录共享；QQKav「本机共享管理」对应项，取消共享请用系统工具",
            })
        else:
            rows.append({"kind": "共享", "level": "信息", "path": "(本机共享)",
                         "value": "未发现自定义共享", "reason": "共享清点完成"})

        log("体检完成：%d 项（高危 %d）。" % (
            len(rows), sum(1 for r in rows if r["level"] == "高危")))
        return rows, fixables

    # ---------- 修复 ----------
    def _backup_dir(self, ctx):
        base = os.path.join(ctx.app_dir or os.getcwd(), "legacy_fix_backups")
        os.makedirs(base, exist_ok=True)
        return base

    def _do_fix(self, ctx, log):
        rows, fixables = self.collect(log)
        if not fixables:
            return None, "没有需要修复的高危项。"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        bdir = os.path.join(self._backup_dir(ctx), stamp)
        os.makedirs(bdir, exist_ok=True)
        manifest = {"time": datetime.now().isoformat(), "items": [], "applied": []}
        mf_path = os.path.join(bdir, "manifest.json")

        def _flush():
            # 每改一项就重写 manifest：中途异常时，已修改的项仍然可回滚
            with open(mf_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, ensure_ascii=False, indent=2)

        _flush()
        for item in fixables:
            hive = HIVE_NAMES[item["hive"]]
            subkey, name = item["subkey"], item["name"]
            if item["kind"] == "文件关联":
                _reg_set(hive, subkey, name or "", item["new_value"], item["new_type"])
                manifest["applied"].append({**item, "action": "set_assoc"})
            else:
                _reg_delete_value(hive, subkey, name)
                manifest["applied"].append({**item, "action": "delete_value"})
            manifest["items"].append(item)
            _flush()
            log("已修复：%s\\%s [%s]" % (item["hive"], subkey, name or "(默认)"))

        return bdir, "已修复 %d 项高危；备份：%s" % (len(fixables), bdir)

    def _do_rollback(self, ctx, log):
        base = self._backup_dir(ctx)
        if not os.path.isdir(base):
            return "没有修复备份，无需回滚。", 0
        runs = sorted(d for d in os.listdir(base)
                      if os.path.isdir(os.path.join(base, d)))
        if not runs:
            return "没有修复备份，无需回滚。", 0
        latest = runs[-1]
        mf_path = os.path.join(base, latest, "manifest.json")
        with open(mf_path, encoding="utf-8") as f:
            manifest = json.load(f)
        restored = 0
        for item in manifest.get("applied", []):
            try:
                hive = HIVE_NAMES[item["hive"]]
            except (KeyError, TypeError):
                log("回滚跳过损坏项（未知 hive）：%r" % item.get("hive"))
                continue
            # 按备份记录的原类型还原（旧备份无 old_type 时退回 REG_SZ 兼容）
            old_type = item.get("old_type", winreg.REG_SZ)
            old_value = item["old_value"]
            if old_type == winreg.REG_BINARY and isinstance(old_value, list):
                old_value = bytes(old_value)  # JSON 往返把 bytes 变成了 list
            if item["action"] in ("delete_value", "set_assoc"):
                _reg_set(hive, item["subkey"], item["name"], old_value, old_type)
            restored += 1
            log("已回滚：%s\\%s [%s]" % (item["hive"], item["subkey"], item["name"] or "(默认)"))
        return "已回滚 %d 项（备份 %s）。" % (restored, latest), restored

    def run(self, action_id, ctx, log):
        if action_id == "detect":
            rows, fixables = self.collect(log)
            hi = sum(1 for r in rows if r["level"] == "高危")
            msg = ("体检完成：%d 项，其中高危 %d（可修复）、关注 %d。\n\n"
                   "高危项可点「修复高危项(可回滚)」处理；关注项需人工确认。"
                   % (len(rows), hi, sum(1 for r in rows if r["level"] == "关注")))
            return ActionResult(
                action=action_id, message=msg, title="经典体检", show_dialog=True,
                data={"rows": rows},
                report={"classic_trojans_readonly": True, "rows": rows,
                        "fixable": fixables, "caution": CAUTION},
            )

        if action_id == "fix":
            bdir, msg = self._do_fix(ctx, log)
            if bdir is None:
                rows = [{"kind": "-", "level": "信息", "path": "(修复)",
                         "value": msg, "reason": CAUTION}]
            else:
                rows, _ = self.collect(log)
                for r in rows:
                    if r["level"] == "高危":
                        r["level"] = "已修复"
            return ActionResult(
                action=action_id, message=msg, title="修复高危项", show_dialog=True,
                data={"rows": rows},
                report={"fixed_backup_dir": bdir, "message": msg},
            )

        if action_id == "rollback":
            msg, n = self._do_rollback(ctx, log)
            rows, _ = self.collect(log)
            return ActionResult(
                action=action_id, message=msg, title="回滚上次修复", show_dialog=True,
                data={"rows": rows},
                report={"restored": n, "message": msg},
            )

        raise RuntimeError("模块 %s 不支持操作：%s" % (self.meta["id"], action_id))
