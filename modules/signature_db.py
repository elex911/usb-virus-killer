# -*- coding: utf-8 -*-
"""
本地特征库模块（空库起步）
--------------------------
设计红线：
  - 不预置任何样本/哈希/正则；文件不存在时只有「初始化空库」会创建空 rules。
  - 每条规则必须有 source（可核出处）、evidence（T1/T2/T3）、first_seen。
  - T3（他人/委托人转述）只登记，不得启用；T4 禁止入库。
  - 只有 enabled=true 且校验通过的 T1/T2 规则参与扫描。
  - 命中只是规则匹配，不是病毒确认；本模块不隔离、不删除、不修复。
"""
import hashlib
import json
import os
import re
from datetime import datetime

from . import folder_virus as fv
from core.api import Action, ActionResult, ModuleBase
from core.widgets import ResultTable

DB_FILENAME = "signature_db.json"
SCHEMA_VERSION = "1.0"
ALLOWED_TYPES = ("sha256", "filename_regex", "content_regex")
ALLOWED_EVIDENCE = ("T1", "T2", "T3")
PLACEHOLDER_SOURCES = {"", "未知", "unknown", "xx", "x", "某", "test", "示例", "example"}
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_CONTENT_BYTES = 1024 * 1024

CAUTION = (
    "特征库命中 ≠ 病毒确认；本模块只报告，不隔离、不删除。"
    "只有带可核 source、T1/T2 证据且显式 enabled=true 的规则才参与扫描。"
)

EMPTY_DB = {
    "schema_version": SCHEMA_VERSION,
    "_readme": CAUTION,
    "rules": [],
}


def db_path(ctx):
    custom = (ctx.settings or {}).get("signature_db_path")
    if custom:
        return custom
    return os.path.join(ctx.app_dir or os.getcwd(), DB_FILENAME)


def write_empty_db(path):
    """仅在文件不存在时创建空库；绝不覆盖用户已有规则。"""
    if os.path.exists(path):
        return False
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(EMPTY_DB, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return True


def load_db(path):
    if not os.path.isfile(path):
        raise RuntimeError("未找到特征库：%s\n请先点「初始化空库」。" % path)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise RuntimeError("特征库解析失败：%s" % exc)


def validate_db(db):
    """返回 (全局错误列表, 每条规则状态列表, 可启用规则列表)。"""
    errors = []
    statuses = []
    enabled = []
    if not isinstance(db, dict):
        return ["特征库根节点必须是对象"], [], []
    rules = db.get("rules")
    if not isinstance(rules, list):
        return ["rules 必须是数组"], [], []

    seen_ids = set()
    for i, rule in enumerate(rules):
        label = "rules[%d]" % i
        if not isinstance(rule, dict):
            msg = "规则必须是对象"
            errors.append(label + ": " + msg)
            statuses.append({"id": label, "type": "-", "enabled": False,
                             "issues": [msg], "effective": False})
            continue

        rid = str(rule.get("id") or "").strip()
        issues = []
        if not rid:
            issues.append("id 不能为空")
        elif rid in seen_ids:
            issues.append("id 重复")
        else:
            seen_ids.add(rid)

        typ = str(rule.get("type") or "").strip().lower()
        if typ not in ALLOWED_TYPES:
            issues.append("type 必须是 %s" % "/".join(ALLOWED_TYPES))

        value = str(rule.get("value") or "").strip()
        if not value:
            issues.append("value 不能为空")
        elif typ == "sha256" and not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            issues.append("sha256 的 value 必须是 64 位十六进制")
        elif typ in ("filename_regex", "content_regex"):
            try:
                re.compile(value)
            except re.error as exc:
                issues.append("正则无效：%s" % exc)

        source = str(rule.get("source") or "").strip()
        if source.lower() in PLACEHOLDER_SOURCES or "某XX" in source:
            issues.append("source 不能是占位符，必须是可核出处")

        evidence = str(rule.get("evidence") or "").strip().upper()
        if evidence not in ALLOWED_EVIDENCE:
            issues.append("evidence 必须是 T1/T2/T3")
        elif evidence == "T3" and bool(rule.get("enabled", False)):
            issues.append("T3 不得启用为判定依据，只能登记")

        first_seen = str(rule.get("first_seen") or "").strip()
        try:
            datetime.strptime(first_seen, "%Y-%m-%d")
        except ValueError:
            issues.append("first_seen 必须是 YYYY-MM-DD")

        is_enabled = bool(rule.get("enabled", False))
        effective = is_enabled and not issues
        statuses.append({
            "id": rid or label,
            "type": typ,
            "enabled": is_enabled,
            "issues": issues,
            "effective": effective,
        })
        for msg in issues:
            errors.append("%s: %s" % (rid or label, msg))
        if effective:
            enabled.append({
                "id": rid,
                "type": typ,
                "value": value,
                "source": source,
                "evidence": evidence,
                "first_seen": first_seen,
            })
    return errors, statuses, enabled


def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _scan_target(root, enabled, log):
    matches = []
    errors = []
    scanned = skipped = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if "__WORM_QUARANTINE_" not in d]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if "__WORM_QUARANTINE_" in p:
                continue
            try:
                size = os.path.getsize(p)
            except Exception as exc:
                skipped += 1
                errors.append("%s: 读取大小失败 %s" % (p, exc))
                continue
            if size > MAX_FILE_BYTES:
                skipped += 1
                continue
            scanned += 1

            for rule in enabled:
                try:
                    typ = rule["type"]
                    value = rule["value"]
                    hit = False
                    if typ == "sha256":
                        hit = _hash_file(p) == value.lower()
                    elif typ == "filename_regex":
                        hit = bool(re.search(value, fn, re.I))
                    elif typ == "content_regex":
                        with open(p, "rb") as f:
                            raw = f.read(MAX_CONTENT_BYTES)
                        text = raw.decode("utf-8", errors="ignore") + "\n" + \
                               raw.decode("latin-1", errors="ignore")
                        hit = bool(re.search(value, text, re.I))
                    if hit:
                        matches.append({
                            "id": rule["id"],
                            "type": typ,
                            "level": "命中",
                            "path": p,
                            "value": value[:160],
                            "source": rule["source"],
                            "evidence": rule["evidence"],
                            "first_seen": rule["first_seen"],
                        })
                except Exception as exc:
                    errors.append("%s / %s: 匹配失败 %s" % (rule["id"], p, exc))

    log("特征库扫描完成：文件 %d 个，跳过 %d 个，命中 %d 条。"
        % (scanned, skipped, len(matches)))
    return matches, scanned, skipped, errors


class Module(ModuleBase):
    meta = {
        "id": "signature_db",
        "name": "本地特征库",
        "version": "1.0",
        "description": "空库起步；有出处、T1/T2、显式启用才参与扫描；只报告不隔离。",
        "order": 30,
    }

    def actions(self):
        return [
            Action("init", "初始化空库", target_mode="none", order=10),
            Action("validate", "校验规则", target_mode="none", order=20),
            Action("scan", "按库扫描(只读)", target_mode="required",
                   confirm="将只读扫描目标文件并报告规则命中，不隔离、不删除。\n继续？",
                   order=30),
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
            columns=[("id", "规则ID", 120), ("type", "类型", 110),
                     ("level", "结论", 80), ("path", "路径", 420),
                     ("value", "规则值/说明", 260)],
            tag_key="level",
            tag_map={"命中": "#b8860b", "待核": "#b8860b",
                     "规则错误": "#c0392b", "信息": "#666"},
            caution=CAUTION,
            on_detail=self.detail,
            height=11,
        )

    def render(self, action_id, result, view, ctx):
        view.set_rows(result.data.get("rows", []))

    def detail(self, row):
        return (
            "规则ID：%s\n类型：%s\n结论：%s\n\n路径：%s\n规则值：%s\n\n"
            "证据等级：%s\n出处：%s\n首见日期：%s\n\n"
            "注意：命中仅表示规则匹配，不等同于病毒确认；本模块未做任何修改。"
            % (row.get("id", ""), row.get("type", ""), row.get("level", ""),
               row.get("path", ""), row.get("value", ""),
               row.get("evidence", ""),
               row.get("source", ""), row.get("first_seen", ""))
        )

    def _validate_rows(self, statuses, errors):
        rows = []
        for st in statuses:
            if st["issues"]:
                level = "规则错误"
                detail = "；".join(st["issues"])
            elif st["effective"]:
                level = "待核"
                detail = "已启用；仅在按库扫描时参与只读匹配"
            else:
                level = "信息"
                detail = "未启用；不参与扫描"
            rows.append({
                "id": st["id"], "type": st["type"], "level": level,
                "path": "(规则)", "value": detail,
            })
        if not rows:
            rows.append({
                "id": "-", "type": "-", "level": "信息",
                "path": "(空库)", "value": "没有任何规则；不会参与扫描。",
            })
        return rows

    def run(self, action_id, ctx, log):
        path = db_path(ctx)

        if action_id == "init":
            created = write_empty_db(path)
            msg = ("已创建空特征库：%s\n当前 0 条规则；请自行添加有出处的规则。"
                   % path) if created else ("特征库已存在，未覆盖：%s" % path)
            return ActionResult(
                action=action_id, message=msg, title="特征库", show_dialog=True,
                data={"rows": [{"id": "-", "type": "-", "level": "信息",
                                "path": path, "value": msg}]},
                report={"db_path": path, "created": created, "rules": 0},
            )

        db = load_db(path)
        errors, statuses, enabled = validate_db(db)
        n_enabled = len(enabled)

        if action_id == "validate":
            rows = self._validate_rows(statuses, errors)
            msg = ("规则 %d 条：可启用 %d / 无效或未启用 %d；校验错误 %d 条。\n\n"
                   "校验错误不会被执行。T3 与占位符出处不得启用。"
                   % (len(statuses), n_enabled, len(statuses) - n_enabled, len(errors)))
            return ActionResult(
                action=action_id, message=msg, title="规则校验", show_dialog=True,
                data={"rows": rows},
                report={"db_path": path, "rule_count": len(statuses),
                        "enabled": n_enabled, "errors": errors, "statuses": statuses},
            )

        if action_id == "scan":
            eng = fv.Engine(ctx.target, ctx.is_drive, ctx.allow_fixed)
            eng.precheck()
            if not enabled:
                msg = "没有已启用且有效的规则，未执行匹配。\n请先用「校验规则」查看错误原因。"
                return ActionResult(
                    action=action_id, message=msg, title="按库扫描", show_dialog=True,
                    data={"rows": self._validate_rows(statuses, errors)},
                    report={"db_path": path, "matched": 0, "errors": errors},
                )
            matches, scanned, skipped, scan_errors = _scan_target(ctx.target, enabled, log)
            rows = list(matches) + [{
                "id": "-", "type": "-", "level": "信息",
                "path": "(汇总)",
                "value": "扫描 %d 个文件，跳过 %d 个；命中仅表示规则匹配。"
                         % (scanned, skipped),
            }]
            return ActionResult(
                action=action_id,
                message="按库扫描完成：文件 %d 个，命中 %d 条，跳过 %d 个。\n\n"
                        "命中仅表示规则匹配，不等同于病毒确认；本模块不隔离、不删除。"
                        % (scanned, len(matches), skipped),
                title="按库扫描", show_dialog=True,
                data={"rows": rows},
                report={
                    "db_path": path,
                    "schema_version": db.get("schema_version"),
                    "rule_count": len(statuses),
                    "enabled_rules": n_enabled,
                    "scanned_files": scanned,
                    "skipped_files": skipped,
                    "matched": len(matches),
                    "matches": matches,
                    "validation_errors": errors,
                    "scan_errors": scan_errors,
                    "caution": CAUTION,
                },
            )

        raise RuntimeError("模块 %s 不支持操作：%s" % (self.meta["id"], action_id))
