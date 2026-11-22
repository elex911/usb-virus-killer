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
from core import scan_guard
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
    "db_version": 0,
    "updated_at": "",
    "packs": [],
    "rules": [],
}

BACKUP_DIRNAME = "signature_db_backups"
MAX_BACKUPS = 10

FP_FILENAME = "fp_feedback.jsonl"          # 误报候选记录（Avira 误报申诉思路的本地化）


def fp_path(ctx):
    return os.path.join(ctx.app_dir or os.getcwd(), FP_FILENAME)


def read_fp(path):
    """读取误报候选记录；返回 list[dict]，文件不存在返回空列表。"""
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue
            if isinstance(item, dict):
                out.append(item)
    return out


def append_fp(path, entries):
    """追加误报候选；返回实际新增条数（按 (rule_id, path) 去重）。"""
    existing = {(e.get("rule_id"), e.get("path")) for e in read_fp(path)}
    added = 0
    if entries:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            for e in entries:
                key = (e.get("rule_id"), e.get("path"))
                if key in existing:
                    continue
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
                existing.add(key)
                added += 1
    return added


def extract_matches_from_report(data):
    """从导出的报告 JSON 里抽取特征库命中列表。

    兼容两种结构：
      1. 主程序「导出报告」：module_results.signature_db.report.matches
      2. 直接是 scan 的 report：顶层 matches
    """
    if not isinstance(data, dict):
        return []
    mods = data.get("module_results")
    if isinstance(mods, dict):
        rec = mods.get("signature_db") or {}
        rep = rec.get("report") if isinstance(rec, dict) else {}
        matches = rep.get("matches") if isinstance(rep, dict) else None
        if isinstance(matches, list):
            return [m for m in matches if isinstance(m, dict)]
    if isinstance(data.get("matches"), list):
        return [m for m in data["matches"] if isinstance(m, dict)]
    return []


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


def backup_db(path):
    """导入规则包前备份当前库；保留最近 MAX_BACKUPS 份，返回备份路径。"""
    if not os.path.isfile(path):
        return ""
    parent = os.path.dirname(os.path.abspath(path))
    bdir = os.path.join(parent, BACKUP_DIRNAME)
    os.makedirs(bdir, exist_ok=True)
    cur = load_db(path)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(bdir, "%s_v%s.json" % (stamp, cur.get("db_version", 0)))
    with open(path, "rb") as src, open(dest, "wb") as dst:
        dst.write(src.read())
    backups = sorted(f for f in os.listdir(bdir) if f.endswith(".json"))
    for old in backups[:-MAX_BACKUPS]:
        try:
            os.remove(os.path.join(bdir, old))
        except OSError:
            pass
    return dest


def latest_backup(path):
    parent = os.path.dirname(os.path.abspath(path))
    bdir = os.path.join(parent, BACKUP_DIRNAME)
    if not os.path.isdir(bdir):
        return ""
    files = sorted(f for f in os.listdir(bdir) if f.endswith(".json"))
    return os.path.join(bdir, files[-1]) if files else ""


def rules_sha256(rules):
    """规则集合规范化哈希：防篡改/防半包。签名验证需外部信任根，本工具不假称具备。"""
    canonical = json.dumps(rules, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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

    guard_stats = scan_guard.new_stats()
    for p, size, _isdir in scan_guard.walk_entries(
            root, guard_stats,
            skip_dir=lambda n: "__WORM_QUARANTINE_" in n,
            max_file_bytes=MAX_FILE_BYTES):
        scanned += 1
        fn = os.path.basename(p)
        for rule in enabled:
            try:
                typ = rule["type"]
                value = rule["value"]
                hit = False
                method = {"sha256": "文件哈希", "filename_regex": "特征(文件名)",
                          "content_regex": "特征(内容)"}.get(typ, "未知")
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
                        "method": method,
                        "level": "命中",
                        "path": p,
                        "value": value[:160],
                        "source": rule["source"],
                        "evidence": rule["evidence"],
                        "first_seen": rule["first_seen"],
                    })
            except Exception as exc:
                errors.append("%s / %s: 匹配失败 %s" % (rule["id"], p, exc))

    skipped = guard_stats["skipped_large"] + guard_stats["skipped_reparse"] + \
              guard_stats["skipped_depth"] + guard_stats["unreadable"]
    log("特征库扫描完成：文件 %d 个，跳过 %d 个，命中 %d 条。"
        % (scanned, skipped, len(matches)))
    return matches, scanned, skipped, errors, guard_stats


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
            Action("import_pack", "导入规则包(版本化)", target_mode="none", prompt="file",
                   prompt_title="选择规则包 JSON 文件",
                   confirm="规则包必须是带 name/version/source/rules 的 JSON。\n"
                           "version 必须大于当前库版本（禁止降级/重复导入）；\n"
                           "导入前自动备份当前库，可回滚。继续？",
                   order=40),
            Action("rollback_db", "回滚上次导入", target_mode="none", order=50),
            Action("fp_mark", "登记误报候选", target_mode="none", prompt="file",
                   prompt_title="选择包含特征库命中的导出报告 JSON",
                   confirm="将把所选报告里的特征库命中登记为「误报候选」写入本地\n"
                           "fp_feedback.jsonl，供规则复核时参考。\n"
                           "本操作不会自动修改/删除任何规则，继续？",
                   order=60),
            Action("fp_view", "查看误报记录", target_mode="none", order=70),
        ]

    def prepare_context(self, ctx, raw_target, allow_fixed=True):
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

        if action_id == "fp_mark":
            return self._fp_mark(action_id, ctx, log)

        if action_id == "fp_view":
            fpath = fp_path(ctx)
            entries = read_fp(fpath)
            rows = [{
                "id": e.get("rule_id", "-"), "type": "-",
                "level": "待核", "path": e.get("path", ""),
                "value": "规则值：%s | 登记时间：%s"
                         % (str(e.get("value", ""))[:80], e.get("time", "")),
            } for e in entries] or [{
                "id": "-", "type": "-", "level": "信息",
                "path": "(误报记录)", "value": "暂无记录；先用「导出报告」再用「登记误报候选」。",
            }]
            return ActionResult(
                action=action_id, message="误报候选记录 %d 条（文件：%s）。\n"
                        "记录仅供参考，不会自动修改规则；复核后请自行调整规则库。"
                        % (len(entries), fpath),
                title="误报记录", show_dialog=True, data={"rows": rows},
                report={"fp_file": fpath, "pending": len(entries)},
            )

        db = load_db(path)
        errors, statuses, enabled = validate_db(db)
        n_enabled = len(enabled)

        if action_id == "validate":
            rows = self._validate_rows(statuses, errors)
            pending_fp = len(read_fp(fp_path(ctx)))
            fp_note = ("\n误报候选待复核：%d 条（用「查看误报记录」查看）。" % pending_fp
                       if pending_fp else "")
            msg = ("规则 %d 条：可启用 %d / 无效或未启用 %d；校验错误 %d 条。\n\n"
                   "校验错误不会被执行。T3 与占位符出处不得启用。%s"
                   % (len(statuses), n_enabled, len(statuses) - n_enabled, len(errors),
                      fp_note))
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
            matches, scanned, skipped, scan_errors, guard_stats = _scan_target(ctx.target, enabled, log)
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
                    "scan_stats": {
                        "已扫描": scanned, "跳过": skipped,
                        "重解析点跳过": guard_stats["skipped_reparse"],
                        "超大跳过": guard_stats["skipped_large"],
                        "超深跳过": guard_stats["skipped_depth"],
                        "无法读取": guard_stats["unreadable"] + len(scan_errors),
                        "检测": len(matches), "未知": len(scan_errors),
                    },
                    "caution": CAUTION,
                },
            )

        if action_id == "import_pack":
            return self._import_pack(action_id, path, ctx, log)

        if action_id == "rollback_db":
            bk = latest_backup(path)
            if not bk:
                return ActionResult(
                    action=action_id, ok=False, show_dialog=True, title="回滚上次导入",
                    message="没有可回滚的备份（尚未导入过规则包）。",
                    data={"rows": [{"id": "-", "type": "-", "level": "信息",
                                    "path": "(回滚)", "value": "无备份"}]},
                    report={"restored": 0},
                )
            src = load_db(bk)
            cur_ver = load_db(path).get("db_version", 0)
            with open(bk, "rb") as fsrc, open(path, "wb") as fdst:
                fdst.write(fsrc.read())
            msg = "已回滚到备份：%s（库版本 %s → %s）。" % (
                os.path.basename(bk), cur_ver, src.get("db_version", 0))
            return ActionResult(
                action=action_id, message=msg, title="回滚上次导入", show_dialog=True,
                data={"rows": [{"id": "-", "type": "-", "level": "信息",
                                "path": bk, "value": msg}]},
                report={"restored": 1, "backup": bk, "db_version": src.get("db_version", 0)},
            )

        raise RuntimeError("模块 %s 不支持操作：%s" % (self.meta["id"], action_id))

    def _fp_mark(self, action_id, ctx, log):
        report_file = getattr(ctx, "pick", "") or ""
        if not report_file or not os.path.isfile(report_file):
            return ActionResult(
                action=action_id, ok=False, show_dialog=True, title="登记误报候选",
                message="未选择有效的报告 JSON 文件。", data={"rows": []},
                report={"logged": 0},
            )
        try:
            with open(report_file, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            return ActionResult(
                action=action_id, ok=False, show_dialog=True, title="登记误报候选",
                message="报告 JSON 解析失败：%s" % exc, data={"rows": []},
                report={"logged": 0},
            )
        matches = extract_matches_from_report(data)
        if not matches:
            return ActionResult(
                action=action_id, ok=False, show_dialog=True, title="登记误报候选",
                message="该报告里没有找到特征库命中（matches 为空或结构不符）。\n"
                        "请先「按库扫描」并「导出报告」，再选该报告文件。",
                data={"rows": []}, report={"logged": 0},
            )
        stamp = datetime.now().isoformat()
        entries = [{
            "time": stamp,
            "rule_id": m.get("id", ""),
            "path": m.get("path", ""),
            "value": m.get("value", ""),
            "source": m.get("source", ""),
            "evidence": m.get("evidence", ""),
            "report": report_file,
            "status": "待复核",
        } for m in matches]
        fpath = fp_path(ctx)
        added = append_fp(fpath, entries)
        skipped = len(entries) - added
        log("误报候选登记完成：新增 %d，重复跳过 %d。" % (added, skipped))
        rows = [{
            "id": m.get("id", "-"), "type": m.get("type", "-"),
            "level": "待核", "path": m.get("path", ""),
            "value": "规则值：%s" % str(m.get("value", ""))[:120],
        } for m in matches] or [{"id": "-", "type": "-", "level": "信息",
                                 "path": "(误报)", "value": "无命中"}]
        return ActionResult(
            action=action_id, message="已登记误报候选 %d 条（重复跳过 %d 条）。\n"
                    "记录文件：%s\n\n注意：这只是复核参考，不会自动修改规则；\n"
                    "确认误报后请自行从规则库移除或停用对应规则。"
                    % (added, skipped, fpath),
            title="登记误报候选", show_dialog=True, data={"rows": rows},
            report={"fp_file": fpath, "logged": added, "duplicates": skipped,
                    "total_matches": len(matches)},
        )

    def _import_pack(self, action_id, path, ctx, log):
        pack_path = getattr(ctx, "pick", "") or ""
        if not pack_path or not os.path.isfile(pack_path):
            return ActionResult(
                action=action_id, ok=False, show_dialog=True, title="导入规则包",
                message="未选择有效的规则包文件。",
                data={"rows": []}, report={"imported": 0},
            )
        try:
            with open(pack_path, encoding="utf-8") as f:
                pack = json.load(f)
        except Exception as exc:
            return ActionResult(
                action=action_id, ok=False, show_dialog=True, title="导入规则包",
                message="规则包 JSON 解析失败：%s" % exc, data={"rows": []},
                report={"imported": 0},
            )
        if isinstance(pack, dict) and isinstance(pack.get("pack"), dict):
            pack = pack["pack"]

        name = str(pack.get("name") or "").strip()
        source = str(pack.get("source") or "").strip()
        version = pack.get("version")
        rules = pack.get("rules")
        errs = []
        if not name or name.lower() in PLACEHOLDER_SOURCES:
            errs.append("pack.name 不能为空/占位")
        if source.lower() in PLACEHOLDER_SOURCES:
            errs.append("pack.source 必须是可核出处")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            errs.append("pack.version 必须是 >=1 的整数")
        if not isinstance(rules, list) or not rules:
            errs.append("pack.rules 必须是非空数组")

        db = load_db(path)
        cur_ver = int(db.get("db_version", 0) or 0)
        imported_versions = {p.get("version") for p in db.get("packs", [])}
        if isinstance(version, int) and version <= cur_ver:
            errs.append("版本必须大于当前库版本 %d（禁止降级）" % cur_ver)
        if isinstance(version, int) and version in imported_versions:
            errs.append("版本 %d 已导入过，禁止重复导入" % version)

        integrity = "not-provided"
        declared = str(pack.get("sha256") or "").strip().lower()
        if declared:
            if not re.fullmatch(r"[0-9a-f]{64}", declared):
                errs.append("sha256 字段必须是 64 位十六进制")
            elif isinstance(rules, list) and rules_sha256(rules) != declared:
                errs.append("完整性校验失败：规则内容与 sha256 不符（疑似篡改或下载不完整）；旧库未改动")
            else:
                integrity = "sha256-verified"
        if errs:
            return ActionResult(
                action=action_id, ok=False, show_dialog=True, title="导入规则包",
                message="规则包校验未通过：\n- " + "\n- ".join(errs),
                data={"rows": [{"id": "-", "type": "-", "level": "规则错误",
                                "path": pack_path, "value": e} for e in errs]},
                report={"imported": 0, "errors": errs},
            )

        perr, pstat, _pen = validate_db({"rules": rules})
        if perr:
            return ActionResult(
                action=action_id, ok=False, show_dialog=True, title="导入规则包",
                message="规则包内 %d 条规则校验失败，整包拒绝（不做部分导入）。\n%s"
                        % (len(perr), "；".join(perr[:6])),
                data={"rows": self._validate_rows(pstat, perr)},
                report={"imported": 0, "errors": perr},
            )

        backup = backup_db(path)
        old_ids = {r.get("id") for r in db.get("rules", []) if isinstance(r, dict)}
        new_ids = [r.get("id") for r in rules]
        replaced = len(old_ids & set(new_ids))
        merged = [r for r in db.get("rules", []) if r.get("id") not in set(new_ids)] + rules
        packs = list(db.get("packs", []))
        packs.append({
            "name": name, "version": version, "source": source,
            "updated_at": str(pack.get("updated_at") or ""),
            "sha256": _hash_file(pack_path),
            "rules_sha256": rules_sha256(rules),
            "integrity": integrity,
            "signature_verified": False,  # 无外部信任根/证书，不声称数字签名
            "imported_at": datetime.now().isoformat(),
            "rule_count": len(rules), "replaced": replaced,
        })
        new_db = {
            "schema_version": SCHEMA_VERSION, "_readme": CAUTION,
            "db_version": version,
            "updated_at": datetime.now().isoformat(),
            "packs": packs, "rules": merged,
        }
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(new_db, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        log("规则包已导入：v%d，规则 %d 条（替换 %d 条）。" % (version, len(rules), replaced))
        notice = ("完整性校验：SHA-256 通过" if integrity == "sha256-verified"
                  else "完整性提示：本包未提供 sha256，仅做版本与规则校验（无数字签名验证）")
        msg = ("规则包导入成功：%s v%d\n新增/更新 %d 条规则（替换同 id %d 条）；"
               "库版本 %d → %d。\n%s\n备份：%s"
               % (name, version, len(rules), replaced, cur_ver, version,
                  notice, backup or "(原库为空，无备份)"))
        return ActionResult(
            action=action_id, message=msg, title="导入规则包", show_dialog=True,
            data={"rows": [{"id": "-", "type": "-", "level": "信息",
                            "path": path, "value": msg}]},
            report={"imported": 1, "pack": name, "version": version,
                    "rule_count": len(rules), "replaced": replaced,
                    "db_version": version, "backup": backup, "sha256": packs[-1]["sha256"],
                    "integrity": integrity, "signature_verified": False},
        )
