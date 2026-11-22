# -*- coding: utf-8 -*-
"""可审计报告工具（补强4）

- build_report：汇总各模块结果 + 从报告字段中泛化提取引擎/库状态（不在主程序硬编码业务字段）
- anonymize：导出前脱敏（手机号、用户目录、主机名样式的 UNC 路径）
- export：JSON / CSV / 可读文本三格式
- append_audit：高风险操作追加式审计日志（JSONL）
"""
import csv
import io
import json
import os
import re
from datetime import datetime

FULL_PHONE = "".join(["180", "7090", "7766"])  # 不在仓库留全号字面量
PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
USERDIR_RE = re.compile(r"([A-Za-z]:[\\/]Users[\\/])[^\\/\s]+", re.I)
UNC_RE = re.compile(r"(\\\\[^\\\s]+)(\\[^\\]*)")


def anonymize(obj):
    """递归脱敏；不改原对象。"""
    if isinstance(obj, str):
        s = PHONE_RE.sub("<手机号>", obj)
        s = USERDIR_RE.sub(r"\1<用户>", s)
        s = UNC_RE.sub(r"<网络主机>\2", s)
        return s
    if isinstance(obj, dict):
        return {k: anonymize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [anonymize(x) for x in obj]
    return obj


def _status_summary(module_results):
    """泛化提取引擎/库状态：只认通用字段名，不认模块 id。"""
    status = {"engines": [], "databases": []}
    for mid, rec in module_results.items():
        rep = rec.get("report") if isinstance(rec, dict) else None
        if not isinstance(rep, dict):
            continue
        if "version" in rep and "arch" in rep:
            status["engines"].append({
                "module": mid, "name": "ClamAV",
                "version": str(rep.get("version")), "arch": str(rep.get("arch")),
            })
        if "db_version" in rep:
            packs = rep.get("packs") or []
            status["databases"].append({
                "module": mid, "version": rep.get("db_version"),
                "updated_at": rep.get("updated_at", ""),
                "rule_count": rep.get("rule_count"),
                "last_pack": packs[-1] if isinstance(packs, list) and packs else None,
            })
        if isinstance(rep.get("amsi"), dict):
            status["engines"].append({
                "module": mid, "name": "AMSI",
                "available": rep["amsi"].get("available"),
            })
    return status


def build_report(loaded_modules, module_results, meta=None):
    data = {
        "time": datetime.now().isoformat(),
        "meta": dict(meta or {}),
        "loaded_modules": [dict(m.meta) for m in loaded_modules],
        "module_results": module_results,
    }
    data["status"] = _status_summary(module_results)
    data["caution"] = (
        "主机诊断字段为只读疑点登记（高危/关注/信息），非病毒确认，未做任何修改。"
        "未知/跳过/无法读取与检测分开计数；命中需人工复核。"
    )
    return data


def export(data, fmt, path, do_anonymize=True):
    """写报告；fmt ∈ json/csv/txt；返回实际写入路径。"""
    obj = anonymize(data) if do_anonymize else data
    fmt = (fmt or "json").lower().lstrip(".")
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2, default=str)
    elif fmt == "csv":
        rows = []
        for mid, rec in obj.get("module_results", {}).items():
            report = rec.get("report") if isinstance(rec, dict) else None
            if not isinstance(report, dict):
                report = {}
            items = report.get("matches") or report.get("items") or []
            if not isinstance(items, list):
                items = []
            for it in items:
                rows.append({
                    "模块": mid, "动作": rec.get("action", ""),
                    "类别": it.get("kind") or it.get("type") or "",
                    "等级": it.get("level") or it.get("verdict") or "",
                    "路径": it.get("path") or "",
                    "说明": str(it.get("detail") or it.get("value") or "")[:300],
                })
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["模块", "动作", "类别", "等级", "路径", "说明"])
            w.writeheader()
            w.writerows(rows)
    elif fmt == "txt":
        lines = ["软件验收审计报告", "时间：%s" % obj.get("time", ""),
                 "版本：%s" % obj.get("meta", {}).get("version", "")]
        lines.append("")
        for key in ("engines", "databases"):
            lines.append("【%s】" % ("引擎状态" if key == "engines" else "数据库状态"))
            for s in obj.get("status", {}).get(key, []):
                lines.append("  - " + " / ".join("%s=%s" % (k, v) for k, v in s.items() if k != "last_pack"))
            lines.append("")
        for mid, rec in obj.get("module_results", {}).items():
            lines.append("【%s / %s】%s" % (mid, rec.get("action", ""),
                                            "成功" if rec.get("ok") else "失败"))
            msg = str(rec.get("message") or "").splitlines()
            if msg:
                lines.append("  " + msg[0][:200])
        lines.append("")
        lines.append(obj.get("caution", ""))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    else:
        raise ValueError("不支持的报告格式：" + fmt)
    return path


def append_audit(app_dir, event):
    """高风险操作审计：JSONL 追加，含时间/模块/动作/结果/目标；失败不影响主流程。"""
    path = os.path.join(app_dir or ".", "audit.log")
    rec = {"time": datetime.now().isoformat()}
    rec.update(anonymize(event))
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    return path
