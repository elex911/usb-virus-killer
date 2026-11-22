"""单文件离线 HTML 报告（内联 CSS/JS，断网可看，无外部依赖）。

必须出现在报告里的三样东西（缺一样就是失真）：
1. **解析失败分区**——跳过不等于干净；
2. **各项能力的真实状态**（编录是否可用、吊销是否启用、YARA 是否启用）；
3. **隔离区加密强度的边界说明**——不防有盘写权限者。
"""

from __future__ import annotations

import html
import os
import time
from typing import Dict, List, Optional

MAX_ROWS = 3000     # 防止报告本身把内存/浏览器拖死


def _e(val) -> str:
    if val is None:
        return "-"
    return html.escape(str(val), quote=True)


def _rows(items, cols, renderer):
    out = []
    for it in items[:MAX_ROWS]:
        out.append("<tr>" + "".join("<td>%s</td>" % renderer(it, c) for c in cols) + "</tr>")
    if not items:
        out.append('<tr><td colspan="%d" class="empty">无记录</td></tr>' % len(cols))
    return "\n".join(out)


def _badge(level: str) -> str:
    cls = {"黑": "bad", "白": "ok", "灰": "warn"}.get(level, "warn")
    name = {"黑": "确证恶意", "白": "白名单", "灰": "待复核"}.get(level, level)
    return '<span class="badge %s">%s</span>' % (cls, _e(name))


def generate(path: str, summary, index=None, revocation=None,
             pending_notes: Optional[List[str]] = None,
             meta: Optional[Dict[str, str]] = None) -> str:
    meta = meta or {}
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    blacks = [r for r in summary.results if r.level == "黑"]
    whites = [r for r in summary.results if r.level == "白"]
    grays = [r for r in summary.results if r.level == "灰"]
    errors = summary.errors

    q_items: List[object] = []
    if summary.quarantine_status and "（" in summary.quarantine_status:
        pass
    q_items = meta.get("quarantine_items") or []

    def cell(it, col):
        if col == "level":
            return _badge(getattr(it, "level", ""))
        if col == "path":
            return '<span class="mono">%s</span>' % _e(getattr(it, "path", ""))
        if col == "size":
            n = getattr(it, "size", 0) or 0
            return "%.1f KB" % (n / 1024.0) if n < 1024 * 1024 else "%.1f MB" % (n / 1048576.0)
        if col == "basis":
            return _e(getattr(it, "basis", "") or "-")
        if col == "reasons":
            rs = getattr(it, "reasons", []) or []
            return "; ".join(_e(x) for x in rs[:4])
        if col == "rules":
            rs = getattr(it, "rules", []) or []
            return " ".join('<span class="badge bad">%s</span>' % _e(x) for x in rs) or "-"
        if col == "action":
            act = getattr(it, "action", "") or "-"
            qid = getattr(it, "quarantine_id", "")
            return _e(act) + ("<br><span class=\"mono muted\">%s</span>" % _e(qid) if qid else "")
        if col == "error":
            return _e(getattr(it, "error", ""))
        if col == "sha256":
            return '<span class="mono">%s</span>' % _e(getattr(it, "sha256", "") or "-")
        if col == "original":
            return '<span class="mono">%s</span>' % _e(getattr(it, "original_path", ""))
        if col == "status":
            return _e(getattr(it, "status", ""))
        if col == "created":
            return _e(getattr(it, "created", ""))
        if col == "id":
            return '<span class="mono">%s</span>' % _e(getattr(it, "id", ""))
        if col == "psource":
            return _e(getattr(it, "source", "") or "-")
        if col == "pname":
            return _e(getattr(it, "name", "") or "-")
        if col == "praw":
            raw = getattr(it, "raw", "") or ""
            return '<span class="mono">%s</span>' % _e(raw[:160] or "-")
        if col == "ptarget":
            tgt = getattr(it, "target", "") or ""
            exists = getattr(it, "exists", None)
            mark = "" if exists is None else (" ✓" if exists else " ✗不存在")
            return '<span class="mono">%s</span>%s' % (_e(tgt or "-"), _e(mark))
        if col == "plevel":
            lv = getattr(it, "level", "")
            if not lv:
                return '<span class="badge warn">未关联</span>'
            return _badge(lv)
        return _e(str(getattr(it, col, "-")))

    wl = index.summary() if index is not None else "未建立编录索引"
    rv = revocation.summary() if revocation is not None else "吊销检查未启用"
    notes = pending_notes or []

    doc = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PortableAV 离线取证报告 %(ts)s</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--bd:#334155;--fg:#e2e8f0;--mut:#94a3b8;--ok:#10b981;--warn:#f59e0b;--bad:#ef4444}
*{box-sizing:border-box}
body{margin:0;padding:22px;background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
h1{font-size:20px;margin:0 0 4px}
.wrap{max-width:1400px;margin:0 auto}
.sub{color:var(--mut);font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px}
.card .k{color:var(--mut);font-size:12px}
.card .v{font-size:22px;font-weight:700}
.v.bad{color:var(--bad)}.v.ok{color:var(--ok)}.v.warn{color:var(--warn)}
.panel{background:var(--card);border:1px solid var(--bd);border-radius:8px;margin:16px 0;overflow:hidden}
.panel h2{font-size:15px;margin:0;padding:11px 14px;border-bottom:1px solid var(--bd);background:rgba(255,255,255,.03)}
.panel .body{padding:0}
table{width:100%%;border-collapse:collapse}
th,td{padding:9px 12px;border-bottom:1px solid var(--bd);vertical-align:top;text-align:left}
th{color:var(--mut);font-size:12px;white-space:nowrap}
tr:hover td{background:rgba(56,189,248,.05)}
.mono{font-family:Consolas,monospace;font-size:12.5px;word-break:break-all}
.muted{color:var(--mut)}
.badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:12px;font-weight:600}
.badge.bad{background:rgba(239,68,68,.2);color:#fca5a5}
.badge.warn{background:rgba(245,158,11,.2);color:#fcd34d}
.badge.ok{background:rgba(16,185,129,.18);color:#6ee7b7}
.empty{text-align:center;color:var(--mut);padding:18px}
.notice{border-left:3px solid var(--warn);padding:10px 14px;margin:12px 0;background:rgba(245,158,11,.08)}
ul{margin:6px 0 0 18px}
</style></head><body><div class="wrap">
<h1>PortableAV 离线取证报告</h1>
<div class="sub">目标：%(root)s ｜ 模式：%(mode)s ｜ 生成时间：%(ts)s ｜ 耗时：%(elapsed).2fs</div>

<div class="notice"><b>能力边界（务必先读）</b>
<ul>
<li>隔离区使用 AES-256-GCM，但主密钥保存在同一介质；能读该介质的人仍可解密。它防的是误执行、静态查杀误报与随手拷走。</li>
<li>白名单仅对「当前文件」生效，不覆盖同目录其他文件（防白加黑侧加载）。</li>
<li>「解析失败」分区里的文件<b>没有被检查</b>，不能视为干净。</li>
</ul></div>

<div class="cards">
<div class="card"><div class="k">确证恶意（黑）</div><div class="v bad">%(n_black)d</div></div>
<div class="card"><div class="k">白名单放行</div><div class="v ok">%(n_white)d</div></div>
<div class="card"><div class="k">待复核（灰）</div><div class="v warn">%(n_gray)d</div></div>
<div class="card"><div class="k">解析失败</div><div class="v %(err_cls)s">%(n_err)d</div></div>
<div class="card"><div class="k">已扫描 / 见到</div><div class="v">%(scanned)d / %(seen)d</div></div>
</div>

<div class="panel"><h2>检测能力状态</h2><div class="body"><table>
<tr><th>编录白名单</th><td>%(wl)s</td></tr>
<tr><th>吊销检查</th><td>%(rv)s</td></tr>
<tr><th>规则引擎</th><td>%(mt)s</td></tr>
<tr><th>隔离区</th><td>%(qs)s</td></tr>
<tr><th>跳过的链接/超大/后缀</th><td>%(skip_link)d / %(skip_big)d / %(skip_ext)d %(trunc)s</td></tr>
</table>%(notes)s</div></div>

<div class="panel"><h2>1. 确证恶意（%(n_black)d）</h2><div class="body"><table>
<thead><tr><th>判定</th><th>命中规则</th><th>文件</th><th>处置</th></tr></thead>
<tbody>%(rows_black)s</tbody></table></div></div>

<div class="panel"><h2>2. 白名单放行（%(n_white)d，仅列前 %(max)d 条）</h2><div class="body"><table>
<thead><tr><th>判定</th><th>依据</th><th>文件</th><th>说明</th></tr></thead>
<tbody>%(rows_white)s</tbody></table></div></div>

<div class="panel"><h2>3. 待复核（%(n_gray)d，仅列前 %(max)d 条）</h2><div class="body"><table>
<thead><tr><th>判定</th><th>原因</th><th>文件</th><th>SHA-256</th></tr></thead>
<tbody>%(rows_gray)s</tbody></table></div></div>

<div class="panel"><h2>4. 解析失败 / 读取失败（%(n_err)d）—— 这些文件没有被检查</h2><div class="body"><table>
<thead><tr><th>错误</th><th>文件</th></tr></thead>
<tbody>%(rows_err)s</tbody></table></div></div>

<div class="panel"><h2>5. 持久化矩阵（%(n_p)d）—— 与扫描结果的关联</h2><div class="body"><table>
<thead><tr><th>关联</th><th>来源</th><th>名称</th><th>命令</th><th>解析到的目标</th></tr></thead>
<tbody>%(rows_p)s</tbody></table>%(perr)s</div></div>

<div class="panel"><h2>6. 隔离区清单（%(n_q)d）</h2><div class="body"><table>
<thead><tr><th>ID</th><th>状态</th><th>时间</th><th>原路径</th><th>SHA-256</th></tr></thead>
<tbody>%(rows_q)s</tbody></table></div></div>

<div class="panel"><h2>7. 扫描参数与取证影响</h2><div class="body"><table>
<tr><th>单文件上限</th><td>%(lim_size)s</td></tr>
<tr><th>最大深度</th><td>%(lim_depth)s</td></tr>
<tr><th>线程</th><td>%(workers)s</td></tr>
<tr><th>工作目录</th><td class="mono">%(workdir)s</td></tr>
<tr><th>取证影响</th><td>%(evnote)s</td></tr>
</table></div></div>
</div></body></html>
""" % {
        "ts": _e(time.strftime("%Y-%m-%d %H:%M:%S")),
        "root": _e(summary.root),
        "mode": _e(meta.get("mode", "离线取证模式")),
        "elapsed": summary.elapsed,
        "n_black": len(blacks), "n_white": len(whites), "n_gray": len(grays),
        "n_err": len(errors), "err_cls": "bad" if errors else "",
        "scanned": summary.files_scanned, "seen": summary.files_seen,
        "wl": _e(wl), "rv": _e(rv), "mt": _e(summary.matcher_status or "未启用"),
        "qs": _e(summary.quarantine_status or "未启用"),
        "skip_link": summary.skipped_link, "skip_big": summary.skipped_big,
        "skip_ext": summary.skipped_ext,
        "trunc": "（已达文件数上限，结果被截断）" if summary.truncated else "",
        "notes": ("<tr><th>一致性修复</th><td>%s</td></tr>"
                  % "<br>".join(_e(n) for n in notes)) if notes else "",
        "rows_black": _rows(blacks, ["level", "rules", "path", "action"], cell),
        "rows_white": _rows(whites, ["level", "basis", "path", "reasons"], cell),
        "rows_gray": _rows(grays, ["level", "reasons", "path", "sha256"], cell),
        "rows_err": _rows(errors, ["error", "path"], cell),
        "rows_q": _rows(q_items, ["id", "status", "created", "original", "sha256"], cell),
        "n_q": len(q_items),
        "rows_p": _rows(meta.get("persistence_items") or [],
                        ["plevel", "psource", "pname", "praw", "ptarget"], cell),
        "n_p": len(meta.get("persistence_items") or []),
        "perr": ("<div class=\"notice\" style=\"margin:10px 14px\">持久化解析问题：%s</div>"
                 % "<br>".join(_e(x) for x in (meta.get("persist_errors") or [])[:20]))
                if meta.get("persist_errors") else "",
        "max": MAX_ROWS,
        "lim_size": "%d MB" % (meta.get("max_file_mb", 100)),
        "lim_depth": _e(meta.get("max_depth", "-")),
        "workers": _e(meta.get("workers", "-")),
        "workdir": _e(meta.get("workdir", "-")),
        "evnote": _e(meta.get("evidence_note", "未记录")),
    }
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(doc)
    return path
