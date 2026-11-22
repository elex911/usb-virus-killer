# -*- coding: utf-8 -*-
"""
模块化主程序
------------
本文件只负责：加载模块 -> 生成按钮/标签页 -> 调度模块 -> 汇总报告。
不认识任何具体病毒判据；新增功能只需添加模块，无需修改这里。
"""
import json
import os
import queue
import threading
import traceback
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from .api import ActionResult, Context
from .registry import app_dir, load_modules
from . import report_tools
from . import iso_writer as report_tools_iso

APP_TITLE = "模块化病毒查杀工具"
APP_VER = "2.0"


class App:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE + "  v" + APP_VER)
        self.root.geometry("1020x700")
        self.root.minsize(860, 580)

        self.modules, self.module_errors = load_modules()
        self.module_by_id = {}
        for m in self.modules:
            self.module_by_id[m.meta.get("id")] = m

        self.ctx = Context(app_dir=app_dir())
        self.q = queue.Queue()
        self.views = {}
        self.results = {}
        self.all_buttons = []
        self.busy = False

        self._build_ui()
        self._refresh_drives()
        self._log("已加载 %d 个模块：%s" % (
            len(self.modules), "、".join(m.meta.get("name", m.meta["id"]) for m in self.modules)
        ))
        for name, err in self.module_errors:
            self._log("[模块加载失败] %s：%s" % (name, err))
        if self.module_errors:
            self.status.configure(text="有 %d 个模块加载失败，详见日志" % len(self.module_errors),
                                  foreground="#b8860b")
        self.root.after(120, self._poll)

    # ---------- UI ----------
    def _build_ui(self):
        frm = ttk.Frame(self.root, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="模块化病毒查杀工具", font=("Microsoft YaHei UI", 16, "bold")).pack(anchor="w")
        ttk.Label(
            frm,
            text="功能全部由模块提供：U盘查杀、主机诊断……后续新增功能只需放入 plugins 目录的模块文件。",
            foreground="#555",
        ).pack(anchor="w", pady=(2, 10))

        top = ttk.LabelFrame(frm, text="目标位置（文件类模块使用）", padding=10)
        top.pack(fill="x")
        self.target = tk.StringVar()
        self.cb = ttk.Combobox(top, textvariable=self.target, width=52)
        self.cb.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Button(top, text="刷新盘符", command=self._refresh_drives).grid(row=0, column=1, padx=4)
        ttk.Button(top, text="选择目录…", command=self._pick_dir).grid(row=0, column=2, padx=4)
        self.allow_fixed = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            top, text="允许固定磁盘（移动硬盘被误识别时勾选）",
            variable=self.allow_fixed,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        top.columnconfigure(0, weight=1)
        self.info = ttk.Label(top, text="当前无 U 盘插入；可先选目录做扫描测试。", foreground="#888")
        self.info.grid(row=2, column=0, columnspan=3, sticky="w", pady=(4, 0))

        # 操作区：完全由模块的 actions() 生成
        action_area = ttk.Frame(frm)
        action_area.pack(fill="x", pady=(10, 0))
        action_modules = [m for m in self.modules if m.actions()]
        cols = min(3, max(1, len(action_modules)))
        for idx, mod in enumerate(action_modules):
            box = ttk.LabelFrame(action_area, text=mod.meta.get("name", mod.meta["id"]), padding=8)
            box.grid(row=idx // cols, column=idx % cols, sticky="nsew", padx=(0, 8), pady=(0, 8))
            for j, act in enumerate(sorted(mod.actions(), key=lambda a: a.order)):
                btn = ttk.Button(
                    box, text=act.label,
                    command=lambda mid=mod.meta["id"], aid=act.id: self._run(mid, aid),
                )
                # danger 仅作模块声明；当前 ttk 主题不统一支持按钮前景色，不强改主题。
                btn.grid(row=j // 2, column=j % 2, sticky="w", padx=(0, 6), pady=(0, 4))
                self.all_buttons.append(btn)

        global_box = ttk.LabelFrame(action_area, text="通用", padding=8)
        grow = (len(action_modules) + cols - 1) // cols
        global_box.grid(row=grow, column=0, sticky="w", padx=(0, 8), pady=(0, 8))
        self.b_export = ttk.Button(global_box, text="导出报告", command=self._export)
        self.b_export.grid(row=0, column=0, sticky="w")
        self.b_iso = ttk.Button(global_box, text="生成报告ISO", command=self._export_iso)
        self.b_iso.grid(row=0, column=1, sticky="w", padx=(6, 0))
        self.all_buttons.extend([self.b_export, self.b_iso])

        # 标签页：完全由模块的 build_view() 生成
        self.nb = ttk.Notebook(frm)
        self.nb.pack(fill=tk.BOTH, expand=True)
        for mod in self.modules:
            tab = ttk.Frame(self.nb, padding=8)
            view = None
            try:
                view = mod.build_view(tab, self.ctx)
            except Exception as exc:
                ttk.Label(tab, text="模块视图加载失败：%s" % exc, foreground="#c0392b").pack(anchor="w")
            if view is not None:
                self.views[mod.meta["id"]] = view
            self.nb.add(tab, text=mod.meta.get("tab") or mod.meta.get("name", mod.meta["id"]))

        logf = ttk.LabelFrame(frm, text="日志", padding=6)
        logf.pack(fill="x", pady=(10, 0))
        self.log = scrolled_text = tk.Text(logf, height=6, font=("Consolas", 10), state="disabled")
        scrolled_text.pack(fill="x")
        sb = ttk.Scrollbar(logf, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.status = ttk.Label(frm, text="就绪", foreground="#2c7")
        self.status.pack(anchor="w", pady=(4, 0))
        ttk.Label(
            frm,
            text="作者：军不见    电话：180******66",
            foreground="#888",
        ).pack(anchor="w")

    def _refresh_drives(self):
        targets = []
        seen = set()
        for mod in self.modules:
            try:
                suggested = mod.suggest_targets() or []
            except Exception as exc:
                # 静默吞掉会让"为什么下拉框是空的"无法诊断，记录后继续
                self._log("[盘符] %s 候选获取失败：%s" % (mod.meta.get("id"), exc))
                continue
            for item in suggested:
                # 多个模块都会给出同一批盘符，按规范化文本去重，避免下拉框重复项
                key = " ".join(str(item).split()).lower()
                if not key or key in seen:
                    continue
                seen.add(key)
                targets.append(item)
        hints = []
        for mod in self.modules:
            try:
                h = mod.target_hint(len(targets))
            except Exception as exc:
                self._log("[盘符] %s 提示获取失败：%s" % (mod.meta.get("id"), exc))
                continue
            if h and h not in hints:
                hints.append(h)
        self.cb["values"] = targets
        if targets and not self.target.get():
            self.target.set(targets[0].split()[0])
        self.info.configure(text="；".join(hints) if hints else "未发现可处理盘符；可先选目录做测试。")

    def _pick_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.target.set(d)

    def _log(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", str(msg) + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_busy(self, busy):
        self.busy = busy
        state = "disabled" if busy else "normal"
        for b in self.all_buttons:
            b.configure(state=state)
        self.status.configure(
            text="处理中…" if busy else "就绪",
            foreground="#b8860b" if busy else "#2c7",
        )

    # ---------- 调度 ----------
    def _run(self, module_id, action_id):
        if self.busy:
            return
        mod = self.module_by_id.get(module_id)
        if mod is None:
            messagebox.showerror("错误", "模块不存在：" + module_id)
            return
        action = next((a for a in mod.actions() if a.id == action_id), None)
        if action is None:
            messagebox.showerror("错误", "模块 %s 不存在操作 %s" % (module_id, action_id))
            return

        if action.target_mode == "required":
            try:
                ok = mod.prepare_context(self.ctx, self.target.get(), self.allow_fixed.get())
            except Exception as exc:
                messagebox.showerror("错误", "目标解析失败：" + str(exc))
                return
            if not ok:
                messagebox.showerror("错误", "请先选择目标盘符或目录。")
                return
        else:
            self.ctx.target = ""
            self.ctx.is_drive = False
            self.ctx.allow_fixed = bool(self.allow_fixed.get())

        # 先取目标再确认：确认框可依据 ctx.pick 显示动态摘要（如回滚清单）
        self.ctx.pick = ""
        if action.prompt == "directory":
            pick = filedialog.askdirectory(title=action.prompt_title or "选择目录")
            if not pick:
                return
            self.ctx.pick = pick
        elif action.prompt == "file":
            pick = filedialog.askopenfilename(
                title=action.prompt_title or "选择文件",
                filetypes=[("规则包 JSON", "*.json"), ("所有文件", "*.*")],
            )
            if not pick:
                return
            self.ctx.pick = pick

        confirm = action.confirm
        try:
            dynamic = mod.action_confirm(action.id, self.ctx, lambda m: self._log(m))
            if dynamic:
                confirm = dynamic
        except Exception as exc:
            self._log("动态确认生成失败，沿用静态确认：%s" % exc)
        if confirm and not messagebox.askyesno("确认", confirm):
            return

        self._set_busy(True)
        threading.Thread(target=self._worker, args=(mod, action), daemon=True).start()

    def _worker(self, mod, action):
        def log(m):
            self.q.put(("log", str(m)))

        try:
            res = mod.run(action.id, self.ctx, log)
            if not isinstance(res, ActionResult):
                if isinstance(res, dict):
                    res = ActionResult(data=res)
                else:
                    res = ActionResult(data={}, message="" if res is None else str(res))
            res.action = action.id
            for line in res.logs:
                log(line)
            self.q.put(("result", mod.meta["id"], action.id, res))
        except Exception as exc:
            self.q.put(("log", traceback.format_exc()))
            self.q.put(("error", "%s / %s：%s" % (
                mod.meta.get("name", mod.meta["id"]), action.label, exc,
            )))

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "log":
                    self._log(msg[1])
                elif kind == "error":
                    self._log("[错误] " + msg[1])
                    messagebox.showerror("错误", msg[1])
                    self._set_busy(False)
                elif kind == "result":
                    _, mid, action_id, res = msg
                    mod = self.module_by_id.get(mid)
                    view = self.views.get(mid)
                    if mod is not None and view is not None:
                        try:
                            mod.render(action_id, res, view, self.ctx)
                        except Exception as exc:
                            self._log("[渲染失败] %s：%s" % (mid, exc))
                    self.results[mid] = {
                        "time": datetime.now().isoformat(),
                        "module": mod.meta.get("name", mid) if mod else mid,
                        "action": action_id,
                        "result": res,
                    }
                    # 高风险操作写追加式审计日志（脱敏）；失败只记日志不影响主流程
                    try:
                        danger = any(a.id == action_id and a.danger for a in (mod.actions() if mod else []))
                        if danger:
                            report_tools.append_audit(self.ctx.app_dir, {
                                "module": mod.meta.get("name", mid) if mod else mid,
                                "action": action_id, "ok": res.ok,
                                "target": self.ctx.target or self.ctx.pick,
                                "summary": (res.message or "").splitlines()[:1],
                            })
                    except Exception as exc:
                        self._log("[审计日志失败] %s" % exc)
                    if res.message and res.show_dialog:
                        title = res.title or (mod.meta.get("name", mid) if mod else "提示")
                        if res.ok:
                            messagebox.showinfo(title, res.message)
                        else:
                            messagebox.showwarning(title, res.message)
                    elif res.message and not res.ok:
                        messagebox.showwarning(mod.meta.get("name", mid) if mod else "提示", res.message)
                    short = res.message.splitlines()[0] if res.message else "完成"
                    self.status.configure(text="最近完成：%s" % short[:60], foreground="#2c7")
                    self._set_busy(False)
        except queue.Empty:
            pass
        except Exception:
            # 任何未预期异常都不能断掉轮询链（否则界面假死），记录后继续调度
            try:
                self._log("[内部] 轮询处理异常：\n" + traceback.format_exc())
            except Exception:
                pass
        finally:
            self.root.after(120, self._poll)

    # ---------- 报告 ----------
    def _export(self):
        if not self.results:
            messagebox.showinfo("提示", "请先执行任一模块的扫描或诊断。")
            return
        f = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON 报告", "*.json"), ("CSV 清单", "*.csv"), ("文本摘要", "*.txt")],
        )
        if not f:
            return
        fmt = os.path.splitext(f)[1].lower().lstrip(".") or "json"
        do_mask = messagebox.askyesno("脱敏", "导出前脱敏手机号与用户目录？（建议：对外分享时选是）")

        module_results = {}
        data = {}
        # 各模块经契约钩子自行声明要提升到报告顶层的字段（如 v1.x 兼容字段）；
        # 主程序不认识具体字段名
        for mid, rec in self.results.items():
            res = rec["result"]
            module_results[mid] = {
                "module": rec["module"],
                "action": rec["action"],
                "time": rec["time"],
                "ok": res.ok,
                "message": res.message,
                "report": res.report if res.report is not None else res.data,
            }
            mod = self.module_by_id.get(mid)
            if mod is None:
                continue
            try:
                extra = mod.report_export(res)
            except Exception as exc:
                self._log("[报告导出] %s：%s" % (mid, exc))
                continue
            if isinstance(extra, dict):
                data.update(extra)

        data.update(report_tools.build_report(
            self.modules, module_results,
            {"version": APP_VER, "target": self.ctx.target},
        ))
        try:
            report_tools.export(data, fmt, f, do_anonymize=bool(do_mask))
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))
            return
        self._log("报告已导出（%s%s）：%s" % (fmt.upper(), "·已脱敏" if do_mask else "", f))


    def _export_iso(self):
        src = filedialog.askdirectory(title="选择存放报告文件的目录（仅内容刻录，非引导盘）")
        if not src:
            return
        out = filedialog.asksaveasfilename(
            title="保存报告 ISO", defaultextension=".iso", filetypes=[("ISO 镜像", "*.iso")])
        if not out:
            return
        try:
            r = report_tools_iso.build_iso(src, out)
        except Exception as exc:
            messagebox.showerror("生成 ISO 失败", str(exc))
            return
        messagebox.showinfo(
            "报告 ISO 已生成",
            "文件：%s\n大小：%.1f MiB\n报告文件：%d 个\nSHA-256：%s\n\n"
            "这是数据光盘镜像（内容刻录），不是启动盘；引导需完整 WinPE 环境。"
            % (r["path"], r["size"] / 1048576, r["files"], r["sha256"]),
        )
        self._log("报告 ISO 已生成：" + r["path"])


def main():
    root = tk.Tk()
    try:
        root.iconbitmap(default="")
    except Exception:
        pass
    App(root)
    root.mainloop()
