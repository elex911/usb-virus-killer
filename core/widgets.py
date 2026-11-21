# -*- coding: utf-8 -*-
"""给模块复用的通用结果表格控件。"""
import tkinter as tk
from tkinter import ttk


class ResultTable(ttk.Frame):
    """
    参数：
      columns: [(key, 表头, 宽度), ...]
      tag_key: 用哪一列的值做着色标签（如 verdict / level）
      tag_map: {值: 前景色}
      caution: 表格上方提示语
      on_detail: 双击行回调，接收该行 dict
    """

    def __init__(self, master, columns, tag_key="verdict", tag_map=None,
                 caution="", on_detail=None, height=12):
        super().__init__(master)
        self.columns = list(columns)
        self.tag_key = tag_key
        self.rows = []
        self.on_detail = on_detail

        if caution:
            ttk.Label(self, text=caution, foreground="#b8860b", wraplength=780,
                      justify="left").pack(anchor="w", pady=(0, 6))

        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True)
        self.tv = ttk.Treeview(
            wrap,
            columns=tuple(c[0] for c in self.columns),
            show="headings",
            height=height,
        )
        for key, text, width in self.columns:
            self.tv.heading(key, text=text)
            self.tv.column(key, width=width, anchor="w")
        for value, color in (tag_map or {}).items():
            self.tv.tag_configure(value, foreground=color)

        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=vs.set)
        self.tv.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tv.bind("<Double-1>", self._on_double)

    def set_rows(self, rows):
        self.rows = list(rows or [])
        self.tv.delete(*self.tv.get_children())
        for row in self.rows:
            values = tuple(str(row.get(c[0], "")) for c in self.columns)
            tag_value = str(row.get(self.tag_key, ""))
            tags = (tag_value,) if tag_value in self.tv.tag_names() else ()
            self.tv.insert("", "end", values=values, tags=tags)

    def _on_double(self, event=None):
        if not self.on_detail:
            return
        sel = self.tv.selection()
        if not sel:
            return
        i = self.tv.index(sel[0])
        if 0 <= i < len(self.rows):
            self.on_detail(self.rows[i])
