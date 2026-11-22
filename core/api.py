# -*- coding: utf-8 -*-
"""
模块接口定义
------------
所有功能模块的契约都在这里。新增功能时只需要新建一个模块类：
  1. 继承 ModuleBase；
  2. 声明 meta（id/name/version/description/order）；
  3. 实现 actions() 与 run()；
  4. 可选实现 build_view() / render() / detail() / prepare_context() / suggest_targets()。

主程序不认识具体业务，只按这份契约调度模块。
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Action:
    """模块对外暴露的一个操作按钮。"""

    id: str
    label: str
    confirm: Optional[str] = None          # 执行前确认文本；None 表示不确认
    target_mode: str = "required"          # required=必须有目标；none=不需要目标
    danger: bool = False                   # 仅用于界面着色提示，不控制权限
    order: int = 100
    prompt: str = ""                       # "directory"：先选目录；"file"：先选文件（主线程完成）
    prompt_title: str = ""


@dataclass
class ActionResult:
    """模块执行结果。模块返回本对象或普通 dict 均可。"""

    action: str = ""
    ok: bool = True
    message: str = ""
    title: str = ""
    show_dialog: bool = False
    data: Dict[str, Any] = field(default_factory=dict)
    report: Optional[Dict[str, Any]] = None
    logs: List[str] = field(default_factory=list)


@dataclass
class Context:
    """主程序传给模块的只读上下文（字段可由模块读取，不应反向操作 UI）。"""

    target: str = ""
    is_drive: bool = False
    allow_fixed: bool = True   # 本地固定磁盘与系统盘默认可查杀；处置另有护栏
    app_dir: str = ""
    pick: str = ""                         # 由 Action.prompt=directory 预选的目录
    settings: Dict[str, Any] = field(default_factory=dict)


class ModuleBase:
    """所有功能模块的基类。"""

    meta: Dict[str, Any] = {
        "id": "base",
        "name": "基础模块",
        "version": "0.0",
        "description": "",
        "order": 999,
    }

    def actions(self) -> List[Action]:
        return []

    def prepare_context(self, ctx: Context, raw_target: str, allow_fixed: bool = True) -> bool:
        """把界面上的目标文本解析进 ctx。返回 False 表示目标无效。"""
        ctx.target = (raw_target or "").strip().strip('"')
        ctx.is_drive = False
        ctx.allow_fixed = bool(allow_fixed)
        return bool(ctx.target)

    def suggest_targets(self) -> List[str]:
        """给「目标位置」下拉框提供候选（如盘符列表）。"""
        return []

    def target_hint(self, count: int) -> str:
        return ""

    def build_view(self, parent, ctx: Context):
        """返回一个 tkinter Widget 作为本模块标签页内容；返回 None 表示不需要标签页。"""
        return None

    def render(self, action_id: str, result: ActionResult, view, ctx: Context) -> None:
        """在主线程把结果渲染到 build_view 返回的控件上。"""
        return None

    def detail(self, row: Dict[str, Any]) -> str:
        """表格双击详情文本。"""
        return "\n".join("%s：%s" % (k, v) for k, v in row.items())

    def action_confirm(self, action_id: str, ctx: Context, log=lambda m: None):
        """执行前动态确认文本（主线程调用）；None 表示沿用 Action.confirm 静态文本。

        用于需要在确认框展示真实数据摘要的动作（如回滚前显示隔离清单）。
        """
        return None

    def report_export(self, result: "ActionResult") -> Dict[str, Any]:
        """导出 JSON 报告时本模块贡献的顶层字段；默认不贡献任何字段。

        需要保持 v1.x 报告兼容的模块覆写本方法（如 folder_virus 的
        root/meta/items/hidden_items）。主程序不认识具体字段名。
        """
        return {}
