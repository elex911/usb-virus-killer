# -*- coding: utf-8 -*-
"""
模块注册表
----------
内置模块：随程序一起打包，稳定可靠。
外部模块：放到程序目录下的 plugins\\*.py，启动时自动加载，无需改主程序。
"""
import glob
import importlib
import inspect
import os
import sys
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader

from .api import ModuleBase

# 新增内置功能时，只在这里加一行 import 路径；主程序无需改动。
BUILTIN_MODULES = (
    "modules.folder_virus",
    "modules.classic_trojans",
    "modules.host_diagnostics",
    "modules.signature_db",
    "modules.clamav_bridge",
    "modules.modern_threats",
    "modules.amsi_scan",
)


def app_dir():
    """程序根目录：源码运行时为项目目录；打包后为 exe 所在目录。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def _module_classes(py_module):
    found = []
    for _, cls in inspect.getmembers(py_module, inspect.isclass):
        if cls is ModuleBase or not issubclass(cls, ModuleBase):
            continue
        if not getattr(cls, "meta", None):
            continue
        if not cls.meta.get("id"):
            continue
        found.append(cls)
    return found


def load_modules():
    """返回 (模块实例列表, 加载错误列表)。"""
    errors = []
    instances = []
    seen_ids = set()

    for name in BUILTIN_MODULES:
        try:
            py_module = importlib.import_module(name)
        except Exception as exc:
            errors.append((name, str(exc)))
            continue
        for cls in _module_classes(py_module):
            try:
                inst = cls()
                mid = inst.meta.get("id")
                if mid in seen_ids:
                    errors.append((mid, "模块 ID 重复，已跳过"))
                    continue
                seen_ids.add(mid)
                instances.append(inst)
            except Exception as exc:
                errors.append((name + "." + cls.__name__, str(exc)))

    plugin_dir = os.path.join(app_dir(), "plugins")
    if os.path.isdir(plugin_dir):
        for path in sorted(glob.glob(os.path.join(plugin_dir, "*.py"))):
            base = os.path.basename(path)
            if base.startswith("_"):
                continue
            name = "_fk_plugin_" + os.path.splitext(base)[0]
            try:
                loader = SourceFileLoader(name, path)
                spec = spec_from_loader(name, loader)
                if spec is None:
                    raise RuntimeError("无法创建模块规格")
                py_module = module_from_spec(spec)
                sys.modules[name] = py_module
                loader.exec_module(py_module)
                classes = _module_classes(py_module)
                if not classes:
                    raise RuntimeError("未找到继承 ModuleBase 且带 meta.id 的模块类")
                for cls in classes:
                    inst = cls()
                    mid = inst.meta.get("id")
                    if mid in seen_ids:
                        errors.append((base, "模块 ID 重复，已跳过：" + str(mid)))
                        continue
                    seen_ids.add(mid)
                    instances.append(inst)
            except Exception as exc:
                errors.append((base, str(exc)))

    instances.sort(key=lambda m: (int(m.meta.get("order", 100)), str(m.meta.get("name", ""))))
    return instances, errors
