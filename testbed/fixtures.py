# -*- coding: utf-8 -*-
"""测试台样本工厂。

红线：只合成安全样本——
  · 「被藏原文件 + 同名 .lnk 伪装」用真实目录属性与最小 Shell Link 复现，
    不包含任何真实恶意代码、漏洞利用或 payload；
  · autorun.inf 只写无危害内容（open=notepad.exe）；
  · 不触碰系统目录与真实用户数据，全部产物在测试台 results 目录内。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import folder_virus as fv


def make_lnk(path, target):
    """最小可读 Shell Link：与 tests 一致，只放目标路径，不依赖 COM。"""
    with open(path, "wb") as f:
        f.write(target.encode("utf-16-le"))


def _hide(path):
    fv.set_attr(path, fv.FILE_ATTRIBUTE_HIDDEN | fv.FILE_ATTRIBUTE_SYSTEM)


def build_infected_usb(root, groups=4, nested=True):
    """合成被感染 U 盘：隐藏原目录 + 同名 .lnk 伪装 + autorun.inf + 干净对照。

    返回 ground truth dict，供场景断言与数据统计。
    """
    os.makedirs(root)
    truth = {
        "root": root,
        "hidden_originals": [],
        "mimic_lnks": [],
        "autorun": None,
        "clean_paths": [],
        "nested_hidden": None,
    }
    for i in range(1, groups + 1):
        d = os.path.join(root, "资料%02d" % i)
        os.makedirs(d)
        with open(os.path.join(d, "说明.txt"), "w", encoding="utf-8") as f:
            f.write("安全合成样本：这是被藏起来的原始资料目录。")
        _hide(d)
        truth["hidden_originals"].append(d)
        lnk = os.path.join(root, "资料%02d.lnk" % i)
        make_lnk(lnk, d)
        truth["mimic_lnks"].append(lnk)

    if nested:
        nd = os.path.join(root, "资料01", "私人备份")
        os.makedirs(nd)
        with open(os.path.join(nd, "备份.txt"), "w", encoding="utf-8") as f:
            f.write("安全合成样本：嵌套被藏目录。")
        _hide(nd)
        truth["nested_hidden"] = nd
        truth["hidden_originals"].append(nd)

    auto = os.path.join(root, "autorun.inf")
    with open(auto, "w", encoding="utf-8") as f:
        f.write("[autorun]\nopen=notepad.exe\nicon=none.ico\nlabel=USB\n")
    truth["autorun"] = auto

    cd = os.path.join(root, "正常文件夹")
    os.makedirs(cd)
    with open(os.path.join(cd, "readme.txt"), "w", encoding="utf-8") as f:
        f.write("clean benchmark item")
    clean_lnk = os.path.join(root, "产品手册.lnk")
    make_lnk(clean_lnk, r"D:\Docs\manual.docx")
    truth["clean_paths"] = [cd, clean_lnk]
    return truth


def build_clean_usb(root):
    """合成干净 U 盘：不应产生任何「恶意/可疑」判定。"""
    os.makedirs(root)
    truth = {"root": root, "paths": []}
    for name in ("照片", "文档"):
        d = os.path.join(root, name)
        os.makedirs(d)
        with open(os.path.join(d, "a.txt"), "w", encoding="utf-8") as f:
            f.write("clean")
        truth["paths"].append(d)
    lnk = os.path.join(root, "照片.lnk")
    make_lnk(lnk, os.path.join(root, "照片"))
    truth["paths"].append(lnk)
    return truth
