# -*- coding: utf-8 -*-
"""扫描边界守卫（补强2）

统一处理三类边界，避免每个扫描模块各写一套：
1) 重解析点（junction / symlink / mount point）与目录软链：一律不跟随，防止扫描越界到系统目录或网络路径；
2) 体积上限、递归深度上限：防止超大文件与深层递归拖死；
3) 统一统计口径：scanned / skipped_reparse / skipped_large / skipped_depth / unreadable。

接缝：_lstat / _walk 可被测试注入，真实环境走 os.lstat / os.walk(followlinks=False)。
"""
import os
import stat

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
DEFAULT_MAX_DEPTH = 32

_lstat = os.lstat
_walk = lambda root: os.walk(root, followlinks=False)


def _reset_seams():
    global _lstat, _walk
    _lstat = os.lstat
    _walk = lambda root: os.walk(root, followlinks=False)


def is_reparse(path):
    """重解析点/符号链接判定；lstat 失败按「不可判定」处理（交由调用方记 unreadable）。"""
    try:
        st = _lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(getattr(st, "st_mode", 0)):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def new_stats():
    return {"scanned": 0, "skipped_reparse": 0, "skipped_large": 0,
            "skipped_depth": 0, "unreadable": 0}


def walk_entries(root, stats, skip_dir=None, max_file_bytes=None,
                 max_depth=DEFAULT_MAX_DEPTH, include_dirs=False):
    """产出 (path, size, is_dir)；重解析点剪枝，体积/深度超限计数后跳过。"""
    root_abs = os.path.abspath(root)
    for dirpath, dirnames, filenames in _walk(root):
        try:
            depth = len(os.path.relpath(os.path.abspath(dirpath), root_abs).split(os.sep))
            if os.path.relpath(os.path.abspath(dirpath), root_abs) == ".":
                depth = 0
        except ValueError:
            depth = max_depth
        if depth >= max_depth:
            stats["skipped_depth"] += len(dirnames) + len(filenames)
            dirnames[:] = []
            continue

        keep = []
        for name in dirnames:
            if skip_dir and skip_dir(name):
                continue
            if is_reparse(os.path.join(dirpath, name)):
                stats["skipped_reparse"] += 1
                continue
            keep.append(name)
        dirnames[:] = keep

        for name in filenames:
            p = os.path.join(dirpath, name)
            if skip_dir and skip_dir(name):
                continue
            if is_reparse(p):
                stats["skipped_reparse"] += 1
                continue
            try:
                size = os.path.getsize(p)
            except OSError:
                stats["unreadable"] += 1
                if include_dirs:
                    yield p, 0, False
                continue
            if max_file_bytes is not None and size > max_file_bytes:
                stats["skipped_large"] += 1
                continue
            stats["scanned"] += 1
            yield p, size, False

        if include_dirs:
            for name in dirnames:
                p = os.path.join(dirpath, name)
                yield p, 0, True
