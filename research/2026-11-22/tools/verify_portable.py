#!/usr/bin/env python3
"""校验绿包完整性（WinPE 里没有 sha256sum，所以自带一个）。

用途：U 盘插过中毒机器后，先跑这个再跑扫描。
发现任何差异一律以非 0 退出，不做"自动修复"——被改过的包只能重新拷。

用法：
    runtime\\python.exe tools\\verify_portable.py [包目录]
    python tools\\verify_portable.py dist_portable\\PortableAV
"""

from __future__ import annotations

import hashlib
import json
import os
import sys


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_expected(root: str):
    """优先读 VERIFY.json；退而读 SHA256SUMS.txt。返回 (映射, 来源说明)。"""
    manifest = os.path.join(root, "VERIFY.json")
    if os.path.isfile(manifest):
        with open(manifest, encoding="utf-8") as f:
            data = json.load(f)
        rows = {row["path"].replace("\\", "/"): row["sha256"] for row in data.get("files", [])}
        return rows, "VERIFY.json（%s，python %s）" % (
            data.get("built_at", "?"), data.get("python_version", "?"))

    sums = os.path.join(root, "SHA256SUMS.txt")
    if os.path.isfile(sums):
        rows = {}
        with open(sums, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2 and len(parts[0]) == 64:
                    rows[parts[1].lstrip("*").replace("\\", "/")] = parts[0].lower()
        return rows, "SHA256SUMS.txt"

    return {}, ""


def verify(root: str, quiet: bool = False) -> int:
    root = os.path.abspath(root)
    expected, source = load_expected(root)
    if not expected:
        print("找不到 VERIFY.json 或 SHA256SUMS.txt：%s" % root)
        print("这不是合格的绿包（或清单被删）。")
        return 2

    print("校验：%s" % root)
    print("清单：%s，%d 个文件" % (source, len(expected)))

    missing, changed, ok = [], [], 0
    for rel, want in sorted(expected.items()):
        path = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            missing.append(rel)
            continue
        try:
            got = sha256_file(path)
        except OSError as exc:
            changed.append((rel, "读取失败：%s" % exc))
            continue
        if got.lower() != want.lower():
            changed.append((rel, "期望 %s… 实得 %s…" % (want[:16], got[:16])))
        else:
            ok += 1

    # 清单之外多出来的文件：不算失败，但要列出来（可能是产物，也可能是塞进来的东西）
    extra = []
    expected_set = {r.lower() for r in expected}
    for cur, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ("_work", "__pycache__")]
        for name in names:
            rel = os.path.relpath(os.path.join(cur, name), root).replace("\\", "/")
            if rel.lower() in expected_set:
                continue
            if rel in ("VERIFY.json", "SHA256SUMS.txt"):
                continue
            extra.append(rel)

    print("  OK      %d" % ok)
    if missing:
        print("  缺失    %d" % len(missing))
        for rel in missing[:20]:
            print("    - %s" % rel)
    if changed:
        print("  被改动  %d" % len(changed))
        for rel, why in changed[:20]:
            print("    ! %s（%s）" % (rel, why))
    if extra and not quiet:
        print("  额外文件 %d（不在清单内）" % len(extra))
        for rel in extra[:20]:
            print("    ? %s" % rel)

    if missing or changed:
        print()
        print("结论：包已被改动或损坏，不要用它做取证。重新从可信副本拷贝。")
        return 1
    print()
    print("结论：与清单一致。")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    else:
        root = argv[0]
    quiet = "--quiet" in argv
    return verify(root, quiet=quiet)


if __name__ == "__main__":
    raise SystemExit(main())
