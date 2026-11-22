"""命令行入口。

子命令：
  env     显示环境识别、磁盘、离线系统盘
  scan    扫描（默认演练，不处置；加 --apply 才隔离）
  list    列出隔离区
  restore 还原某个隔离项
  verify  校验隔离区一致性（启动修复 + 逐个可解密性检查）
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import catroot, chain as chainmod, drives, env as envmod, matcher as matchmod
from . import paths as pathmod, pe as pemod, quarantine as qmod, report as reportmod
from . import revoke, scan as scanmod, trust

DEFAULT_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")


def _load_roots(arg: Optional[str]) -> List[chainmod.Cert]:
    p = arg or os.path.join(DEFAULT_RULES, "roots")
    if not os.path.isdir(p):
        return []
    return chainmod.load_roots_from_dir(p)


def _load_blacklist(arg: Optional[str]) -> revoke.RevocationList:
    d = arg or os.path.join(DEFAULT_RULES, "revoked")
    files = []
    if os.path.isdir(d):
        files = [os.path.join(d, n) for n in sorted(os.listdir(d)) if n.lower().endswith((".json", ".txt"))]
    elif os.path.isfile(d):
        files = [d]
    return revoke.load_blacklists(files) if files else revoke.RevocationList()


def cmd_env(args) -> int:
    e = envmod.detect()
    print("运行模式：%s（%s）" % (e.mode, e.hint))
    print("命中信号：%s" % (", ".join(e.signals) or "无"))
    for k, v in e.detail.items():
        print("  %-12s %s" % (k, v))
    print()
    ds = drives.list_drives()
    for line in drives.describe_drives(ds):
        print("  盘符 %s" % line)
    print()
    systems = drives.find_offline_systems(ds, in_pe=e.is_offline)
    if not systems:
        print("未定位到离线系统盘（可改用 --target 指定目录）")
    for s in systems:
        print("  离线系统：%s" % s.label)
    return 0


def _infer_cat_dir(target: str) -> str:
    """按目标推断 CatRoot 目录：目标可能是盘根、Windows 目录或任意子目录。"""
    t = os.path.abspath(target)
    cands = [t, os.path.join(t, "Windows")]
    parent = os.path.dirname(t)
    if parent and os.path.basename(parent).lower().startswith("windows"):
        cands.append(parent)
    for c in cands:
        d = catroot.cat_dir_for(c)
        if os.path.isdir(d):
            return d
    return ""


def cmd_scan(args) -> int:
    e = envmod.detect()
    target = args.target
    if not target:
        systems = [s for s in drives.find_offline_systems(in_pe=e.is_offline) if s.complete]
        if not systems:
            print("错误：未指定 --target，且未定位到完整的离线系统盘。")
            return 2
        target = systems[0].windows_dir
        print("未指定目标，自动选用：%s" % target)
    if not os.path.isdir(target):
        print("错误：目标不是目录：%s" % target)
        return 2

    roots = _load_roots(args.roots)
    rl = _load_blacklist(args.blacklist)
    print("根证书：%d 张%s" % (len(roots), "" if roots else "（缺失 → 签名一律不判白）"))
    print("吊销名单：%s" % rl.summary())

    index = None
    if not args.no_catalog:
        cat_dir = args.catalog or _infer_cat_dir(target)
        if cat_dir and os.path.isdir(cat_dir):
            files = catroot.list_cat_files(cat_dir, limit=args.catalog_limit or None)
            print("建立编录索引：%d 个 .cat ..." % len(files))
            index = catroot.build_index(files, roots, revocation=rl)
            print("  %s" % index.summary())
        else:
            print("  ！未找到 CatRoot 目录（可用 --catalog 指定），编录白名单不可用")

    matcher, status = matchmod.build_matcher(args.rules)
    print("规则引擎：%s" % status)

    qm = None
    if args.quarantine:
        try:
            qm = qmod.Quarantine(args.quarantine, system_drive=e.system_drive or "X:")
        except Exception as exc:
            print("错误：隔离区不可用：%s" % exc)
            return 2
        notes = qm.recover()
        for n in notes:
            print("  [一致性修复] %s" % n)

    dry = not args.apply
    if dry:
        print("模式：演练（不处置）。要真正隔离请加 --apply。")

    lim = scanmod.Limits(max_file_bytes=args.limit_mb * 1024 * 1024,
                         max_depth=args.max_depth,
                         max_files=args.max_files)

    def protect(p: str) -> bool:
        return pathmod.is_system_critical(p, e.system_drive or "C:")

    def on_progress(done: int, total: int) -> None:
        if args.quiet:
            return
        if done == total or done % 200 == 0:
            sys.stdout.write("\r  扫描 %d/%d" % (done, total))
            sys.stdout.flush()

    summ = scanmod.scan_tree(target, roots, index=index, matcher=matcher, limits=lim,
                            quarantine=qm, dry_run=dry, protect=protect,
                            exclude_dirs=[args.quarantine] if args.quarantine else [],
                            revocation=rl)
    if not args.quiet:
        sys.stdout.write("\r" + " " * 40 + "\r")

    print()
    print("扫描完成：见到 %d，已扫描 %d，耗时 %.2fs"
          % (summ.files_seen, summ.files_scanned, summ.elapsed))
    print("  黑 %d ｜ 白 %d ｜ 灰 %d ｜ 解析失败 %d"
          % (summ.count("黑"), summ.count("白"), summ.count("灰"), len(summ.errors)))
    print("  跳过：链接 %d ｜ 超大 %d ｜ 后缀 %d"
          % (summ.skipped_link, summ.skipped_big, summ.skipped_ext))
    for r in [x for x in summ.results if x.level == "黑"][:20]:
        print("  [黑] %s  %s  %s" % (",".join(r.rules) or r.basis, r.action, r.path))

    if args.report:
        qitems = qm.list_items() if qm else []
        out = reportmod.generate(args.report, summ, index=index, revocation=rl,
                                 meta={"mode": e.hint, "max_file_mb": args.limit_mb,
                                       "max_depth": args.max_depth,
                                       "workers": "自动",
                                       "quarantine_items": qitems})
        print("报告：%s" % out)
    return 0


def cmd_list(args) -> int:
    qm = qmod.Quarantine(args.quarantine, system_drive="X:")
    items = qm.list_items()
    print("隔离区：%s（%d 项）" % (qm.root, len(items)))
    for it in items:
        print("  %s  %-9s %s  %s" % (it.id, it.status, it.created, it.original_path))
    return 0


def cmd_restore(args) -> int:
    qm = qmod.Quarantine(args.quarantine, system_drive="X:")
    try:
        dest = qm.restore(args.id)
    except qmod.RestoreConflict as exc:
        print("拒绝还原：%s" % exc)
        return 3
    except Exception as exc:
        print("还原失败：%s: %s" % (type(exc).__name__, exc))
        return 1
    print("已还原到：%s" % dest)
    return 0


def cmd_verify(args) -> int:
    qm = qmod.Quarantine(args.quarantine, system_drive="X:")
    notes = qm.recover()
    for n in notes:
        print("  [修复] %s" % n)
    bad = 0
    for it in qm.list_items():
        blob = os.path.join(qm.item_dir, it.id + ".qbin")
        if it.status == "stored" and not os.path.isfile(blob):
            print("  [缺失] %s 密文不见了" % it.id)
            bad += 1
    print("隔离项 %d，异常 %d" % (len(qm.list_items()), bad))
    return 0 if bad == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="portableav",
                                description="PortableAV 离线取证查杀（原型）")
    sub = p.add_subparsers(dest="cmd")

    e = sub.add_parser("env", help="显示环境/磁盘/离线系统盘")
    e.set_defaults(func=cmd_env)

    s = sub.add_parser("scan", help="扫描目标目录")
    s.add_argument("--target", default="", help="目标目录或盘根（默认取第一个离线系统盘）")
    s.add_argument("--roots", default="", help="离线根证书目录（PEM/DER/CRT）")
    s.add_argument("--blacklist", default="", help="吊销黑名单文件或目录")
    s.add_argument("--catalog", default="", help="CatRoot 目录（默认按目标推断）")
    s.add_argument("--catalog-limit", type=int, default=0, help="最多索引多少个 .cat（调试用）")
    s.add_argument("--no-catalog", action="store_true", help="不建编录索引")
    s.add_argument("--rules", default="", help="YARA 规则文件（缺 yara-x 时忽略）")
    s.add_argument("--quarantine", default="", help="隔离区目录（不填则不能处置）")
    s.add_argument("--apply", action="store_true", help="真正执行隔离（默认演练）")
    s.add_argument("--report", default="", help="输出单文件 HTML 报告")
    s.add_argument("--limit-mb", type=int, default=100, help="单文件上限 MB")
    s.add_argument("--max-depth", type=int, default=12)
    s.add_argument("--max-files", type=int, default=0)
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(func=cmd_scan)

    l = sub.add_parser("list", help="列出隔离区")
    l.add_argument("--quarantine", required=True)
    l.set_defaults(func=cmd_list)

    r = sub.add_parser("restore", help="还原隔离项")
    r.add_argument("--quarantine", required=True)
    r.add_argument("--id", required=True)
    r.set_defaults(func=cmd_restore)

    v = sub.add_parser("verify", help="校验隔离区一致性")
    v.add_argument("--quarantine", required=True)
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        build_parser().print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已中断")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
