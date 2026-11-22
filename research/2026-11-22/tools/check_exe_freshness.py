"""校验单文件 exe 是否由当前源码构建（防"源码已修、exe 还是旧的"）。

背景事故：源码 13:27 已放行系统盘扫描，而 exe 是 11:37 打的，界面照旧弹
「安全拦截：目标是系统盘 C:\\，拒绝处理」。`dist/` 被 .gitignore 排除，
所以"改了源码忘记重打包"没有任何机制会提醒。

判据（两条互补，任一不过即 FAIL）：
1. **语义哨兵**：解开 exe 内嵌 PYZ，取指定模块的字符串常量，检查
   - FORBIDDEN 里的旧话术必须不存在；
   - REQUIRED 里的放行文案必须存在。
2. **时间戳**：core/ 与 modules/ 下任一 .py 比 exe 新 → 判过期。

注意：不能用"字符串集合完全相等"来比。CPython 会把 `"a %s b" % (x,)`
编译成 BUILD_STRING 的分段常量（'a '、' b'），集合比对必然误报。
所以只做哨兵包含判断。

用法：
  python tools/check_exe_freshness.py dist/文件夹病毒查杀工具.exe
退出码：0=PASS  1=FAIL  2=无法解析
"""
import datetime
import marshal
import os
import sys
import tempfile
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 检查哪些模块的字符串常量
MODULES = ["modules.folder_virus", "core.app"]

# 旧版拦截话术：出现在 exe 里就说明打的是旧源码
FORBIDDEN = ["拒绝处理", "安全拦截：目标是系统盘"]

# 新版放行文案：缺一条就说明 exe 落后于源码
REQUIRED = [
    "允许本地固定磁盘",      # core/app.py 复选框（默认勾选）
    "系统关键路径",          # modules/folder_virus.py 处置确认
    "只报告",                # 关键路径不隔离的口径
]

SCAN_DIRS = ["core", "modules"]


def _pyz_to_code(exe, suffix):
    from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader

    arch = CArchiveReader(exe)
    pyz_name = next((n for n in arch.toc if str(n).endswith(".pyz")), None)
    if not pyz_name:
        raise RuntimeError("exe 内没有 PYZ 归档")
    data = arch.extract(pyz_name)
    if isinstance(data, tuple):
        data = data[0]
    fd, tmp = tempfile.mkstemp(suffix=".pyz")
    os.close(fd)
    with open(tmp, "wb") as f:
        f.write(data)
    try:
        pyz = ZlibArchiveReader(tmp)
        name = next((m for m in pyz.toc if str(m).endswith(suffix)), None)
        if not name:
            return None
        code = pyz.extract(name)
        if isinstance(code, tuple):
            code = code[-1]
        if not isinstance(code, types.CodeType):
            code = marshal.loads(code)
        return code
    finally:
        os.remove(tmp)


def embedded_strings(code):
    found = set()

    def walk(c, seen=None):
        seen = seen or set()
        if id(c) in seen:
            return
        seen.add(id(c))
        for k in c.co_consts:
            if isinstance(k, str):
                found.add(k)
            elif isinstance(k, (tuple, list, frozenset, set)):
                for v in k:
                    if isinstance(v, str):
                        found.add(v)
            elif isinstance(k, types.CodeType):
                walk(k, seen)

    walk(code)
    return found


def newest_source():
    newest, where = 0.0, ""
    for d in SCAN_DIRS:
        base = os.path.join(REPO, d)
        for root, _dirs, files in os.walk(base):
            for n in files:
                if not n.endswith(".py"):
                    continue
                p = os.path.join(root, n)
                m = os.path.getmtime(p)
                if m > newest:
                    newest, where = m, p
    return newest, where


def fmt(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def main(argv):
    if len(argv) < 2:
        print("用法: python tools/check_exe_freshness.py <exe>")
        return 2
    exe = argv[1]
    if not os.path.isfile(exe):
        print("FAIL: exe 不存在: %s" % exe)
        return 2

    exe_mtime = os.path.getmtime(exe)
    print("exe   : %s" % exe)
    print("size  : %d bytes" % os.path.getsize(exe))
    print("mtime : %s" % fmt(exe_mtime))

    src_mtime, src_path = newest_source()
    print("最新源码: %s  (%s)" % (fmt(src_mtime), os.path.relpath(src_path, REPO)))

    blob = ""
    missing_modules = []
    try:
        for suffix in MODULES:
            code = _pyz_to_code(exe, suffix)
            if code is None:
                missing_modules.append(suffix)
                continue
            blob += "\n".join(embedded_strings(code))
    except Exception as exc:
        print("FAIL: 解析 exe 失败: %s: %s" % (type(exc).__name__, exc))
        return 2

    ok = True
    if missing_modules:
        ok = False
        print("FAIL: exe 内缺少模块: %s" % ", ".join(missing_modules))

    stale = [w for w in FORBIDDEN if w in blob]
    if stale:
        ok = False
        print("FAIL: exe 内仍含旧拦截话术: %s" % "、".join(stale))

    absent = [w for w in REQUIRED if w not in blob]
    if absent:
        ok = False
        print("FAIL: exe 内缺少放行口径文案: %s" % "、".join(absent))

    if src_mtime > exe_mtime + 2:
        ok = False
        print("FAIL: 源码比 exe 新（%.0f 分钟），exe 已过期；请重新打包"
              % ((src_mtime - exe_mtime) / 60.0))

    print("RESULT: %s" % ("PASS（exe 与当前源码一致）" if ok else "FAIL（请重新打包）"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
