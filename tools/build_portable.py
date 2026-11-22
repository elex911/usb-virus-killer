#!/usr/bin/env python3
"""把 PortableAV 打成 WinPE 可用的绿包（embeddable Python，零安装、零解压）。

为什么不用 PyInstaller onefile：
onefile 在 Python 启动**之前**就把自己解压到 %TEMP%；WinPE 下 %TEMP% 是 X: 内存盘，
几十 MB 直接吃掉 scratch space。embeddable 目录形态压根没有解压这一步。

来源校验的诚实说明：
python.org 对该文件只提供 `.asc`（GPG），**没有 md5/sha256 文件**。
所以本脚本：保存 .asc、打印自算 SHA-256、支持 `--expected-sha256` 强制比对，
但**不声称已完成签名验证**（构建环境没有可信公钥环）。

用法：
    python tools/build_portable.py --out dist_portable/PortableAV --force
    python tools/build_portable.py --threads 8 --expected-sha256 <hash>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

PY_VERSION = "3.11.9"
ZIP_NAME = "python-%s-embed-amd64.zip" % PY_VERSION
ZIP_URL = "https://www.python.org/ftp/python/%s/%s" % (PY_VERSION, ZIP_NAME)
SIG_URL = ZIP_URL + ".asc"
UA = "PortableAV-build/1.0"
CHUNK = 256 * 1024


def log(msg: str = "") -> None:
    print(msg, flush=True)


def step(msg: str) -> None:
    log("==> %s" % msg)


def warn(msg: str) -> None:
    log("[!] %s" % msg)


def _request(url: str, method: str = "GET", headers: Optional[dict] = None):
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    return urllib.request.urlopen(req, timeout=60)


def remote_meta(url: str) -> Tuple[int, bool]:
    with _request(url, method="HEAD") as resp:
        length = int(resp.headers.get("Content-Length") or 0)
        ranges = (resp.headers.get("Accept-Ranges") or "").lower()
    return length, "bytes" in ranges


def _fetch_range(url: str, start: int, end: int, dest: str, retries: int = 3) -> int:
    want = end - start + 1
    last = None
    for attempt in range(retries):
        try:
            with _request(url, headers={"Range": "bytes=%d-%d" % (start, end)}) as resp:
                if resp.status != 206 and not (resp.status == 200):
                    raise IOError("HTTP %s for range %d-%d" % (resp.status, start, end))
                written = 0
                with open(dest, "wb") as f:
                    while True:
                        block = resp.read(CHUNK)
                        if not block:
                            break
                        f.write(block)
                        written += len(block)
            if written != want:
                raise IOError("range %d-%d got %d bytes, want %d" % (start, end, written, want))
            return written
        except Exception as exc:  # 重试是这里唯一合理的处理
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise IOError("range %d-%d failed after %d tries: %s" % (start, end, retries, last))


def ranged_download(url: str, dest: str, threads: int = 8,
                    parts_dir: Optional[str] = None) -> dict:
    """分段并发下载后按序合并。不支持 Range 时退回单线程并**明确告警**。"""
    length, ranged = remote_meta(url)
    if length <= 0:
        raise IOError("服务器未返回 Content-Length：%s" % url)
    if not ranged or threads <= 1:
        warn("目标不支持 Range 或线程数为 1：退回单线程下载（违反多线程要求，请在报告里注明）")
        with _request(url) as resp, open(dest, "wb") as f:
            shutil.copyfileobj(resp, f, CHUNK)
        return {"bytes": os.path.getsize(dest), "threads": 1, "ranged": False}

    parts_dir = parts_dir or (dest + ".parts")
    os.makedirs(parts_dir, exist_ok=True)
    spans: List[Tuple[int, int, str]] = []
    for i in range(threads):
        start = length * i // threads
        end = length * (i + 1) // threads - 1
        spans.append((start, end, os.path.join(parts_dir, "part%02d" % i)))

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_fetch_range, url, s, e, p) for s, e, p in spans]
        got = [f.result() for f in futures]

    with open(dest, "wb") as out:
        for (_s, _e, p) in spans:
            with open(p, "rb") as f:
                shutil.copyfileobj(f, out, CHUNK)
    shutil.rmtree(parts_dir, ignore_errors=True)

    size = os.path.getsize(dest)
    if size != length:
        raise IOError("合并后大小不符：want %d got %d" % (length, size))
    log("    分段：%s（每段 %d 字节）" % (got, got[0] if got else 0))
    return {"bytes": size, "threads": threads, "ranged": True}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_pth(runtime_dir: str) -> str:
    """写 python311._pth：让 runtime 能找到标准库、site-packages 和上一级（portableav 包）。"""
    cands = [n for n in os.listdir(runtime_dir) if n.lower().endswith("._pth")]
    if not cands:
        raise IOError("embeddable 包里找不到 python*._pth")
    name = cands[0]
    lines = [name.replace("._pth", ".zip"), ".", "Lib\\site-packages", "..", "import site"]
    with open(os.path.join(runtime_dir, name), "w", encoding="ascii", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    log("    写入 %s：%s" % (name, " | ".join(lines)))
    return name


def install_wheels(host_python: str, python_version: str, workdir: str,
                   site_packages: str) -> List[str]:
    """用宿主 python 的 pip 下 wheel（不依赖目标机联网，也不在绿包里装 pip）。"""
    os.makedirs(site_packages, exist_ok=True)
    wheel_dir = os.path.join(workdir, "wheels")
    shutil.rmtree(wheel_dir, ignore_errors=True)
    os.makedirs(wheel_dir, exist_ok=True)
    minor = "".join(python_version.split(".")[:2])
    # 注意：不要加 --no-deps。cryptography 仍依赖 cffi（_cffi_backend），
    # 之前误以为它无运行时依赖，结果装上了却 import 失败。
    cmd = [host_python, "-m", "pip", "download", "cryptography",
           "--only-binary=:all:", "--platform", "win_amd64",
           "--python-version", minor, "--implementation", "cp",
           "-d", wheel_dir]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except Exception as exc:
        warn("pip download 异常：%s" % exc)
        return []
    if proc.returncode != 0:
        warn("pip download 失败：%s" % (proc.stderr.strip().splitlines()[-1:] or "")[:200])
        return []

    installed = []
    for name in sorted(os.listdir(wheel_dir)):
        if not name.endswith(".whl"):
            continue
        with zipfile.ZipFile(os.path.join(wheel_dir, name)) as zf:
            zf.extractall(site_packages)
        installed.append(name)
        log("    安装 %s" % name)
    return installed


def copy_tree(src: str, dst: str, exclude_dirs, exclude_suffix=(".pyc",)) -> int:
    count = 0
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        rel = os.path.relpath(root, src)
        target_root = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(target_root, exist_ok=True)
        for name in files:
            if any(name.endswith(s) for s in exclude_suffix):
                continue
            shutil.copy2(os.path.join(root, name), os.path.join(target_root, name))
            count += 1
    return count


def build(args) -> int:
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.abspath(args.out or os.path.join(repo, "dist_portable", "PortableAV"))
    work = os.path.join(repo, ".workbuddy", "build_portable")
    os.makedirs(work, exist_ok=True)

    step("准备输出目录：%s" % out_dir)
    if os.path.isdir(out_dir):
        if not args.force:
            warn("输出目录已存在，加 --force 覆盖：%s" % out_dir)
            return 2
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    zip_path = os.path.join(work, ZIP_NAME)
    dl = {"bytes": 0, "threads": 0, "ranged": False, "reused": False}
    if args.skip_download and os.path.isfile(zip_path):
        step("复用已下载归档：%s" % zip_path)
        dl = {"bytes": os.path.getsize(zip_path), "threads": 0, "ranged": False, "reused": True}
        warn("本次未重新下载：清单里的 threads/ranged 记录的是 0/False（复用归档）")
    else:
        step("下载 %s（%d 线程分段）" % (ZIP_NAME, args.threads))
        dl = ranged_download(ZIP_URL, zip_path, threads=args.threads)

    digest = sha256_file(zip_path)
    hash_source = "自算"
    if args.expected_sha256:
        want = args.expected_sha256.strip().lower()
        if digest != want:
            warn("SHA-256 不匹配：期望 %s，实得 %s" % (want, digest))
            return 3
        hash_source = "与 --expected-sha256 一致"
    log("    字节 %d ｜ threads=%s ｜ ranged=%s" % (dl["bytes"], dl["threads"], dl["ranged"]))
    log("    sha256 %s（%s）" % (digest, hash_source))

    sig_path = os.path.join(work, ZIP_NAME + ".asc")
    signature_saved = False
    try:
        with _request(SIG_URL) as resp, open(sig_path, "wb") as f:
            shutil.copyfileobj(resp, f)
        signature_saved = True
        log("    已保存 .asc（未验证：构建环境无可信公钥环）")
    except Exception as exc:
        warn("未能保存 .asc：%s" % exc)

    step("解压 embeddable runtime")
    runtime_dir = os.path.join(out_dir, "runtime")
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(runtime_dir)
    write_pth(runtime_dir)

    py_exe = os.path.join(runtime_dir, "python.exe")
    if not os.path.isfile(py_exe):
        warn("解压后没有 python.exe")
        return 4

    step("收集第三方 wheel（cryptography）")
    host_python = args.host_python or shutil.which("python") or sys.executable
    wheels = install_wheels(host_python, PY_VERSION,
                            work, os.path.join(runtime_dir, "Lib", "site-packages"))
    if not wheels:
        warn("cryptography 未装入：签名/隔离功能将不可用（引擎会如实报错，不会降级为明文）")

    step("复制 VC++ 运行库 DLL")
    missing = []
    sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    for dll in ("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll"):
        src = os.path.join(sys32, dll)
        if os.path.isfile(src):
            shutil.copy2(src, runtime_dir)
            log("    %s" % dll)
        else:
            missing.append(dll)
            warn("System32 缺少 %s" % dll)

    step("复制 PortableAV 源码")
    app_src = os.path.join(repo, "portableav")
    app_dst = os.path.join(out_dir, "portableav")
    n = copy_tree(app_src, app_dst, exclude_dirs={"_work", "__pycache__", "tests"})
    bat_src = os.path.join(app_src, "run_portableav.bat")
    if os.path.isfile(bat_src):
        shutil.copy2(bat_src, os.path.join(out_dir, "run_portableav.bat"))
    log("    复制 %d 个文件" % n)

    step("生成完整性清单")
    files = []
    for root, _dirs, names in os.walk(out_dir):
        for name in names:
            p = os.path.join(root, name)
            rel = os.path.relpath(p, out_dir).replace("\\", "/")
            files.append({"path": rel, "size": os.path.getsize(p), "sha256": sha256_file(p)})
    manifest = {
        "tool": "tools/build_portable.py",
        "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "python_version": PY_VERSION,
        "source_url": ZIP_URL,
        "source_bytes": dl["bytes"],
        "source_sha256": digest,
        "hash_source": hash_source,
        "signature_saved": signature_saved,
        "signature_note": ("asc 已保存但未验证：构建环境无可信公钥环" if signature_saved
                           else "无签名文件"),
        "download": dl,
        "missing_dlls": missing,
        "wheels": wheels,
        "file_count": len(files),
        "files": files,
    }
    with open(os.path.join(out_dir, "VERIFY.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "SHA256SUMS.txt"), "w", encoding="ascii", newline="\n") as f:
        for row in files:
            f.write("%s  %s\n" % (row["sha256"], row["path"]))
    log("    %d 个文件" % len(files))

    step("自检：绿包内的 python 能否导入产品与 cryptography")
    env = dict(os.environ)
    env["PYTHONPATH"] = out_dir
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run([py_exe, "-c",
                           "import sys, portableav;"
                           "print('python', sys.version.split()[0]);"
                           "print('portableav', portableav.__version__)"],
                          capture_output=True, text=True, env=env, timeout=120)
    log("    rc=%d %s" % (proc.returncode, (proc.stdout or proc.stderr).strip().replace("\n", " | ")))
    if proc.returncode != 0:
        warn("自检失败：绿包无法启动")
        return 5

    proc2 = subprocess.run([py_exe, "-c",
                            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM;"
                            "print('cryptography OK')"],
                           capture_output=True, text=True, env=env, timeout=120)
    if proc2.returncode == 0:
        log("    %s" % proc2.stdout.strip())
    else:
        tail = (proc2.stderr or "").strip().splitlines()
        warn("cryptography 不可用：隔离区会拒绝运行（这是设计，不是 bug）")
        if tail:
            warn("    原因：%s" % tail[-1][:200])
    return 0

    log()
    log("构建完成")
    log("  输出：%s" % out_dir)
    log("  清单：%s" % os.path.join(out_dir, "VERIFY.json"))
    if missing:
        warn("缺少 VC++ DLL：%s（WinPE 里 python 可能起不来）" % ", ".join(missing))
    log("  下一步：整包拷到 U 盘，运行 run_portableav.bat")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="构建 PortableAV 绿包（embeddable，无安装）")
    ap.add_argument("--out", default="", help="输出目录，默认 dist_portable/PortableAV")
    ap.add_argument("--threads", type=int, default=8, help="分段下载线程数")
    ap.add_argument("--expected-sha256", default="", help="从可信渠道取得的归档 SHA-256，强制比对")
    ap.add_argument("--host-python", default="", help="用于下载 wheel 的宿主 python")
    ap.add_argument("--skip-download", action="store_true", help="复用已下载归档")
    ap.add_argument("--force", action="store_true", help="覆盖已存在的输出目录")
    return build(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
