# -*- coding: utf-8 -*-
"""报告 ISO 生成（补强6）：纯标准库最小 ISO9660 写入器。

范围：仅「内容刻录」——把导出的报告文件打包成可读取的数据 DVD 镜像。
不做引导盘：可启动 DVD 需要完整 WinPE/独立启动环境，复制应用或报告不会让系统启动。
"""
import hashlib
import json
import os
from datetime import datetime

SECTOR = 2048
MAX_ISO_BYTES = int(4.3 * 1024 ** 3)  # 4.7GB DVD 实际约 4.38GiB，留刻录余量
SYSTEM_SECTORS = 16
PVD_SECTOR = 16
TERM_SECTOR = 17
ROOT_SECTOR = 18
DATA_START = 19


def _both(value, width):
    return value.to_bytes(width, "little") + value.to_bytes(width, "big")


def _dt7():
    now = datetime.now()
    return bytes([now.year - 1900, now.month, now.day,
                  now.hour, now.minute, now.second, 0])


def _pad(s, width):
    return s.encode("ascii", "replace")[:width].ljust(width, b" ")


def _dir_record(lba, size, is_dir, identifier):
    flags = 2 if is_dir else 0
    rec = bytearray()
    rec += bytes([0, 0]) + _both(lba, 4) + _both(size, 4)
    rec += _dt7() + bytes([flags, 0, 0]) + _both(1, 2)
    rec += bytes([len(identifier)]) + identifier
    if len(rec) % 2:
        rec += b"\x00"
    rec[0] = len(rec)
    return bytes(rec)


def _root_record(lba, size):
    return _dir_record(lba, size, True, b"\x00")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_files(source_dir):
    """收集报告文件（不递归；只收普通文件），返回 [(路径, ISO 文件名, 大小)]。"""
    out = []
    for name in sorted(os.listdir(source_dir)):
        p = os.path.join(source_dir, name)
        if not os.path.isfile(p) or os.path.islink(p):
            continue
        ascii_name = name.upper().replace(" ", "_").encode("ascii", "ignore").decode("ascii")
        if not ascii_name:
            ascii_name = "REPORT"
        iso_name = ascii_name + ";1"
        if len(iso_name) > 128:
            raise ValueError("文件名过长（ISO9660 上限 128）：" + name)
        out.append((p, iso_name, os.path.getsize(p)))
    return out


def build_iso(source_dir, out_path, max_bytes=MAX_ISO_BYTES):
    """生成 ISO；内含 SHA256SUMS.TXT;1 清单。返回摘要 dict。"""
    files = source_files(source_dir)
    total = sum(sz for _p, _n, sz in files)
    manifest_lines = ["# SHA-256 清单（报告 ISO）"]
    for p, name, sz in files:
        manifest_lines.append("%s  %s  %d bytes" % (_sha256_file(p), name, sz))
    mpath = os.path.join(source_dir, "_iso_manifest_tmp")
    with open(mpath, "w", encoding="utf-8") as f:
        f.write("\n".join(manifest_lines) + "\n")
    files.append((mpath, "SHA256SUMS.TXT;1", os.path.getsize(mpath)))
    total = sum(sz for _p, _n, sz in files)

    entries = []
    lba = DATA_START
    for p, name, sz in files:
        sectors = max(1, (sz + SECTOR - 1) // SECTOR)
        entries.append((p, name, sz, lba, sectors))
        lba += sectors
    volume_sectors = lba
    if volume_sectors * SECTOR > max_bytes:
        os.remove(mpath)
        raise ValueError("报告内容 %.2f MiB 超过 ISO 上限 %.2f GiB，未生成镜像"
                         % (total / 1048576, max_bytes / (1024 ** 3)))

    root_data = _dir_record(ROOT_SECTOR, SECTOR, True, b"\x00") + \
                _dir_record(ROOT_SECTOR, SECTOR, True, b"\x01")
    for _p, name, sz, data_lba, _secs in entries:
        root_data += _dir_record(data_lba, sz, False, name.encode("ascii"))
    root_data = root_data.ljust(SECTOR, b"\x00")

    pvd = bytearray(SECTOR)
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    pvd[8:40] = _pad("USB-VIRUS-KILLER", 32)
    pvd[40:72] = _pad("REPORT_ISO", 32)
    pvd[72:80] = _both(volume_sectors, 4)
    pvd[112:116] = _both(1, 2)   # 卷集号：2+2=4 字节（8 字节切片会缩短 bytearray）
    pvd[120:124] = _both(1, 2)   # 卷序号：2+2=4 字节
    pvd[124:128] = _both(SECTOR, 2)
    pvd[128:136] = _both(0, 4)
    pvd[156:190] = _root_record(ROOT_SECTOR, SECTOR)
    pvd[190:318] = _pad("usb-virus-killer report export", 128)
    pvd[813:830] = _dt7() + b"\x00" * 10
    pvd[830:847] = _dt7() + b"\x00" * 10
    pvd[881] = 1

    term = bytearray(SECTOR)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1

    tmp = out_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(b"\x00" * (SECTOR * SYSTEM_SECTORS))
        f.write(pvd)
        f.write(term)
        f.write(root_data)
        for p, _name, sz, _lba, sectors in entries:
            with open(p, "rb") as src:
                payload = src.read()
            f.write(payload.ljust(sectors * SECTOR, b"\x00"))
    os.replace(tmp, out_path)
    os.remove(mpath)
    return {"path": out_path, "size": os.path.getsize(out_path),
            "sectors": volume_sectors, "files": len(files),
            "sha256": _sha256_file(out_path), "max_bytes": max_bytes}


def read_back_check(iso_path):
    """独立读回校验：解析 PVD 与根目录记录，返回 (卷标, [(名字, 大小)])。"""
    with open(iso_path, "rb") as f:
        f.seek(PVD_SECTOR * SECTOR)
        pvd = f.read(SECTOR)
        assert pvd[1:6] == b"CD001" and pvd[0] == 1, "PVD 签名无效"
        assert int.from_bytes(pvd[124:126], "little") == SECTOR, "逻辑块大小异常"
        f.seek(ROOT_SECTOR * SECTOR)
        root = f.read(SECTOR)
    names = []
    i = 0
    while i < len(root):
        length = root[i]
        if length < 34:
            break
        rec = root[i:i + length]
        ident = rec[33:33 + rec[32]]
        if ident not in (b"\x00", b"\x01"):
            names.append((ident.decode("ascii", "replace"),
                          int.from_bytes(rec[10:14], "little")))
        i += length
    return pvd[40:72].decode("ascii", "replace").strip(), names
