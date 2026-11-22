# -*- coding: utf-8 -*-
"""
离线注册表 Hive 只读解析器
--------------------------
直接解析磁盘上的 regf 二进制文件，**不调用 RegLoadKey、不提权、不挂载、
不修改目标 hive**。适用于 WinPE 下分析目标系统盘，也可在正常 Windows 下
分析已挂载的离线盘。

支持范围（够用于持久化点排查，不是通用 regf 实现）：
  - REGF 头 / HBIN / CELL（含已分配负长度）
  - NK 键节点、LF/LH/LI/RI 子键索引
  - VK 值节点、REG_SZ/REG_EXPAND_SZ/REG_DWORD/REG_MULTI_SZ/REG_BINARY
  - 大数据（db cell）分段读取

边界（T1=代码原文，T3=机制说明）：
  - 只读：本模块任何路径都不会写入 hive 文件；修复动作在别的模块、且强制先备份。
  - 不解析事务日志（.LOG/.LOG1）、不解析差异/虚拟化 hive，离线视图 = 磁盘上最后一次落盘状态。
  - 解析失败一律抛 HiveError，不返回"空注册表"——空结果不能当排除证据。
"""
import struct

HBIN_BASE = 0x1000
NK_SIG = b"nk"
VK_SIG = b"vk"
MAX_CELL = 16 * 1024 * 1024
MAX_VALUE_BYTES = 4 * 1024 * 1024

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7


class HiveError(Exception):
    """hive 结构异常或未支持格式；一律视为解析失败而非空结果。"""


def _u16(buf, off):
    if off + 2 > len(buf):
        raise HiveError("结构越界(u16) offset=%d" % off)
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    if off + 4 > len(buf):
        raise HiveError("结构越界(u32) offset=%d" % off)
    return struct.unpack_from("<I", buf, off)[0]


def _decode_name(raw, compressed):
    if compressed:
        return raw.decode("latin-1", "replace")
    try:
        return raw.decode("utf-16-le", "replace").rstrip("\x00")
    except Exception:
        return raw.decode("latin-1", "replace")


def _decode_data(value_type, data):
    if value_type in (REG_SZ, REG_EXPAND_SZ):
        return data.decode("utf-16-le", "replace").rstrip("\x00")
    if value_type == REG_MULTI_SZ:
        try:
            text = data.decode("utf-16-le", "replace").rstrip("\x00")
            return [x for x in text.split("\x00") if x]
        except Exception:
            return []
    if value_type == REG_DWORD:
        if len(data) < 4:
            raise HiveError("REG_DWORD 数据不足 4 字节")
        return struct.unpack_from("<I", data, 0)[0]
    if value_type == REG_NONE:
        return b""
    return data


class Key:
    """已解析的键节点（只读快照）。"""

    __slots__ = ("name", "path", "flags", "subkey_offset", "subkey_count",
                 "value_offset", "value_count", "hive")

    def __init__(self, hive, name, path, flags, subkey_offset, subkey_count,
                 value_offset, value_count):
        self.hive = hive
        self.name = name
        self.path = path
        self.flags = flags
        self.subkey_offset = subkey_offset
        self.subkey_count = subkey_count
        self.value_offset = value_offset
        self.value_count = value_count

    def subkey_names(self):
        return [k.name for k in self.hive._subkeys(self)]

    def values(self):
        return self.hive._values(self)

    def __repr__(self):
        return "<Key %s>" % (self.path or "\\")


class RegistryHive:
    """以只读方式打开一个 regf 文件。用 with 语句确保句柄关闭。"""

    def __init__(self, path):
        self.path = path
        self._f = open(path, "rb")
        try:
            head = self._f.read(0x1000)
            if len(head) < 0x30 or head[:4] != b"regf":
                raise HiveError("不是有效的 regf 文件：%s" % path)
            self._root_offset = _u32(head, 0x24)
            self._bins_size = _u32(head, 0x28)
            self._f.seek(0, 2)
            self._size = self._f.tell()
            if self._bins_size and HBIN_BASE + self._bins_size > self._size:
                raise HiveError("hive 声明长度超过文件实际大小")
            if not (0 <= self._root_offset < min(self._size, MAX_CELL)):
                raise HiveError("根键偏移异常：%d" % self._root_offset)
        except Exception:
            self._f.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self._f and not self._f.closed:
            self._f.close()

    def _cell(self, offset):
        if offset < 0 or offset > MAX_CELL:
            raise HiveError("cell 偏移越界：%d" % offset)
        abs_off = HBIN_BASE + offset
        if abs_off + 4 > self._size:
            raise HiveError("cell 超出文件范围：%d" % offset)
        self._f.seek(abs_off)
        raw_size = self._f.read(4)
        if len(raw_size) != 4:
            raise HiveError("cell 长度不可读：%d" % offset)
        size = struct.unpack("<i", raw_size)[0]
        in_use = size < 0
        size = -size if size < 0 else size
        if size < 4 or size > MAX_CELL:
            raise HiveError("cell 长度异常：%d @ %d" % (size, offset))
        if abs_off + size > self._size:
            raise HiveError("cell 内容超出文件范围：%d" % offset)
        data = self._f.read(size - 4)
        if len(data) != size - 4:
            raise HiveError("cell 内容不可完整读取：%d" % offset)
        return data, in_use

    def _nk(self, offset, parent_path=""):
        data, in_use = self._cell(offset)
        if not in_use or len(data) < 72 or data[:2] != NK_SIG:
            raise HiveError("无效的 NK cell：%d" % offset)
        flags = _u16(data, 2)
        # NK 名称长度在 payload 0x48，名称自 0x4C 起（实测 regf：
        # 0x44 另有一个保留/最大长度字段，不能按旧版 0x44/0x48 读取）。
        name_len = _u16(data, 72)
        if name_len > 512 or 76 + name_len > len(data):
            raise HiveError("NK 名称长度异常：%d" % name_len)
        name = _decode_name(data[76:76 + name_len], bool(flags & 0x20))
        path = (parent_path.rstrip("\\") + "\\" + name) if name else parent_path
        return Key(self, name, path, flags,
                   _u32(data, 28), _u32(data, 20),
                   _u32(data, 40), _u32(data, 36))

    @property
    def root(self):
        return self._nk(self._root_offset)

    def open(self, path):
        """按大小写不敏感路径取键；路径用 \\ 分隔，如 Select 或 CONTROLSET001\\Services。"""
        cur = self.root
        if not path or path == "\\":
            return cur
        parts = [p for p in str(path).replace("/", "\\").split("\\") if p]
        for part in parts:
            found = None
            for child in self._subkeys(cur):
                if child.name.lower() == part.lower():
                    found = child
                    break
            if found is None:
                return None
            cur = found
        return cur

    def _subkeys(self, key):
        if (not key.subkey_count or key.subkey_count >= 0xFFFFFF00
                or not key.subkey_offset):
            return []
        data, _ = self._cell(key.subkey_offset)
        sig = data[:2]
        if sig in (b"lf", b"lh"):
            count = _u16(data, 2)
            if count > key.subkey_count + 1024:
                raise HiveError("子键索引数量异常")
            offsets = [_u32(data, 4 + i * 8) for i in range(count)]
        elif sig == b"li":
            count = _u16(data, 2)
            offsets = [_u32(data, 4 + i * 4) for i in range(count)]
        elif sig == b"ri":
            count = _u16(data, 2)
            offsets = []
            for i in range(count):
                sub, _ = self._cell(_u32(data, 4 + i * 4))
                if sub[:2] not in (b"lf", b"lh", b"li"):
                    raise HiveError("RI 指向非子键索引")
                n = _u16(sub, 2)
                step = 8 if sub[:2] in (b"lf", b"lh") else 4
                offsets.extend(_u32(sub, 4 + j * step) for j in range(n))
        else:
            raise HiveError("未知子键索引签名：%r" % sig)
        return [self._nk(off, key.path) for off in offsets]

    def _values(self, key):
        if (not key.value_count or key.value_count >= 0xFFFFFF00
                or not key.value_offset):
            return {}
        data, _ = self._cell(key.value_offset)
        # 值列表 cell 直接存放 count 个 VK cell 偏移，没有额外的长度前缀。
        count = min(key.value_count, len(data) // 4)
        if count > 65535:
            raise HiveError("值数量异常")
        out = {}
        for i in range(count):
            off = _u32(data, i * 4)
            out.update(self._vk(off))
        return out

    def _vk(self, offset):
        data, in_use = self._cell(offset)
        if not in_use or len(data) < 20 or data[:2] != VK_SIG:
            raise HiveError("无效的 VK cell：%d" % offset)
        name_len = _u16(data, 2)
        if name_len > 1024 or 20 + name_len > len(data):
            raise HiveError("VK 名称长度异常：%d" % name_len)
        flags = _u16(data, 16)
        name = _decode_name(data[20:20 + name_len], bool(flags & 0x01))
        raw_size = _u32(data, 4)
        data_off = _u32(data, 8)
        vtype = _u32(data, 12)
        size = raw_size & 0x7FFFFFFF
        if size > MAX_VALUE_BYTES:
            raise HiveError("值数据过大：%d" % size)
        if raw_size & 0x80000000:
            # 高位 = 数据直接内联在 VK cell 内，紧跟名称之后（data_offset 无效）。
            start = 20 + name_len
            if start + size > len(data):
                raise HiveError("VK 内联数据越界：%d" % offset)
            payload = data[start:start + size]
        elif size == 0:
            payload = b""
        elif size >= 0x8000:
            db, _ = self._cell(data_off)
            if db[:2] != b"db" or len(db) < 8:
                raise HiveError("大数据 cell 签名无效")
            seg_count = _u32(db, 4)
            if 8 + seg_count * 4 > len(db):
                raise HiveError("大数据段索引越界")
            chunks = []
            remaining = size
            for i in range(seg_count):
                seg, _ = self._cell(_u32(db, 8 + i * 4))
                take = min(len(seg), remaining)
                chunks.append(seg[:take])
                remaining -= take
                if remaining <= 0:
                    break
            payload = b"".join(chunks)
        else:
            cell, _ = self._cell(data_off)
            payload = cell[:size]
        return {name: (vtype, _decode_data(vtype, payload))}

    def value(self, key_path, value_name, default=None):
        key = self.open(key_path)
        if key is None:
            return default
        vals = key.values()
        for k, v in vals.items():
            if k.lower() == value_name.lower():
                return v[1]
        return default


def select_current_number(hive):
    """离线 SYSTEM hive 没有 CurrentControlSet：必须读 Select\\Current。"""
    raw = hive.value("Select", "Current")
    if raw is None:
        raise HiveError("SYSTEM hive 缺少 Select\\Current，无法定位活动控制集")
    try:
        num = int(raw)
    except (TypeError, ValueError):
        raise HiveError("Select\\Current 不是整数：%r" % (raw,))
    if num < 1 or num > 999:
        raise HiveError("Select\\Current 超出合理范围：%d" % num)
    return num


def control_set_name(hive):
    return "ControlSet%03d" % select_current_number(hive)


def _to_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, (list, tuple)):
        return "; ".join(str(x) for x in value)
    return "" if value is None else str(value)


def read_persistence(hive_system, hive_software, hive_users=()):
    """只读汇总三类持久化点。返回 (rows, errors)，每项含 source/name/value/note。

    rows 只是"待人工复核的线索"，不在这里判恶意：本函数不做任何查杀动作。
    """
    rows, errors = [], []
    cs = control_set_name(hive_system) if hive_system else None

    def add(source, name, value, note=""):
        rows.append({"source": source, "name": name,
                     "value": _to_text(value), "note": note})

    if cs:
        try:
            services = hive_system.open(cs + "\\Services")
            if services:
                for svc in hive_system._subkeys(services):
                    vals = svc.values()
                    image = next((v[1] for k, v in vals.items()
                                  if k.lower() == "imagepath"), None)
                    start = next((v[1] for k, v in vals.items()
                                  if k.lower() == "start"), None)
                    if image:
                        add("服务/驱动(%s)" % cs, svc.name, image,
                            "Start=%s；离线注册表，需核对文件签名与来源" % start)
        except Exception as exc:
            errors.append("Services 解析失败：%s" % exc)

    if hive_software:
        for sub in ("Microsoft\\Windows\\CurrentVersion\\Run",
                    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"):
            try:
                key = hive_software.open(sub)
                if key:
                    for k, (_, v) in key.values().items():
                        if sub.endswith("Shell Folders") and not str(v).lower().endswith(("exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs")):
                            continue
                        add("SOFTWARE\\" + sub, k, v)
            except Exception as exc:
                errors.append("%s 解析失败：%s" % (sub, exc))
        try:
            wl = hive_software.open("Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
            if wl:
                for k in ("Shell", "Userinit"):
                    v = next((val[1] for n, val in wl.values().items()
                              if n.lower() == k.lower()), None)
                    if v is not None:
                        add("Winlogon", k, v, "正常值通常为 explorer.exe / userinit.exe,")
        except Exception as exc:
            errors.append("Winlogon 解析失败：%s" % exc)

    for idx, hive_user in enumerate(hive_users):
        for sub in ("Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"):
            try:
                key = hive_user.open(sub)
                if key:
                    for k, (_, v) in key.values().items():
                        add("用户%d\\%s" % (idx + 1, sub), k, v)
            except Exception as exc:
                errors.append("用户 hive %d %s 解析失败：%s" % (idx + 1, sub, exc))
    return rows, errors
