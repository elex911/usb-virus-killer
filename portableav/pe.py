"""最小 PE 解析：只为 Authenticode 哈希与签名表定位服务。

不追求覆盖 PE 全部结构，只保证：
- 所有偏移都做边界检查，畸形文件抛 PEError 而不是 IndexError；
- 节区按 PointerToRawData 排序（Authenticode 规范要求）；
- DataDirectory[4]（Security）里的值是**文件偏移**，不是 RVA——这条错了哈希必错。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Tuple

IMAGE_DIRECTORY_ENTRY_SECURITY = 4
_SIGNATURE = b"PE\x00\x00"
_MAGIC_PE32 = 0x10B
_MAGIC_PE32P = 0x20B


class PEError(Exception):
    """PE 结构非法。调用方必须捕获并计入「解析失败」，不得视为干净。"""


@dataclass(frozen=True)
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_ptr: int


@dataclass(frozen=True)
class PEInfo:
    is_64: bool
    size_of_headers: int
    checksum_offset: int          # OptionalHeader.CheckSum 的绝对文件偏移
    security_dir_offset: int      # DataDirectory[4] 这 8 字节的绝对文件偏移
    cert_file_offset: int         # 签名表文件偏移（0 表示无签名）
    cert_size: int
    sections: Tuple[Section, ...]
    file_size: int
    size_of_image: int
    subsystem: int

    @property
    def has_signature(self) -> bool:
        return self.cert_file_offset > 0 and self.cert_size > 0

    @property
    def sorted_sections(self) -> List[Section]:
        return sorted(self.sections, key=lambda s: s.raw_ptr)

    @property
    def hashed_tail_end(self) -> int:
        """签名表之前的文件末尾（overlay 只算到签名表起点）。"""
        if self.has_signature:
            return min(self.cert_file_offset, self.file_size)
        return self.file_size


def _u16(b: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(b):
        raise PEError("读 u16 越界 @%d" % off)
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(b):
        raise PEError("读 u32 越界 @%d" % off)
    return struct.unpack_from("<I", b, off)[0]


def parse_header(fp) -> PEInfo:
    """只读文件头与节表（不读节区内容），fp 需支持 seek/read。"""
    fp.seek(0, 2)
    file_size = fp.tell()
    if file_size < 0x40:
        raise PEError("文件过短：%d" % file_size)
    fp.seek(0)
    dos = fp.read(0x40)
    if len(dos) < 0x40 or dos[:2] != b"MZ":
        raise PEError("缺少 MZ 头")
    e_lfanew = _u32(dos, 0x3C)
    if e_lfanew <= 0 or e_lfanew + 24 > file_size:
        raise PEError("e_lfanew 越界：%d" % e_lfanew)
    fp.seek(e_lfanew)
    nt = fp.read(24)
    if len(nt) < 24 or nt[:4] != _SIGNATURE:
        raise PEError("缺少 PE 签名")
    num_sections = _u16(nt, 6)
    size_opt = _u16(nt, 20)
    if num_sections > 96:
        raise PEError("节区数量异常：%d" % num_sections)
    opt_off = e_lfanew + 24
    if opt_off + size_opt > file_size:
        raise PEError("OptionalHeader 越界")
    fp.seek(opt_off)
    opt = fp.read(size_opt)
    magic = _u16(opt, 0)
    if magic not in (_MAGIC_PE32, _MAGIC_PE32P):
        raise PEError("未知 OptionalHeader magic：0x%X" % magic)
    is_64 = magic == _MAGIC_PE32P

    size_of_headers = _u32(opt, 60)
    size_of_image = _u32(opt, 56)
    subsystem = _u16(opt, 68)
    checksum_offset = opt_off + 64

    dd_off = 96 if not is_64 else 112
    num_rva = _u32(opt, 92 if not is_64 else 108)
    if num_rva <= IMAGE_DIRECTORY_ENTRY_SECURITY:
        cert_off, cert_size, sec_dir_off = 0, 0, 0
    else:
        sec_dir_off = opt_off + dd_off + IMAGE_DIRECTORY_ENTRY_SECURITY * 8
        if sec_dir_off + 8 > opt_off + size_opt:
            raise PEError("DataDirectory[4] 越界")
        cert_off = _u32(opt, dd_off + IMAGE_DIRECTORY_ENTRY_SECURITY * 8)
        cert_size = _u32(opt, dd_off + IMAGE_DIRECTORY_ENTRY_SECURITY * 8 + 4)

    if cert_off and cert_off + cert_size > file_size:
        # 常见于被截断/被追加写坏的文件：宁可报错，不静默按无签名处理
        raise PEError("签名表越界：off=%d size=%d file=%d" % (cert_off, cert_size, file_size))

    sec_off = opt_off + size_opt
    if sec_off + num_sections * 40 > file_size:
        raise PEError("节表越界")
    fp.seek(sec_off)
    sec_raw = fp.read(num_sections * 40)
    sections: List[Section] = []
    for i in range(num_sections):
        base = i * 40
        name = sec_raw[base:base + 8].split(b"\x00")[0].decode("latin-1", "replace")
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", sec_raw, base + 8)
        sections.append(Section(name, vsize, va, raw_size, raw_ptr))

    return PEInfo(is_64=is_64, size_of_headers=size_of_headers,
                  checksum_offset=checksum_offset, security_dir_offset=sec_dir_off,
                  cert_file_offset=cert_off, cert_size=cert_size,
                  sections=tuple(sections), file_size=file_size,
                  size_of_image=size_of_image, subsystem=subsystem)


def hash_ranges(pe: PEInfo) -> List[Tuple[int, int]]:
    """按 Authenticode 规范给出需要哈希的 [start, end) 区间。

    顺序即规范顺序：头部三段 → 各节区（按 raw_ptr 升序）→ 尾部 overlay。
    """
    ranges: List[Tuple[int, int]] = []
    # 1. 文件头到 CheckSum 之前
    ranges.append((0, pe.checksum_offset))
    # 2. 跳过 4 字节 CheckSum，到 DataDirectory[4] 之前
    if pe.security_dir_offset:
        ranges.append((pe.checksum_offset + 4, pe.security_dir_offset))
        # 3. 跳过 8 字节 DataDirectory[4]，到 PE 头结束
        head_end = min(pe.size_of_headers, pe.hashed_tail_end)
        ranges.append((pe.security_dir_offset + 8, head_end))
    else:
        ranges.append((pe.checksum_offset + 4, min(pe.size_of_headers, pe.hashed_tail_end)))
    # 4. 节区
    end_of_last = 0
    for s in pe.sorted_sections:
        if s.raw_size <= 0 or s.raw_ptr <= 0:
            continue
        start = s.raw_ptr
        end = start + s.raw_size
        if start >= pe.hashed_tail_end:
            continue
        end = min(end, pe.hashed_tail_end)
        if start < end:
            ranges.append((start, end))
            end_of_last = max(end_of_last, end)
    # 5. overlay（最后一个节区之后到签名表起点）
    if end_of_last and end_of_last < pe.hashed_tail_end:
        ranges.append((end_of_last, pe.hashed_tail_end))
    # 只去掉完全重复的区间（畸形文件里可能有重叠节区）；
    # 不做区间归并——规范是「按顺序逐段哈希」，重叠就按规范重复哈希，
    # 擅自去重会得到与微软签名时不同的摘要。
    seen = set()
    out: List[Tuple[int, int]] = []
    for start, end in ranges:
        if start >= end or (start, end) in seen:
            continue
        seen.add((start, end))
        out.append((start, end))
    return out
