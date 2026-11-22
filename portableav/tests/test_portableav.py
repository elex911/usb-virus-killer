"""PortableAV 离线引擎测试。

设计要点：
- 凡是能合成的都用合成数据（PE/DER），保证在任何机器（含 CI）可复跑；
- 凡是需要真实系统文件的，用「存在才断言，不存在打印 SKIP」，不让环境差异变成假失败；
- 真实文件那部分验证的是「微软签名机写入的摘要 == 我们自算的摘要」，
  这是外部 oracle，不是自己跟自己对。
"""

from __future__ import annotations

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from portableav import authsig, drives, env, paths, pe


# --------------------------------------------------------------- 合成 PE

def _build_pe32(cert_size=0x40, overlay=0x100):
    """构造一个最小 PE32：2 个节区、1 段 overlay、尾部签名表。"""
    e_lfanew = 0x40
    opt_off = e_lfanew + 24
    size_opt = 224
    sec_off = opt_off + size_opt
    total_header = sec_off + 2 * 40
    size_of_headers = 0x200
    assert total_header <= size_of_headers

    buf = bytearray(b"\x00" * size_of_headers)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, e_lfanew + 4, 0x14C)      # machine i386
    struct.pack_into("<H", buf, e_lfanew + 6, 2)           # numberOfSections
    struct.pack_into("<H", buf, e_lfanew + 20, size_opt)   # sizeOfOptionalHeader
    struct.pack_into("<H", buf, opt_off, 0x10B)            # magic PE32
    struct.pack_into("<I", buf, opt_off + 56, 0x3000)      # SizeOfImage
    struct.pack_into("<I", buf, opt_off + 60, size_of_headers)
    struct.pack_into("<I", buf, opt_off + 92, 16)          # NumberOfRvaAndSizes
    cert_off = 0x200 + 0x200 + 0x200 + overlay
    struct.pack_into("<I", buf, opt_off + 96 + 32, cert_off)
    struct.pack_into("<I", buf, opt_off + 96 + 32 + 4, cert_size if cert_off else 0)

    for i, (name, va, raw_ptr) in enumerate(((".text", 0x1000, 0x200), (".data", 0x2000, 0x400))):
        base = sec_off + i * 40
        buf[base:base + len(name)] = name.encode()
        struct.pack_into("<I", buf, base + 8, 0x200)    # VirtualSize
        struct.pack_into("<I", buf, base + 12, va)      # VirtualAddress
        struct.pack_into("<I", buf, base + 16, 0x200)   # SizeOfRawData
        struct.pack_into("<I", buf, base + 20, raw_ptr)

    # 节区内容 + overlay：用可辨识的填充，便于验证「改哪会变、改哪不会变」
    buf += b"\xAA" * 0x200
    buf += b"\xBB" * 0x200
    buf += b"\xCC" * overlay
    buf += b"\x00" * cert_size
    return bytes(buf)


class _MemFile:
    """给 parse_header/authenticode_digest 用的内存文件（只需 seek/read）。"""

    def __init__(self, data: bytes):
        self._d = data
        self._p = 0

    def seek(self, off, whence=0):
        if whence == 0:
            self._p = off
        elif whence == 1:
            self._p += off
        else:
            self._p = len(self._d) + off
        return self._p

    def read(self, n=-1):
        if n is None or n < 0:
            out = self._d[self._p:]
            self._p = len(self._d)
            return out
        out = self._d[self._p:self._p + n]
        self._p += len(out)
        return out

    def tell(self):
        return self._p


# ------------------------------------------------------------------ PE

def test_pe_header_fields():
    data = _build_pe32()
    info = pe.parse_header(_MemFile(data))
    assert info.is_64 is False
    assert info.size_of_headers == 0x200
    assert info.checksum_offset == 0x40 + 24 + 64
    assert info.security_dir_offset == 0x40 + 24 + 96 + 32
    assert info.cert_file_offset == 0x700       # 0x200*3 + 0x100 overlay
    assert info.cert_size == 0x40
    assert len(info.sections) == 2
    assert info.has_signature is True


def test_pe_rejects_malformed():
    with pytest.raises(pe.PEError):
        pe.parse_header(_MemFile(b"NOTMZ" + b"\x00" * 100))
    bad = bytearray(_build_pe32())
    struct.pack_into("<I", bad, 0x3C, 0x7FFFFFF0)   # e_lfanew 越界
    with pytest.raises(pe.PEError):
        pe.parse_header(_MemFile(bytes(bad)))


def test_hash_ranges_follow_spec():
    info = pe.parse_header(_MemFile(_build_pe32()))
    ranges = pe.hash_ranges(info)
    # opt_off = 0x40+24 = 0x58；CheckSum = 0x98；DataDirectory[4] = 0x58+96+32 = 0xD8
    assert ranges == [
        (0, 0x98),          # 头 -> CheckSum 前
        (0x9C, 0xD8),       # 跳过 4 字节 CheckSum -> DataDirectory[4] 前
        (0xE0, 0x200),      # 跳过 8 字节 -> SizeOfHeaders
        (0x200, 0x400),     # .text
        (0x400, 0x600),     # .data
        (0x600, 0x700),     # overlay（到签名表起点为止，不含签名表）
    ], ranges


def test_digest_excludes_checksum_and_security_dir():
    data = bytearray(_build_pe32())
    base = authsig.authenticode_digest(_MemFile(bytes(data)), pe.parse_header(_MemFile(bytes(data))), "sha256")[0]

    data[0x98] ^= 0xFF                      # CheckSum
    assert authsig.authenticode_digest(_MemFile(bytes(data)), pe.parse_header(_MemFile(bytes(data))), "sha256")[0] == base

    data[0x98] ^= 0xFF
    # DataDirectory[4].Size 改成仍在文件内的合法值（0x40 -> 0x30）：
    # 该 8 字节不参与哈希，所以摘要必须不变
    struct.pack_into("<I", data, 0xD8 + 4, 0x30)
    info = pe.parse_header(_MemFile(bytes(data)))
    assert info.cert_size == 0x30
    assert authsig.authenticode_digest(_MemFile(bytes(data)), info, "sha256")[0] == base


def test_out_of_range_cert_table_is_error_not_unsigned():
    """签名表越界必须报错：静默当作「无签名」会让被截断的样本混成干净文件。"""
    data = bytearray(_build_pe32())
    struct.pack_into("<I", data, 0xD8, 0x700)      # cert offset 不变
    struct.pack_into("<I", data, 0xD8 + 4, 0x400)  # size 超出文件尾
    with pytest.raises(pe.PEError):
        pe.parse_header(_MemFile(bytes(data)))


def test_digest_changes_on_section_edit():
    data = bytearray(_build_pe32())
    base = authsig.authenticode_digest(_MemFile(bytes(data)), pe.parse_header(_MemFile(bytes(data))), "sha256")[0]
    data[0x210] ^= 0xFF                     # 节区内部
    assert authsig.authenticode_digest(_MemFile(bytes(data)), pe.parse_header(_MemFile(bytes(data))), "sha256")[0] != base


def test_digest_changes_on_overlay_edit():
    data = bytearray(_build_pe32())
    base = authsig.authenticode_digest(_MemFile(bytes(data)), pe.parse_header(_MemFile(bytes(data))), "sha256")[0]
    data[0x610] ^= 0xFF                     # overlay 属于哈希范围
    assert authsig.authenticode_digest(_MemFile(bytes(data)), pe.parse_header(_MemFile(bytes(data))), "sha256")[0] != base


def test_digest_ignores_cert_table_bytes():
    data = bytearray(_build_pe32())
    base = authsig.authenticode_digest(_MemFile(bytes(data)), pe.parse_header(_MemFile(bytes(data))), "sha256")[0]
    data[0x720] ^= 0xFF                     # 签名表内部
    assert authsig.authenticode_digest(_MemFile(bytes(data)), pe.parse_header(_MemFile(bytes(data))), "sha256")[0] == base


# ----------------------------------------------------------------- DER

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = bytearray()
        chunk.append(p & 0x7F)
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def test_der_short_and_long_length():
    short = authsig.read_tlv(b"\x04\x03abc", 0)
    assert (short.tag, short.value_len, short.end) == (0x04, 3, 5)
    payload = b"x" * 200
    long_form = _tlv(0x04, payload)
    t = authsig.read_tlv(long_form, 0)
    assert t.value_len == 200 and t.end == len(long_form)
    with pytest.raises(authsig.SigError):
        authsig.read_tlv(b"\x04\x7F" + b"x" * 10, 0)   # 声明 127 字节但只有 10


def test_parse_spc_indirect_extracts_sha256():
    digest = bytes(range(32))
    algid = _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1") + _tlv(0x05, b""))
    digest_info = _tlv(0x30, algid + _tlv(0x04, digest))
    spc = _tlv(0x30, _tlv(0x30, _oid("1.3.6.1.4.1.311.2.1.15")) + digest_info)
    algo, hexed = authsig.parse_spc_indirect(spc)
    assert algo == "sha256"
    assert hexed == digest.hex()


def test_parse_spc_indirect_extracts_sha1():
    digest = bytes(range(20))
    algid = _tlv(0x30, _oid("1.3.14.3.2.26") + _tlv(0x05, b""))
    digest_info = _tlv(0x30, algid + _tlv(0x04, digest))
    spc = _tlv(0x30, _tlv(0x30, _oid("1.3.6.1.4.1.311.2.1.15")) + digest_info)
    algo, hexed = authsig.parse_spc_indirect(spc)
    assert (algo, hexed) == ("sha1", digest.hex())


def test_oid_roundtrip():
    for dotted in ("1.3.6.1.4.1.311.2.1.4", "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.9.4"):
        enc = _oid(dotted)
        assert authsig.decode_oid(enc, authsig.read_tlv(enc, 0)) == dotted


# ------------------------------------------------------------ 路径翻译

@pytest.mark.parametrize("raw,expected,remapped,unresolved", [
    (r'"C:\Program Files\App\a b.exe" --silent', r"D:\Program Files\App\a b.exe", True, False),
    (r"C:\Windows\System32\svchost.exe -k netsvcs", r"D:\Windows\System32\svchost.exe", True, False),
    (r"\SystemRoot\System32\drivers\evil.sys", r"D:\Windows\System32\drivers\evil.sys", False, False),
    (r"\??\C:\x\y.sys", r"D:\x\y.sys", True, False),
    (r"\\?\C:\x\y.exe", r"D:\x\y.exe", True, False),
    (r"\\.\C:\x\y.sys", r"D:\x\y.sys", True, False),
    (r"%SystemRoot%\system32\cmd.exe /c calc", r"D:\Windows\system32\cmd.exe", False, False),
    (r"%ProgramFiles(x86)%\App\b.exe /q", r"D:\Program Files (x86)\App\b.exe", False, False),
    (r"%ProgramData%\Microsoft\a.exe", r"D:\ProgramData\Microsoft\a.exe", False, False),
    (r"System32\drivers\x.sys", r"D:\Windows\System32\drivers\x.sys", False, False),
    (r"\Windows\Temp\a.exe", r"D:\Windows\Temp\a.exe", False, False),
    (r"D:\already.exe", r"D:\already.exe", False, False),
    (r"\\server\share\a.exe", r"\\server\share\a.exe", False, True),
    (r"svchost.exe", r"svchost.exe", False, True),
    ("", "", False, True),
])
def test_translate_cases(raw, expected, remapped, unresolved):
    r = paths.translate(raw, "D:")
    assert (r.translated, r.remapped, r.unresolved) == (expected, remapped, unresolved), r


def test_translate_device_map():
    r = paths.translate(r"\Device\HarddiskVolume3\Windows\a.exe", "D:", device_map={3: "E:"})
    assert r.translated == r"E:\Windows\a.exe"
    # 映射到真实盘后不得再被重映射成目标盘
    assert r.remapped is False
    r2 = paths.translate(r"\Device\HarddiskVolume9\Windows\a.exe", "D:")
    assert r2.unresolved is True


def test_translate_is_idempotent():
    once = paths.translate(r"C:\Windows\a.exe", "D:").translated
    twice = paths.translate(once, "D:").translated
    assert once == twice == r"D:\Windows\a.exe"


def test_system_critical_guard():
    assert paths.is_system_critical(r"D:\Windows\System32\config\SYSTEM", "D:")
    assert paths.is_system_critical(r"D:\Windows\System32\winlogon.exe", "D:")
    assert paths.is_system_critical(r"D:\bootmgr", "D:")
    assert not paths.is_system_critical(r"D:\Users\Public\a.exe", "D:")


# ------------------------------------------------------------ 环境识别

def test_env_true_pe():
    r = env.detect(environ={"SystemDrive": "X:", "windir": "X:\\Windows"},
                   minint_probe=lambda: True, explorer_exists=lambda p: False)
    assert r.mode == env.MODE_WINPE and r.is_offline is True


def test_env_stale_minint_is_only_suspected():
    """普通 Windows 上残留 MiniNT 键时必须降级为「疑似」，不能直接判 PE。"""
    r = env.detect(environ={"SystemDrive": "C:", "windir": "C:\\Windows"},
                   minint_probe=lambda: True, explorer_exists=lambda p: True)
    assert r.mode == env.MODE_SUSPECTED
    assert r.is_offline is True          # 离线语义下宁可少做


def test_env_normal_windows():
    r = env.detect(environ={"SystemDrive": "C:", "windir": "C:\\Windows"},
                   minint_probe=lambda: False, explorer_exists=lambda p: True)
    assert r.mode == env.MODE_WINDOWS and r.is_offline is False


def test_env_probe_exception_does_not_crash():
    def boom():
        raise OSError("denied")
    r = env.detect(environ={"SystemDrive": "C:", "windir": "C:\\Windows"},
                   minint_probe=boom, explorer_exists=lambda p: True)
    assert r.mode == env.MODE_WINDOWS
    assert "异常" in r.detail["minint_key"]


def test_env_double_count_same_evidence():
    """systemdrive 与 windir 同在 X: 时不能加权重判成 2 条证据。"""
    r = env.detect(environ={"SystemDrive": "X:", "windir": "X:\\Windows"},
                   minint_probe=lambda: False, explorer_exists=lambda p: False)
    assert r.mode == env.MODE_SUSPECTED
    assert "windir_x" not in r.signals


# ------------------------------------------------------------ 盘符定位

def _fake_pool():
    return [drives.Drive("C:", drives.DRIVE_FIXED),
            drives.Drive("D:", drives.DRIVE_FIXED),
            drives.Drive("E:", drives.DRIVE_REMOVABLE),
            drives.Drive("X:", drives.DRIVE_RAMDISK)]


def test_find_offline_systems_complete_and_partial():
    present = {r"C:\Windows\System32\ntoskrnl.exe", r"C:\Windows\System32\config\SYSTEM",
               r"D:\Windows\System32\ntoskrnl.exe"}

    def sub(p):
        return {"C:\\": ["Windows"], "D:\\": ["Windows"], "E:\\": ["Windows"], "X:\\": ["Windows"]}.get(p, [])

    found = drives.find_offline_systems(_fake_pool(), exists=lambda p: p in present,
                                        in_pe=True, subdirs=sub)
    by_drive = {s.drive: s for s in found}
    assert by_drive["C:"].complete is True
    assert by_drive["D:"].complete is False and "SYSTEM" in by_drive["D:"].missing
    assert "E:" not in by_drive            # 可移动盘默认不作为目标
    assert "X:" not in by_drive            # PE 自身盘必须排除


def test_find_offline_systems_multi_boot_dirs():
    present = {r"D:\Windows\System32\ntoskrnl.exe", r"D:\Windows\System32\config\SYSTEM",
               r"D:\Windows.old\System32\ntoskrnl.exe", r"D:\Windows.old\System32\config\SYSTEM"}
    found = drives.find_offline_systems(
        [drives.Drive("D:", drives.DRIVE_FIXED)],
        exists=lambda p: p in present, in_pe=False,
        subdirs=lambda p: ["Windows", "Windows.old"] if p == "D:\\" else [])
    assert [s.windows_dir for s in found] == [r"D:\Windows", r"D:\Windows.old"]
    assert all(s.complete for s in found)


def test_find_offline_systems_empty_is_allowed():
    """找不到目标必须返回空，由调用方决定怎么提示——绝不自动猜一个盘。"""
    assert drives.find_offline_systems(_fake_pool(), exists=lambda p: False,
                                       in_pe=True, subdirs=lambda p: ["Windows"]) == []


# ------------------------------------------- 真实文件：外部 oracle 核对

_REAL = [r"C:\Windows\System32\kernel32.dll",
         r"C:\Windows\System32\drivers\disk.sys",
         r"C:\Windows\explorer.exe"]


def test_real_files_digest_matches_signer():
    """微软签名机写入的摘要 == 我们自算的摘要。不等就说明哈希实现错了。"""
    checked = 0
    for p in _REAL:
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as f:
            info = pe.parse_header(f)
            sigs = authsig.embedded_signatures(f, info)
            assert sigs, "系统文件应当有内嵌签名：%s" % p
            ok, detail = authsig.check_digest_matches(f, info, sigs[0])
            assert ok is True, "%s -> %s" % (p, detail)
            checked += 1
    if not checked:
        pytest.skip("无可用系统签名文件（非 Windows 环境）")


def test_notepad_has_no_embedded_signature():
    """notepad.exe 走 CatRoot 编录签名；据此判恶意是错的，用例把这个事实钉住。"""
    p = r"C:\Windows\System32\notepad.exe"
    if not os.path.isfile(p):
        pytest.skip("非 Windows 环境")
    with open(p, "rb") as f:
        info = pe.parse_header(f)
        assert authsig.embedded_signatures(f, info) == []


# ---------------------------------------------- WIN_CERTIFICATE 链与尾部载荷

def _win_cert(body: bytes, rev=0x0200, ctype=2) -> bytes:
    """构一条 WIN_CERTIFICATE：dwLength 含 8 字节头，且补齐到 8 字节对齐。"""
    total = 8 + len(body)
    pad = (8 - total % 8) % 8
    return (struct.pack("<IHH", total + pad, rev, ctype) + body
            + b"\x00" * pad)


def _pe_with_cert(cert_blob: bytes) -> bytes:
    data = bytearray(_build_pe32(cert_size=len(cert_blob)))
    cert_off = 0x700
    data[cert_off:cert_off + len(cert_blob)] = cert_blob
    return bytes(data)


def test_dual_certificate_chain_enumerated():
    """双签名文件的两个 WIN_CERTIFICATE 必须都能枚举到（对齐不能错）。"""
    blob = _win_cert(b"ABCD" * 8) + _win_cert(b"WXYZ" * 4, rev=0x0100)
    info = pe.parse_header(_MemFile(_pe_with_cert(blob)))
    sigs = authsig.embedded_signatures(_MemFile(_pe_with_cert(blob)), info)
    assert len(sigs) == 2
    assert [s.revision for s in sigs] == [0x0200, 0x0100]
    # 内容不是合法 PKCS#7，必须报错而不是静默当成「无签名」
    assert all(s.error for s in sigs)


def test_tail_slack_detects_appended_payload():
    """签名表里 ASN.1 结束之后还塞了 20 字节 → 必须能算出来。"""
    body = _tlv(0x30, b"abc") + b"\xDE\xAD" * 10
    assert authsig.tail_slack(body) == 20
    assert authsig.tail_slack(_tlv(0x30, b"abc")) == 0
    assert authsig.tail_slack(b"\xFF\xFF\xFF") == -1     # 解析不了 → -1
