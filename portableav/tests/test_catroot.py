"""catroot + trust 的判定层测试。

核心证据是「伪造编录不得产生白名单」——这条只能靠造一个假 CA 来证明，
真实微软编录只能证明"能通过"，证明不了"该拒的会拒"。
"""

from __future__ import annotations

import glob
import hashlib
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _der as D
from portableav import authsig, catroot, chain, pe, trust

ROOTS_DIR = os.environ.get("PORTABLEAV_ROOTS", "")
NOTEPAD = r"C:\Windows\System32\notepad.exe"
KERNEL32 = r"C:\Windows\System32\kernel32.dll"


# ---------------------------------------------------------------- 伪造编录

def _write_cat(tmpdir, blob, name="fake.cat"):
    p = os.path.join(tmpdir, name)
    with open(p, "wb") as f:
        f.write(blob)
    return p


def _forged_cat(victim_digest):
    """攻击者：自建 CA → 代码签名证书 → 一张含被害文件摘要的编录。"""
    ca_key, ca = D.make_cert("Attacker Root CA", is_ca=True, code_signing=False, serial=71)
    leaf_key, leaf = D.make_cert("Attacker Publisher", ca, ca_key, serial=72)
    ctl = D.build_ctl([victim_digest])
    blob = D.build_pkcs7(ctl, D.OID_CTL, leaf, leaf_key)
    return ca, blob


def test_forged_cat_rejected_and_hash_not_indexed(tmp_path):
    victim = hashlib.sha256(b"some-victim-file").digest()
    ca, blob = _forged_cat(victim)
    cat_path = _write_cat(str(tmp_path), blob)

    # 根集合里没有攻击者 CA → 必须拒绝
    trusted_roots = [chain.parse_cert(D.cert_der(D.make_cert("Real Root", is_ca=True,
                                                             code_signing=False, serial=1)[1]))]
    idx = catroot.build_index([cat_path], trusted_roots)
    assert idx.files_verified == 0
    assert idx.usable is False
    assert idx.lookup(victim) is None
    assert idx.files_rejected and "根" in idx.files_rejected[0][1] or idx.files_rejected


def test_same_cat_accepted_when_root_is_trusted(tmp_path):
    """同一张编录，只要它的 CA 在受信根里，就应该通过——
    这说明上面的拒绝是"因为链不对"，不是因为解析器一律拒绝。"""
    victim = hashlib.sha256(b"some-victim-file").digest()
    ca, blob = _forged_cat(victim)
    cat_path = _write_cat(str(tmp_path), blob)
    roots = [chain.parse_cert(D.cert_der(ca))]
    idx = catroot.build_index([cat_path], roots)
    assert idx.files_verified == 1
    assert idx.usable is True
    assert idx.lookup(victim) == "sha256"


def test_no_roots_makes_index_unusable(tmp_path):
    _, blob = _forged_cat(b"x" * 32)
    cat_path = _write_cat(str(tmp_path), blob)
    idx = catroot.build_index([cat_path], [])
    assert idx.usable is False
    assert "根" in idx.reason


def test_tampered_cat_hashes_not_indexed(tmp_path):
    """签名后往编录里塞哈希（篡改内容）→ 验签失败 → 哈希不得入索引。"""
    ca_key, ca = D.make_cert("Root C", is_ca=True, code_signing=False, serial=81)
    leaf_key, leaf = D.make_cert("Pub C", ca, ca_key, serial=82)
    victim = hashlib.sha256(b"victim").digest()
    ctl = D.build_ctl([victim])
    blob = D.build_pkcs7(ctl, D.OID_CTL, leaf, leaf_key)
    roots = [chain.parse_cert(D.cert_der(ca))]

    # 在 eContent 里替换一个字节：摘要与 messageDigest 不再一致
    bad = blob.replace(b"victim", b"VICTIM")
    if bad == blob:
        bad = bytearray(blob)
        idx0 = bad.find(victim)
        assert idx0 > 0
        bad[idx0] ^= 0xFF
        bad = bytes(bad)
    cat_path = _write_cat(str(tmp_path), bad)
    idx = catroot.build_index([cat_path], roots)
    assert idx.files_verified == 0
    assert idx.lookup(victim) is None


def test_name_based_ctl_extracts_hash_from_attribute(tmp_path):
    """名字型编录（打印机驱动那类）的哈希在 SPC_INDIRECT_DATA 属性里。"""
    ca_key, ca = D.make_cert("Root N", is_ca=True, code_signing=False, serial=91)
    leaf_key, leaf = D.make_cert("Pub N", ca, ca_key, serial=92)
    digest = hashlib.sha1(b"named-member").digest()
    ctl = D.build_name_ctl([("driver.sys", digest)])
    blob = D.build_pkcs7(ctl, D.OID_CTL, leaf, leaf_key)
    cat_path = _write_cat(str(tmp_path), blob)
    idx = catroot.build_index([cat_path], [chain.parse_cert(D.cert_der(ca))])
    assert idx.files_verified == 1
    assert idx.lookup(digest) == "sha1"
    # 回归：10 字符的 UTF-16 文件名正好 20 字节，绝不能被当成 SHA-1 摘要
    assert idx.lookup("driver.sys".encode("utf-16-le")) is None


# ---------------------------------------------------------------- 判定层

def test_judge_gray_when_no_signature_and_no_index(tmp_path):
    src = r"C:\Windows\System32\notepad.exe"
    if not os.path.isfile(src):
        pytest.skip("非 Windows 环境")
    v = trust.judge_pe(src, [], index=None)
    assert v.level == trust.LEVEL_GRAY
    assert "编录" in " ".join(v.reasons)


def test_judge_gray_when_index_unusable(tmp_path):
    src = r"C:\Windows\System32\notepad.exe"
    if not os.path.isfile(src):
        pytest.skip("非 Windows 环境")
    idx = catroot.CatIndex(usable=False, reason="无根证书")
    v = trust.judge_pe(src, [], index=idx)
    assert v.level == trust.LEVEL_GRAY


def test_judge_white_by_catalog(tmp_path):
    """用真实编录命中 notepad：白，依据必须是「编录签名」。"""
    src = NOTEPAD
    if not os.path.isfile(src) or not ROOTS_DIR or not os.path.isdir(ROOTS_DIR):
        pytest.skip("缺少真实根证书或系统文件")
    roots = chain.load_roots_from_dir(ROOTS_DIR)
    cats = glob.glob(r"C:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"
                     r"\Microsoft-Windows-Notepad-System*.cat")
    if not cats:
        pytest.skip("本机无 notepad 编录")
    idx = catroot.build_index(cats, roots)
    assert idx.usable, idx.summary()
    v = trust.judge_pe(src, roots, index=idx)
    assert v.level == trust.LEVEL_WHITE
    assert v.basis == trust.WHITE_CATALOG
    assert v.catalog_file.lower().endswith(".cat")


def test_judge_white_by_embedded_signature():
    src = KERNEL32
    if not os.path.isfile(src) or not ROOTS_DIR or not os.path.isdir(ROOTS_DIR):
        pytest.skip("缺少真实根证书或系统文件")
    roots = chain.load_roots_from_dir(ROOTS_DIR)
    v = trust.judge_pe(src, roots, index=None)
    assert v.level == trust.LEVEL_WHITE
    assert v.basis == trust.WHITE_EMBEDDED


def test_judge_black_when_content_modified(tmp_path):
    """签名有效但内容被改 → 必须判黑，不能因为"签名在"就放行。"""
    src = KERNEL32
    if not os.path.isfile(src) or not ROOTS_DIR or not os.path.isdir(ROOTS_DIR):
        pytest.skip("缺少真实根证书或系统文件")
    roots = chain.load_roots_from_dir(ROOTS_DIR)
    data = bytearray(open(src, "rb").read())
    # 改节区里一个字节（签名表保持不动）
    info = pe.parse_header(open(src, "rb"))
    sec = info.sorted_sections[0]
    data[sec.raw_ptr + 32] ^= 0xFF
    bad = os.path.join(str(tmp_path), "tampered_kernel32.dll")
    with open(bad, "wb") as f:
        f.write(bytes(data))
    v = trust.judge_pe(bad, roots, index=None)
    assert v.level == trust.LEVEL_BLACK, v.summary()


def test_judge_non_pe_is_gray(tmp_path):
    p = os.path.join(str(tmp_path), "a.txt")
    with open(p, "w") as f:
        f.write("hello")
    v = trust.judge_any(p, [])
    assert v.level == trust.LEVEL_GRAY
    assert "非 PE" in " ".join(v.reasons)
