"""端到端链路测试：隔离 → 还原 → 扫描调度 → 报告 → 吊销。

这些用例全部用合成数据，任何机器都能跑，不依赖系统文件。
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from portableav import matcher, quarantine, report, revoke, scan, trust

EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def _write(path: str, data: bytes) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


# ------------------------------------------------------------ 隔离区

def test_quarantine_roundtrip(tmp_path):
    src = _write(os.path.join(str(tmp_path), "t", "eicar.com"), EICAR)
    before = hashlib.sha256(EICAR).hexdigest()
    qm = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    item = qm.quarantine_file(src, ["EICAR-Test-File"])
    assert item.status == quarantine.ST_STORED
    assert not os.path.exists(src), "隔离后原路径必须为空"

    blob = open(os.path.join(qm.item_dir, item.id + ".qbin"), "rb").read()
    assert b"EICAR-STANDARD" not in blob, "密文里不得出现明文"
    assert item.sha256 == before

    dest = qm.restore(item.id)
    assert os.path.isfile(dest)
    assert hashlib.sha256(open(dest, "rb").read()).hexdigest() == before


def test_keyring_not_stored_with_ciphertext(tmp_path):
    """主密钥必须单独文件，不能写进清单；元数据里只能是被包裹的 DEK。"""
    src = _write(os.path.join(str(tmp_path), "t", "a.bin"), b"hello" * 100)
    qm = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    item = qm.quarantine_file(src)
    assert os.path.isfile(qm.keyring_path)
    master = open(qm.keyring_path, "rb").read()
    assert len(master) == 32

    manifest = open(qm.manifest_path, encoding="utf-8").read()
    assert master.hex().upper() not in manifest.upper(), "清单里不得出现主密钥"
    import base64 as b64
    assert master not in b64.b64decode(item.key_wrapped), "包裹后的 DEK 不应等于主密钥"
    # 被包裹的 DEK = 32 字节密钥 + 16 字节 GCM tag
    assert len(b64.b64decode(item.key_wrapped)) == 48
    assert len(b64.b64decode(item.wrap_nonce)) == 12


def test_restore_refuses_to_overwrite(tmp_path):
    src = _write(os.path.join(str(tmp_path), "t", "b.bin"), b"payload")
    qm = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    item = qm.quarantine_file(src)
    _write(src, b"someone-else-created-this")     # 原路径被重新占用
    with pytest.raises(quarantine.RestoreConflict):
        qm.restore(item.id)
    assert open(src, "rb").read() == b"someone-else-created-this"


def test_restore_detects_corrupted_blob(tmp_path):
    src = _write(os.path.join(str(tmp_path), "t", "c.bin"), b"payload-123")
    qm = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    item = qm.quarantine_file(src)
    blob_path = os.path.join(qm.item_dir, item.id + ".qbin")
    data = bytearray(open(blob_path, "rb").read())
    data[-1] ^= 0xFF                              # 破坏 GCM tag
    open(blob_path, "wb").write(bytes(data))
    with pytest.raises(Exception):
        qm.restore(item.id)
    assert not os.path.exists(src), "校验失败时不得写回任何文件"


def test_recover_pending_with_original_gone_becomes_stored(tmp_path):
    src = _write(os.path.join(str(tmp_path), "t", "d.bin"), b"abc")
    qm = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    item = qm.quarantine_file(src)
    # 人为把状态退回 pending，模拟"删完原文件、还没写 stored 就断电"
    qm._items[item.id].status = quarantine.ST_PENDING
    qm._flush()
    qm2 = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    notes = qm2.recover()
    assert qm2._items[item.id].status == quarantine.ST_STORED
    assert notes


def test_recover_pending_with_original_present_drops_ciphertext(tmp_path):
    src = _write(os.path.join(str(tmp_path), "t", "e.bin"), b"abc")
    qm = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    item = qm.quarantine_file(src)
    blob = os.path.join(qm.item_dir, item.id + ".qbin")
    _write(src, b"abc")                            # 原文件又出现了（模拟中断/回滚）
    qm._items[item.id].status = quarantine.ST_PENDING
    qm._flush()
    qm2 = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    qm2.recover()
    assert qm2._items[item.id].status == quarantine.ST_FAILED
    assert not os.path.exists(blob), "原文件还在时不该留着密文"


def test_guard_refuses_x_drive():
    with pytest.raises(ValueError):
        quarantine.Quarantine("X:\\PortableAV_Quarantine")


# ------------------------------------------------------------ 扫描调度

def _scan(target, **kw):
    kw.setdefault("matcher", matcher.EicarMatcher())
    return scan.scan_tree(target, [], index=None, limits=scan.Limits(), **kw)


def test_scan_detects_eicar_and_quarantines(tmp_path):
    root = os.path.join(str(tmp_path), "tree")
    _write(os.path.join(root, "evil", "eicar.com"), EICAR)
    _write(os.path.join(root, "ok", "note.txt"), b"hello")
    qm = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    summ = _scan(root, quarantine=qm, dry_run=False, protect=lambda p: False)
    assert summ.count(trust.LEVEL_BLACK) == 1
    assert summ.quarantine_status
    assert qm.stats().get(quarantine.ST_STORED) == 1
    assert not os.path.exists(os.path.join(root, "evil", "eicar.com"))


def test_scan_dry_run_does_not_touch_files(tmp_path):
    root = os.path.join(str(tmp_path), "tree")
    _write(os.path.join(root, "eicar.com"), EICAR)
    qm = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    summ = _scan(root, quarantine=qm, dry_run=True, protect=lambda p: False)
    black = [r for r in summ.results if r.level == trust.LEVEL_BLACK]
    assert black and "未处置" in black[0].action
    assert os.path.isfile(os.path.join(root, "eicar.com"))


def test_scan_protected_path_only_alerts(tmp_path):
    root = os.path.join(str(tmp_path), "tree")
    _write(os.path.join(root, "eicar.com"), EICAR)
    qm = quarantine.Quarantine(os.path.join(str(tmp_path), "q"))
    summ = _scan(root, quarantine=qm, dry_run=False, protect=lambda p: True)
    black = [r for r in summ.results if r.level == trust.LEVEL_BLACK]
    assert black and "仅告警" in black[0].action
    assert os.path.isfile(os.path.join(root, "eicar.com")), "护栏必须挡住处置"
    assert qm.stats().get(quarantine.ST_STORED, 0) == 0


def test_scan_counts_parse_failure_separately(tmp_path):
    root = os.path.join(str(tmp_path), "tree")
    _write(os.path.join(root, "bad.exe"), b"MZ" + b"\x00" * 100)   # 畸形 PE
    summ = _scan(root)
    assert len(summ.errors) == 1
    assert summ.count(trust.LEVEL_GRAY) == 0, "解析失败不得混进灰名单"
    assert "PE 解析失败" in summ.errors[0].error


def test_scan_skips_big_files(tmp_path):
    root = os.path.join(str(tmp_path), "tree")
    p = os.path.join(root, "big.bin")
    os.makedirs(root, exist_ok=True)
    with open(p, "wb") as f:
        f.write(b"\x00" * 4096)
    summ = scan.scan_tree(root, [], index=None, matcher=matcher.EicarMatcher(),
                          limits=scan.Limits(max_file_bytes=1024))
    assert summ.skipped_big == 1
    assert summ.files_scanned == 0


def test_scan_does_not_follow_reparse(tmp_path):
    root = os.path.join(str(tmp_path), "tree")
    _write(os.path.join(root, "a.txt"), b"x")
    summ = _scan(root)
    assert summ.files_scanned == 1


# ------------------------------------------------------------ 吊销

def test_blacklist_json_and_text(tmp_path):
    p1 = os.path.join(str(tmp_path), "b.json")
    open(p1, "w", encoding="utf-8").write(json.dumps(
        {"sha1": ["aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd"]}))
    p2 = os.path.join(str(tmp_path), "b.txt")
    open(p2, "w", encoding="utf-8").write(
        "# comment\n" + "11" * 32 + "\n")
    rl = revoke.load_blacklists([p1, p2])
    assert rl.loaded
    assert len(rl.sha1) == 1 and len(rl.sha256) == 1
    assert "吊销黑名单" in rl.summary()


def test_empty_blacklist_is_reported_not_silent(tmp_path):
    p = os.path.join(str(tmp_path), "empty.txt")
    open(p, "w", encoding="utf-8").write("# nothing here\n")
    rl = revoke.load_blacklist(p)
    assert rl.loaded is False
    assert "未启用" in rl.summary()


# ------------------------------------------------------------ 报告

def test_report_contains_failure_section_and_escapes(tmp_path):
    root = os.path.join(str(tmp_path), "tree")
    # 用 Windows 合法的特殊字符验证转义（< > 不能出现在文件名里）
    odd = "a&b'c.txt"
    _write(os.path.join(root, odd), b"x")
    _write(os.path.join(root, "bad.exe"), b"MZ" + b"\x00" * 50)
    summ = _scan(root)
    out = os.path.join(str(tmp_path), "r.html")
    report.generate(out, summ, index=None, revocation=None,
                    meta={"mode": "测试", "max_file_mb": 1, "max_depth": 3,
                          "workers": 4, "quarantine_items": []})
    doc = open(out, encoding="utf-8").read()
    assert "解析失败" in doc
    assert "没有被检查" in doc
    assert "a&b'c.txt" not in doc, "文件名必须转义"
    assert "a&amp;b&#x27;c.txt" in doc or "a&amp;b'c.txt" in doc
    assert "能读该介质的人仍可解密" in doc
