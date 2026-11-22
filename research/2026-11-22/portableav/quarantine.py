"""加密隔离区（AES-256-GCM + keyring 包裹每条目 DEK）。

设计取舍（与"把 key 写在密文旁边"的做法相反）：
- 每条目一把随机密钥（DEK），用 keyring 主密钥包裹后存清单；
- 主密钥单独存 `_keyring.bin`，不与任何密文同文件；
- **必须诚实**：主密钥仍在同一介质上，能读盘的人仍可解密。它防的是
  误执行、静态查杀误报、随手拷走，不是取证级对手。这句话要出现在报告首页。

崩溃一致性（照抄主项目踩过的坑）：
- 先写密文（原子替换）→ 清单记 `pending` → 删原文件 → 清单改 `stored`；
- `recover()`：pending 且原文件已消失 → 视为 stored；pending 且原文件还在 → 删密文记 failed。
  这样任何一步断电都不会出现"原文件没了、密文也没了"。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

MANIFEST = "manifest.json"
KEYRING = "_keyring.bin"
ITEM_DIR = "items"

ST_PENDING = "pending"
ST_STORED = "stored"
ST_FAILED = "failed"
ST_RESTORED = "restored"


class QuarantineUnavailable(RuntimeError):
    """缺少加密依赖——绝不退化成明文存放。"""


class RestoreConflict(RuntimeError):
    """目标路径已有文件。按红线：不覆盖。"""


@dataclass
class Item:
    id: str
    original_path: str
    size: int
    sha256: str
    created: str
    status: str = ST_PENDING
    rules: List[str] = field(default_factory=list)
    key_wrapped: str = ""
    wrap_nonce: str = ""
    error: str = ""


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except Exception as exc:  # 没有 cryptography 就不允许隔离
        raise QuarantineUnavailable(
            "缺少 cryptography，拒绝以明文方式存放隔离文件：%s" % exc)


def _atomic_write(path: str, data: bytes) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def guard_output_dir(path: str, system_drive: str = "X:") -> None:
    """禁止把隔离区/日志/报告放到 WinPE 的内存盘（X:）。"""
    drive = os.path.splitdrive(os.path.abspath(path))[0].upper()
    if drive and drive == system_drive.upper():
        raise ValueError("拒绝把输出写到 %s（WinPE 内存盘，空间极小且断电即失）" % drive)


class Quarantine:
    def __init__(self, root: str, system_drive: str = "X:"):
        guard_output_dir(root, system_drive)
        self.root = os.path.abspath(root)
        self.item_dir = os.path.join(self.root, ITEM_DIR)
        self.manifest_path = os.path.join(self.root, MANIFEST)
        self.keyring_path = os.path.join(self.root, KEYRING)
        os.makedirs(self.item_dir, exist_ok=True)
        self._items: Dict[str, Item] = {}
        self._load()

    # ---------------------------------------------------------- 清单

    def _load(self) -> None:
        self._items = {}
        if not os.path.isfile(self.manifest_path):
            return
        try:
            data = json.loads(open(self.manifest_path, encoding="utf-8").read())
        except (OSError, ValueError):
            return
        for row in data.get("items", []):
            try:
                self._items[row["id"]] = Item(**{k: row[k] for k in Item.__dataclass_fields__
                                                 if k in row})
            except Exception:
                continue

    def _flush(self) -> None:
        payload = {"schema": 1, "tool": "PortableAV", "updated": _now(),
                   "items": [asdict(i) for i in self._items.values()]}
        _atomic_write(self.manifest_path,
                      json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))

    # ---------------------------------------------------------- 密钥

    def _master_key(self, create: bool = True) -> bytes:
        AESGCM = _aesgcm()
        if os.path.isfile(self.keyring_path):
            raw = open(self.keyring_path, "rb").read()
            if len(raw) == 32:
                return raw
            raise QuarantineUnavailable("keyring 长度异常（%d 字节）" % len(raw))
        if not create:
            raise QuarantineUnavailable("keyring 不存在")
        key = AESGCM.generate_key(bit_length=256)
        try:
            fd = os.open(self.keyring_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return open(self.keyring_path, "rb").read()
        with os.fdopen(fd, "wb") as f:
            f.write(key)
            f.flush()
            os.fsync(f.fileno())
        return key

    # ---------------------------------------------------------- 隔离

    def quarantine_file(self, path: str, rules: Optional[List[str]] = None) -> Item:
        AESGCM = _aesgcm()
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        data = open(path, "rb").read()
        digest = hashlib.sha256(data).hexdigest()
        size = len(data)

        master = self._master_key()
        dek = AESGCM.generate_key(bit_length=256)
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(master).encrypt(wrap_nonce, dek, None)
        nonce = os.urandom(12)

        qid = uuid.uuid4().hex[:12]
        payload = AESGCM(dek).encrypt(nonce, data, qid.encode("ascii"))
        _atomic_write(os.path.join(self.item_dir, qid + ".qbin"), nonce + payload)

        item = Item(id=qid, original_path=path, size=size, sha256=digest,
                    created=_now(), status=ST_PENDING, rules=list(rules or []),
                    key_wrapped=base64.b64encode(wrapped).decode("ascii"),
                    wrap_nonce=base64.b64encode(wrap_nonce).decode("ascii"))
        self._items[qid] = item
        self._flush()

        # 删除前再核一次内容，防止"加密的是旧内容、删的是新内容"
        try:
            now_digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
        except OSError as exc:
            item.status = ST_FAILED
            item.error = "删除前复核失败：%s" % exc
            self._flush()
            return item
        if now_digest != digest:
            item.status = ST_FAILED
            item.error = "文件在隔离过程中被修改，已放弃（原文件保留）"
            self._flush()
            return item

        try:
            os.remove(path)
        except OSError as exc:
            item.status = ST_FAILED
            item.error = "移除原文件失败：%s" % exc
            self._flush()
            return item

        item.status = ST_STORED
        self._flush()
        return item

    # ---------------------------------------------------------- 还原

    def restore(self, qid: str) -> str:
        AESGCM = _aesgcm()
        item = self._items.get(qid)
        if item is None:
            raise KeyError("无此隔离项：%s" % qid)
        if item.status == ST_RESTORED:
            raise RestoreConflict("该隔离项已还原过")
        blob_path = os.path.join(self.item_dir, qid + ".qbin")
        if not os.path.isfile(blob_path):
            raise FileNotFoundError("隔离文件缺失：%s" % blob_path)

        master = self._master_key(create=False)
        dek = AESGCM(master).decrypt(base64.b64decode(item.wrap_nonce),
                                     base64.b64decode(item.key_wrapped), None)
        blob = open(blob_path, "rb").read()
        if len(blob) < 12:
            raise ValueError("隔离文件损坏（长度不足）")
        data = AESGCM(dek).decrypt(blob[:12], blob[12:], qid.encode("ascii"))
        if hashlib.sha256(data).hexdigest() != item.sha256:
            raise ValueError("解密后哈希不一致，拒绝写回（可能已损坏）")

        dest = item.original_path
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        try:
            fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            raise RestoreConflict("目标路径已有同名文件，按规则不覆盖：%s" % dest)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

        item.status = ST_RESTORED
        self._flush()
        try:
            os.unlink(blob_path)
        except OSError:
            pass
        return dest

    # ---------------------------------------------------------- 一致性

    def recover(self) -> List[str]:
        """启动时修复崩溃遗留状态，返回处理说明（给报告用）。"""
        notes: List[str] = []
        for item in list(self._items.values()):
            blob = os.path.join(self.item_dir, item.id + ".qbin")
            if item.status != ST_PENDING:
                continue
            if not os.path.exists(item.original_path):
                if os.path.isfile(blob):
                    item.status = ST_STORED
                    notes.append("%s：原文件已不在，密文完好 → 记为 stored" % item.id)
                else:
                    item.status = ST_FAILED
                    item.error = "pending 状态下密文与原文件都不存在"
                    notes.append("%s：密文与原文件均缺失 → 记为 failed（内容已不可恢复）" % item.id)
            else:
                if os.path.isfile(blob):
                    try:
                        os.unlink(blob)
                    except OSError:
                        pass
                item.status = ST_FAILED
                item.error = "未完成隔离，原文件仍在"
                notes.append("%s：原文件仍在 → 删除密文并记为 failed" % item.id)
        if notes:
            self._flush()
        return notes

    def list_items(self) -> List[Item]:
        return sorted(self._items.values(), key=lambda i: i.created)

    def stats(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for i in self._items.values():
            out[i.status] = out.get(i.status, 0) + 1
        return out


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")
