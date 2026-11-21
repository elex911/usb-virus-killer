# 一次性校验脚本：从 PyInstaller exe 内嵌归档抽出 core.app 模块字节码，核对手机号掩码
import marshal  # noqa: E402
import sys

sys.path.insert(0, ".")
from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader  # noqa: E402

EXE = r"dist\文件夹病毒查杀工具.exe"
# 全号不在仓库留字面量：分段拼出（与 GUI 掩码规则一致：前3 + 中6掩码 + 后2）
FULL = "".join(["180", "7090", "7766"]).encode("utf-8")
MASK = "180******66".encode("utf-8")

pkg = CArchiveReader(EXE)
pyz_name = next(n for n in pkg.toc if str(n).endswith(".pyz") or str(n) == "PYZ-00.pyz")
print("pyz 条目:", pyz_name, "toc=", pkg.toc[pyz_name])
blob = pkg.extract(str(pyz_name))
assert blob[:4] == b"PYZ\x00", f"PYZ magic 不对: {blob[:8]!r}"
import tempfile, os  # noqa: E402
tmp = os.path.join(tempfile.gettempdir(), "fk_pyz_check.pyz")
with open(tmp, "wb") as f:
    f.write(blob)
pyz = ZlibArchiveReader(tmp)

hits = {}
for name in list(pyz.toc):
    if str(name).endswith(("core.app", "modules.classic_trojans")):
        data = marshal.dumps(pyz.extract(str(name)))
        hits[str(name)] = (data.count(FULL), data.count(MASK))

ok = True
for name, (full, mask) in sorted(hits.items()):
    print(f"{name}: 全号={full} 掩码={mask}")
    if name.endswith("core.app"):
        ok = ok and full == 0 and mask == 1

print("VERIFY", "PASS" if ok else "FAIL")
