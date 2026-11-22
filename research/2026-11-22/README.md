# 研究成果快照 · 2026-11-22

本目录是 **`dcc0fc7` 时点的只读快照**，用于留档与交付核对。权威代码在仓库根的同名目录；
这里不承接开发，改动请在主线做，再重新快照。

## 这一版包含什么

| 目录 | 内容 |
|---|---|
| `portableav/` | WinPE 离线取证查杀引擎（V0.4）：路径翻译、离线盘定位、PE 解析、Authenticode 摘要、证书链 + RFC3161 时间戳、`.cat` 编录索引、吊销、持久化矩阵、加密隔离、HTML 报告、CLI |
| `core/` | 只带两件：`__init__.py` 与 `offline_registry.py`。PortableAV 的持久化矩阵**复用**这套只读 hive 解析（不另造第二套），所以快照必须带上，否则 `persist` 会静默降级——快照首跑就是被 `test_persist` 顶出来的 |
| `portableav/DESIGN.md` | 设计说明：六条铁律裁决、我改掉的规范、判定分级、分阶段路线、未验证清单 |
| `tools/` | `build_portable.py`（绿包构建，8 段并发下载）、`verify_portable.py`（绿包逐文件校验）、`check_exe_freshness.py`（exe 与源码一致性门禁） |
| `tests/` | GUI 侧新增用例：系统盘门禁、未勾选拒绝、关键路径只报告 |
| `docs/` | `AGENTS.md`（项目红线）、`使用说明.md`（GUI 工具说明） |

## 不在本目录、但需要知道的两件产物

构建产物体积大且被 `.gitignore` 排除，因此**只登记哈希，不拷贝**（见 `VERIFY.json`）：

| 产物 | 重建方式 | 登记信息 |
|---|---|---|
| `dist/文件夹病毒查杀工具.exe` | `python -m PyInstaller 文件夹病毒查杀工具.spec --noconfirm` | 12,480,916 字节，SHA-256 `2fbd7001…` |
| `dist_portable/PortableAV/` | `python tools/build_portable.py --out dist_portable/PortableAV --threads 8` | 224 文件 / 32.1 MB，归档 `009d6bf7…` |

## 怎么验证

```bat
:: 1) 快照自身的引擎测试（相对自身路径导入，测的是快照，不是活代码）
python -m pytest research\2026-11-22\portableav\tests -q

:: 2) GUI 侧门禁用例
python -m pytest tests\test_local_disk_scan.py -q

:: 3) 交付 exe 是否与源码一致（PASS 才可交付）
python tools\check_exe_freshness.py dist\文件夹病毒查杀工具.exe
```

## 与主线的差异核对

```bat
:: 快照只读；若想知道主线改了哪些，用 diff 而不是"感觉"
git diff --stat dcc0fc7 -- portableav
```

## 已知边界（别当成成品）

- 未在真实 **WinPE** 里跑过；缺 DLL、只读 `X:`、BitLocker 锁盘都无实测。
- `yara-x` 未安装：当前生效的规则只有内置 EICAR 特征。
- 双签名（SHA-1+SHA-256）**无真实样本**（本机 7191 个系统文件里 0 个）。
- 绿包清单**未签名**：能改文件的人也能改清单。
- 吊销只支持指纹清单，**不是完整 CRL/OCSP**。

详见 `portableav/DESIGN.md` §9 与 `docs/AGENTS.md` 的红线条目。
