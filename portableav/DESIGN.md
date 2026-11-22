# PortableAV 设计说明（WinPE 离线便携取证查杀）

> 本文是立项口径，不是宣传文案。所有「已实现」都对应可复跑用例；所有「没做」都列在 §9，不藏在正文里。
> 证据分级沿用项目惯例：**T1** 原始事实（代码/官方文档原文）｜**T2** 可复算（附脚本或命令）｜**T3** 二手陈述｜**T4** 推演。

## 0. 一句话定位

在 **WinPE（或任意离线环境）** 下，对**目标系统盘**做只读取证式扫描 + 可控处置：
不依赖目标系统的任何活体服务，能发现休眠的持久化与蠕虫类威胁，处置可回滚。

**明确不做**：不做实时防护、不做内存取证、不做感染型病毒的"修复"（只做隔离+可回滚+告警）、
不承诺查杀率、不替代商业杀软。

## 1. 先接受的事实（都有出处，不接受的请推翻我）

| # | 事实 | 出处 | 影响 |
|---|---|---|---|
| F1 | Python 3.11 不能运行在 Windows 7 上（官方发布页逐版本标注）；`yara-x` 要求 Python ≥3.9 | python.org 发布页；PyPI yara-x | 「Python 3.11 绿包 + 支持 Win7」不可同时成立 → §3 决策 D1 |
| F2 | WinPE 下 `%TEMP%` 指向内存盘 X:，可写空间通常只有几十到几百 MB | 规范自带 + 通用常识（T3，量级需实机测） | 禁 onefile、TEMP 必须重定向 |
| F3 | 很多系统文件（如 `notepad.exe`）**没有**内嵌签名，签名只在 CatRoot 编录里 | 本机实测：`notepad.exe` 内嵌签名数 = 0，而系统 API 判 Valid（T2） | 缺 CatRoot 索引就会把干净系统文件判成"未签名" |
| F4 | Authenticode 的 `eContent` 里放的是**裸的 SpcIndirectDataContent SEQUENCE**，不是 CMS 规范的 OCTET STRING | 实测 kernel32/explorer/disk.sys 解析（T2） | 按 CMS 规范写会直接解不出摘要 |
| F5 | 离线 SYSTEM hive 没有 `CurrentControlSet`，必须先读 `Select\Current` | 前一轮已实现并验证（T2） | 注册表解析必须走 ControlSet00X |

## 2. 六条铁律的落地裁决

| 铁律 | 裁决 | 落地方式 |
|---|---|---|
| 1 零 X:\ 写入 | **接受，且扩展** | 禁 onefile；`TEMP/TMP` 强制指向绿包内 `temp/`；日志、隔离、报告一律不落 X:；启动时自检并显示实际输出目录 |
| 2 脱离活体服务 | **接受，但限定范围** | 仅在 `is_offline` 时禁用 WinVerifyTrust/CryptSvc/WMI/COM；常规 Windows 模式仍可用活体检查（两者不互斥） |
| 3 只加密隔离 | **改写**（见 D2） | 密文+元数据先落盘并 fsync → 再移出原路径；密钥不与被加密数据同文件；全程可回滚；关键路径只报告 |
| 4 白名单防洗白 | **接受，并加约束** | `.cat` 自身必须先验签；白名单只放行本文件；`.cat` 解析条数低于阈值视为索引失败（不当作"全部干净"） |
| 5 单点异常不中断 | **接受，但必须留痕** | 每个文件独立 try/except；**失败计入「解析失败」分区**，绝不并入「干净」。跳过 ≠ 干净 |
| 6 离线资产防篡改 | **接受，但指出局限** | 清单 + Ed25519 签名；公钥硬编码在启动器内。**同一 U 盘内的自校验防不了能替换启动器的人**，这条会写进 README |

## 3. 我改掉的四处规范（附理由）

**D1｜不支持 Win7，最低 Win10 x64。**
理由：F1 是硬约束。可选方案只有"放弃 Win7"或"维护两套 runtime（3.8 无 yara-x / 3.11 有）"。
后者会让验证矩阵翻倍、行为分叉且必然漂移，收益（Win7 存量机）远小于成本。
若你坚持 Win7，正确做法是**单独出一个 3.8 降级包**（只做哈希+注册表+签名，无 YARA），而不是把两套塞进一个包。

**D2｜"加密隔离"的密钥不与密文同文件；并明确加密强度边界。**
原方案把 `key_b64`、`nonce` 写在密文同目录的 JSON 里——钥匙和锁放一个口袋，加密只剩"防误双击"。
本案改为：每条目独立随机 DEK，用 keyring 主密钥包裹后存元数据；主密钥单独存放。
**但必须诚实**：主密钥仍在同一可写介质上，能读盘的人仍能解密。这条能力是「防误执行 / 防静态查杀误报 / 防随手拷走」，
**不是**"防取证级对手"。这句话会印在报告首页，不靠用户自己猜。

**D3｜不引 regipy，复用已双路验证的 `core/offline_registry.py`。**
理由：那套解析器已经与在线 `winreg` 逐值比对通过；再引一个第三方解析器会产生两套语义（对畸形 hive 的容错不同），
出问题时无法判断谁对。第三方依赖也增加绿包体积与 license 面。

**D4｜删除"误报率归零"这类不可验收指标。**
`System32` 里必然存在无 `.cat`、无内嵌签名的第三方组件与硬链接文件，"归零"不可达。
改为可量化口径：**抽样 N 个文件 → 输出「放行 / 待复核 / 判定可疑」三类计数 + 放行依据**，人工可复核。

## 4. 架构分层

```
portableav/
  env.py       环境识别（复合判据：MiniNT / X: 盘 / 无 explorer，≥2 条才判 PE）
  drives.py    盘符枚举与离线系统盘定位（ntoskrnl + SYSTEM 双条件，支持多系统）
  paths.py     盘符漂移翻译（C:\、%VAR%、\SystemRoot\、\??\、\Device\HarddiskVolumeN）
  pe.py        最小 PE 解析（仅供哈希与签名表定位，全部边界检查）
  authsig.py   Authenticode 摘要（自算）+ 内嵌签名解析（摘要/算法/嵌套/尾部载荷）
  chain.py     X.509 解析 + PKCS#7 验签（内容摘要/签名/链到受信根/EKU）
  timestamp.py RFC 3161 时间戳令牌验证（证书过期的唯一合法出路）
  catroot.py   目标盘 .cat 索引（先验 .cat 自身签名，再按三种条目形态取哈希）
  trust.py     判定层：白/灰/黑 分级与放行依据；吊销命中即判黑
  revoke.py    吊销/黑名单加载与链上检查（无名单时明确标注"未启用"）
  matcher.py   规则匹配：内置 EICAR + 可选 yara-x 适配（缺包不伪装成已扫描）
  scan.py      扫描调度（scandir + 线程池 + 限额 + 失败分区）
  quarantine.py加密隔离与还原（keyring 包裹 DEK、原子写、O_EXCL、崩溃恢复）
  report.py    单文件离线 HTML 报告（内联 CSS，强制含"解析失败"分区与能力边界）
  cli.py       命令行：env / scan / persist / list / restore / verify
  persist.py   持久化矩阵：注册表(复用 core.offline_registry) + 任务 XML + 启动目录，并与扫描结果关联
```

**分层原则**：采集层（env/drives/paths/persist）只读；判定层（authsig/catroot/trust）不算分只给依据；
处置层（quarantine）必须在判定层给出「确证恶意」时才允许动作；报告层不改任何状态。

## 5. 双模式路由

| | 常规 Windows 模式 | 离线取证模式（PE / 疑似 PE） |
|---|---|---|
| 目标 | 本机或指定目录 | 定位到的离线系统盘（可多选） |
| 签名 | 可用系统 API 交叉验证 | 只走自算摘要 + CatRoot 索引 |
| 进程/内存 | 可做（复用主项目模块） | **禁用**（目标进程不存在，强杀无意义） |
| 注册表 | 在线 + 离线皆可 | 只离线解析 hive 文件 |
| 处置 | 隔离（可回滚） | 隔离（可回滚）；目标盘不可写时降级为只报告 |

判定为「疑似 PE」时**按离线执行**——宁可少做活体检查，也不对休眠系统误下"进程已清理"的结论。

## 6. 判定分级与放行规则

| 级别 | 条件 | 动作 |
|---|---|---|
| 白（放行） | 内嵌签名摘要一致 **且** 证书链到可信根 **且** 未命中吊销黑名单 | 仅记录依据，不处置；**不跳过同目录无签名 DLL** |
| 白（编录） | 文件 Authenticode 摘要命中「已验证签名的 .cat」CTL 表 | 同上；索引来源必须标注 |
| 灰（待复核） | 无签名 / 签名不可解析 / `.cat` 缺失 / 尾部异常载荷 | 进报告，**默认不处置** |
| 黑（确证） | 命中 YARA 高置信规则，或签名摘要与被篡改内容不符 | 允许隔离（关键路径除外，只告警） |

`authsig.is_trusted_by_digest()` 只证明"文件与签名时一致"，**不足以放行**——证书链校验完成前不得单独使用。

## 7. 处置语义（与主项目红线对齐）

- **隔离 = 加密 + 移出原路径 + 可回滚**，不销毁内容；
- 先落盘密文与元数据（fsync）→ 再移除原路径；任一步失败保持原状并记 `failed`；
- 目标路径已存在文件时**不覆盖**（`O_EXCL`），留人工处理；
- 系统关键路径（`System32\config`、`drivers`、`CatRoot`、`WinSxS`、`bootmgr`、`pagefile.sys` 等）
  **只进报告，不隔离、不改属性**——判据恰好是"隐藏+系统属性"，误动会让目标机起不来；
- 隔离区位置优先级：U 盘可写 → 写 U 盘；否则目标盘独立目录（需显式授权）；都不可写 → 只报告。

## 8. 分阶段与验收

| 阶段 | 内容 | 验收证据 |
|---|---|---|
| **V0.1** | 路径翻译 / 环境识别 / 离线盘定位 / PE 解析 / Authenticode 摘要与内嵌签名 | 真实文件「签名内摘要 == 自算摘要」；PE 头与 pefile 逐字段一致 |
| **V0.2** | 证书链验签、RFC3161 时间戳、`.cat` 索引（先验自身签名）、判定层白/灰/黑 | 合成 CA 链（含伪造被拒）；真实 1453 个编录 1442 验签通过、96135 条哈希、3.78s；notepad 双摘要命中 |
| **V0.3（本轮）** | 扫描调度、吊销接线、加密隔离、HTML 报告、CLI、`rules/` 信任资产约定 | 81 用例全绿；端到端演示：EICAR 判黑并隔离、密文无明文、还原 SHA-256 一致、重复还原被拒、畸形 PE 进"解析失败" |
| **V0.4（本轮）** | 持久化矩阵：注册表（复用已验证的 `core/offline_registry`）+ 计划任务 XML + 启动目录，并与扫描结果按路径关联 | 90 用例全绿；本机真实任务 **228 条、0 解析错误**；合成夹具覆盖"两个 Exec / 无动作 / 坏 XML"；报告第 5 节显示 `LinkedToEicar` 为「确证恶意」、其余「未关联」 |
| **V0.5（本轮）** | 绿包本体：embeddable runtime、8 段并发下载、wheel 离线化、完整性清单、自带校验器、启动器 | 构建出 224 文件 / 32.1 MB；绿包内实跑「扫描→隔离→还原」全通；`verify_portable.py` 能定位被改动与缺失文件 |

## 9. 未实现 / 未验证（不得当成已完成）

1. **吊销名单本身需要外部数据**：代码已实现"链上任意一级命中即判黑"，但仓库不内置任何名单
   （`rules/revoked/` 为空）。没有名单时报告会明确写"吊销检查未启用"，不会假装检查过。
2. `catroot.py` 里"名字型编录"的判定用 ASCII-UTF16 启发式：理论上存在极少数条目被误分类，
   后果是**漏放行**（该文件降为灰）或索引里多一条无法被任何真实文件撞上的假哈希（需原像攻击才可利用）。
3. **YARA 只做了适配层，未装引擎**：本机没有 `yara-x`，当前实际生效的只有内置 EICAR 特征；
   报告里会写"yara-x 未启用"。不要把"有适配层"当成"有完整规则查杀"。
4. **没有跨进程锁**：隔离区清单是单进程语义（同机同时开两个扫描进程会互相覆盖清单）。
5. **绿包已可构建，但只在本机（常规 Windows）验证过**：见 §12.6。真 WinPE、只读 U 盘、
   BitLocker 锁盘、缺 VC++ 运行库的机器都还没有实测证据；`VERIFY.json` 只做内容比对、
   **没有签名**（能改文件的人也能改清单）。
6. **WinPE 实机未验证**：本机无 PE 环境，`env.detect` 只用注入参数验证过逻辑，没有真机证据。
7. **双签名（SHA-1 + SHA-256）路径无真实样本**：本机 `System32` + `SysWOW64` 共 7191 个可执行文件，双签名样本 **0 个**（Win11 时代基本只剩 SHA-256 单签）。
   WIN_CERTIFICATE 链的枚举与对齐只有合成用例覆盖；"遇到双签名优先校验 SHA-256"这条策略**尚未在真实样本上验证**。
8. Rust 静态引擎、BitLocker 解锁、`$MFT` 直读、感染型修复、MBR/EFI 校验 —— 均未做。

## 10. 本轮实测数据（T2，可复跑）

- `System32` 抽样 80 个 exe/dll/sys（<6MB）：**38 个有内嵌签名，摘要全部一致**（sha256 36 / sha1 2）；42 个无内嵌签名；0 个不一致；0 个解析异常；耗时 0.11s。
- 3 个大文件逐字节核对：kernel32.dll（哈希 798,708 字节）、explorer.exe（5,566,452 字节）、disk.sys（126,964 字节）。
- 合成 PE 上验证四条不变量：改 CheckSum / DataDirectory[4] / 签名表 → 摘要不变；改节区 / overlay → 摘要改变。
- 双签名普查：`System32` + `SysWOW64` 共 7191 个文件扫描，**双签名 0 个** → 该分支只能算"未验证"，见 §9-7。
- 编录索引（本机 62 张受信根）：1453 个 `.cat` → 验签通过 **1442**、拒绝 5、解析失败 **0**，共 **96135** 条摘要，耗时 **3.78s**。
  - 被拒的 5 个是 2014 年的 OEM 驱动编录：证书早已过期且**完全没有时间戳**，无法证明当时有效 → 拒绝，其文件降为灰。
  - `notepad.exe` 的 Authenticode SHA-1/SHA-256 **双双命中**编录；随机 32 字节摘要不命中。
- 编录哈希口径（实测，纠正常见说法）：编录里存的是**文件 Authenticode 摘要**，不是整文件哈希。
  整文件 SHA-1/SHA-256 在 1453 个 `.cat` 中命中 0 次。
- 证书过期不是死路：本机微软编录的叶证书 2026-06-17 到期、中间证书 2026-10-19 到期，
  靠 RFC3161 令牌（genTime 2026-03-01，且 imprint 与签名值一致）证明"签名当时有效"。

## 11. 用法

```bash
# 0) 先准备离线信任资产（见 rules/README.md），否则签名一律不判白
#    导出根证书 → portableav/rules/roots/*.cer
#    吊销名单   → portableav/rules/revoked/*.txt|json

# 1) 看环境与可用的离线系统盘
python -m portableav env

# 2) 演练扫描（默认不处置），出报告
python -m portableav scan --target D:\ --report report.html

# 3) 真正处置：必须显式给隔离区 + --apply
python -m portableav scan --target D:\ \
    --quarantine E:\PortableAV_Quarantine \
    --apply --report report.html

# 4) 隔离区运维
python -m portableav list    --quarantine E:\PortableAV_Quarantine
python -m portableav verify  --quarantine E:\PortableAV_Quarantine
python -m portableav restore --quarantine E:\PortableAV_Quarantine --id <隔离ID>

# 5) 只看持久化矩阵（不扫描）
python -m portableav persist --windows D:\Windows
```

**端到端演示实测**（5 个样本的合成目录，T2）：

| 样本 | 期望 | 实测 |
|---|---|---|
| `notepad.exe` 的副本 | 编录白名单 | 白（依据：编录签名） |
| `kernel32.dll` 的副本 | 内嵌签名白名单 | 白（依据：内嵌签名，链到受信根） |
| EICAR 测试文件 | 判黑并隔离 | 黑 → 已加密隔离，原路径消失 |
| `MZ` + 全零的畸形 PE | 进"解析失败"而非"灰" | 解析失败 1，未混入灰名单 |
| 普通文本 | 待复核 | 灰（非 PE，未做签名判定） |

隔离后核对：密文 96 字节、**不含任何明文片段**；还原后 SHA-256 与隔离前逐字节一致；
对同一项再次还原被拒绝（`exit 3`）。

**持久化联动实测**（合成 Windows 目录）：

| 条目 | 目标 | 报告里的判定 |
|---|---|---|
| `Tasks\LinkedToEicar` | `<target>\Users\Public\evil.exe` | **确证恶意**（该文件被 EICAR 规则命中） |
| `Tasks\EvilTask` | `C:\Users\Public\evil.exe` | 未关联（目标不在本次扫描范围，标注 ✗不存在） |
| `Tasks\EvilTask` | `%SystemRoot%\System32\cmd.exe` → `C:\Windows\System32\cmd.exe` | 未关联（✓存在） |
| `Tasks\EmptyTask` | — | 未关联（已标注"没有 Exec 动作"） |
| `Startup\run.lnk` | 实际路径 | 待复核（非 PE，未做签名判定） |

本机真实环境另有验证：`C:\Windows\System32\Tasks` 下 **228 条任务、0 解析错误**。

### 11.1 双击启动（无参数）与「一闪而过」

双击 `run_portableav.bat` 等于**零参数**运行。早期版本在这种情况下打印 `usage` 后
`exit 0` 结束，控制台窗口随之关闭——用户看到的就是「一闪而过」。现在分三条路：

| 场景 | 行为 |
|---|---|
| 双击（真实终端、无参数） | 进交互菜单，结束后 `pause` 停住窗口 |
| 终端里无参数（非 tty） | 打印用法 + `exit 2`，**不会挂住等输入**（脚本误参能被发现） |
| 带参数 | 一次性执行，不 pause（可脚本化） |

`PAV_INTERACTIVE=1` 可强制进菜单——用于管道里做验证，也是「快捷方式带不了参数」时的出口。

菜单的三条安全约束：

1. **常规 Windows 下禁用「自动定位」**：`find_offline_systems` 会把**正在运行**的系统当成
   「离线系统盘」。照扫既慢，又可能把系统文件送进隔离区——那是处置在用系统，不是取证。
2. **隔离要输入 `yes`**：默认演练（不处置），只有显式确认才等价于 `--apply`。
3. **表头如实显示信任材料**：根证书 0 张时明写「一律不判白」。否则 `白 0`
   会被误读成签名校验坏了——这是最容易让人得出错误结论的地方。

## 12. 绿包（WinPE 可运行的形态）

### 12.1 为什么是 embeddable，不是 PyInstaller

onefile 在 Python 启动**之前**就把自己解压到 `%TEMP%`；WinPE 下那是 X: 内存盘。
embeddable 目录形态没有解压这一步，启动即用。

### 12.2 目录结构

```
PortableAV/
  run_portableav.bat     启动器（先设 TMPDIR/TEMP/TMP，再拉 runtime）
  portableav/            产品源码 + rules/
    rules/roots/*.cer    离线根证书（需自行导出，见 rules/README.md）
    rules/revoked/       吊销名单
  runtime/               
    python.exe, python311.zip, python311._pth
    vcruntime140.dll, vcruntime140_1.dll, msvcp140.dll
    Lib/site-packages/   cryptography + cffi + pycparser
  VERIFY.json            逐文件 SHA-256 + 构建元数据
  SHA256SUMS.txt         同上的纯文本版
  _work/                 运行时创建（临时/隔离/报告）
```

`python311._pth` 内容为：`python311.zip | . | Lib\site-packages | .. | import site`。
最后那个 `..` 让 `import portableav` 能找到包（不放宽 `PYTHONPATH` 也能跑）。

### 12.3 构建与校验

```bash
python tools/build_portable.py --out dist_portable/PortableAV --force --threads 8
runtime\python.exe tools\verify_portable.py dist_portable\PortableAV
```

- 下载：**8 段 Range 并发**、按序合并、逐段长度校验（不支持 Range 时退回单线程并告警）；
- 依赖：用宿主 python 的 pip 下 **win_amd64 / cp311** wheel 再解压，不在目标机装 pip；
- 校验：`VERIFY.json` + `SHA256SUMS.txt`，改动/缺失一律非 0 退出，不做自动修复；
- **`--force` 不得销毁隔离样本**：默认工作目录在 `<包目录>\_work`，加密隔离区就在里面。
  早期 `--force` 直接 `rmtree(out)`，会把已隔离样本一起删掉且**无法还原**。
  现在检测到 `_work\quarantine` 有未还原条目即 `exit 3` 拒绝；确要丢弃须显式
  `--discard-work`。清单损坏时按 `.qbin` 数量保守计数——没有证据证明"这里没东西"时不许删。

### 12.4 实测数据（本机构建，T2）

| 项 | 值 |
|---|---|
| 归档 | python-3.11.9-embed-amd64.zip，11,249,023 字节 |
| 下载 | 8 段并发，`ranged=True`，分段 [1406127, 1406128×7] |
| 归档 SHA-256 | `009d6bf7…cfd3b`（自算；python.org 只提供 .asc，**未做 GPG 校验**） |
| 依赖 | cryptography 50.0.2 + cffi 2.1.1 + pycparser 3.12 |
| 产物 | 224 个文件，32.1 MB |
| 自检 | 绿包内 `import portableav` → 0.1.0；`AESGCM` 可用 |

**绿包内实跑**（启动器 → 扫描 → 隔离 → 还原）：

- EICAR 判黑并**加密隔离**，原路径消失；密文 96 字节、不含明文片段；
- `restore` 还原后 SHA-256 与隔离前一致；
- 报告落在 `_work/report_*.html`，第 7 节记录工作目录与取证影响；
- 同目录的 `kernel32.dll` 副本判白（内嵌签名链到受信根）。

### 12.5 踩坑记录

1. **`cryptography` 仍依赖 `cffi`**（`_cffi_backend`）。构建时若加 `--no-deps`，
   wheel 装上了但 `import` 直接失败——"现代 cryptography 无运行时依赖"是错的。
2. **`tempfile` 在 Windows 上先看 `TMPDIR`**，只设 `TEMP`/`TMP` 会被继承的 `TMPDIR` 覆盖。
3. **本机 PowerShell 执行策略禁止 `.ps1`**：构建逻辑改为 Python，`.ps1` 只留薄壳转调，
   避免两套实现漂移。
4. 默认工作目录曾落在 `portableav/_work`（包内源码目录），已改为程序根（见 §13）。

### 12.6 仍未验证

- **没有在真实 WinPE 里跑过**。本机是常规 Windows；PE 下的差异（缺 DLL、只读 X:、
  scratch 空间、BitLocker 锁盘）都还没有实测证据。
- 只读 U 盘：`runtime/` 不写（`PYTHONDONTWRITEBYTECODE=1`），但 `_work` 需要可写；
  只读介质需用 `PAV_WORK` 指向别的可写盘。
- 启动器校验清单只做"内容比对"，**没有签名**：能改文件的人也能改清单。
  真正的防投毒需要 Ed25519 签名 + 公钥硬编码，尚未实现。

## 13. 运行位置与临时目录（"拷到 C 盘跑"到底解决了什么）

这一条值得单独写，因为很容易得出错误结论。

**事实（PyInstaller 官方文档）**：onefile 的解压位置由运行时 `TMP`/`TEMP`（Windows 走
`GetTempPathW`）决定，或构建时用 `--runtime-tmpdir` 静态指定；**与 exe 放在哪个盘无关**。
所以「把整包拷到 C 盘再运行」**并不能**阻止它往 X: 解压——除非同时改掉临时目录。

**时序陷阱**：onefile 的解压发生在 Python 进程启动**之前**（bootloader 阶段）。
在 Python 代码里 `os.environ["TEMP"]=...` 对"已经发生的解压"无效。要真正解决只有两条路：

1. **onedir / embeddable 绿包**（推荐）：压根不解压；
2. onefile + 启动器先设临时目录，或构建时加 `--runtime-tmpdir`。

**第三个坑（实测踩到）**：Windows 上 `tempfile` 的候选顺序是 **`TMPDIR` → `TEMP` → `TMP`**。
只设后两个、而环境里已存在 `TMPDIR` 时，会继续用旧目录——看起来设了，其实没生效。
`workdir.apply_env()` 三个都设，并把 `tempfile.tempdir` 直接钉死。

**代码能管的和管不了的**（`workdir.py`）：

| 事项 | 由谁控制 |
|---|---|
| onefile 解压目录 | 启动器 `run_portableav.bat` 设 `TMPDIR/TEMP/TMP`，或构建期 `--runtime-tmpdir` |
| 本进程后续临时文件 | `workdir.apply_env()`（已含 TMPDIR） |
| 隔离区 / 报告 / 日志 | `--workdir`，默认 `<程序目录>\_work` |
| 是否允许写被检盘 | 默认**不允许**；需 `--workdir` 显式指定或 `--allow-target-write` |

**为什么默认不写被检盘**：写目标盘 = 修改证据。同一套工具在"取证"和"处置"两种用途下，
写盘的含义完全不同。所以默认工作目录在程序所在处（U 盘或别的盘），落在被检盘上时
报告第 7 节会写明"属于处置行为，不是纯取证"。

**你提到的场景（把绿包拷到 C 盘跑）**：可行，且在被检盘就是 C 盘时它确实是"写目标盘"。
程序会这样提示：`程序位于目标盘：工作目录随之落在被检盘上`，并在报告里留下同样的声明。
如果只是想让运行时别占内存盘、又不想碰被检盘，正确做法是把 `PAV_WORK` 指向另一块可写盘。
