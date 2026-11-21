# 员工D贴条：测试、测试台与安全边界（2026-11-21）

## 一、功能总结（T1）

### 1.1 测试台（testbed/）
- fixtures.py:27-73 `build_infected_usb`：隐藏原目录+同名 .lnk 伪装+autorun.inf+干净对照，返回 ground truth；红线声明在 fixtures.py:2-9（只合成安全样本）。fixtures.py:76-89 `build_clean_usb` 误报基准。
- run_testbed.py:44-47 `@case` 装饰器注册，执行器 main（run_testbed.py:438-495）按名排序跑全部场景，落 `testbed/results/<run_id>/report.json`（:489-491），退出码 0/1（:495）。
- 实际场景 16 个：编号 01-11、13-17（**12 号空洞**，run_testbed.py:258 直接从 11 跳到 13），覆盖：样本构建/感染盘扫描 TP-FP-FN 计数（:69-93）/干净盘误报（:96-107）/查杀隔离清单（:110-133）/回滚（:136-149）/免疫二次拒绝（:152-167）/空库零命中（:170-188）/ClamAV 跨次污染（:191-214）与 EICAR 检出（:217-231）/现代威胁与主机诊断低噪音（:234-255）/经典木马体检（:258-272）/规则包全链路（:275-306）/GUI 烟测（:307-341）/AMSI 接缝注入+降级（:344-372）/修复脚本+误报登记（:375-416）。
- 最新报告 testbed/results/20261121_114618/report.json：16/16 全过（T1 已读取核对）。

### 1.2 单元回归（tests/test_modular.py，15 用例）
- 覆盖：模块发现（:26）、插件热发现（:39）、引擎判定+查杀+回滚（:67-113）、主机诊断只读口径（:116）、特征库校验含 T3/占位符/坏正则拒绝（:125-186）、ClamAV 解析+mock 无删除参数（:189-227）、真实主机低噪音与注入检出（:230-290、:293-358）、规则包 降级/重复/坏包 整包拒绝（:361-411）、ClamAV 日志污染回归（:414-438）、freshclam 中文摘要（:441-465）、AMSI 降级+分级（:468-513）、误报反馈去重（:516-547）、修复脚本全注释+未诊断拒绝（:550-582）、GUI 装配（:585-618）。

### 1.3 测试数据确曾反哺改进（证据链 T1）
- git b7af3cd："Fix drive hint duplication + freshclam summary + stale ClamAV log contamination; add testbed harness"——修复与测试同 commit；对应 tests/test_modular.py:414 用例 docstring「clamscan --log 是追加写…（回归）」与 :608-614 盘符去重断言。
- git c23137b："Clean test temp residue from repo; ignore fk_* temp dirs; add cleanup to classic_trojans test"——残留问题被认过账，但只修了 classic_trojans 一个用例。
- T3：testbed/results/ 下 7 个 tb_restore_* 空目录，推测是场景05 回滚调试期反复运行残留。

### 1.4 边界声明现状
- 使用说明.md:41 明确拒绝 QQKav 四功能（粉碎/网马/Winsock/开机删毒）；:221-227 边界声明（内核驱动、常驻防护、文件粉碎），:216 提示「查杀后必须全盘扫描」。
- README.md:40-46 安全边界：隔离可回滚、诊断只读、空库起步、ClamAV 非实时。
- 与代码一致性核查：查杀只隔离（场景04 断言 moved==quarantined==5）、ClamAV 无 --remove/--move（tests:222-223）、修复脚本全注释输出（tests:573-575）、AMSI 不可用降级（tests:481-482）——声明与行为一致（T1）。
- **不一致点**：README.md:7-16 模块表只有 5 个模块，漏「经典木马查杀」与「AMSI 脚本扫描」两个已上线模块（使用说明.md:30 已写经典木马）。

### 1.5 仓库卫生与 git
- 根目录 6 个 fk_* 残留目录，内容与 tests/test_modular.py 的 mkdtemp prefix 一一对应：fk_amsi_a(含 a.ps1)、fk_amsi_b(空, app_dir)、fk_amsi_c(evil.vbs/sus.js/note.txt)、fk_ct(legacy_fix_backups)、fk_fp(fp_feedback.jsonl 等)、fk_fx(修复脚本.ps1)（T1 已 ls 核对）。
- clamav_last_scan.log：真实 clamscan 输出（2026-11-21 11:46，EICAR 命中 1），运行遗留。
- testbed/results/：12 个 run 目录中 10 个为空，另有 13 个 probe/debug 目录。
- .gitignore:1-35 覆盖评估：fk_*/、testbed/results/、*.log、build/、dist/、__pycache__ 均已覆盖，git 仓库本身干净（git status 仅 ?? blackboard/，5 个提交，T1）。残留只在磁盘，不在库内。

## 二、改进建议（按优先级，先证伪）

### 建议1：给 tests 三个无 finally 用例补清理（P0）
- 证伪：fk_*/ 已进 .gitignore（:35）→ 只防入库不防磁盘堆积；testbed 侧已有 cleanup 模式（run_testbed.py:433-435）可直接照搬，无技术障碍。
- 【收益：根除根目录 fk_* 反复再生；成本：约 10 行 try/finally；风险：无；可行性：高】
- 落点：tests/test_modular.py:474-513（test_amsi_scan）、:519-547（test_fp_feedback）、:553-582（test_fixscript）。

### 建议2：补异常路径场景（P1）
- 证伪：场景02-05 已覆盖主路径与回滚，但全部在"理想目录"上跑；权限拒绝文件、隔离目标已存在冲突、signature_db.json 损坏、U盘中途拔出均无覆盖。修复脚本"未诊断拒绝"路径 tests:579-581 有、testbed 场景17 没有，两套体系未对齐。
- 【收益：查杀类工具最怕异常路径误删；成本：约 3-4 个新场景；风险：mock 权限拒绝在 Windows 有平台差异；可行性：中高】
- 顺带：补 12 号编号空洞或重排，避免报告总数与编号误导。

### 建议3：弱断言收紧（P1）
- 证伪：`len(rows) < 120`（run_testbed.py:243）是魔法阈值，真实主机数据漂移会偶发误红；场景15 author_ok（run_testbed.py:328、tests:606）断言作者电话属业务文案而非功能行为，改名即红。
- 【收益：降低 CI/复跑噪音；成本：低；风险：低；可行性：高】

### 建议4：README 模块表补齐 + 两文档口径对齐（P1）
- 证伪：使用说明.md:30 已含经典木马，README 漏——不是功能缺失而是文档债；模块总数 GUI views==7（run_testbed.py:336）已可作核对基准。
- 【收益：边界声明可信度；成本：几分钟；风险：无；可行性：高】
- 落点：README.md:7-16。

### 建议5：ClamAV 场景环境解耦（P2）
- 证伪：场景08/09 硬编码 `D:\ClamAV\eicar-test`（run_testbed.py:198、:219），有 skip 兜底，但 skip 返回 True（:221）与"通过"不可区分，且场景08 无 EICAR 时退化为"clamscan 必须存在否则失败"（:205）——两场景语义不一致。
- 【收益：可移植；成本：环境变量+报告加 skipped 字段；风险：低；可行性：高】

### 建议6：清磁盘遗留物（P2，需主管裁决后执行）
- 根目录 6 个 fk_* 目录、clamav_last_scan.log、testbed/results/ 下 10 个空 run 与 13 个 probe/debug 目录均可删（均已 ignore，不入库）；__pycache__/build/.pytest_cache 同理。fk_ct_mmhxlegk 内 legacy_fix_backups 是回滚备份残留，删除前应确认不再需要（T3）。
- 【收益：目录清爽，审计友好；成本：一条命令；风险：低（先核对后删）；可行性：高】

## 三、bug/隐患清单

| # | 位置 | 问题 | 依据 |
|---|---|---|---|
| B1 | tests/test_modular.py:474,477,494,519,553 | 三个用例临时目录建在 ROOT 且无 finally → 每跑一次根目录多 2-3 个 fk_* 目录 | fk_amsi_a/b/c、fk_fp、fk_fx 残留与 prefix 逐字对应（T1） |
| B2 | tests/test_modular.py:336,357 | test_classic_trojans 的 finally 用 `shutil.rmtree(..., ignore_errors=True)`，Windows 文件占用时静默残留 | fk_ct_mmhxlegk/legacy_fix_backups 存在（T1；成因 T3：句柄占用） |
| B3 | run_testbed.py:243 | `len(rows) < 120` 魔法阈值，环境漂移会假红 | T1 |
| B4 | run_testbed.py:198-205,219-221 | EICAR 路径硬编码 D:\ClamAV；skip 与 pass 返回值同形（True），报告无法区分「没测」和「过了」 | T1 |
| B5 | run_testbed.py:468 | log lambda 丢弃 ≥100 字符的消息，长日志在 report.json 中不可追溯 | T1 |
| B6 | run_testbed.py:258 | 场景编号 12 空洞，命名 01-17 暗示 17 场景实际 16 | T1 |
| B7 | run_testbed.py:132 | `r["moved"] == 5` 硬编码 fixtures 默认 groups=4+autorun，改 fixtures 参数即脆断 | T1 |
| B8 | README.md:7-16 | 模块表缺 classic_trojans / amsi_scan，与使用说明.md:30、core/registry 实际 7 模块不符 | T1 |
| B9 | testbed/results/ | 历史探测目录（amsi_probe*、fp_probe* 等 13 个）未随 cleanup 清理，属测试代码外手工产物 | T1 已 ls；成因 T3 |
| B10 | 根目录 clamav_last_scan.log | 真实扫描日志含本机路径 D:\ClamAV\...，已 ignore 不入库，但属工具未自清理的运行遗留（与 B 项修复测试声称的"日志隔离"行为相对照，log 文件本身保留在设计之内，T3 归类为可接受遗留） | T1 |

## 四、结论
测试体系成熟度高：接缝注入+ground truth 断言+数据反哺闭环有实证（1.3），红线纪律贯穿 fixtures 与文档。主要短板是 tests 侧清理不彻底（B1/B2）与异常路径覆盖缺口，均低成本低风险可修。遗留物建议核对后统一清理（建议6）。
