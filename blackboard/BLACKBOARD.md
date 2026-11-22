# 本文件为主管终稿（主管汇总，2026-11-21）

依据：TASK.md + 四张贴条（A 检测查杀 / B 架构代码 / C 交互体验 / D 测试与边界）。关键断言已经主管回查源码复核。证据分级沿用 T1=代码原文 / T2=可复算 / T3=推测（已标注）。

> 更新（2026-11-22）：当前内置模块数为 **8**（含 `active_defense`），本地固定磁盘与系统盘默认可查杀。下文「三、发现的冲突」等条目中的「7 模块 / README 缺模块」为当时历史快照，不代表当前状态。

---

## 一、功能总结

### 1. 架构
- 契约层：Action/ActionResult/Context 三 dataclass + ModuleBase 默认实现，9 个模块全部实现 actions/run/build_view/render/detail 契约，无一破坏（core/api.py:17-96）。
- 注册表：9 内置模块经 BUILTIN_MODULES 声明式注册；plugins/*.py 动态加载，`_fk_plugin_` 前缀隔离 sys.modules，单模块失败不中断（core/registry.py:19-28, 59-101）。
- 主程序：自述"只调度不认识业务"（app.py:5-6）；按钮/标签页由模块生成（app.py:87-120）；worker 线程 + queue 120ms 轮询回主线程（app.py:235, 258-293）；报告导出含 v1.x 兼容字段（app.py:296-343）。但存在硬编码例外（见三.3）。
- 入口：FolderVirusKiller.py 仅 22 行，--restore 直调 Engine.restore（FolderVirusKiller.py:13-16）；根目录 HostDiagnostics.py 为 3 行兼容 shim。
- 打包：spec 隐藏导入覆盖 9 模块+core 三件（文件夹病毒查杀工具.spec:9）；datas=[] 不捆绑特征库，外部交付，与文档口径自洽。

### 2. 检测与查杀
- 本地特征库：空库起步绝不覆盖（modules/signature_db.py:120-131），当前 0 规则（T2）；规则校验完备（T3 禁启用 :196-197、正则可编译 :183-187）；规则包版本化导入+禁降级+整包拒绝（:623-661）；字节级备份保留 10 份可回滚（:228-246）；扫描只读、跳过 >64MB 与隔离目录（:275-305）。
- ClamAV 桥接：不捆绑引擎，PATH+常见安装根发现（modules/clamav_bridge.py:74-92）；扫描前清残留日志防跨次污染（:328-335）；freshclam 三态中文摘要（:144-187）；只报告绝不用 --remove/--move（docstring:9, :206-209）。
- AMSI 脚本评估：Win10+ 经 amsi.dll，高危/关注/信息三级（modules/amsi_scan.py:36-109）；不可用优雅降级（:25-29, 181-191）；接缝可注入便于测试（:44-47）。
- 文件夹病毒：双置信判定（高置信=隐藏属性+同名原文件+同名 .lnk，modules/folder_virus.py:193-203）；.lnk 二进制解析不依赖 COM（:112-125）；隔离入 __WORM_QUARANTINE_ 时间戳目录、写 manifest 可回滚（:250-322）；autorun.inf 免疫（:324-334）；本地磁盘/系统盘默认放行，系统关键路径只报告不隔离（:139-158, :34-40）。
- 离线取证（只读）：core/offline_registry.py 直接解析 regf（不挂载/不提权），离线 SYSTEM 无 CurrentControlSet、须读 Select\\Current；modules/offline_forensics.py 做 MiniNT+X: 复合识别、目标盘定位、C:\\→真实盘符翻译、任务 XML 与 PE 安全目录（core/offline_registry.py:280-301, modules/offline_forensics.py:66-140）。红线：MiniNT 单信号只算疑似；无内嵌签名不等于恶意（notepad 靠 CatRoot）；X:\\ 禁写；当前非 WinPE 原生程序，Rust 静态引擎未实现。
- 现代威胁（只读）：6 类采集——WMI 订阅/计划任务/BHO/脚本关联/进程路径/勒索痕迹（modules/modern_threats.py:140-345）；白名单降噪（:48-51）。**注意：WMI 订阅与脚本关联两个采集点实现有误，检测能力实际失效（见三.1/2）。**

### 3. 诊断与修复
- 经典木马：QQ 尾巴启动项特征、txtfile 关联劫持、IFEO Debugger、hosts 劫持、IE 首页、net share（modules/classic_trojans.py:164-381）；修复前写备份 manifest 可回滚（:393-441）；拒绝粉碎/网马/Winsock 重置（docstring:18-21）。
- 主机诊断：只读采集 Run/IFEO/AppInit/Winlogon/服务 DLL（modules/host_diagnostics.py:87-236）；修复走导出全注释 PowerShell 脚本、人工复核执行（:271-307）。

### 4. 测试与安全边界
- 测试台：16 场景全过（testbed/results/20261121_114618，T1 已核对），含 TP-FP-FN 计数、回滚、免疫、EICAR、GUI 烟测（testbed/run_testbed.py:69-341）；样本红线——只合成安全样本（testbed/fixtures.py:2-9）。
- 单元回归：15 用例覆盖校验拒绝/降级/污染回归/契约（tests/test_modular.py）。
- 数据反哺闭环有实证：修复与回归测试同 commit（git b7af3cd、c23137b，T1）。
- 边界声明与行为一致：查杀只隔离、ClamAV 无删除参数、修复脚本全注释、AMSI 降级（tests/test_modular.py:222-223, 573-575, 481-482 已核对）。
- git 仓库干净：残留物均已 gitignore，只在磁盘不在库内（.gitignore:1-35，T1）。

---

## 二、主管批注（贴条矛盾裁决）

1. **"7 模块契约完整"（B）vs "README 只列 5 模块"（C/D）**：两者不矛盾——代码契约完整，文档滞后。采信 C/D，文档漂移列为 P0。
2. **"弹窗文案全中文无违规"（C）vs B 记录的异常英文内嵌**：C 自己已标注为可接受边界（主文案中文）。裁决：不算违规，不立项。
3. **"测试体系成熟度高"（D 结论）vs "3 用例无 finally 污染根目录"（D B1/B2 + B 目睹磁盘残留）**：结论成立但有限定——成熟度高指断言设计与红线纪律，卫生问题独立成立，不因整体好而豁免。
4. **A5 扫描缓存（P2）**：砍。当前库 0 规则，性能收益未兑现；待规则量上来再做。
5. **C3 报告 txt/html 导出（P1→砍）**：双口径需与 JSON 同步维护，长期成本大于收益；日志区已散见关键信息。降为"暂不做"。
6. **C5 danger 按钮着色、C4 exe 名统一（P2）**：保留但不进 Top 10，属锦上添花，等 P0/P1 落地后顺手做。
7. **C6 手机号隐私（P3）**：不立项。牵连测试断言需联动修改，且属作者个人决定，非工程缺陷；仅提醒作者自查。
8. **B2 host_diagnostics 接缝注入（高→降 P2）**：收益是"可离线测试"，非用户价值；纯函数已可测。待异常路径场景（三.10）暴露真实需求再做。
9. **B4 死接缝清理（optional/ask_directory）**：并入三.8 一并处理（契约诚实，成本极低）。

---

## 三、建议 Top 10（多人独立指出项置前列）

### P0（正确性/失效缺陷，先修）

1. **修 modern_threats WMI 订阅枚举层级（恒漏报）**【A 指出，主管复核证实】
   依据：modern_threats.py:146-153 把 CommandLineEventConsumer 当值读，实际结构是 EventSubscriptions\{GUID}\CommandLineEventConsumer\{GUID}\CommandLineTemplate 子键值，现实现该检测点大概率恒漏报（T2）。
   收益：核心持久化检测点从失效变有效 / 成本：约 15 行 / 风险：低（只读）。
2. **修 collect_file_associations 只读扩展名直挂键（恒漏报）**【A 指出】
   依据：modern_threats.py:239-243 读 HKCR\.js 直挂键；标准命令挂在 ProgID（jsfile/VBSFile 等），默认劫持手法检测不到（T2）。
   收益：恢复检测能力 / 成本：每扩展名多一次 ProgID 间接查询 / 风险：低。
3. **界面层一致性：去 app.py 业务硬编码 + 失败弹窗按 ok 分级**【B、C 独立指出，合并】
   依据：app.py:329-336 硬编码 folder_virus/host_diagnostics 报告字段，违背 app.py:5-6 模块化声明；app.py:284-285 show_dialog=True 一律 showinfo，失败（如 clamav_bridge.py:284 引擎缺失 ok=False）也弹 info 图标。
   收益：架构自洽 + 失败警示不降级 / 成本：hook 化约 1-2h + 一处 if/elif / 风险：低。
4. **tests 三用例补 try/finally 清理**【D 根因定位，B 目睹磁盘残留，双重确认】
   依据：tests/test_modular.py:474,477,494,519,553 mkdtemp(dir=ROOT) 无 finally；磁盘现存 fk_amsi_a/b/c、fk_fp、fk_fx 六目录与 prefix 逐字对应（T1）；testbed 已有 cleanup 模式可照搬（run_testbed.py:433-435）。
   收益：根除 fk_* 反复再生 / 成本：约 10 行 / 风险：无。
5. **修 4 处文档漂移**【C、D 双重独立确认】
   依据：README.md:9-15 模块表仅 5 个缺 classic_trojans/amsi_scan（registry.py:20-26 实为 7）；使用说明.md:207 hidden-import 仅 4 个缺 3（spec:9 全有，照文档打包静默丢模块）；使用说明.md:120 "模块设置"机制 ctx.settings 无入口不可达（api.py:54 + app.py:36-42）；使用说明.md:82 "三个按钮" vs 实际 7 个（signature_db.py:336-354）。
   收益：避免打包丢模块、口径可信 / 成本：改数行文档 / 风险：无。

### P1（可靠性）

6. **classic_trojans 修复回滚保真：manifest 逐项先写 + 保留注册表值类型**【A 指出】
   依据：classic_trojans.py:402-415 全部改完才写 manifest，中途异常已改项不可回滚；:434-438 回滚一律 REG_SZ，原 REG_EXPAND_SZ 类型被改。
   收益：消除不可回滚窗口 / 成本：约 15 行 / 风险：低。
7. **ClamAV rc=2 标注"扫描部分出错"**【A B2】
   依据：clamav_bridge.py:362-369 rc=2 且 found>0 按 ok=True 走，错误输出被吞，用户不知扫描不完整。
   收益：结果可信 / 成本：几行 / 风险：无。
8. **界面健壮性小修打包：_refresh_drives/_poll 补日志、_poll 的 after 移 finally、死接缝清理**【B 3/5/6，合并立项】
   依据：app.py:146-160 静默 continue；app.py:258-293 after 在 try 外，非预期异常可断轮询链假死（T3）；api.py:55 ask_directory 与 target_mode="optional" 无模块使用且语义未实现。
   收益：故障可诊断、消除假死路径、契约诚实 / 成本：合计约 20 行 / 风险：无。

### P2（低优先）

9. **folder_virus.scan 排除自身隔离目录 + 清理磁盘遗留物**【A + D】
   依据：folder_virus.py:163-173 枚举无 __WORM_QUARANTINE_ 过滤（signature_db.py:275、amsi_scan.py:85 均已排除），重扫噪声+嵌套隔离；根目录 6 个 fk_* 目录与 clamav_last_scan.log 属运行/测试遗留（T1，主管已 ls 核对），均已 gitignore 不入库。
   收益：消除重扫误报 / 成本：1 行过滤 / 风险：低。
10. **测试健壮性：补异常路径场景 + 弱断言收紧**【D 2/3，合并立项】
    依据：场景 02-05 全在理想目录跑，权限拒绝/中途拔盘/损坏库无覆盖（run_testbed.py:69-149）；len(rows)<120 魔法阈值与 author 电话断言会环境漂移假红（run_testbed.py:243, :328）。
    收益：查杀工具最怕异常路径误删，降低 CI 噪音 / 成本：3-4 场景+数行 / 风险：mock 权限拒绝有平台差异，可行性中高。

### 遗留物处置建议（需用户确认后执行，主管只建议不执行）
- **可删**：根目录 6 个 fk_* 临时目录、clamav_last_scan.log（已 ignore，不入库；日志属 clamscan 设计内产物，删除无损）。
- **删前确认**：fk_ct_mmhxlegk 内 legacy_fix_backups 是回滚备份残留（D 标 T3），确认无需回滚再删。
- **可顺手删**：testbed/results/ 下 10 个空 run 与 13 个 probe 目录、build/、__pycache__。
- 命令示例（确认后）：`rm -rf fk_* clamav_last_scan.log`；但根因是三.4 的 finally 缺失，先修测试再删，否则删完还会再生。

---

## 四、结论
架构分层、红线纪律与测试反哺闭环是本项目三大亮点；核心缺陷集中在两个检测点实现错误（恒漏报）、界面层一处违背自身声明的硬编码、文档与代码漂移、tests 清理缺失，均可低成本修复。P0 五项落地后，工具的实际检测能力与可信度才有实质提升。
