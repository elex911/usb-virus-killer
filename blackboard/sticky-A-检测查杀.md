# 贴条A：检测与查杀能力评审（员工A，2026-11-21）

## 一、功能总结（T1，均落到 文件:行号）

### 1. 本地特征库（modules/signature_db.py）
- 空库起步设计：文件不存在时仅「初始化空库」创建，绝不覆盖已有库（signature_db.py:120-131）；当前 signature_db.json 为 0 条规则、0 个规则包（实复算，T2）。
- 规则校验：type 限 sha256/filename_regex/content_regex（:24），sha256 须 64 位十六进制（:181），正则可编译校验（:183-187），source 占位符黑名单拦截（:26,:190），evidence 限 T1/T2/T3 且 T3 禁止启用（:25,:196-197），first_seen 强制 YYYY-MM-DD（:199-203），id 去重（:169-172）。
- 版本化导入/禁降级：pack 须 name/source/version≥1/rules 非空（:623-635）；version ≤ 当前库版本拒绝（:640-641）；版本号已导入过拒绝重复（:639,:642-643）；整包校验失败拒绝部分导入（:653-661）；导入后按规则 id 合并替换并记录 pack sha256（:664-674）。
- 备份/回滚：导入前字节级备份到 signature_db_backups，保留最近 10 份（:44-45,:228-246）；回滚取最新备份整体覆盖（:522-543）。
- 扫描：只读匹配（:338-340,:480-517）；跳过 >64MB 文件（:27,:286-288）、跳过 __WORM_QUARANTINE_ 隔离目录（:275,:278）；content_regex 读前 1MB 双编码匹配（:28,:300-305）。
- 误报反馈：从导出报告 JSON 抽取命中（:92-110），追加写入 fp_feedback.jsonl 并按 (rule_id,path) 去重（:73-89），登记不改规则（:347-353,:593-601）。

### 2. ClamAV 桥接（modules/clamav_bridge.py）
- 引擎发现：设置项自定义路径 → PATH → 常见安装根递归 glob（:74-92）；不捆绑引擎/库（docstring:8）。
- 引擎检查：版本（:122-125）、PE 架构自解析 MZ/PE 头（:59-71）、库文件清点（:103-119）。
- freshclam 三态摘要：DB_LINE_RE 解析 updated/up-to-date/错误行（:144-149,:152-187），rc=0 时分「已更新/已最新」两态并附版本；失败时保留原始输出末段 1200 字符便于排查（:182-187）；更新需用户显式确认（:202-205）。
- 扫描防污染：clamscan --log 为追加写，扫描前先删除残留日志再调用（:328-335）；结果合并 stdout+日志去重解析 FOUND（:30,:128-141,:346-347）；Infected files 统计回退 len(found)（:348-349）；只报告，绝不用 --remove/--move（docstring:9,:206-209）。

### 3. AMSI 脚本评估（modules/amsi_scan.py）
- Win10+ 经 amsi.dll：AmsiInitialize/OpenSession/ScanBuffer（:50-79），app 名 "usb-virus-killer"（:59）。
- 判定分级：result=1 高危、1600-32767 关注、其余信息（:36-37,:104-109）。
- 优雅降级：非 Windows/amsi.dll 缺失/初始化失败输出信息级并跳过（:25-29,:50-69,:181-191）。
- 11 类脚本扩展名、2MB 上限、跳过隔离目录（:31-34,:82-91）；可注入接缝便于测试（:44-47）。

### 4. 经典木马（modules/classic_trojans.py）
- QQ 尾巴启动项特征：KNOWN_RUN_NAMES/KNOWN_FILE_TOKENS/WINDIR_ROOT_FILES 命中高危（:164-166,:213-216）；位置启发分级（system32/临时目录/非标准目录，:218-225）。
- txtfile 关联劫持：非系统默认记事本值即高危，可还原（:171-177,:295-312）。
- IFEO Debugger 全量枚举，有 Debugger 值即高危可修（:179,:314-330）。
- hosts 劫持：非 localhost/127.0.0.1/::1 基线映射报关注（:180-181,:349-366）；IE 首页检查（:332-340）；net share 共享清点（:118-132,:368-381）。
- 修复先备份 manifest 后改注册表，可回滚（:393-416,:418-441）；拒绝文件粉碎/网马拦截/Winsock 重置（docstring:18-21）。

### 5. 文件夹病毒（modules/folder_virus.py）
- 双置信判定：高置信=隐藏+系统属性同名原文件+同名 .lnk（:193-201）；中置信=.lnk 内容含 wscript/cmd 等 SUSPECT_TOKENS 且自身隐藏（:44-49,:202-203）；仅中置信默认不隔离（:204-205）。
- .lnk 二进制解析不依赖 COM（:112-125）；autorun.inf 一律恶意（:216-221）；浅层可疑脚本只报可疑（:223-240）。
- 隔离=移入 __WORM_QUARANTINE_ 时间戳目录并写 manifest/README，可回滚（:250-294,:296-322）；恢复隐藏属性并记录（:273-284）；autorun.inf 免疫目录（:324-334）。
- 安全门禁：拒系统盘、拒非可移动/本地盘、固定盘需显式允许（:139-158）。

### 6. 现代威胁（modules/modern_threats.py）
- 6 类只读采集：WMI 事件订阅（:140-165）、计划任务 TaskCache Actions 二进制抽路径（:168-207）、BHO（:210-231）、脚本关联（:234-255）、进程路径（:258-306）、勒索痕迹（赎金笔记+扩展名≥3 批量，:62-71,:309-345）。
- 降噪白名单 SAFE_PATH_RE（:48-51）；键不存在视为无此类项（:97-137）；口径只用高危/关注/信息，不写「恶意」（:38-45）。

## 二、改进建议（按优先级，均先证伪）

1. 【P0】修 modern_threats WMI 订阅枚举层级。证伪：已读 collect_wmi（modern_threats.py:146-163），当前遍历 EventSubscriptions 下一层并读「\<name>\CommandLineEventConsumer」默认值；而实际结构是 EventSubscriptions\CommandLineEventConsumer\{GUID} 下读 CommandLineTemplate（T2 依据注册表结构可复算，个别系统变体 T3）。按现实现该检测点大概率恒漏报。收益：核心持久化检测点从失效变有效 / 成本：约 15 行 / 风险：低（只读）/ 可行性：高。
2. 【P0】修 collect_file_associations 恒漏报。证伪：modern_threats.py:239-243 只读 HKCR\.js\shell\open\command 等扩展名直挂键；标准系统命令挂在 ProgID（jsfile/VBSFile/htafile 等），扩展名直挂键默认不存在 → 默认劫持手法检测不到（T2）。收益：恢复检测能力 / 成本：每扩展名多一次 ProgID 间接查询 / 风险：低 / 可行性：高。
3. 【P1】_do_fix 异常中断会丢备份。证伪：classic_trojans.py:402-415 先逐项改注册表、循环全部结束才写 manifest.json；中途任一项 _reg_delete_value/_reg_set 抛异常（如权限不足），已改项无 manifest → 无法回滚。建议逐项先写 manifest（或先备份后修改+逐项 try）。收益：消除不可回滚窗口 / 成本：~10 行 / 风险：低 / 可行性：高。
4. 【P1】回滚保留注册表值类型。证伪：manifest 只存 old_value 不存类型（classic_trojans.py:400-411），回滚一律 REG_SZ（:434-438），原值若为 REG_EXPAND_SZ 等回滚后类型被改（T2）。收益：回滚保真 / 成本：~5 行 / 风险：低 / 可行性：高。
5. 【P2】特征库扫描哈希/读取缓存。证伪：_scan_target（signature_db.py:291-305）对每文件按规则逐条匹配，N 条 sha256 规则同一文件被哈希 N 次，content_regex 每规则重读文件；现无任何缓存。建议单次遍历：每文件算一次哈希+读一次内容再对全部规则匹配。收益：多规则时 O(N×S)→O(S) / 成本：~20 行 / 风险：低（结果等价）/ 可行性：高。
6. 【P2】folder_virus.scan 排除自身隔离目录。证伪：Engine.scan（folder_virus.py:163-173）枚举无 __WORM_QUARANTINE_ 过滤，而 signature_db.py:275 与 amsi_scan.py:85 均已排除；查杀后重扫会把隔离区内容再判「恶意」，clean 时 rel 路径含旧隔离目录名造成嵌套隔离（T2 可推演）。收益：消除重扫噪声与嵌套 / 成本：1 行过滤 / 风险：低 / 可行性：高。

## 三、Bug 与设计隐患

- B1【隐患 T2】IFEO 全量「高危+可修」一刀切：classic_trojans.py:315-330 对所有带 Debugger 的子键报高危，一键「修复」会删除全部 Debugger 值；合法软件（部分杀软/调试工具）也用 IFEO Debugger，可能误删。建议区分目标进程重要性或降为「关注+人工确认」。
- B2【隐患 T2】clamav_bridge.py:362-369：rc=2（发生错误）且 found>0 时按 ok=True 成功路径走，错误输出被吞，用户不知扫描不完整。建议 rc==2 时在汇总行标注「扫描部分出错」。
- B3【小 T2】磁盘上 signature_db.json 缺 db_version/updated_at/packs 键（实查），与 EMPTY_DB（signature_db.py:35-42）不一致；import_pack 用 .get 默认值兼容（:638-639），功能不受影响，但属旧版遗留结构，建议下次导入后自然归一。
- B4【小 T3】amsi_scan 会话未关闭：_default_load_amsi 打开 handle/session（amsi_scan.py:58-67），扫描结束无 AmsiCloseSession/AmsiUninitialize；进程退出即回收，实际影响极小。
- B5【小 T2】classic_trojans.py:219 硬编码 "c:\\windows\\" 判定，SystemRoot 非 C: 的机器漏判（罕见）。
- B6【小 T2】hosts 基线判断（classic_trojans.py:354）：形如 "127.0.0.1 localhost 附加域名" 的行 parts[:2] 命中基线即整行跳过，附加映射漏报。
- B7【设计口径 T2】folder_virus.py:233 referenced_here 用子串匹配（lnk 目标路径 in 脚本路径），可能把无关脚本误标「可疑」；仅报告不隔离，影响有限。

（本贴条只评审，未改任何业务代码。）
