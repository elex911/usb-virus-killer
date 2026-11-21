# U盘病毒查杀工具 独立验收报告

验收人：独立验收员（与开发方隔离）　验收日期：2026-11-22
验收对象：D:\Personal\Temp\acc_verify_1326\　依据：README.md、使用说明.md、AGENTS.md
纪律：只运行测试与打包，未修改任何源码文件。

## 一、文档声明清单及逐条核验结果

| # | 文档声明 | 核验方式 | 结果 |
|---|---|---|---|
| 1 | 7 个内置模块（README.md:9-17、使用说明.md:27-35 各 7 行） | 遍历 core/registry.load_modules() | 符合：7 个实例，0 错误，模块名一一对应 |
| 2 | 模块三方一致（AGENTS.md:28：registry==spec==文档表） | 脚本核对 | 符合：BUILTIN_MODULES 7（registry.py:19-27）= spec hiddenimports 7 = 文档表 7 行 |
| 3 | pytest 回归（使用说明.md:209-212 命令） | 照抄命令执行 | 符合：19 passed (0.78s)；`python tests\test_modular.py` 直跑亦 ALL PASS |
| 4 | 测试台全 PASS、report.json 落盘（AGENTS.md:11） | 运行 testbed/run_testbed.py | 符合：18/18 PASS，report.json 写入 testbed\results\ |
| 5 | 测试覆盖清单（使用说明.md:216 列 14 类） | 对照 19 个用例名与 [OK] 输出 | 符合：模块发现/插件/隔离回滚/只读口径/备份修复回滚/特征库/规则包/误报/ClamAV/现代威胁/AMSI/修复脚本/报告契约/GUI 装配均有对应用例 |
| 6 | PyInstaller 打包命令（使用说明.md:211） | 真实执行 | 符合：exit=0，dist\文件夹病毒查杀工具.exe 11.1 MB（文档"11 MB"吻合） |
| 7 | hidden-import 七个，漏一个静默丢模块（使用说明.md:214） | 核对命令与 spec | 符合：命令 7 个 = spec 7 个，无遗漏 |
| 8 | compileall 命令（使用说明.md:209） | 执行 | 符合：无错误 |
| 9 | exe 双击运行 | 启动打包 exe，枚举窗口标题 | 符合：窗口「模块化病毒查杀工具 v2.0」真实显示，进程退出无残留 |
| 10 | 特征库七按钮、ClamAV 三按钮（使用说明.md:82,123） | 遍历 actions() | 符合：7/3，与文案逐字一致 |
| 11 | 只隔离不删除、可回滚（README.md:44） | 审 modules/folder_virus.py | 符合：clean 仅 shutil.move 进隔离区（:277），无删除用户文件调用；manifest 逐项落盘（:262-267,280） |
| 12 | 回滚不覆盖、拒绝穿越路径（使用说明.md:60） | 审 folder_virus.py:319-334 | 符合：dst 存在跳过；`..`/绝对路径/盘符路径拒绝 |
| 13 | 免疫创建只读 autorun.inf 文件夹（使用说明.md:59） | 审 folder_virus.py:346-356 | 符合：mkdir+隐藏/系统/只读属性 |
| 14 | 主机诊断只读（README.md:12） | 审 host_diagnostics.py | 符合：查询仅 Query*/Enum*；Set-ItemProperty 仅出现在导出的修复脚本文本内且默认全注释（:262,271-283） |
| 15 | 经典木马修复前备份、可回滚（使用说明.md:40） | 审 classic_trojans.py:408-437 | 符合：legacy_fix_backups\时间戳\manifest.json，每改一项即落盘 |
| 16 | 现代威胁只读、不创建诱饵（使用说明.md:155） | 审 modern_threats.py | 符合：全 Query/Enum/scandir，无 kill/写入；勒索检测只读（:340） |
| 17 | 特征库空库起步、T3 只登记、T4/占位符拒绝、64MB 跳过、内容正则 1MB（使用说明.md:80,98-100,108） | 审 signature_db.py:25-28,191-197 + 查看 signature_db.json | 符合：rules:[]；MAX_FILE_BYTES=64MB；MAX_CONTENT_BYTES=1MB；备份保留 10 份（:45） |
| 18 | ClamAV 绝无 --remove/--move、只报告（使用说明.md:125-126） | 审 clamav_bridge.py:335 | 符合：命令仅 --recursive --log；等级「外部命中」 |
| 19 | 自动发现 D:\ClamAV 引擎（使用说明.md:135） | 实调 find_clamscan(ctx) | 符合：返回 D:\ClamAV\app\clamav-1.5.5.win.x64\clamscan.exe 与 freshclam.exe |
| 20 | 报告导出：module_results+兼容字段（使用说明.md:199-204） | 审 app.py:306-355 + 各模块 report_export | 符合：app.py 无业务字段硬编码，走模块 report_export() 钩子 |
| 21 | 作者电话掩码三处同步（AGENTS.md:21） | grep 全库 | 符合：app.py:132、tests/test_modular.py:924、两份文档均 180******66 |
| 22 | 高风险操作二次确认（使用说明.md:223） | 审 folder_virus.py actions confirm 字段 | 符合：查杀/免疫/回滚均带 confirm 文本 |
| 23 | 拒绝功能清单：不粉碎/不网马拦截/不 Winsock 重置/不开机删毒（使用说明.md:41） | grep 全 modules | 符合：未发现任何对应实现 |
| 24 | 目录结构（README.md:54-61） | ls | 符合：core/modules/plugins/tests 均在，dist/build 打包时生成 |

## 二、不符项清单

1.〔文档错·轻微〕README.md:13 模块表该行写作「经典木马体检（只读）……高危项备份后修复」：整模块标注"（只读）"却同时声明"修复"，口径自相矛盾；实际模块名为「经典木马查杀」，含写操作（修复高危项/回滚），使用说明.md:30 的表述（体检只读/修复可回滚）才是准确口径。证据：modules/classic_trojans.py:94-104 存在 KEY_SET_VALUE 写入。
2.〔文档错·轻微〕使用说明.md:59 免疫声明未提前置条件：代码在目标已存在 autorun.inf 时直接报错拒绝（folder_virus.py:349-350），文档未说明「需先清理已有 autorun.inf」。
3.〔文档错·轻微〕README.md:12 主机诊断功能列未提「导出修复脚本」按钮（实际存在，host_diagnostics.py actions），与使用说明.md:31 不一致，属 README 描述不完整。

未发现「代码有但文档没说」的隐藏功能：各模块 actions() 声明的按钮全部在文档中出现；未发现文档红线（删除文件/终止进程/写注册表/联网下载）之外的隐藏行为。

## 三、无法验证项及原因

1. Python 3.8+ 下限兼容（README.md:5）：本机仅 3.12.10，未验证 3.8 环境。
2. 使用说明.md:129-138 的 ClamAV 环境事实（版本 1.5.5、EICAR 三层验证、GPG 验签、库版本）：属开发环境历史记录，本验收未重跑 EICAR 与 freshclam，仅验证了引擎路径发现与命令构造无删除参数。
3. AMSI 真机 provider（Defender）实际检出：测试为接缝注入模拟，真实 provider 行为随主机杀软状态而变，无法在验收环境定论。
4. GUI 交互细节（双击行看依据、下拉框联动等）：仅通过测试台源码级烟测与单测验证，未做人工鼠标操作。

## 四、总体结论

**通过**。
pytest 19/19、测试台 18/18、真实打包产物 11.1 MB、hidden-import 7/7、模块四方一致（7=7=7=7）、exe 烟测窗口真实显示、全部安全红线（只隔离不删除/只读口径/无 --remove/--move/空特征库/掩码）经代码审计与脚本核验吻合。所列 3 处不符项均为文档表述层面轻微瑕疵（README 模块行口径标注、免疫前置条件、主机诊断按钮省略），不影响功能与安全边界，建议开发方在下一次文档修订中更正。
