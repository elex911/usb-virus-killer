# 员工C贴条：交互与用户体验（2026-11-21）

## 一、功能总结（T1 落点）

### 界面流程（core/app.py）
- 首启动动线完整：加载模块→自动刷新盘符（app.py:45）→无 U 盘时提示「未发现可处理盘符；可先选目录做测试」（app.py:166）→未选目标点扫描报中文引导「请先选择目标盘符或目录」（app.py:209）。
- 盘符下拉由各模块 suggest_targets() 汇总并按规范化文本去重，包含 U 盘与本地固定盘（app.py:141-170）；「允许本地固定磁盘」默认勾选并透传 prepare_context（app.py:77-81, 206-218）；系统盘处置另有二次确认，关键路径只报告不隔离。
- 标签页/按钮完全由模块生成：操作区 3 列网格（app.py:88-98），signature_db 有 7 个按钮排 2 列×4 行（app.py:98 + modules/signature_db.py:336-354）；模块视图加载失败有中文兜底（app.py:117）。
- 忙态管理：执行中禁用全部按钮、状态栏「处理中…」（app.py:179-187），后台线程+queue 轮询防 tkinter 线程不安全（app.py:235, 258-293）。
- 报告导出仅 JSON 一种格式（app.py:300），含 module_results 及 v1.x 兼容字段（app.py:303-339）。

### 文案口径（modules/*.py）
- 所有弹窗主文案、确认框、表格表头均为中文，无「弹英文原文」违规：抽检 amsi_scan.py:124-248、clamav_bridge.py:201-378、signature_db.py:336-691、folder_virus.py:351-464、host_diagnostics.py:321-415、modern_threats.py:368-416、classic_trojans.py:239-477 全部中文表头（如 folder_virus.py:383）。
- 边界情况：失败 message 内嵌异常原文（英文），如 signature_db.py:561「报告 JSON 解析失败：%s」、app.py:253 完整英文 traceback 只进日志不弹窗——主文案中文，可接受（T3 判断：不算违规，属边界）。
- 高危操作均有二次确认且写明后果与可回滚性：folder_virus.py:353-360、classic_trojans.py:241、signature_db.py:339,343,350。

### 控件（core/widgets.py）
- ResultTable 支持着色标签、双击详情、caution 提示条（widgets.py:26-27, 47, 58-66），双击行索引与数据行对齐正确（widgets.py:64-66）。

### 文档现状
- 使用说明.md 结构完整：运行方式、界面结构、7 模块逐一口径、开发指南、边界声明；但存在内部漂移（见三）。
- README.md 为精简版，模块表不全（见三）。

### 打包与产物
- spec 隐藏导入覆盖全部 8 个内置模块+core 三件（文件夹病毒查杀工具.spec:9）；dist\ 有 11.6MB exe、signature_db.json 空库、plugins\_示例模块.py.template，与使用说明.md:13-14,80 所述一致（ls 佐证，T1）。
- spec datas=[] 未捆绑 signature_db.json，靠外部文件交付——与文档口径自洽。

## 二、改进建议（先证伪后提）

1. 【P0】修四处文档漂移（详见三之 1/2/3/4）
   收益：避免照文档打包丢 3 个模块、用户找不到「模块设置」；成本：改 4 行文档；风险：无；可行性：高。证伪：已核对 spec:9 与 registry.py:19-27，漂移确凿，非文档简写。
2. 【P1】弹窗按 ok 分级：app.py:284 只要 show_dialog=True 就 showinfo，失败（如 clamav_bridge.py:284 引擎缺失 ok=False）也弹 info 图标
   收益：失败警示不降级；成本：app.py 一处 if/elif；风险：无；可行性：高。证伪：现有分支已区分 !ok+!show_dialog 走 showwarning（app.py:286-287），仅 show_dialog=True 分支漏判。
3. 【P1】报告增加人类可读导出（txt/html）
   收益：新手/送审场景不必读 JSON；成本：中等（需汇总各模块 report 结构）；风险：字段口径需与 JSON 版同步维护；可行性：中。证伪：现有日志区已散见关键信息，但无汇总视图，建议保留。
4. 【P2】exe 文件名与窗口标题统一（spec:25「文件夹病毒查杀工具」 vs app.py:20「模块化病毒查杀工具」）
   收益：消除双击后名字对不上的困惑；成本：改一处常量或 spec name；风险：改 spec 需重新打包；可行性：高。
5. 【P2】danger 按钮视觉区分：api.py:25 已有 danger 字段，app.py:97 注释明说未着色
   收益：「查杀/免疫/修复高危项」与只读按钮可一眼区分；成本：ttk style 配置一段；风险：跨主题兼容需试；可行性：中高。
6. 【P3】公开仓库去除/模糊作者手机号（app.py:133、README.md:3、使用说明.md:3，已托管 GitHub=T3 前提）
   收益：隐私；成本：3 处删除；风险：与回归测试「GUI 装配与作者信息」断言冲突（使用说明.md:210），需同步改测试；可行性：中。

## 三、bug/漂移清单（行号+依据）

1. 使用说明.md:82「三个按钮」vs 实际 7 个按钮（signature_db.py:336-354：init/validate/scan/import_pack/rollback_db/fp_mark/fp_view），且与同文档 :33 表格自相矛盾。T1。
2. 使用说明.md:120「也可在模块设置里指定 clamscan_path / freshclam_path」——ctx.settings（api.py:54）在 app.py 全程未填充（app.py:36-42 仅设 app_dir/ask_directory），无任何设置界面，该机制用户不可达。T1（代码侧）+T3（判「无入口」）。
3. 使用说明.md:207 PyInstaller 命令 hidden-import 缺 modules.classic_trojans / modules.modern_threats / modules.amsi_scan；spec:9 三个都在。照文档命令打包会静默丢 3 个模块。T1。
4. README.md:9-15 模块表只有 5 个，缺「经典木马查杀」「AMSI 脚本扫描」（registry.py:20-26 共 7 个）。T1。
5. README.md:38「新增功能只需…在 core/registry.py 注册」与使用说明.md:159-163 方式A（plugins 自动发现、无需注册，registry.py:74-101 佐证）口径冲突，README 少说了一种方式。T1。
6. 窗口标题 vs exe 名不一致（app.py:20 vs spec:25，同使用说明.md:7）。T1。
7. 【T3，不下结论】使用说明.md:9 与 README.md:5 声称「Python 3.8+」，TASK.md 称 3.12 项目；未实测 3.8 环境，无法证伪，存疑。
8. 【T3】spec:29 upx=True：UPX 加壳的单文件 exe 是国内杀软常见误报诱因，与「第二意见扫描器」定位相冲，建议实测各家误报率后再决定是否关掉。
9. 【T3】dist\plugins 只含模板无实际插件、dist\signature_db.json 为空库（ls+cat 佐证）：与文档一致，非 bug，仅记录现状。
