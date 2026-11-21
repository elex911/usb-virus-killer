# 黑板任务书（2026-11-21）

## 评审对象
`C:\Users\Administrator\WorkBuddy\2026-11-19-12-13-08\usb-virus-killer\`
（U 盘快捷方式病毒查杀 GUI 工具，Python 3.12 + tkinter，模块化架构，已托管 GitHub）

## 任务
对软件做一次全面评审，产出两部分：
1. **功能总结**——从各自分管领域客观描述现有功能（须落到 文件:行号 或具体文件名）
2. **改进建议**——按优先级列出，每条注明：收益 / 成本 / 风险 / 可行性判断

## 纪律（全员遵守）
- 证据分级标注：T1=代码原文可定位；T2=可复算；T3=推测须明说；T4=禁止当结论
- 每条关键断言须能落到具体文件与行号
- 主动证伪：建议前先检查"是否已有现成实现/是否与现有设计冲突"
- 禁止迎合：发现设计缺陷直说，不绕弯
- 严禁修改任何业务代码——本次只评审不改动
- 每人把评审结果写入黑板目录下自己的贴条文件，格式见黑板索引

## 分工
- 员工A（sticky-A-检测查杀.md）：signature_db.py / clamav_bridge.py / amsi_scan.py / classic_trojans.py / folder_virus.py / modern_threats.py / signature_db.json
- 员工B（sticky-B-架构代码.md）：core/api.py / core/registry.py / core/app.py / core/widgets.py / FolderVirusKiller.py / 模块化设计与接缝、错误处理、技术债
- 员工C（sticky-C-交互体验.md）：core/app.py 界面流 / widgets / 使用说明.md / README.md / 打包 spec / dist 产物 / 文案
- 员工D（sticky-D-测试与边界.md）：testbed/ / tests/ / 安全边界声明 / 根目录遗留物（fk_* 临时目录、日志文件）/ git 仓库卫生

## 主管职责（全部贴条完成后）
通读四张贴条 → 去重合并 → 裁决冲突建议 → 按"高性价比优先"排序 → 产出终稿 BLACKBOARD.md（功能总结 + 建议清单 Top N）
