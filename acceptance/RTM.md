# 需求追踪矩阵（RTM）— usb-virus-killer v2.0

验收日期：2026-11-22　验收人：AI 独立验收（军不见委托）
需求来源：README.md 模块表 + AGENTS.md 红线 + 使用说明.md 功能章节
证据等级：T2（可脚本复现，脚本与命令随证据栏标注）

## 一、功能需求覆盖

| ID | 需求条目 | 验证用例（pytest / 测试台场景） | 证据（2026-11-22 实测） | 结论 |
|---|---|---|---|---|
| FR-01 | 模块化架构：7 内置模块注册 + 插件热加载 | test_discovery / test_plugin_hot_discovery / 测试台14 GUI装配 | pytest 19/19；testbed 18/18 | 通过 |
| FR-02 | 感染判定：文件夹病毒双置信判定（TP/FP/FN 计数） | test_engine_and_rollback / 场景02 感染盘扫描、场景03 干净盘误报 | 场景02-03 PASS | 通过 |
| FR-03 | 查杀隔离（只隔离不删除，含 manifest 清单） | test_engine_and_rollback / 场景04 | 场景04 PASS | 通过 |
| FR-04 | 回滚还原：路径穿越/绝对路径拒绝、目标已存在不覆盖 | test_restore_safety 场景一 / 场景05 | pytest 通过；场景05 PASS | 通过 |
| FR-05 | 隔离中断安全：逐项落盘，Ctrl+C 后清单不丢 | test_restore_safety 场景二（KeyboardInterrupt 注入） | pytest 通过 | 通过 |
| FR-06 | 免疫 autorun.inf（重复免疫拒绝） | — / 场景06 | PASS | 通过 |
| FR-07 | 本地特征库：空库初始化/T3与占位符拒绝/规则命中只报告 | test_signature_db_empty_and_rules / 场景07 | pytest 通过；场景07 PASS | 通过 |
| FR-08 | 规则包 v2：版本化导入/禁降级/备份回滚/整包拒绝 | test_signature_db_pack / 场景13 | pytest 通过；场景13 PASS | 通过 |
| FR-09 | 误报反馈台账：登记/去重/查看/空报告拒绝 | test_fp_feedback | pytest 通过 | 通过 |
| FR-10 | ClamAV 桥接：命中解析/无删除参数/只报告 | test_clamav_bridge_parse_and_mock / 场景09 EICAR | pytest 通过；场景09 PASS | 通过 |
| FR-11 | ClamAV 跨次扫描日志不污染 | test_clamav_log_not_contaminated / 场景08 | pytest 通过；场景08 PASS | 通过 |
| FR-12 | ClamAV rc=2 部分出错明示（partial_error） | test_clamav_partial_error | pytest 通过 | 通过 |
| FR-13 | freshclam 更新三态中文摘要 | test_freshclam_summary | pytest 通过 | 通过 |
| FR-14 | 主机诊断只读（Run/IFEO/AppInit/Winlogon/服务DLL） | test_host_diagnostics / 场景11 | pytest 通过；场景11 PASS | 通过 |
| FR-15 | 修复脚本导出（默认全注释，未诊断拒绝） | test_fixscript / 场景16 | pytest 通过；场景16 PASS | 通过 |
| FR-16 | 现代威胁：WMI 三层订阅遍历 + 文件关联 ProgID 间接查询 | test_modern_threats（注入检出+假零命中反查） | pytest 通过 | 通过 |
| FR-17 | 经典木马：QQ尾巴/IFEO/hosts/共享/txtfile 劫持检测 | test_classic_trojans / 场景12 | pytest 通过；场景12 PASS | 通过 |
| FR-18 | 经典木马修复：逐项落盘 manifest + 按原类型回滚 | test_classic_trojans + test_classic_rollback_tampered_item | pytest 通过 | 通过 |
| FR-19 | AMSI 脚本评估：不可用降级/分级判定/隔离区跳过 | test_amsi_scan / 场景15 | pytest 通过；场景15 PASS | 通过 |
| FR-20 | 契约化报告导出（report_export 钩子，7 模块覆盖） | test_report_export_contract | pytest 通过 | 通过 |
| FR-21 | GUI 装配：视图/按钮/作者信息（掩码 180******66） | test_gui_assembly / 场景14 | pytest 通过；场景14 PASS | 通过 |
| FR-22 | 异常路径优雅失败（坏目标/锁定文件/损坏规则库） | — / 场景17、18 | 两场景 PASS | 通过 |

## 二、红线需求（AGENTS.md，行为级验证）

| ID | 红线 | 验证方式 | 结论 |
|---|---|---|---|
| NR-01 | 只隔离不删除（ClamAV/特征库/查杀全链路无删除调用） | test_clamav_bridge_parse_and_mock 断言无删除参数；grep 无 os.remove 于扫描路径 | 通过 |
| NR-02 | 口径分离：T1-T4 标注，不混用 | test_signature_db_empty_and_rules 拒绝无来源规则 | 通过 |
| NR-03 | 不碰真实恶意样本 | fixtures.py 仅合成样本 + EICAR；testbed 全程未引入外部样本 | 通过 |
| NR-04 | 隐私：全库无完整手机号字面量 | grep 全号 = 0 命中（2026-11-22 复查，verify 脚本与 RTM 引用已改分段拼出）；exe 内嵌字节码校验 全号=0/掩码=1 VERIFY PASS | 通过 |
| NR-05 | 报告只读诊断为主，修复全注释 | test_fixscript 断言注释率；场景16 | 通过 |
| NR-06 | 文档-代码-spec 三向一致 | hidden-import 7==7；模块表 7==7；打包命令与 spec 一致 | 通过 |

## 二·补、删除调用精确核查（NR-01 佐证）

扫描/查杀/特征库/ClamAV/AMSI/现代威胁/主机诊断/经典木马 8 个模块 `os.remove|os.unlink|rmtree|rmdir` 全量扫描仅 2 处，均为工具自身产物管理、非用户数据删除：

- signature_db.py:243 —— 备份轮换删除第 11 份以前的旧规则包备份（fr[size]=10 上限机制）
- clamav_bridge.py:332 —— 扫描前清除本工具自己的上次扫描日志（防跨次污染，FR-11 的实现手段）

## 三、覆盖率统计

- 功能需求 FR：22/22 映射到至少 1 个可执行用例（100%）
- 红线需求 NR：6/6 有行为级验证（100%）
- 验证资产：pytest 19 用例 + 测试台 18 场景（编号已修正为连续 01-18）

## 四、验收过程发现并当场修正

| 发现 | 等级 | 处置 |
|---|---|---|
| 测试台场景编号跳 12（历史空洞）且 17 撞号 ×2 | 一般 | 已修正为连续 01-18，回归 19/19 通过 |
