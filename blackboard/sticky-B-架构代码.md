# 贴条 B：架构与代码质量（员工B）

## 一、功能总结（客观现状）

1. 契约层 `core/api.py`：Action/ActionResult/Context 三个 dataclass + ModuleBase 默认实现（api.py:17-96）。Action.prompt 支持 directory|file（api.py:27），主线程弹窗后经 `ctx.pick` 注入（app.py:220-232）。Action/ActionResult/dict 三种返回兼容（app.py:243-247）。
2. 注册表 `core/registry.py`：7 个内置模块经 BUILTIN_MODULES 声明式注册（registry.py:19-27）；plugins/*.py 动态加载（registry.py:74-101），以 `_fk_plugin_` 前缀隔离 sys.modules，ID 去重（registry.py:66-72,95-98），单模块失败收集为 errors 不中断（registry.py:59-60），按 (order,name) 排序（registry.py:103）。
3. 主程序 `core/app.py`：自述"只调度不认识业务"（app.py:5-6）。按钮完全由 actions() 生成（app.py:87-99），标签页由 build_view() 生成并容错降级（app.py:111-120）；worker 线程执行 + queue 120ms 轮询回主线程（app.py:235,258-293）；报告导出含 v1.x 兼容字段（app.py:296-343）。盘符下拉由各模块 suggest_targets 聚合去重（app.py:140-166）。
4. `core/widgets.py`：ResultTable 通用表格，tag 着色、双击详情回调（widgets.py:7-66）。空表 set_rows 安全（已实测 `tv.delete()` 空参不抛错，T2）。
5. `FolderVirusKiller.py`：仅 22 行入口，--restore 直调 Engine.restore（FolderVirusKiller.py:13-16），其余转 core.app。根目录 HostDiagnostics.py 为 3 行兼容 shim（HostDiagnostics.py:3）。
6. `modules/host_diagnostics.py`：只读采集 collect()（87-236，Run/IFEO/AppInit/Winlogon/服务 DLL），判级纯函数 _level_for_command（74-80）；fixscript 导出全注释 PowerShell 脚本（271-307，305 行 utf-8-sig+CRLF）；红线口径分离（文件头 8-12、build_view caution 341-351）。
7. 接口一致性：7 个模块全部实现 actions/run/build_view/render/detail 全套（folder_virus.py:349-414、host_diagnostics.py:319-364、amsi_scan.py:122-171、clamav_bridge.py:199-251、signature_db.py:334-423 等），无一破坏契约。classic_trojans 需接缝者已接缝（见下）。

## 二、改进建议（按优先级，均已证伪）

1. 【高】消除主程序对具体模块的硬编码耦合。app.py:329-339 硬编码 "folder_virus"/"host_diagnostics" 模块 ID 及其 report 字段名，直接违背 app.py:5-6 的自我声明。建议改为模块侧 hook（如 ModuleBase.export_compat(report)->dict，app 通用遍历）。
   收益：架构自洽，新增模块无需改 app；成本：低（约 1-2h）；风险：低（v1.x 兼容字段由 folder_virus 模块自供，报告消费者不变）；可行性：高。
2. 【高】host_diagnostics 补接缝注入。classic_trojans.py:35-44 已有 `_reg_enum_values` 可替换默认值设计，且被测试利用（tests/test_modular.py:322）；host_diagnostics.collect() 直接调 winreg（host_diagnostics.py:97,108,130,140 等），判级只能真机验证。证伪结果：_level_for_command/_fix_command_for 是纯函数已可测（test_fixscript:550 已覆盖部分），但 collect 的采集→判级链路无离线回归。建议给 collect 注入 winreg 门面参数（默认真实现）。
   收益：采集/判级逻辑可离线测试与未来扩展；成本：中；风险：低；可行性：高。
3. 【中】_refresh_drives 静默吞异常：app.py:146-147、159-160 `except Exception: continue`，模块出错连日志都没有，用户只见盘符缺失无从排查。一行改为 `except Exception as e: self._log(...)` 即可。app.py:205-206 prepare_context 异常只弹窗不落 traceback，同样建议补日志。
   收益：故障可诊断；成本：极低；风险：无；可行性：高。
4. 【中】清理死接缝/死分支：a) Context.ask_directory（api.py:55，app.py:37 注入）经 grep 确认无任何模块读取——死字段；b) Action.target_mode="optional"（api.py:24）无模块使用，且 app.py:211-214 把 optional 与 none 同等处理（清空 target），"可用可不用"语义根本未实现。建议：要么实现（optional 时仍调 prepare_context、失败不阻断），要么删掉并在 api.py 注明。插件作者按文档写 optional 会被坑。
   收益：契约诚实，误导成本为零；成本：低；风险：低（删除前已确认无人使用）；可行性：高。
5. 【低】meta 契约文档漂移：app.py:120 支持 meta["tab"] 键，但 api.py:61-67 的 meta 文档只列 id/name/version/description/order；现仅 amsi_scan.py:119 使用。补一行文档即可。另 registry.py:87 先注册 sys.modules 再 exec_module，exec 失败会残留脏条目（影响极小，顺手 try/finally 清理）。
6. 【低】_poll 健壮性：app.py:258-293 中 after(120, self._poll) 在 try 之外、except 只捕 queue.Empty；若 try 块内非预期异常（如 285 行 messagebox 在某些主题下的回调异常），轮询链断裂，busy 永锁、界面假死（T3：未复现，属结构性隐患）。建议 after 移入 finally。
   收益：消除假死路径；成本：极低；风险：无；可行性：高。

## 三、bug / 隐患清单

1. host_diagnostics.py:262-267：PowerShell 命令只对 value_name 做了 `'` 转义（263,267），key_path 未转义。IFEO 子键名（exe 文件名）合法可含单引号，生成的脚本将语法错或行为漂移。缓解：脚本默认全注释+人工复核（271-283），实际风险有限。T2。
2. host_diagnostics.py:369/388：诊断结果存实例属性 `_last_rows`，两个 action 间隐式传状态。当前 busy 互斥（app.py:191）下安全；但同实例被多次 run 的时序依赖对插件作者不可见，属易踩坑设计（T3：未来并发/重载场景）。
3. host_diagnostics.py:101：`e.strerror` 可能为 None，文案呈"读取失败（None）"，小瑕疵。T2。
4. app.py:247：模块返回裸字符串时 ok=True、show_dialog=False，结果仅进状态栏；契约过宽，模块作者若预期弹窗会静默失败。建议 api.py 注明或收紧。
5. app.py:124：`self.log = scrolled_text = ...` 双赋值，风格噪音，与全局变量无异。
6. app.py:165：`targets[0].split()[0]`——若某模块 suggest_targets 返回首项以空白开头则取错盘符（T3：现模块均无此格式，边缘）。
7. tests/test_modular.py:117 依赖根目录 HostDiagnostics.py 兼容 shim 而非 modules.host_diagnostics 正名，测试路径与生产路径不一致（属员工D范围，此处仅登记）。

—— 员工B（架构与代码质量），只评审未改任何业务代码
