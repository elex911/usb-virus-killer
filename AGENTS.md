# AGENTS.md — 本仓库的 AI 协作规则（任何 agent 会话先读这份）

> 本文件是跨会话记忆的唯一通道：周二的 agent 必须继承周一的决策。
> 个人方法论上层见用户级 skill `dev-playbook`；本文件是它在仓库层的投影。

## 技术栈与结构

- Python 3.8+ 纯标准库（tkinter GUI，无第三方运行时依赖）；打包 PyInstaller onefile/noconsole。
- 契约层 `core/api.py`（Action/ActionResult/Context/ModuleBase）→ `core/registry.py` 注册 → `modules/*.py` 业务 → `core/app.py` 只做装配调度。
- 外部插件放 `plugins/*.py`（源码运行=项目根；exe 运行=`dist/plugins/`）。
- 测试：`tests/test_modular.py`（pytest）+ `testbed/run_testbed.py`（场景测试台，report.json 落盘）。

## 绝不许碰（红线，违反即返工）

1. **只隔离不删除**：任何查杀动作不得直接删除用户文件；隔离必须可回滚；manifest 逐项落盘（中途异常已改项仍可回滚）。
2. **口径分离**：只读诊断用「高危/关注/信息」，查杀判定用「恶意/可疑/正常」，特征库命中用「命中/待核」——三套词汇不得混用；诊断结果绝不进隔离。
3. **不预置/伪造病毒库特征**：规则必须有 id/type/value/source/evidence/first_seen；T3 来源只能登记不得启用。
4. **ClamAV 桥接**：不捆绑引擎（GPLv2+体积）；扫描命令绝无 `--remove/--move`；更新库需用户显式确认。
5. **界面不弹英文原文**；报告导出走模块 `report_export()` 钩子，禁止在 app.py 硬编码业务模块的报告字段。
6. **测试环境用后必清**：临时目录 try/finally shutil.rmtree；测试注册表操作用接缝注入模拟，不做真实写入后不清理的事。
7. **隐私**：作者电话一律掩码 `180******66`（界面/文档/测试断言三处同步）；不得把任何密钥/真实路径样本写进交付物。
8. **本地磁盘与系统盘护栏**（用户 2026-11-22 明确授权 C 盘完整查杀）：本地固定磁盘默认可查杀，`allow_fixed` 在 Context / 各模块 `prepare_context` / GUI 三处默认均为 True；系统盘处置前必须二次确认。`Windows` / `Program Files` / `ProgramData` / `System Volume Information` / `$Recycle.Bin` / `Recovery` / 页面文件等关键路径只进报告，**不隔离、不改隐藏属性、不作强杀确证锚点**——这是防系统不可启动的底线，不是功能缺失；改动时不得用"完整查杀"为由移除。

## 改动纪律（每步验收标准）

- **逐步交叉验证**：一步＝一次写入/改动/命令，完成即用 ≥2 种独立机制验证（回读全文 / 独立脚本实测 / 三向比对），全过才下一步。
- **测试先行**：修 bug 先写失败用例复现，再实现转绿；新功能先定验收断言再动手。
- **同类项全抓**：修一处后 tokenize/正则全类排查同类问题。
- **文档三向比对**：改动涉及模块增删时，registry 模块数 == spec hidden-import 数 == README/使用说明模块表行数（脚本核对），hidden-import 少一个＝exe 静默丢模块。
- **打包验证**：hidden-import 数 == BUILTIN_MODULES 数；打包前移走旧 exe；`OPENBLAS_NUM_THREADS=1`；烟测=全进程枚举窗口标题真实显示（onefile 父进程无窗口是假象）。
- **验收口径**：pytest 全绿 + 测试台全 PASS + exe 烟测 + 远端哈希一致，四样齐才叫"完成"。

## 已知约束与环境

- 系统 Python：`C:\Users\Administrator\AppData\Local\Programs\Python\Python312\python.exe`（workbuddy 自带 3.13 无 tkinter/pytest）。
- exe 内容验证只能抽 PYZ 字节码（明文字节搜索因压缩必然 0 命中，是无效手段）。
- ClamAV 引擎装在 `D:\ClamAV\app\clamav-1.5.5.win.x64\`；测试样本只用 EICAR 与合成样本，**绝不碰真实恶意样本**。

## 当前遗留（接手前知悉）

- git 历史旧提交仍含作者全号（用户知情，暂不重写历史）。
- 根目录历史 fk_* 临时目录 31 个为存量残留，再生已由 tests finally 根治；删除需用户确认。
