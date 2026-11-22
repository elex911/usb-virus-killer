"""PortableAV —— WinPE 离线便携取证查杀引擎（原型）。

设计边界（写在最前面，避免被当成成品）：
- 本包只做「只读分析 + 可控处置」，默认不删除任何文件。
- WinPE 模式下不调用 WinVerifyTrust / CryptSvc / WMI / Task Scheduler COM。
- 目标系统盘上的系统关键路径只报告，不作处置锚点。
- 加密隔离区防的是「误执行、静态查杀误报、随手拷走」，
  不防对隔离盘有写权限的攻击者（密钥与被加密数据同在可写介质上）。
"""

__version__ = "0.1.0"

# 只读优先：任何模块都不得默认开启写操作。
DEFAULT_READONLY = True
