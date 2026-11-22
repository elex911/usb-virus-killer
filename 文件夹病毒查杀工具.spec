# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['FolderVirusKiller.py'],  # 相对路径：CI 与本机均可构建（原绝对路径导致 CI 找不到脚本）
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['core.app', 'core.api', 'core.registry', 'core.widgets', 'core.scan_guard', 'core.report_tools', 'core.iso_writer', 'modules.folder_virus', 'modules.classic_trojans', 'modules.host_diagnostics', 'modules.signature_db', 'modules.clamav_bridge', 'modules.modern_threats', 'modules.amsi_scan'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='文件夹病毒查杀工具',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
