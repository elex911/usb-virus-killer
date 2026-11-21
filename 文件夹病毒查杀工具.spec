# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:/Users/Administrator/WorkBuddy/2026-11-19-12-13-08/usb-virus-killer/FolderVirusKiller.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['core.app', 'core.registry', 'core.widgets', 'modules.folder_virus', 'modules.classic_trojans', 'modules.host_diagnostics', 'modules.signature_db', 'modules.clamav_bridge', 'modules.modern_threats'],
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
