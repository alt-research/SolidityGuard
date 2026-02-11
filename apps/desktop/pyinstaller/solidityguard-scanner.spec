# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for SolidityGuard scanner — produces a single native binary."""

import os

block_cipher = None

a = Analysis(
    [os.path.join('..', '..', '..', '.claude', 'skills', 'solidity-guard', 'scripts', 'solidity_guard.py')],
    pathex=[os.path.join('..', '..', '..', '.claude', 'skills', 'solidity-guard', 'scripts')],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    excludes=[
        'tkinter', 'unittest', 'pydoc', 'doctest', 'xmlrpc', 'lib2to3',
        'rich', 'rich.console', 'rich.table', 'rich.panel', 'rich.progress',
        'weasyprint', 'PIL', 'numpy', 'pandas', 'matplotlib',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='solidityguard-scanner',
    debug=False,
    strip=True,
    upx=True,
    console=True,
)
