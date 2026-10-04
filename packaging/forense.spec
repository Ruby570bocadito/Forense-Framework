# PyInstaller spec: standalone Forense-Framework (no Python needed on the examiner's machine).
#
#   pip install . pyinstaller
#   pyinstaller packaging/forense.spec --noconfirm
#   dist/forense/forense --version          (dist\forense\forense.exe on Windows)
#
# A folder build ("onedir") starts much faster than a single file and is what the
# release workflow zips. Volatility 3 is not bundled: install Python and
# "pip install volatility3" (or set vol_path) to analyse memory dumps.
import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))  # noqa: F821 - SPECPATH is set by PyInstaller

NATIVE = ["evtx", "pyscca", "pyesedb", "pytsk3", "pyewf", "pyvhdi", "pyvmdk", "pyqcow", "pyvshadow", "pybde",
          "yara_x", "olefile"]

datas = collect_data_files("forense")  # locales, templates, static files, Sigma rules
hiddenimports = collect_submodules("forense") + NATIVE + ["yaml", "flask", "jinja2", "markupsafe"]

a = Analysis(
    ["forense_entry.py"],
    pathex=[ROOT],  # the checkout itself, also when the package is installed in editable mode
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "ruff", "volatility3"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="forense",
    console=True,
    icon=None,
    version=None,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="forense")
