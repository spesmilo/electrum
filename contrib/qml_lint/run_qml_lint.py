#!/usr/bin/env python3
#
# Copyright (C) 2026 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php
#
# This script runs qmllint over the QML sources of the QML GUI and of the
# plugins. See https://github.com/spesmilo/electrum/issues/10802
#
# The types of the 'org.electrum' QML module are registered from Python at
# runtime (see qeapp.py), so qmllint cannot resolve the module on its own.
# This script generates a minimal qmldir + qmltypes stub for the module into a
# temporary directory and passes it to qmllint via '-I'. With the module
# resolvable, a misspelled type name fails the lint (with a "did you mean"
# suggestion) instead of drowning in unresolved-import noise.
#
# Which warning categories gate CI is configured in .qmllint.ini at the repo
# root; qmllint discovers that file by walking up from each linted file.
#
# qmllint is not distributed with PyQt6; we take it from the PySide6 wheels
# (PySide6-Addons is needed for the QtMultimedia types used by QRScan.qml).
# The pinned install command lives in the 'qml-lint' job in
# .github/workflows/tests.yml -- that is the single version authority.
#
# If CI fails with "[import]" errors on valid 'org.electrum' types, the likely
# cause is a registration in qeapp.py that this script's regex did not match.

import os
import os.path
import re
import subprocess
import sys
import tempfile

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(project_root)

QEAPP_PATH = "electrum/gui/qml/qeapp.py"


def find_qmllint() -> str:
    # Invoke the real qmllint binary bundled inside the PySide6 package, not the
    # 'pyside6-qmllint' wrapper: the wrapper exits 0 on its own argument errors.
    try:
        import PySide6
    except ImportError:
        sys.exit("error: PySide6 is not installed.\n"
                 "See the 'qml-lint' job in .github/workflows/tests.yml for the pinned\n"
                 "install command (PySide6-Essentials + PySide6-Addons).")
    exe_name = "qmllint.exe" if sys.platform == "win32" else "qmllint"
    exe_path = os.path.join(PySide6.__path__[0], exe_name)
    if not os.path.exists(exe_path):
        sys.exit(f"error: qmllint binary not found at {exe_path}")
    return exe_path


def get_registered_type_names() -> list:
    reg_re = re.compile(r"qmlRegisterType\(\w+, 'org\.electrum', 1, 0, '(\w+)'\)")
    names = []
    with open(QEAPP_PATH, "r", encoding="utf-8") as f:
        for line in f.read().splitlines():
            code = line.split("#", 1)[0]  # commented-out registrations must not enter the stub
            m = reg_re.search(code)
            if m:
                names.append(m.group(1))
            elif "qmlRegister" in code and "org.electrum" in code:
                sys.exit(f"error: unrecognized 'org.electrum' registration in {QEAPP_PATH}:\n"
                         f"    {line.strip()}\n"
                         "Update the regex in this script, or the stub will lack this type\n"
                         "and valid QML using it will fail the lint with [import] errors.")
    if len(names) < 20:  # 29 as of 2026-08; guards against the registrations moving elsewhere
        sys.exit(f"error: found only {len(names)} qmlRegisterType calls in {QEAPP_PATH}.\n"
                 "Did the registrations move? Update this script.")
    return names


def write_module_stub(imports_dir: str, type_names: list) -> None:
    module_dir = os.path.join(imports_dir, "org", "electrum")
    os.makedirs(module_dir)
    with open(os.path.join(module_dir, "qmldir"), "w", encoding="utf-8") as f:
        f.write("module org.electrum\ntypeinfo plugins.qmltypes\n")
    components = "".join(
        '    Component { name: "%s"; exports: ["org.electrum/%s 1.0"]; '
        'accessSemantics: "reference"; prototype: "QObject" }\n' % (name, name)
        for name in type_names
    )
    with open(os.path.join(module_dir, "plugins.qmltypes"), "w", encoding="utf-8") as f:
        f.write("import QtQuick.tooling 1.2\nModule {\n" + components + "}\n")


def get_qml_files() -> list:
    bfiles = subprocess.check_output(["git", "ls-files", "--", "*.qml"])
    files = bfiles.decode("utf-8").splitlines()
    if not files:  # an empty list would make the lint vacuously green
        sys.exit("error: 'git ls-files' found no .qml files.")
    return files


def main():
    qmllint_path = find_qmllint()
    qml_files = get_qml_files()
    type_names = get_registered_type_names()
    with tempfile.TemporaryDirectory() as imports_dir:
        write_module_stub(imports_dir, type_names)
        proc = subprocess.run([qmllint_path, "-I", imports_dir] + qml_files)
    print(f"qmllint: checked {len(qml_files)} files "
          f"({len(type_names)} org.electrum stub types), exit code {proc.returncode}")
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
