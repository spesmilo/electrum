#!/usr/bin/python3
# For usage in shell, to get the version of electrum, without needing electrum installed.
# usage: ./print_electrum_version.py [--with-commit]
#
# For example:
# $ VERSION=$("$CONTRIB"/print_electrum_version.py)
# instead of
# $ VERSION=$(python3 -c "import electrum; print(electrum.version.ELECTRUM_VERSION)")

import importlib.util
import os
import subprocess
import sys


project_root = os.path.abspath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_bare_version() -> str:
    """example: '4.8.0' """
    version_file_path = os.path.join(project_root, "electrum", "version.py")

    # load version.py; needlessly complicated alternative to "imp.load_source":
    version_spec = importlib.util.spec_from_file_location('version', version_file_path)
    version_module = version = importlib.util.module_from_spec(version_spec)
    version_spec.loader.exec_module(version_module)

    elec_ver = getattr(version, "ELECTRUM_VERSION")
    return str(elec_ver)


def get_versionc() -> str:
    """example: '4.8.0-8c0adcd' """
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=project_root)
    commit = str(commit, "utf8").strip()
    commit = commit[:7]
    elec_ver = get_bare_version()
    return f"{elec_ver}-{commit}"


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print(get_bare_version(), file=sys.stdout)
    elif len(sys.argv) == 2 and sys.argv[1] == "--with-commit":
        print(get_versionc(), file=sys.stdout)
    else:
        print("usage: ./print_electrum_version.py [--with-commit]", file=sys.stderr)
        sys.exit(1)

