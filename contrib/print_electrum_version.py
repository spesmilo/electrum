#!/usr/bin/python3
# For usage in shell, to get the version of electrum-grs, without needing electrum-grs installed.
# For example:
# $ VERSION=$("$CONTRIB"/print_electrum_version.py)
# instead of
# $ VERSION=$(python3 -c "import electrum_grs; print(electrum_grs.version.ELECTRUM_VERSION)")

import importlib.util
import os


if __name__ == '__main__':
    project_root = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    version_file_path = os.path.join(project_root, "electrum_grs", "version.py")

    # load version.py; needlessly complicated alternative to "imp.load_source":
    version_spec = importlib.util.spec_from_file_location('version', version_file_path)
    version_module = version = importlib.util.module_from_spec(version_spec)
    version_spec.loader.exec_module(version_module)

    print(version.ELECTRUM_VERSION)
