#!/usr/bin/python3

import importlib.util
import os
import sys

ARCH_DICT = {
    "x86_64": "4",
    "arm64-v8a": "3",
    "armeabi-v7a": "2",
    "x86": "1",
    "null": "0",
}


def get_electrum_version() -> str:
    project_root = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    version_file_path = os.path.join(project_root, "electrum", "version.py")
    # load version.py; needlessly complicated alternative to "imp.load_source":
    version_spec = importlib.util.spec_from_file_location('version', version_file_path)
    version_module = version = importlib.util.module_from_spec(version_spec)
    version_spec.loader.exec_module(version_module)
    return version.ELECTRUM_VERSION


def get_android_versioncode(*, arch_name: str) -> int:
    version_code = 0
    # add ELECTRUM_VERSION
    app_version = get_electrum_version()
    app_version_components = app_version.split('.')
    assert len(app_version_components) == 3, f"version str expected to have 3 components, but got {app_version!r}"
    for i in app_version_components:
        version_code *= 100
        version_code += int(i)
    # add arch
    arch_code = ARCH_DICT[arch_name]
    assert len(arch_code) == 1
    version_code *= 10
    version_code += int(arch_code)
    # compensate for legacy scheme
    # note: up until version 4.5.5, we used a different scheme for version_code.
    #       4_______________4_05_05_00
    #       ^ android arch, ^ app_version (4.5.5.0)
    # This offset ensures that all new-scheme version codes are larger than the old-scheme version codes.
    offset_due_to_legacy_scheme = 45_000_000
    version_code += offset_due_to_legacy_scheme
    return version_code


if __name__ == '__main__':
    try:
        android_arch = sys.argv[1]
    except Exception:
        print(f"usage: {os.path.basename(__file__)} <android_arch>", file=sys.stderr)
        sys.exit(1)
    if android_arch not in ARCH_DICT:
        print(f"usage: {os.path.basename(__file__)} <android_arch>", file=sys.stderr)
        print(f"error: unknown {android_arch=}", file=sys.stderr)
        print(f"       should be one of: {list(ARCH_DICT.keys())}", file=sys.stderr)
        sys.exit(1)
    version_code = get_android_versioncode(arch_name=android_arch)
    assert isinstance(version_code, int), f"{version_code=!r} must be an int."
    print(version_code, file=sys.stdout)
