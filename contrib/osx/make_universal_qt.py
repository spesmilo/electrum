#!/usr/bin/env python3
"""Create universal2 (x86_64+arm64) PyQt6-Qt6 libraries in site-packages.

PyQt6-Qt6 does not ship universal2 wheels on PyPI, only thin x86_64 and arm64 ones.
When cross-building the arm64 app on an x86_64 host, the Qt libraries in the venv
need to contain
  - the build host's slice (x86_64), as pyinstaller imports PyQt6.QtCore during
    its Analysis step, and
  - the target's slice (arm64), which ends up in the app bundle (pyinstaller
    thins all collected binaries to the target arch).

This script downloads both thin wheels (pip verifies them against the hashes pinned
in the requirements file), merges each Mach-O file using lipo, and replaces
<site-packages>/PyQt6/Qt6 with the merged tree. The merged tree is constructed
deterministically and does not depend on the build host architecture.
"""

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile

PACKAGE_NAME = "PyQt6-Qt6"
# the minimum macOS version we request wheels for. arm64 wheels are macos 11+,
# so this is a hard floor; the actual request is bumped up to the build host's
# macOS version (see requested_platform_tag).
MIN_MACOS_MAJOR = 11
MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",  # MH_MAGIC (32-bit)
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64
    b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf",  # FAT_MAGIC, FAT_MAGIC_64
)


def requested_platform_tag(arch: str) -> str:
    """Build a pip '--platform' tag permissive enough to match the pinned wheel.

    'pip download --platform macosx_X_Y_<arch>' matches wheels whose min macOS
    version is <= X.Y. Rather than hardcoding X.Y (which would silently stop
    matching once PyQt6-Qt6 raises its wheels' min macOS above it), we request
    the build host's macOS major version, floored at MIN_MACOS_MAJOR. The host is
    necessarily new enough to provide whatever Qt we are bundling, so this keeps
    matching across future Qt upgrades without edits.
    """
    major = MIN_MACOS_MAJOR
    host_ver = platform.mac_ver()[0]  # e.g. "11.7.10"; "" when not on macOS
    if host_ver:
        major = max(major, int(host_ver.split(".")[0]))
    return f"macosx_{major}_0_{arch}"


def extract_requirement_block(requirements_path: str) -> str:
    """Return the requirement lines (incl. pinned hashes) for PACKAGE_NAME."""
    block_lines = []
    in_block = False
    with open(requirements_path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not in_block:
                if re.match(rf"^{re.escape(PACKAGE_NAME)}==", line, re.IGNORECASE):
                    in_block = True
            if in_block:
                block_lines.append(line)
                if not line.endswith("\\"):
                    break
    if not block_lines:
        raise Exception(f"could not find {PACKAGE_NAME} in {requirements_path}")
    return "\n".join(block_lines) + "\n"


def is_macho(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(4) in MACHO_MAGICS


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_expected_wheel_name(filename: str, arch: str) -> bool:
    # note: the pinned hashes span ALL platform wheels (incl. linux/windows), so a
    # hash match alone does not prove we have the right (thin, macos, $arch) wheel.
    return bool(re.search(rf"-macosx_\d+_\d+_{re.escape(arch)}\.whl$", filename))


def download_wheel(req_block: str, pinned_hashes: set, arch: str, cache_dir: str) -> str:
    """Download (or reuse) the PACKAGE_NAME wheel for the given arch. Returns wheel path."""
    dest_dir = os.path.join(cache_dir, arch)
    if os.path.isdir(dest_dir):
        cached = [fn for fn in sorted(os.listdir(dest_dir)) if fn.endswith(".whl")]
        for fn in cached:
            path = os.path.join(dest_dir, fn)
            if is_expected_wheel_name(fn, arch) and sha256_of_file(path) in pinned_hashes:
                print(f"reusing cached wheel: {path}")
                return path
        # stale/corrupt cache: start over
        shutil.rmtree(dest_dir)
    os.makedirs(dest_dir, exist_ok=True)
    req_file = os.path.join(dest_dir, "requirements.txt")
    with open(req_file, "w", encoding="utf-8") as f:
        f.write(req_block)
    subprocess.run(
        [
            sys.executable, "-m", "pip", "download",
            "--require-hashes", "--no-deps", "--only-binary", ":all:",
            "--platform", requested_platform_tag(arch),
            "-r", req_file, "-d", dest_dir,
        ],
        check=True,
    )
    wheels = [fn for fn in sorted(os.listdir(dest_dir)) if fn.endswith(".whl")]
    if len(wheels) != 1:
        raise Exception(f"expected exactly one downloaded wheel in {dest_dir}, found: {wheels}")
    if not is_expected_wheel_name(wheels[0], arch):
        raise Exception(
            f"downloaded wheel does not look like a thin macos {arch} wheel: {wheels[0]}. "
            f"If {PACKAGE_NAME} now ships 'universal2' wheels, this whole merge step is "
            f"likely obsolete and should be removed (see #7557).")
    path = os.path.join(dest_dir, wheels[0])
    # paranoia: pip already checked the hash, but verify again ourselves
    if sha256_of_file(path) not in pinned_hashes:
        raise Exception(f"sha256 mismatch for downloaded wheel: {path}")
    return path


def unpack_wheel(wheel_path: str, dest_dir: str) -> None:
    if os.path.isdir(dest_dir):
        shutil.rmtree(dest_dir)
    os.makedirs(dest_dir)
    with zipfile.ZipFile(wheel_path) as zf:
        for zinfo in zf.infolist():
            extracted = zf.extract(zinfo, dest_dir)
            # zipfile does not preserve unix permissions; restore them:
            unix_mode = (zinfo.external_attr >> 16) & 0o7777
            if unix_mode:
                os.chmod(extracted, unix_mode)


def merge_trees(x86_tree: str, arm_tree: str, out_tree: str) -> None:
    """Merge the "PyQt6/Qt6" dirs of both unpacked wheels into out_tree.

    The arm64 tree is used as the base (its file set defines the output), and for
    each Mach-O file the x86_64 slice is merged in with lipo.
    """
    x86_qt = os.path.join(x86_tree, "PyQt6", "Qt6")
    arm_qt = os.path.join(arm_tree, "PyQt6", "Qt6")
    for d in (x86_qt, arm_qt):
        if not os.path.isdir(d):
            raise Exception(f"missing PyQt6/Qt6 dir in unpacked wheel: {d}")
    if os.path.isdir(out_tree):
        shutil.rmtree(out_tree)
    num_fat = 0
    for dirpath, dirnames, filenames in os.walk(arm_qt):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, arm_qt)
        os.makedirs(os.path.normpath(os.path.join(out_tree, rel_dir)), exist_ok=True)
        for fn in sorted(filenames):
            arm_file = os.path.join(dirpath, fn)
            rel_file = os.path.normpath(os.path.join(rel_dir, fn))
            x86_file = os.path.join(x86_qt, rel_file)
            out_file = os.path.join(out_tree, rel_file)
            if is_macho(arm_file):
                if not os.path.isfile(x86_file):
                    raise Exception(f"Mach-O file missing from x86_64 wheel: {rel_file}")
                subprocess.run(
                    ["lipo", "-create", x86_file, arm_file, "-output", out_file],
                    check=True,
                )
                subprocess.run(
                    ["lipo", out_file, "-verify_arch", "x86_64", "arm64"],
                    check=True,
                )
                shutil.copymode(arm_file, out_file)
                num_fat += 1
            else:
                # ".a" static archives (plugins/permissions/) contain per-arch objects
                # and are expected to differ between the wheels. They are link-time-only
                # and do not get collected into the app bundle, so no warning for them.
                if os.path.isfile(x86_file) and not fn.endswith(".a"):
                    with open(arm_file, "rb") as f1, open(x86_file, "rb") as f2:
                        if f1.read() != f2.read():
                            print(f"warning: non-Mach-O file differs between wheels "
                                  f"(using arm64 wheel's copy): {rel_file}")
                shutil.copy2(arm_file, out_file)
    # warn about x86_64-only files we are dropping:
    for dirpath, dirnames, filenames in os.walk(x86_qt):
        dirnames.sort()
        for fn in sorted(filenames):
            rel_file = os.path.normpath(
                os.path.join(os.path.relpath(dirpath, x86_qt), fn))
            if not os.path.isfile(os.path.join(arm_qt, rel_file)):
                print(f"warning: file only present in x86_64 wheel (dropped): {rel_file}")
    if num_fat == 0:
        raise Exception("merged zero Mach-O files. Did the PyQt6/Qt6 wheel layout change?")
    print(f"merged {num_fat} Mach-O files into universal2 binaries.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", required=True,
                        help="path to requirements file with pinned PyQt6-Qt6 hashes")
    parser.add_argument("--site-packages", required=True,
                        help="path to the venv's site-packages dir")
    parser.add_argument("--cache-dir", required=True,
                        help="dir to store downloaded wheels and temp files")
    args = parser.parse_args()

    installed_qt = os.path.join(args.site_packages, "PyQt6", "Qt6")
    if not os.path.isdir(installed_qt):
        raise Exception(f"{PACKAGE_NAME} does not appear to be installed: {installed_qt}")

    req_block = extract_requirement_block(args.requirements)
    pinned_hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", req_block))
    if not pinned_hashes:
        raise Exception(f"no pinned hashes found for {PACKAGE_NAME}")

    # guard against a stale venv: the Qt libs we merge must be the same version as
    # the installed PyQt6 bindings expect, or the app only crashes at runtime.
    # (cannot happen in a full make_osx.sh run, but can on manual/partial reruns.)
    m = re.match(rf"^{re.escape(PACKAGE_NAME)}==([^\s\\;]+)", req_block, re.IGNORECASE)
    pinned_version = m.group(1)
    dist_prefix = PACKAGE_NAME.replace("-", "_") + "-"
    installed_versions = [
        fn[len(dist_prefix):-len(".dist-info")]
        for fn in sorted(os.listdir(args.site_packages))
        if fn.startswith(dist_prefix) and fn.endswith(".dist-info")
    ]
    if installed_versions != [pinned_version]:
        raise Exception(
            f"installed {PACKAGE_NAME} version {installed_versions or 'not found'} does not "
            f"match the pinned version {pinned_version}. Stale venv? (rerun the full build)")

    x86_whl = download_wheel(req_block, pinned_hashes, "x86_64", args.cache_dir)
    arm_whl = download_wheel(req_block, pinned_hashes, "arm64", args.cache_dir)

    x86_tree = os.path.join(args.cache_dir, "unpacked_x86_64")
    arm_tree = os.path.join(args.cache_dir, "unpacked_arm64")
    unpack_wheel(x86_whl, x86_tree)
    unpack_wheel(arm_whl, arm_tree)

    merged_tree = os.path.join(args.cache_dir, "merged_Qt6")
    merge_trees(x86_tree, arm_tree, merged_tree)

    shutil.rmtree(installed_qt)
    shutil.move(merged_tree, installed_qt)
    shutil.rmtree(x86_tree)
    shutil.rmtree(arm_tree)
    print(f"replaced {installed_qt} with universal2 merge.")


if __name__ == "__main__":
    main()
