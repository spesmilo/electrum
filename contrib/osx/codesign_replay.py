#!/usr/bin/env python3
"""Replay the code signatures of a signed Electrum.app onto an unsigned build of the same app.

The release app is codesigned and notarized by the release manager. Signing changes only:
- in each Mach-O file, the signature at the end of the file, and three header fields that
  depend on its size: LC_CODE_SIGNATURE's datasize, and __LINKEDIT's filesize and vmsize;
- the files in _CodeSignature/ directories, and Contents/CodeResources (the notarization ticket).

'replay' copies these from the release app into a copy of a builder's unsigned app. If both apps
come from the same source, the result is byte-identical to the release app, which 'manifest' (one
line per file) shows.

Only thin 64-bit Mach-O files are supported: Electrum ships one app per architecture.
Uses only the Python standard library, so it also runs on Linux.

usage: codesign_replay.py replay <signed .app> <unsigned .app>   (modifies the unsigned app)
       codesign_replay.py manifest <.app>
"""

import hashlib
import os
import stat
import struct
import sys
from typing import Callable, Optional, Union

# Mach-O constants, and the structs read below (mach_header_64, segment_command_64, linkedit_data_command),
# are from Apple's <mach-o/loader.h>:
# https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/EXTERNAL_HEADERS/mach-o/loader.h
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
# codesign on macOS >= 12 makes room for a signature in assure_signature_space():
# https://github.com/apple-oss-distributions/Security/blob/97c3a4296c1ea06b0fe1877a7e616aa84450b5b2/OSX/libsecurity_codesigning/lib/codesign_alloc.cpp#L166-L322
# It sets __LINKEDIT's vmsize to its filesize rounded up to 16 KiB, for both architectures.
# The vmsize can therefore shrink as well as grow.
LINKEDIT_VMSIZE_ALIGN = 0x4000
# the directory of a bundle's signing files (BUNDLEDISKREP_DIRECTORY):
# https://github.com/apple-oss-distributions/Security/blob/97c3a4296c1ea06b0fe1877a7e616aa84450b5b2/OSX/libsecurity_codesigning/lib/bundlediskrep.h#L45
CODESIGN_DIR = "_CodeSignature"
# the stapled notarization ticket (copyStapledTicketInBundle()):
# https://github.com/apple-oss-distributions/Security/blob/97c3a4296c1ea06b0fe1877a7e616aa84450b5b2/OSX/libsecurity_codesigning/lib/notarization.cpp#L239
TICKET = os.path.join("Contents", "CodeResources")


class ReplayError(Exception):
    pass


def is_macho(path: str) -> bool:
    """True for a thin 64-bit little-endian Mach-O file."""
    with open(path, "rb") as f:
        return f.read(4) == struct.pack("<I", MH_MAGIC_64)


class MachO:
    """The signature-related fields of a thin 64-bit little-endian Mach-O file."""

    def __init__(self, data: bytearray, path: str) -> None:
        self.path = path
        ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
        self.sig_cmd: Optional[int] = None       # offset of the LC_CODE_SIGNATURE load command
        self.linkedit_cmd: Optional[int] = None  # offset of the __LINKEDIT LC_SEGMENT_64 load command
        off = 32  # sizeof(struct mach_header_64)
        end = off + sizeofcmds
        if end > len(data):
            raise ReplayError(f"{path}: unexpected Mach-O layout")
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmdsize < 8 or off + cmdsize > end:
                raise ReplayError(f"{path}: unexpected Mach-O layout")
            if cmd == LC_SEGMENT_64 and data[off + 8:off + 24].rstrip(b"\0") == b"__LINKEDIT":
                self.linkedit_cmd = off
            elif cmd == LC_CODE_SIGNATURE:
                self.sig_cmd = off
            off += cmdsize
        if off != end or (self.sig_cmd is not None and self.linkedit_cmd is None):
            raise ReplayError(f"{path}: unexpected Mach-O layout")
        self.data = data

    # struct linkedit_data_command: cmd, cmdsize, dataoff, datasize (uint32 each)
    def sig_range(self) -> tuple[int, int]:
        assert self.sig_cmd is not None
        dataoff, datasize = struct.unpack_from("<II", self.data, self.sig_cmd + 8)
        return dataoff, datasize

    def set_signature(self, blob: bytearray) -> None:
        """Replace the signature, keeping its offset, and update the three dependent fields.
        This is what codesign's assure_signature_space() does to a file that has a signature."""
        if self.sig_cmd is None:
            raise ReplayError(f"{self.path}: has no signature to replace (the unsigned build is ad-hoc signed)")
        assert self.linkedit_cmd is not None  # __init__ refuses a signature without __LINKEDIT
        dataoff, datasize = self.sig_range()
        # struct segment_command_64: cmd, cmdsize, segname[16], vmaddr, vmsize, fileoff, filesize, ...
        fileoff, = struct.unpack_from("<Q", self.data, self.linkedit_cmd + 40)
        if dataoff + datasize != len(self.data) or dataoff < fileoff:
            raise ReplayError(f"{self.path}: the signature is not at the end of __LINKEDIT")
        filesize = dataoff + len(blob) - fileoff
        vmsize = -(-filesize // LINKEDIT_VMSIZE_ALIGN) * LINKEDIT_VMSIZE_ALIGN
        del self.data[dataoff:]
        self.data += blob
        struct.pack_into("<I", self.data, self.sig_cmd + 12, len(blob))
        struct.pack_into("<Q", self.data, self.linkedit_cmd + 32, vmsize)
        struct.pack_into("<Q", self.data, self.linkedit_cmd + 48, filesize)


def walk(root: str) -> list[str]:
    """Relative paths of all entries below root, sorted, without following symlinks."""
    def unreadable(e: OSError) -> None:  # os.walk would skip the directory
        raise ReplayError(f"{e.filename}: {e.strerror}")

    out = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=unreadable):
        for name in dirnames + filenames:
            out.append(os.path.relpath(os.path.join(dirpath, name), root))
    return sorted(out)


def is_signing_file(rel: str) -> bool:
    """Files that signing or notarization (stapling) write, besides the Mach-O signatures."""
    return CODESIGN_DIR in rel.split(os.sep) or rel == TICKET


def app_path(app: str, rel: str) -> str:
    """app/rel. Refuses paths that would lead out of the app's own tree through a symlink."""
    path = os.path.join(app, rel)
    if os.path.realpath(path) != os.path.join(os.path.realpath(app), rel):
        raise ReplayError(f"{path}: is a symlink, or inside a symlinked directory")
    return path


def read_macho(path: str) -> MachO:
    with open(path, "rb") as f:
        return MachO(bytearray(f.read()), path)


def write_file(path: str, data: Union[bytes, bytearray], mode: int) -> None:
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def replay(signed_app: str, app: str) -> None:
    """Only replaces signatures and signing files that the (ad-hoc signed) build already has, and
    adds the notarization ticket. Anything else in the signed app is reported by 'manifest'."""
    n_sigs = n_files = 0
    for rel in walk(signed_app):
        src = os.path.join(signed_app, rel)
        if os.path.islink(src) or not os.path.isfile(src):
            continue
        if is_signing_file(rel):
            path = app_path(app, rel)
            if not os.path.isfile(path) and rel != TICKET:
                raise ReplayError(f"{path}: the signed app has this file, the build does not")
            with open(src, "rb") as f:
                write_file(path, f.read(), stat.S_IMODE(os.lstat(src).st_mode))
            n_files += 1
        elif is_macho(src):
            signed = read_macho(src)
            if signed.sig_cmd is None:
                continue
            path = app_path(app, rel)
            if not os.path.isfile(path) or not is_macho(path):
                raise ReplayError(f"{path}: missing, or not a Mach-O file")
            macho = read_macho(path)
            dataoff, datasize = signed.sig_range()
            macho.set_signature(signed.data[dataoff:dataoff + datasize])
            write_file(path, macho.data, stat.S_IMODE(os.lstat(path).st_mode))
            n_sigs += 1
    print(f"replayed {n_sigs} Mach-O signatures and {n_files} other signing files", file=sys.stderr)


def manifest(app: str) -> None:
    """One line per entry: type, permission bits, and the sha256 (files) or target (symlinks).

    Symlinks are listed without permission bits, which Linux shows as 0777 and macOS uses only for
    readlink(). Names and targets that would make a line ambiguous are refused: control characters
    (a newline could fake or hide lines), and " ->" in a symlink name.
    """
    def has_control_chars(s: str) -> bool:
        return any(c < " " or c == "\x7f" for c in s)

    print(f"d {stat.S_IMODE(os.lstat(app).st_mode):04o} .")
    for rel in walk(app):
        path = os.path.join(app, rel)
        if has_control_chars(rel):
            raise ReplayError(f"{path!r}: control character in the name")
        st = os.lstat(path)
        mode = f"{stat.S_IMODE(st.st_mode):04o}"
        if stat.S_ISLNK(st.st_mode):
            target = os.readlink(path)
            if " ->" in rel or has_control_chars(target):
                raise ReplayError(f"{path!r}: symlink name or target cannot be listed unambiguously")
            print(f"l {rel} -> {target}")
        elif stat.S_ISDIR(st.st_mode):
            print(f"d {mode} {rel}")
        elif stat.S_ISREG(st.st_mode):
            with open(path, "rb") as f:
                print(f"f {mode} {hashlib.sha256(f.read()).hexdigest()} {rel}")
        else:
            print(f"? {mode} {rel}")


def main() -> None:
    commands: dict[str, Callable[..., None]] = {"replay": replay, "manifest": manifest}
    cmd, *args = sys.argv[1:] or [""]
    if cmd not in commands or len(args) != (1 if cmd == "manifest" else 2):
        sys.exit(__doc__)
    for d in args:
        # a symlink to a directory would be followed, e.g. to another app
        if os.path.islink(os.path.normpath(d)) or not os.path.isdir(d):
            sys.exit(f"codesign_replay.py: {d} is not a directory (or is a symlink)")
    try:
        commands[cmd](*args)
    except ReplayError as e:
        sys.exit(f"codesign_replay.py: {e}")


if __name__ == "__main__":
    main()
