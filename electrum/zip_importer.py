#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2026 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Importer for a zip archive held in memory.

Written for the external plugin loader, which authorizes an archive by
verifying an ECDSA signature over its sha256. If the archive is then read from
disk *again* -- to import a module, or to read an icon -- someone who can write
to that directory can replace the file between the check and the read, and the
code that gets executed is not the code that was authorized. `zipimport` makes
this especially easy to hit, because it re-opens the archive on every single
module load, and it never verifies the CRC of what it reads.

`MemoryZipImporter` closes that window. The archive is read into memory once,
and every module and resource is served from those bytes. `sha256` is the
digest of the very bytes being held, so a caller that verifies it has no second
read left to race.

This is not a general replacement for `zipimport`: it mounts exactly one
package, deliberately never writes bytecode, and does not implement
`ResourceReader` or nested archives.
"""

import io
import importlib.abc
import importlib.util
import sys
import threading
import zipfile as zipfile_lib
from typing import Dict, Optional, Tuple
import hashlib



class MemoryZipImporter(importlib.abc.SourceLoader, importlib.abc.MetaPathFinder):
    """A meta path finder and source loader backed by an in-memory zip archive.

    `prefix` is the directory inside the archive that holds the package (i.e.
    the directory containing its `__init__.py`), and it is mounted under the
    module name `root_name`. `archive_path` is used for display only: it
    ends up in `__file__` and in tracebacks, and is never opened.
    """

    def __init__(self, blob: bytes, *, root_name: str, prefix: str = '', archive_path: str = '<memory>'):
        self._sha256 = bytes(hashlib.sha256(blob).digest())
        self._zip = zipfile_lib.ZipFile(io.BytesIO(blob))
        self._root_name = root_name
        self._prefix = (prefix.strip('/') + '/') if prefix.strip('/') else ''
        self._archive_path = archive_path
        # ZipFile is not thread-safe, and modules can be imported from any thread
        self._lock = threading.RLock()
        self._modules = {}  # type: Dict[str, Tuple[str, bool]]  # module name -> (member, is_package)
        self._filenames = {}  # type: Dict[str, str]  # synthetic __file__ -> member
        for member in self._zip.namelist():
            entry = self._module_for_member(member)
            if entry is None:
                continue
            fullname, is_pkg = entry
            self._modules[fullname] = (member, is_pkg)
            self._filenames[self._synthetic_path(member)] = member

    def _module_for_member(self, member: str) -> Optional[Tuple[str, bool]]:
        if not member.startswith(self._prefix) or not member.endswith('.py'):
            return None
        rel = member[len(self._prefix):]
        if rel == '__init__.py':
            return self._root_name, True
        elif rel.endswith('/__init__.py'):
            subname, is_pkg = rel[:-len('/__init__.py')], True
        else:
            subname, is_pkg = rel[:-len('.py')], False
        parts = subname.split('/')
        # rejects '', '..', and anything else that is not a legal module name
        if not all(part.isidentifier() for part in parts):
            return None
        return self._root_name + '.' + '.'.join(parts), is_pkg

    def _synthetic_path(self, member: str) -> str:
        return self._archive_path + '/' + member

    @property
    def sha256(self) -> bytes:
        """sha256 of the archive bytes held in memory. This is what a caller
        must verify against, rather than re-hashing the file on disk."""
        return self._sha256

    def read(self, filename: str) -> bytes:
        """Reads a file from the archive, relative to `prefix`."""
        return self._read_member(self._prefix + filename.lstrip('/'))

    def _read_member(self, member: str) -> bytes:
        with self._lock:
            try:
                # note: ZipFile.read() verifies the member CRC, zipimport does not
                return self._zip.read(member)
            except KeyError:
                raise FileNotFoundError(f"{member!r} not found in {self._archive_path}") from None

    # --- MetaPathFinder ---

    def find_spec(self, fullname, path=None, target=None):
        entry = self._modules.get(fullname)
        if entry is None:
            return None
        member, is_pkg = entry
        spec = importlib.util.spec_from_loader(fullname, self, is_package=is_pkg)
        if is_pkg:
            # Empty on purpose. This finder answers for every
            # submodule, so __path__ is never consulted while we are
            # installed. If this method is bypassed we want submodule
            # lookup to fail with ModuleNotFoundError, rather than
            # have PathFinder silently resolve a path on disk.
            spec.submodule_search_locations = []
        return spec

    # --- SourceLoader ---

    def is_package(self, fullname):
        try:
            return self._modules[fullname][1]
        except KeyError:
            raise ImportError(f"{fullname!r} is not in {self._archive_path}", name=fullname) from None

    def get_filename(self, fullname):
        try:
            return self._synthetic_path(self._modules[fullname][0])
        except KeyError:
            raise ImportError(f"{fullname!r} is not in {self._archive_path}", name=fullname) from None

    def get_data(self, path):
        member = self._filenames.get(path)
        if member is None:
            # a resource, addressed by synthetic path or archive-relative name
            if path.startswith(self._archive_path + '/'):
                path = path[len(self._archive_path) + 1:]
                assert path.startswith(self._prefix), path
                path = path[len(self._prefix):]
            member = self._prefix + path.lstrip('/')
        return self._read_member(member)

    # note: we do not override SourceLoader.path_stats(), whose default raises
    # OSError. That disables bytecode caching, so we never write .pyc files
    # (there is no directory to write them to anyway).

    # --- lifecycle ---

    def install(self) -> 'MemoryZipImporter':
        """Registers this finder in sys.meta_path.

        Prepended, so that it is consulted before PathFinder: the package
        `__path__` we hand out must never be resolved through sys.path_hooks,
        which would read the archive from disk again. This cannot shadow
        anything else, as find_spec() only answers for `root_name` and its
        submodules.
        """
        if self not in sys.meta_path:
            sys.meta_path.insert(0, self)
        return self

    def uninstall(self) -> None:
        if self in sys.meta_path:
            sys.meta_path.remove(self)

    def close(self) -> None:
        self.uninstall()
        with self._lock:
            self._zip.close()

    def __repr__(self):
        return f"<MemoryZipImporter {self._root_name} at {self._archive_path} modules={len(self._modules)}>"
