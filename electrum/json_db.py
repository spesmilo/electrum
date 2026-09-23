#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2019 The Electrum Developers
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
import threading
import copy
import json
from typing import TYPE_CHECKING, Optional, Sequence, List, Union, Dict, Any

import jsonpatch
import jsonpointer

from .util import WalletFileException, profiler, sticky_property
from .logging import Logger
from .stored_dict import _FLEX_KEY, BaseDB
from .storage import FileStorage



# We monkeypatch exceptions in the jsonpatch package to ensure they do not contain secrets from the DB.
# We often log exceptions and offer to send them to the crash reporter, so they must not contain secrets.
jsonpointer.JsonPointerException.__str__ = lambda self: """(JPE) 'redacted'"""
jsonpointer.JsonPointerException.__repr__ = lambda self: """<JsonPointerException 'redacted'>"""
setattr(jsonpointer.JsonPointerException, '__cause__', sticky_property(None))
setattr(jsonpointer.JsonPointerException, '__context__', sticky_property(None))
setattr(jsonpointer.JsonPointerException, '__suppress_context__', sticky_property(True))
jsonpatch.JsonPatchException.__str__ = lambda self: """(JPE) 'redacted'"""
jsonpatch.JsonPatchException.__repr__ = lambda self: """<JsonPatchException 'redacted'>"""
setattr(jsonpatch.JsonPatchException, '__cause__', sticky_property(None))
setattr(jsonpatch.JsonPatchException, '__context__', sticky_property(None))
setattr(jsonpatch.JsonPatchException, '__suppress_context__', sticky_property(True))


def key_path(path: Sequence[_FLEX_KEY], key: _FLEX_KEY) -> str:
    def to_str(x: _FLEX_KEY) -> str:
        assert isinstance(x, _FLEX_KEY), repr(x)
        assert x is not None
        if isinstance(x, int):
            return str(int(x))
        else:
            assert isinstance(x, str), f"unexpected key type for: {x!r}"
            return jsonpointer.escape(x)  # RFC 6901: escape '~' and '/'
    items = [to_str(x) for x in path]
    if key is not None:
        items.append(to_str(key))
    return '/'.join(items)


def modifier(func):
    def wrapper(self, *args, **kwargs):
        with self.lock:
            self._modified = True
            return func(self, *args, **kwargs)
    return wrapper

def locked(func):
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return func(self, *args, **kwargs)
    return wrapper



def to_json_data(obj):
    """Convert built-in containers to what json gives back on reload: tuples become
    lists, and sets become lists in a deterministic order. Values in the json tree
    must be in this form, so that they compare equal to what is put later.
    """
    if isinstance(obj, (set, frozenset)):
        return sorted((to_json_data(x) for x in obj), key=lambda x: json.dumps(x, sort_keys=True))
    if isinstance(obj, (list, tuple)):
        return [to_json_data(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_json_data(v) for k, v in obj.items()}
    return obj


class JsonDB(BaseDB):

    def __init__(
            self,
            path: Optional[str],
            *,
            allow_partial_writes = False,
            init_db = True,
    ):
        BaseDB.__init__(self, path)
        self._is_closed = True
        self.pending_changes = []  # type: List[str]
        self._modified = False
        self._force_full_write = False  # set when file cannot be appended to safely
        if self.path:
            self.storage = FileStorage(path, allow_partial_writes=allow_partial_writes)
            if init_db and not self.is_encrypted():
                # open DB if file is not encrypted
                # otherwise, this will be called in self.decrypt
                self.init_db()
        else:
            self.storage = None
            self.json_data = {}
            self._is_closed = False

    def set_data(self, json_str):
        self.json_data = self.load_data(json_str)
        self._structure_version += 1  # existing hints and caches refer to the old data

    def init_db(self):
        if self.storage.is_encrypted():
            assert self.storage.is_past_initial_decryption()
        json_str = self.storage.read()
        self.json_data = self.load_data(json_str)
        self._is_closed = False

    def decrypt(self, password: str):
        self.storage.decrypt(password)
        json_str = self.storage.read()
        self.set_data(json_str)
        self._is_closed = False

    def check_password(self, password):
        self.storage.check_password(password)

    def supports_file_encryption(self):
        return bool(self.storage)

    def get_encryption_version(self):
        return self.storage.get_encryption_version()

    def is_encrypted(self):
        return self.storage and self.storage.is_encrypted()

    def is_encrypted_with_user_pw(self) -> bool:
        return self.storage and self.storage.is_encrypted_with_user_pw()

    def is_encrypted_with_hw_device(self) -> bool:
        return self.storage and self.storage.is_encrypted_with_hw_device()

    def set_password(self, password: str, enc_version=None):
        self.storage.set_password(password, enc_version=enc_version)

    def file_exists(self):
        return self.storage and self.storage.file_exists()

    def _subdict(self, path):
        d = self.json_data
        for k in path[1:]:
            d = d[k]
        return d

    def iter_keys(self, d, path):
        return d.__iter__()

    def dict_len(self, d, path):
        return len(d)

    def dict_contains(self, d, path, key):
        return key in d

    def replace(self, d, path, key, value):
        # called by setattr
        self.put(d, path, key, value)

    @modifier
    def put(self, d, path, key, value):
        value = to_json_data(value)
        is_new = key not in d
        if not is_new and d[key] == value:
            return
        if not is_new and isinstance(d[key], (dict, list)):
            self._structure_version += 1  # the old subtree is detached
        d[key] = value
        self.db_add(path, key, value) if is_new else self.db_replace(path, key, value)

    @modifier
    def clear(self, d, path):
        self._structure_version += 1  # subtrees are detached
        d.clear()
        path, key = path[:-1], path[-1]
        self.db_replace(path, key, {})

    def get(self, d, path, key):
        return d[key]

    def get_hint(self, path):
        return self._subdict(path)

    @modifier
    def remove(self, d, path, key):
        if isinstance(d[key], (dict, list)):
            self._structure_version += 1  # the subtree is detached
        d.pop(key)
        self.db_remove(path, key)

    @modifier
    def list_append(self, _list, path, item):
        item = to_json_data(item)
        n = len(_list)
        _list.append(item)
        self.db_add(path, str(n), item)

    def list_index(self, _list, path, item):
        return _list.index(to_json_data(item))

    def list_len(self, _list, path):
        return len(_list)

    @modifier
    def list_clear(self, _list, path):
        self._structure_version += 1  # subtrees are detached
        _list.clear()
        self.db_remove(path[:-1], path[-1])
        self.db_add(path[:-1], path[-1], [])

    @modifier
    def list_remove(self, _list, path, item):
        item = to_json_data(item)
        n = _list.index(item)
        if isinstance(item, (dict, list)):
            self._structure_version += 1  # the subtree is detached
        _list.remove(item)
        self.db_remove(path, str(n)) # fixme: keys

    def load_data(self, s: str) -> Dict[str, Any]:
        if s == '':
            return {}
        try:
            data = json.loads('[' + s + ']')
            data, patches = data[0], data[1:]
        except Exception:
            if r := self.maybe_load_ast_data(s):
                data, patches = r, []
            elif r := self.maybe_load_incomplete_data(s):
                data, patches = r, []
                self.set_modified(True)
                self._force_full_write = True
            else:
                raise WalletFileException("Cannot read wallet file. (parsing failed)")
        if not isinstance(data, dict):
            raise WalletFileException("Malformed wallet file (not dict)")
        if patches:
            # apply patches
            self.logger.info('found %d patches'%len(patches))
            patch = jsonpatch.JsonPatch(patches)
            data = patch.apply(data)
            self.set_modified(True)
        return data

    def maybe_load_ast_data(self, s) ->Dict[str, Any]:
        """ for old wallets """
        try:
            import ast
            d = ast.literal_eval(s)
            labels = d.get('labels', {})
        except Exception as e:
            return
        data = {}
        for key, value in d.items():
            try:
                json.dumps(key)
                json.dumps(value)
            except Exception:
                self.logger.info(f'Failed to convert label to json format: {key}')
                continue
            data[key] = value
        # json roundtrip: recursively converts int keys to str
        return json.loads(json.dumps(data))

    def maybe_load_incomplete_data(self, s: str) -> Optional[Dict[str, Any]]:
        """Try to recover a file that was truncated mid-write (e.g. crash during append).
        The file consists of a JSON object followed by JSON patches, separated by ',\n'
        (see _append_pending_changes). We parse complete segments with a real JSON parser,
        and drop the incomplete tail (note there might be '{' and '}' in user-controled input).
        """
        decoder = json.JSONDecoder()
        end: Optional[int] = None  # end of last complete segment
        try:
            _, end = decoder.raw_decode(s)  # main json object
            while end < len(s):
                if not (s.startswith(',\n', end) or s[end:] == ','):
                    return None  # unexpected structure, not a truncated append. cannot recover.
                _, end = decoder.raw_decode(s, end + 2)  # patch
        except json.JSONDecodeError:
            if end is None:
                return None  # main json object itself is truncated. cannot recover.
            self.logger.warning(f'found incomplete data, dropping {len(s) - end} trailing characters from json database')
            return self.load_data(s[0:end])

    def set_modified(self, b):
        with self.lock:
            self._modified = b

    def modified(self):
        return self._modified

    @locked
    def add_patch(self, patch):
        self.pending_changes.append(json.dumps(patch))
        self.set_modified(True)

    def db_add(self, path, key: _FLEX_KEY, value) -> None:
        assert isinstance(key, _FLEX_KEY), repr(key)
        self.add_patch({'op': 'add', 'path': key_path(path, key), 'value': value})

    def db_replace(self, path, key: _FLEX_KEY, value) -> None:
        assert isinstance(key, _FLEX_KEY), repr(key)
        self.add_patch({'op': 'replace', 'path': key_path(path, key), 'value': value})

    def db_remove(self, path, key: _FLEX_KEY) -> None:
        assert isinstance(key, _FLEX_KEY), repr(key)
        self.add_patch({'op': 'remove', 'path': key_path(path, key)})

    @locked
    def dump(self, *, human_readable: bool = True) -> str:
        """Serializes the DB as a string.
        'human_readable': makes the json indented and sorted, but this is ~2x slower
        """
        return json.dumps(
            self.json_data,
            indent=4 if human_readable else None,
            sort_keys=bool(human_readable),
        )

    @locked
    def write(self):
        if not self.storage:
            return
        if self._force_full_write or self.storage.should_do_full_write_next():
            self.write_and_force_consolidation()
        else:
            self._append_pending_changes()

    def close(self):
        # do not call write
        self._is_closed = True

    def is_closed(self):
        return self._is_closed

    @locked
    def _append_pending_changes(self):
        if threading.current_thread().daemon:
            raise Exception('daemon thread cannot write db')
        if not self.pending_changes:
            self.logger.info('no pending changes')
            return
        self.logger.info(f'appending {len(self.pending_changes)} pending changes')
        s = ''.join([',\n' + x for x in self.pending_changes])
        self.storage.append(s)
        self.pending_changes = []

    @locked
    @profiler
    def write_and_force_consolidation(self):
        if not self.storage:
            return
        if threading.current_thread().daemon:
            raise Exception('daemon thread cannot write db')
        if not self.modified():
            return
        json_str = self.dump(human_readable=not self.storage.is_encrypted())
        self.storage.write(json_str)
        self.pending_changes = []
        self._force_full_write = False
        self.set_modified(False)
