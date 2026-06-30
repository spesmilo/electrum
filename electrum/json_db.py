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
from contextlib import contextmanager

import jsonpatch
import jsonpointer

from .util import profiler, sticky_property
from .logging import Logger
from .stored_dict import _FLEX_KEY, BaseDB, StorageException
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
            return x
    items = [to_str(x) for x in path]
    if key is not None:
        items.append(to_str(key))
    return '/'.join(items)



def locked(func):
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return func(self, *args, **kwargs)
    return wrapper



class JsonDB(BaseDB):

    def __init__(
            self,
            path: Optional[str],
            *,
            allow_partial_writes = True,
            init_db = True,
    ):
        BaseDB.__init__(self, path)
        self._is_closed = True
        self.lock = threading.RLock()
        self.pending_changes = []  # type: List[str]
        self._write_batch = False
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

    def init_db(self):
        if self.storage.is_encrypted():
            assert self.storage.is_past_initial_decryption()
        json_str = self.storage.read()
        self.json_data = self.load_data(json_str)
        self._is_closed = False
        # write file in case there was a db upgrade
        self.write(force_consolidation=True)

    def decrypt(self, password: str):
        self.storage.decrypt(password)
        json_str = self.storage.read()
        self.set_data(json_str)
        self._is_closed = False

    def check_password(self, password):
        self.storage.check_password(password)

    def supports_file_encryption(self):
        return bool(self.storage)

    def get_encryption_versions(self):
        return self.storage.get_encryption_versions()

    def is_encrypted(self):
        return self.storage and self.storage.is_encrypted()

    def is_encrypted_with_user_pw(self) -> bool:
        return self.storage and self.storage.is_encrypted_with_user_pw()

    def is_encrypted_with_hw_device(self) -> bool:
        return self.storage and self.storage.is_encrypted_with_hw_device()

    def add_password(self, password: str, password_type=None):
        self.storage.add_password(password, password_type=password_type)

    def update_password(self, password: str, new_password: str, new_password_type):
        self.storage.update_password(password, new_password, new_password_type)

    def remove_password(self, password: str):
        self.storage.remove_password(password)

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

    def put(self, d, path, key, value):
        is_new = key not in d
        if not is_new and d[key] == value:
            return
        op = 'dict_add' if is_new else 'dict_replace'
        self.add_pending_change(d, op, path, key, value)

    def clear(self, d, path):
        path, key = path[:-1], path[-1]
        self.add_pending_change(d, 'dict_clear', path, key, None)

    def get(self, d, key):
        return d[key]

    def get_hint(self, path):
        return self._subdict(path)

    def remove(self, d, path, key):
        self.add_pending_change(d, 'dict_remove', path, key, None)

    def list_append(self, _list, path, item):
        self.add_pending_change(_list, 'list_append', path, None, item)

    def list_index(self, _list, path, item):
        return _list.index(item)

    def list_len(self, _list, path):
        return len(_list)

    def list_clear(self, _list, path):
        self.add_pending_change(_list, 'list_clear', path[:-1], path[-1], None)

    def list_remove(self, _list, path, item):
        self.add_pending_change(_list, 'list_remove', path[:-1], path[-1], item)

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
            else:
                raise StorageException("Cannot read wallet file. (parsing failed)")
        if not isinstance(data, dict):
            raise StorageException("Malformed wallet file (not dict)")
        if patches:
            # apply patches
            self.logger.info('found %d patches'%len(patches))
            patch = jsonpatch.JsonPatch(patches)
            data = patch.apply(data)
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

    def maybe_load_incomplete_data(self, s):
        n = s.count('{') - s.count('}')
        i = len(s)
        while n > 0 and i > 0:
            i = i - 1
            if s[i] == '{':
                n = n - 1
            if s[i] == '}':
                n = n + 1
            if n == 0:
                s = s[0:i]
                assert s[-2:] == ',\n'
                self.logger.info('found incomplete data {s[i:]}')
                return self.load_data(s[0:-2])

    @locked
    def add_pending_change(self, hint, op, path, key, value):
        self.pending_changes.append((hint, op, path, key, value))
        if not self._write_batch:
            self.write()

    def db_replace(self, hint, path, key: _FLEX_KEY, value) -> None:
        assert isinstance(key, _FLEX_KEY), repr(key)
        self.add_pending_change(hint, 'replace', key_path(path, key), value)

    def db_remove(self, hint, path, key: _FLEX_KEY) -> None:
        assert isinstance(key, _FLEX_KEY), repr(key)
        self.add_pending_change(hint, 'remove', key_path(path, key), None)

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

    @contextmanager
    def write_batch(self):
        assert self._write_batch is False
        self._write_batch = True
        try:
            yield
        finally:
            self._write_batch = False
        self.write()

    def close(self):
        # do not call write, because we may need to close the DB after an exception was raised during a batch write
        self._is_closed = True

    def is_closed(self):
        return self._is_closed

    def _commit_pending_changes(self):
        patches = []
        for hint, op, _path, key, value in self.pending_changes:
            path = key_path(_path, key)
            if op == 'dict_add':
                hint[key] = value
                patch = {'op': 'add', 'path': path, 'value': value}
            elif op == 'dict_remove':
                hint.pop(key, None)
                patch = {'op': 'remove', 'path': path}
            elif op == 'dict_replace':
                hint[key] = value
                patch = {'op': 'replace', 'path': path, 'value': value}
            elif op == 'dict_clear':
                hint.clear()
                patch = {'op': 'replace', 'path': path, 'value': {}}
            elif op == 'list_append':
                n = len(hint)
                hint.append(value)
                path = key_path(_path, str(n))
                patch = {'op': 'add', 'path': path, 'value': value}
            elif op == 'list_remove':
                hint.remove(value)
                # we replace the whole list because indexes are deprecated
                patch = {'op': 'replace', 'path': path, 'value': hint}
            elif op == 'list_clear':
                hint.clear()
                patch = {'op': 'replace', 'path': path, 'value': []}
            else:
                raise Exception('unknown operation')
            patches.append(patch)
        self.pending_changes = []
        return patches

    @locked
    def write(self, force_consolidation=False):
        if self._is_closed:
            raise StorageException('DB is closed')
        assert self._write_batch is False
        patches = self._commit_pending_changes()
        if not self.storage:
            return
        if force_consolidation or self.storage.should_do_full_write_next():
            self._write_and_force_consolidation()
        else:
            self._append_pending_changes(patches)

    @locked
    def _append_pending_changes(self, patches):
        if threading.current_thread().daemon:
            raise Exception('daemon thread cannot write db')
        if not patches:
            self.logger.info('no pending changes')
            return
        self.logger.info(f'appending {len(patches)} pending changes')
        s = ''.join([',\n' + json.dumps(x) for x in patches])
        self.storage.append(s)

    @locked
    @profiler
    def _write_and_force_consolidation(self):
        if threading.current_thread().daemon:
            raise Exception('daemon thread cannot write db')
        json_str = self.dump(human_readable=not self.storage.is_encrypted())
        self.storage.write(json_str)
