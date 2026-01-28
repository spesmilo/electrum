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
from typing import TYPE_CHECKING, Optional, Sequence, List, Union, Any

import jsonpatch
import jsonpointer

from .util import WalletFileException, profiler, sticky_property
from .logging import Logger
from .stored_dict import FLEX_KEY, BaseDB, json_default


if TYPE_CHECKING:
    from .storage import WalletStorage


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




def key_path(path: Sequence[FLEX_KEY], key: FLEX_KEY) -> str:
    def to_str(x: FLEX_KEY) -> str:
        assert isinstance(x, FLEX_KEY), repr(x)
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




class JsonDB(BaseDB):

    def __init__(
        self,
        s: str,
        *,
        storage: Optional['WalletStorage'] = None,
    ):
        BaseDB.__init__(self)
        self.lock = threading.RLock()
        self.storage = storage
        if self.storage:
            self.storage._db = self
        self.pending_changes = []  # type: List[str]
        self._modified = False
        # load data
        data = self.load_data(s)

        self.json_data = data # json dict
        # write file in case there was a db upgrade
        if self.storage and self.storage.file_exists():
            self.write_and_force_consolidation()

    def _subdict(self, path):
        d = self.json_data
        for k in path[1:]:
            d = d[k]
        return d

    def iter_keys(self, path):
        d = self._subdict(path)
        return d.__iter__()

    def dict_len(self, path):
        d = self._subdict(path)
        return len(d)

    def contains(self, path, key):
        d = self._subdict(path)
        return key in d

    def replace(self, path, key, value):
        # called by setattr
        self.put(path, key, value)

    @modifier
    def put(self, path, key, value):
        d = self._subdict(path)
        value = json.loads(json.dumps(value, default=json_default))
        is_new = key not in d
        d[key] = value
        self.db_add(path, key, value) if is_new else self.db_replace(path, key, value)

    @modifier
    def clear(self, path):
        d = self._subdict(path)
        d.clear()

    def get(self, path, key):
        d = self._subdict(path)
        return d[key]

    @modifier
    def remove(self, path, key):
        d = self._subdict(path)
        d.pop(key)
        self.db_remove(path, key)

    def get_list_item(self, path, s: slice):
        _list = self._subdict(path)
        if isinstance(s, int):
            return _list[s]
        else:
            return _list[s.start:s.stop:s.step]

    @modifier
    def list_append(self, path, item):
        _list = self._subdict(path)
        _list.append(item)
        n = len(_list)
        self.db_add(path, str(n), item)

    def list_index(self, path, item):
        _list = self._subdict(path)
        return _list.index(item)

    def list_len(self, path):
        _list = self._subdict(path)
        return len(_list)

    def list_iter(self, path):
        _list = self._subdict(path)
        return _list.__iter__()

    @modifier
    def list_clear(self, path):
        _list = self._subdict(path)
        _list.clear() # fixme

    @modifier
    def list_remove(self, path, item):
        _list = self._subdict(path)
        n = _list.index(item)
        _list.remove(item)
        self.db_remove(path, str(n))

    def load_data(self, s: str) -> dict:
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

    def maybe_load_ast_data(self, s):
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
        return data

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

    def set_modified(self, b):
        with self.lock:
            self._modified = b

    def modified(self):
        return self._modified

    @locked
    def add_patch(self, patch):
        self.pending_changes.append(json.dumps(patch, default=json_default))
        self.set_modified(True)

    def db_add(self, path, key: FLEX_KEY, value) -> None:
        assert isinstance(key, FLEX_KEY), repr(key)
        self.add_patch({'op': 'add', 'path': key_path(path, key), 'value': value})

    def db_replace(self, path, key: FLEX_KEY, value) -> None:
        assert isinstance(key, FLEX_KEY), repr(key)
        self.add_patch({'op': 'replace', 'path': key_path(path, key), 'value': value})

    def db_remove(self, path, key: FLEX_KEY) -> None:
        assert isinstance(key, FLEX_KEY), repr(key)
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
            default=json_default,
        )

    def _should_convert_to_stored_dict(self, key) -> bool:
        return True

    @locked
    def write(self):
        if self.storage.should_do_full_write_next():
            self.write_and_force_consolidation()
        else:
            self._append_pending_changes()

    def close(self):
        pass

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
        if threading.current_thread().daemon:
            raise Exception('daemon thread cannot write db')
        if not self.modified():
            return
        json_str = self.dump(human_readable=not self.storage.is_encrypted())
        self.storage.write(json_str)
        self.pending_changes = []
        self.set_modified(False)
