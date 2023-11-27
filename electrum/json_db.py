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
from typing import TYPE_CHECKING
import jsonpatch

from . import util
from .util import WalletFileException, profiler
from .logging import Logger

if TYPE_CHECKING:
    from .storage import WalletStorage

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


registered_names = {}
registered_dicts = {}
registered_dict_keys = {}
registered_parent_keys = {}

def register_dict(name, method, _type):
    registered_dicts[name] = method, _type

def register_name(name, method, _type):
    registered_names[name] = method, _type

def register_dict_key(name, method):
    registered_dict_keys[name] = method

def register_parent_key(name, method):
    registered_parent_keys[name] = method

def stored_as(name, _type=dict):
    """ decorator that indicates the storage key of a stored object"""
    def decorator(func):
        registered_names[name] = func, _type
        return func
    return decorator

def stored_in(name, _type=dict):
    """ decorator that indicates the storage key of an element in a StoredDict"""
    def decorator(func):
        registered_dicts[name] = func, _type
        return func
    return decorator


def key_path(path, key):
    def to_str(x):
        if isinstance(x, int):
            return str(int(x))
        else:
            assert isinstance(x, str)
            return x
    return '/' + '/'.join([to_str(x) for x in path + [to_str(key)]])


class StoredObject:

    db = None
    path = None

    def __setattr__(self, key, value):
        if self.db and key not in ['path', 'db'] and not key.startswith('_'):
            if value != getattr(self, key):
                self.db.add_patch({'op': 'replace', 'path': key_path(self.path, key), 'value': value})
        object.__setattr__(self, key, value)

    def set_db(self, db, path):
        self.db = db
        self.path = path

    def to_json(self):
        d = dict(vars(self))
        d.pop('db', None)
        d.pop('path', None)
        # don't expose/store private stuff
        d = {k: v for k, v in d.items()
             if not k.startswith('_')}
        return d


_RaiseKeyError = object() # singleton for no-default behavior

class StoredDict(dict):

    def __init__(self, data, db, path):
        self.db = db
        self.lock = self.db.lock if self.db else threading.RLock()
        self.path = path
        # recursively convert dicts to StoredDict
        for k, v in list(data.items()):
            self.__setitem__(k, v, patch=False)

    @locked
    def __setitem__(self, key, v, patch=True):
        is_new = key not in self
        # early return to prevent unnecessary disk writes
        if not is_new and patch:
            if self.db and json.dumps(v, cls=self.db.encoder) == json.dumps(self[key], cls=self.db.encoder):
                return
        # recursively set db and path
        if isinstance(v, StoredDict):
            #assert v.db is None
            v.db = self.db
            v.path = self.path + [key]
            for k, vv in v.items():
                v.__setitem__(k, vv, patch=False)
        # recursively convert dict to StoredDict.
        # _convert_dict is called breadth-first
        elif isinstance(v, dict):
            if self.db:
                v = self.db._convert_dict(self.path, key, v)
            if not self.db or self.db._should_convert_to_stored_dict(key):
                v = StoredDict(v, self.db, self.path + [key])
        # convert_value is called depth-first
        if isinstance(v, dict) or isinstance(v, str) or isinstance(v, int):
            if self.db:
                v = self.db._convert_value(self.path, key, v)
        # set parent of StoredObject
        if isinstance(v, StoredObject):
            v.set_db(self.db, self.path + [key])
        # convert lists
        if isinstance(v, list):
            v = StoredList(v, self.db, self.path + [key])
        # set item
        dict.__setitem__(self, key, v)
        if self.db and patch:
            op = 'add' if is_new else 'replace'
            self.db.add_patch({'op': op, 'path': key_path(self.path, key), 'value': v})

    @locked
    def __delitem__(self, key):
        dict.__delitem__(self, key)
        if self.db:
            self.db.add_patch({'op': 'remove', 'path': key_path(self.path, key)})

    @locked
    def pop(self, key, v=_RaiseKeyError):
        if key not in self:
            if v is _RaiseKeyError:
                raise KeyError(key)
            else:
                return v
        r = dict.pop(self, key)
        if self.db:
            self.db.add_patch({'op': 'remove', 'path': key_path(self.path, key)})
        return r


class StoredList(list):

    def __init__(self, data, db, path):
        list.__init__(self, data)
        self.db = db
        self.lock = self.db.lock if self.db else threading.RLock()
        self.path = path

    @locked
    def append(self, item):
        n = len(self)
        list.append(self, item)
        if self.db:
            self.db.add_patch({'op': 'add', 'path': key_path(self.path, '%d'%n), 'value':item})

    @locked
    def remove(self, item):
        n = self.index(item)
        list.remove(self, item)
        if self.db:
            self.db.add_patch({'op': 'remove', 'path': key_path(self.path, '%d'%n)})



class JsonDB(Logger):

    def __init__(self, s: str, storage=None, encoder=None, upgrader=None):
        Logger.__init__(self)
        self.lock = threading.RLock()
        self.storage = storage
        self.encoder = encoder
        self.pending_changes = []
        self._modified = False
        # load data
        data = self.load_data(s)
        if upgrader:
            data, was_upgraded = upgrader(data)
            self._modified |= was_upgraded
        # convert to StoredDict
        self.data = StoredDict(data, self, [])
        # write file in case there was a db upgrade
        if self.storage and self.storage.file_exists():
            self.write_and_force_consolidation()

    def load_data(self, s:str) -> dict:
        """ overloaded in wallet_db """
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
        self.pending_changes.append(json.dumps(patch, cls=self.encoder))
        self.set_modified(True)

    @locked
    def get(self, key, default=None):
        v = self.data.get(key)
        if v is None:
            v = default
        return v

    @modifier
    def put(self, key, value):
        try:
            json.dumps(key, cls=self.encoder)
            json.dumps(value, cls=self.encoder)
        except Exception:
            self.logger.info(f"json error: cannot save {repr(key)} ({repr(value)})")
            return False
        if value is not None:
            if self.data.get(key) != value:
                self.data[key] = copy.deepcopy(value)
                return True
        elif key in self.data:
            self.data.pop(key)
            return True
        return False

    @locked
    def get_dict(self, name) -> dict:
        # Warning: interacts un-intuitively with 'put': certain parts
        # of 'data' will have pointers saved as separate variables.
        if name not in self.data:
            self.data[name] = {}
        return self.data[name]

    @locked
    def get_stored_item(self, key, default) -> dict:
        if key not in self.data:
            self.data[key] = default
        return self.data[key]

    @locked
    def dump(self, *, human_readable: bool = True) -> str:
        """Serializes the DB as a string.
        'human_readable': makes the json indented and sorted, but this is ~2x slower
        """
        return json.dumps(
            self.data,
            indent=4 if human_readable else None,
            sort_keys=bool(human_readable),
            cls=self.encoder,
        )

    def _should_convert_to_stored_dict(self, key) -> bool:
        return True

    def _convert_dict(self, path, key, v):
        if key in registered_dicts:
            constructor, _type = registered_dicts[key]
            if _type == dict:
                v = dict((k, constructor(**x)) for k, x in v.items())
            elif _type == tuple:
                v = dict((k, constructor(*x)) for k, x in v.items())
            else:
                v = dict((k, constructor(x)) for k, x in v.items())
        if key in registered_dict_keys:
            convert_key = registered_dict_keys[key]
        elif path and path[-1] in registered_parent_keys:
            convert_key = registered_parent_keys.get(path[-1])
        else:
            convert_key = None
        if convert_key:
            v = dict((convert_key(k), x) for k, x in v.items())
        return v

    def _convert_value(self, path, key, v):
        if key in registered_names:
            constructor, _type = registered_names[key]
            if _type == dict:
                v = constructor(**v)
            else:
                v = constructor(v)
        return v

    @locked
    def write(self):
        if (not self.storage.file_exists()
                or self.storage.is_encrypted()
                or self.storage.needs_consolidation()):
            self.write_and_force_consolidation()
        else:
            self._append_pending_changes()

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
