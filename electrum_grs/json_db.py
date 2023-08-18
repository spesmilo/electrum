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

from . import util
from .util import WalletFileException, profiler
from .logging import Logger

if TYPE_CHECKING:
    from .storage import WalletStorage

JsonDBJsonEncoder = util.MyEncoder

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



class StoredObject:

    db = None

    def __setattr__(self, key, value):
        if self.db:
            self.db.set_modified(True)
        object.__setattr__(self, key, value)

    def set_db(self, db):
        self.db = db

    def to_json(self):
        d = dict(vars(self))
        d.pop('db', None)
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
            self.__setitem__(k, v)

    @locked
    def __setitem__(self, key, v):
        is_new = key not in self
        # early return to prevent unnecessary disk writes
        if not is_new and self[key] == v:
            return
        # recursively set db and path
        if isinstance(v, StoredDict):
            v.db = self.db
            v.path = self.path + [key]
            for k, vv in v.items():
                v[k] = vv
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
            v.set_db(self.db)
        # set item
        dict.__setitem__(self, key, v)
        if self.db:
            self.db.set_modified(True)

    @locked
    def __delitem__(self, key):
        dict.__delitem__(self, key)
        if self.db:
            self.db.set_modified(True)

    @locked
    def pop(self, key, v=_RaiseKeyError):
        if v is _RaiseKeyError:
            r = dict.pop(self, key)
        else:
            r = dict.pop(self, key, v)
        if self.db:
            self.db.set_modified(True)
        return r




class JsonDB(Logger):

    def __init__(self, data, storage=None):
        Logger.__init__(self)
        self.lock = threading.RLock()
        self.storage = storage
        self._modified = False
        # load data
        if data:
            self.load_data(data)
        else:
            self.data = {}

    def load_data(self, s):
        try:
            self.data = json.loads(s)
        except Exception:
            raise WalletFileException("Cannot read wallet file. (parsing failed)")
        if not isinstance(self.data, dict):
            raise WalletFileException("Malformed wallet file (not dict)")

    def set_modified(self, b):
        with self.lock:
            self._modified = b

    def modified(self):
        return self._modified

    @locked
    def get(self, key, default=None):
        v = self.data.get(key)
        if v is None:
            v = default
        return v

    @modifier
    def put(self, key, value):
        try:
            json.dumps(key, cls=JsonDBJsonEncoder)
            json.dumps(value, cls=JsonDBJsonEncoder)
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
    def dump(self, *, human_readable: bool = True) -> str:
        """Serializes the DB as a string.
        'human_readable': makes the json indented and sorted, but this is ~2x slower
        """
        return json.dumps(
            self.data,
            indent=4 if human_readable else None,
            sort_keys=bool(human_readable),
            cls=JsonDBJsonEncoder,
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

    def write(self):
        with self.lock:
            self._write()

    @profiler
    def _write(self):
        if threading.current_thread().daemon:
            self.logger.warning('daemon thread cannot write db')
            return
        if not self.modified():
            return
        json_str = self.dump(human_readable=not self.storage.is_encrypted())
        self.storage.write(json_str)
        self.set_modified(False)
