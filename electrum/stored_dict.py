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
import json
from collections import defaultdict
from typing import TYPE_CHECKING, Optional, Sequence, List, Union, Any


if TYPE_CHECKING:
    from .json_db import JsonDB
    from .storage import WalletStorage




def locked(func):
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return func(self, *args, **kwargs)
    return wrapper


registered_names = defaultdict(dict)
registered_keys = defaultdict(dict)

def _parse_path(path):
    path2 = path.split('/')
    name, suffix = path2[0], path2[1:]
    n = len(suffix)
    assert suffix == n * ['*']
    return name, n

def register_name(path, _type, func):
    name, n = _parse_path(path)
    registered_names[name][n] = _type, func

def register_key(path, func):
    name, n = _parse_path(path)
    registered_keys[name][n + 1] = func


def stored_at(path, _type=dict):
    """ decorator that indicates the storage key of a stored object"""
    def decorator(func):
        register_name(path, _type, func)
        return func
    return decorator

_FLEX_KEY = str | int | None


def _convert_dict_key(path: List[str], key: str) -> _FLEX_KEY:
    """Maybe convert key from str to python type (typically int or IntEnum)"""
    assert all(isinstance(x, str) for x in path), repr(path)
    n = len(path)
    for i, name in enumerate(path):
        if name in registered_keys:
            func = registered_keys[name].get(n - i)
            if func:
                key = func(key)
                break
    assert isinstance(key, _FLEX_KEY), f"unexpected type for {key=!r} at {path=}"
    return key

def _convert_dict_value(path: List[str], v) -> Any:
    assert all(isinstance(x, str) for x in path), repr(path)
    n = len(path)
    for i, key in enumerate(path):
        if key in registered_names:
            reg = registered_names[key].get(n - i - 1)
            if reg:
                _type, constructor = reg
                if _type == dict:
                    v = constructor(**v)
                elif _type == tuple:
                    v = constructor(*v)
                else:
                    v = constructor(v)
                break
    return v



class BaseStoredObject:

    _db: 'JsonDB' = None
    _key: _FLEX_KEY = None
    _parent: Optional['BaseStoredObject'] = None
    _lock: threading.RLock = None

    def set_db(self, db):
        self._db = db
        self._lock = self._db.lock if self._db else threading.RLock()

    def set_parent(self, *, key: _FLEX_KEY, parent: Optional['BaseStoredObject']) -> None:
        assert (key == "") == (parent is None), f"{key=!r}, {parent=!r}"
        assert isinstance(key, _FLEX_KEY), repr(key)
        self._key = key
        self._parent = parent

    @property
    def lock(self):
        return self._lock

    @property
    def path(self) -> Sequence[_FLEX_KEY] | None:
        # return None iff we are pruned from root
        x = self
        s = [x._key]
        while x._parent is not None:
            x = x._parent
            s = [x._key] + s
        if x._key != '':
            return None
        assert self._db is not None
        return s

    def db_add(self, key: _FLEX_KEY, value) -> None:
        assert isinstance(key, _FLEX_KEY), repr(key)
        if self.path:
            self._db.add(self.path, key, value)

    def db_replace(self, key: _FLEX_KEY, value) -> None:
        assert isinstance(key, _FLEX_KEY), repr(key)
        if self.path:
            self._db.replace(self.path, key, value)

    def db_remove(self, key: _FLEX_KEY) -> None:
        assert isinstance(key, _FLEX_KEY), repr(key)
        if self.path:
            self._db.remove(self.path, key)


class StoredObject(BaseStoredObject):
    """for attr.s objects """

    def __setattr__(self, key: str, value):
        assert isinstance(key, str), repr(key)
        if self.path and not key.startswith('_'):
            if value != getattr(self, key):
                self.db_replace(key, value)
        object.__setattr__(self, key, value)

    def to_json(self):
        d = dict(vars(self))
        # don't expose/store private stuff
        d = {k: v for k, v in d.items()
             if not k.startswith('_')}
        return d



_RaiseKeyError = object() # singleton for no-default behavior


class StoredDict(dict, BaseStoredObject):

    def __init__(self, data: dict, db: 'JsonDB'):
        self.set_db(db)
        # recursively convert dicts to StoredDict
        for k, v in list(data.items()):
            self.__setitem__(k, v)

    @locked
    def __setitem__(self, key: _FLEX_KEY, v) -> None:
        assert isinstance(key, _FLEX_KEY), repr(key)
        is_new = key not in self
        # early return to prevent unnecessary disk writes
        if not is_new and self._db and json.dumps(v, cls=self._db.encoder) == json.dumps(self[key], cls=self._db.encoder):
            return
        # convert dict to StoredDict.
        if type(v) == dict and (self._db is None or self._db._should_convert_to_stored_dict(key)):
            v = StoredDict(v, self._db)
        # convert list to StoredList
        elif type(v) == list:
            v = StoredList(v, self._db)
        # reject sets. they do not work well with jsonpatch
        elif isinstance(v, set):
            raise Exception(f"Do not store sets inside jsondb. path={self.path!r}")
        # set db for StoredObject, because it is not set in the constructor
        if isinstance(v, StoredObject):
            v.set_db(self._db)
        # set parent
        if isinstance(v, BaseStoredObject):
            v.set_parent(key=key, parent=self)
        # set item
        dict.__setitem__(self, key, v)
        self.db_add(key, v) if is_new else self.db_replace(key, v)

    @locked
    def __delitem__(self, key: _FLEX_KEY) -> None:
        assert isinstance(key, _FLEX_KEY), repr(key)
        r  = self.get(key, None)
        dict.__delitem__(self, key)
        self.db_remove(key)
        if isinstance(r, BaseStoredObject):
            r._parent = None

    @locked
    def pop(self, key: _FLEX_KEY, v=_RaiseKeyError) -> Any:
        assert isinstance(key, _FLEX_KEY), repr(key)
        if key not in self:
            if v is _RaiseKeyError:
                raise KeyError(key)
            else:
                return v
        r = dict.pop(self, key)
        self.db_remove(key)
        if isinstance(r, BaseStoredObject):
            r._parent = None
        return r

    def setdefault(self, key: _FLEX_KEY, default = None, /):
        assert isinstance(key, _FLEX_KEY), repr(key)
        if key not in self:
            self.__setitem__(key, default)
        return self[key]


class StoredList(list, BaseStoredObject):

    def __init__(self, data, db: 'JsonDB'):
        list.__init__(self, data)
        self.set_db(db)

    @locked
    def append(self, item):
        n = len(self)
        list.append(self, item)
        self.db_add('%d'%n, item)

    @locked
    def remove(self, item):
        n = self.index(item)
        list.remove(self, item)
        self.db_remove('%d'%n)

    @locked
    def clear(self):
        list.clear(self)
        self.db_replace(None, [])



