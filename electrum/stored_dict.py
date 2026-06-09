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
import os
from enum import IntEnum
from collections import defaultdict
from typing import Any, Optional, Tuple, Union, Iterator, Iterable, List, Sequence
from .logging import Logger


_FLEX_KEY = str | int | None

_RaiseKeyError = object() # singleton for no-default behavior

class StorageReadWriteError(Exception): pass

class StorageEncryptionVersion(IntEnum):
    PLAINTEXT = 0
    USER_PASSWORD = 1
    XPUB_PASSWORD = 2


def normalize_key(x: _FLEX_KEY) -> str:
    if isinstance(x, int):
        return int(x)
    elif isinstance(x, str):
        return x
    else:
        raise Exception(f"key {x=}")

def key_to_str(x: _FLEX_KEY) -> str:
    if isinstance(x, int):
        return str(int(x))
    elif isinstance(x, str):
        return x
    else:
        raise Exception(f"key {x=}")


registered_names = {}
registered_keys = {}

def _register_key_or_name(d: dict, path_str: str, value):
    assert path_str.startswith('/')
    path = path_str[1:].split('/')
    path, key = path[0:-1], path[-1]
    for k in path:
        if k not in d:
            d[k] = {}
        d = d[k]
    d[key] = value

def register_name(path, _type, func):
    _register_key_or_name(registered_names, path, (_type, func))

def register_key(path, func):
    _register_key_or_name(registered_keys, path + '/' + 'self', func)



def stored_at(path, _type=dict):
    """ decorator that indicates the storage key of a stored object"""
    def decorator(func):
        register_name(path, _type, func)
        return func
    return decorator


def _walk_path(d, path):
    for k in path:
        if k in d:
            d = d[k]
        elif '*' in d:
            d = d['*']
        else:
            return None
    return d

def _convert_dict_key(path: List[str], key: str) -> _FLEX_KEY:
    """Maybe convert key from str to python type (typically int or IntEnum)"""
    assert all(isinstance(x, str) for x in path), repr(path)
    r = _walk_path(registered_keys, path)
    if r:
        if func := r.get('self'):
            key = func(key)
    assert isinstance(key, _FLEX_KEY), f"unexpected type for {key=!r} at {path=}"
    return key

def _convert_dict_value(path: List[str], v) -> Any:
    assert all(isinstance(x, str) for x in path), repr(path)
    r = _walk_path(registered_names, path)
    if r and type(r) is tuple:
        _type, constructor = r
        if _type == dict:
            v = constructor(**v)
        elif _type == tuple:
            v = constructor(*v)
        else:
            v = constructor(v)
    return v




class BaseDB(Logger):

    def __init__(self, path):
        Logger.__init__(self)
        self._write_batch = None
        self.path = path

    def file_exists(self):
        raise NotImplementedError()

    def get_path(self):
        return self.path

    def set_password(self, password:str):
        raise NotImplementedError()




class BaseStoredObject:

    _db: BaseDB = None
    _key: _FLEX_KEY = None
    _parent: Optional['BaseStoredObject'] = None
    _lock: threading.RLock = None
    _path = None
    _hint = None

    def set_db(self, db):
        self._db = db
        self._lock = self._db.lock if self._db else threading.RLock()

    def set_parent(self, *, key: _FLEX_KEY, parent: Optional['BaseStoredObject']) -> None:
        assert (key == "") == (parent is None), f"{key=!r}, {parent=!r}"
        assert isinstance(key, _FLEX_KEY), repr(key)
        self._key = key
        self._parent = parent
        self._path = self._parent._path + [key] if parent else ['']

    @property
    def lock(self):
        return self._lock

    @property
    def path(self) -> Sequence[_FLEX_KEY] | None:
        return self._path

    def _to_stored_dict_or_list(self, key, value):
        """convert list to StoredList, dict to StoredDict"""
        if isinstance(value, list):
            value = StoredList(self._db, key=key, parent=self)
        elif isinstance(value, dict):
            value = StoredDict(self._db, key=key, parent=self)
        #elif isinstance(value, tuple):
        #    value = StoredList(self._db, key=key, parent=self)
        #    value = tuple(value[:]) # do not expose StoredTuple to callers
        return value

    @property
    def hint(self):
        # cached object returned by the db (performance optimization)
        if self._hint is None:
            self._hint = self._db.get_hint(self._path)
        return self._hint

    def db_get(self, key):
        value = self._db.get(self.hint, key)
        value = self._to_stored_dict_or_list(key, value)
        # set db for StoredObject, because it is not set in the constructor
        if isinstance(value, StoredObject):
            value.set_db(self._db)
            value.set_parent(key=key, parent=self)
        return value

    def get_constructor(self, key):
        if self._constructor:
            r = self._constructor.get(key, self._constructor.get('*', None))
            if type(r) is tuple:
                return r

    def init_constructor(self):
        if self._parent is None:
            self._constructor = registered_names
        else:
            d = self._parent._constructor
            if d is None:
                return
            if self._key in d:
                d = d[self._key]
            elif '*' in d:
                d = d['*']
            else:
                d = None
            if d and type(d) is dict:
                self._constructor = d

    def init_key_converters(self):
        if self._parent is None:
            self._key_converters = registered_keys
        else:
            d = self._parent._key_converters
            if d is None:
                return
            if self._key in d:
                d = d[self._key]
            elif '*' in d:
                d = d['*']
            else:
                d = None
            if d and type(d) is dict:
                self._key_converters = d


class StoredObject(BaseStoredObject):
    """for attr.s objects """

    def __setattr__(self, key: str, value):
        assert isinstance(key, str), repr(key)
        if not key.startswith('_') and self._path:
            if value != getattr(self, key):
                self._db.replace(self.hint, self._path, key, value)
        object.__setattr__(self, key, value)

    def to_json(self):
        d = dict(vars(self))
        # don't expose/store private stuff
        d = {k: v for k, v in d.items()
             if not k.startswith('_')}
        return d


class StoredDict(BaseStoredObject):
    """
    dict-like object that queries the DB
    type conversions are performed here

    the DB object returns simple python objects: list or dict
    this class converts them
    """

    def __init__(self, db: BaseDB, key: _FLEX_KEY, parent):
        BaseStoredObject.__init__(self)
        self._db = db
        self._lock = db.lock
        self._parent = parent
        self._key = normalize_key(key)
        self._path = self._parent._path + [self._key] if parent else ['']
        self._constructor = None # func or Dict[str, func]
        self._key_converters = None
        self.init_constructor()
        self.init_key_converters()

    def dump(self) -> dict:
        data = {}
        for k, v in self.items():
            if isinstance(v, (StoredDict, StoredList)):
                v = v.dump()
            data[k] = v
        return data

    def __getitem__(self, key: _FLEX_KEY) -> Any:
        return self.db_get(key)

    def __setitem__(self, key: _FLEX_KEY, value: Any) -> None:
        if isinstance(value, StoredObject):
            # side effect
            value.set_db(self._db)
            value.set_parent(key=key, parent=self)
        if isinstance(value, (StoredList, StoredDict)):
            value = value.dump()
        self._db.put(self.hint, self._path, key, value)

    def __delitem__(self, key: _FLEX_KEY) -> None:
        self._db.remove(self.hint, self._path, key)

    def __iter__(self) -> Iterator[str]:
        return self._db.iter_keys(self.hint, self._path)

    def __len__(self) -> int:
        return self._db.dict_len(self.hint, self._path)

    # ---- Dict-like extras ----

    def __contains__(self, key: object) -> bool:
        return self._db.dict_contains(self.hint, self._path, key)

    def keys(self) -> Iterable[str]:
        for k in self._db.iter_keys(self.hint, self._path):
            yield k

    def values(self) -> Iterator[Any]:
        for k in self._db.iter_keys(self.hint, self._path):
            yield self[k]

    def items(self) -> Iterator[Tuple[str, Any]]:
        for k in self._db.iter_keys(self.hint, self._path):
            yield (k, self[k])

    def get(self, key: _FLEX_KEY, default: Any = None, add_if_missing=False) -> Any:
        # If add_if_missing is True, create DB entry if it does not exist.
        # This will return StoredDict/StoredList if default is dict/list
        try:
            return self[key]
        except KeyError:
            if add_if_missing:
                self[key] = default
                return self[key]
            return default

    def clear(self) -> None:
        self._db.clear(self.hint, self._path)

    def pop(self, key: _FLEX_KEY, default: Any = _RaiseKeyError) -> Any:
        # This will return dict/list
        try:
            v = self[key]
        except KeyError:
            if default is _RaiseKeyError:
                raise
            return default
        if isinstance(v, (StoredList, StoredDict)):
            v = v.dump()
        del self[key]
        return v

    def update(self, other=(), /, **kwargs) -> None:
        if isinstance(other, dict):
            pairs = list(other.items())
        else:
            pairs = list(other)
        pairs.extend(kwargs.items())
        for k, v in pairs:
            self[k] = v

    def as_dict(self) -> dict:
        """used by keystore"""
        return self.dump()

    def setdefault(self, key: _FLEX_KEY, default = None, /):
        assert isinstance(key, _FLEX_KEY), repr(key)
        if key not in self:
            self.__setitem__(key, default)
        return self[key]


class StoredList(BaseStoredObject):

    def __init__(self, db: BaseDB, key: _FLEX_KEY, parent):
        self._db = db
        self._lock = db.lock
        self._parent = parent
        self._key = normalize_key(key)
        self._path = self._parent._path + [self._key]
        self._constructor = None
        self._key_converters = None
        self.init_constructor()
        self.init_key_converters()

    def _get_list_item(self, key: int):
        key = int(key)
        return self.db_get(key)

    def __getitem__(self, s: slice) -> Any:
        n = self._db.list_len(self.hint, self._path)
        if type(s) is int:
            s = n + s if s < 0 else s
            return self._get_list_item(s)
        elif type(s) is slice:
            start = 0 if s.start is None else s.start if s.start >= 0 else n + s.start
            stop = n if s.stop is None else s.stop if s.stop >= 0 else n + s.stop
            step = 1 if s.step is None else s.step
            return [self._get_list_item(i) for i in range(start, stop, step)]
        else:
            raise Exception()

    def __len__(self):
        return self._db.list_len(self.hint, self._path)

    def __iter__(self) -> Iterator[str]:
        for i in range(self._db.list_len(self.hint, self._path)):
            yield self._get_list_item(i)

    def append(self, value):
        self._db.list_append(self.hint, self._path, value)

    def clear(self):
        self._db.list_clear(self.hint, self._path)
        assert len(self) == 0

    def index(self, item) -> int:
        return self._db.list_index(self.hint, self._path, item)

    def remove(self, item):
        self._db.list_remove(self.hint, self._path, item)

    def dump(self) -> list:
        data = []
        for v in self:
            if isinstance(v, (dict, list)):
                raise Exception()
            if isinstance(v, (StoredDict, StoredList)):
                v = v.dump()
            data.append(v)
        return data



class DictStorage(StoredDict):
    """ stored dict at the root of the file """

    def __init__(self, path: str, init_db: bool = True, allow_partial_writes: bool = True):
        from .json_db import JsonDB
        db = JsonDB(path=path, init_db=init_db, allow_partial_writes=allow_partial_writes)
        StoredDict.__init__(self, db, key='', parent=None)

    def file_exists(self):
        return self._db.file_exists()

    def is_encrypted(self):
        return self._db.is_encrypted()

    def decrypt(self, pw:str):
        return self._db.decrypt(pw)

    def get_path(self):
        return self._db.get_path()

    def set_password(self, password:str, enc_version=None):
        return self._db.set_password(password, enc_version)

    def set_data(self, data:str):
        return self._db.set_data(data)

    def set_modified(self, b: bool):
        return self._db.set_modified(b)

    def write_and_force_consolidation(self):
        self._db.write_and_force_consolidation()

    def get_encryption_version(self) -> StorageEncryptionVersion:
        return self._db.get_encryption_version()

    def check_password(self, password):
        self._db.check_password(password)

    def supports_file_encryption(self):
        return self._db.supports_file_encryption()

    def is_encrypted_with_hw_device(self):
        return self._db.is_encrypted_with_hw_device()

    def is_encrypted_with_user_pw(self):
        return self._db.is_encrypted_with_user_pw()

    def write(self):
        return self._db.write()

    def close(self):
        return self._db.close()

    def is_closed(self):
        return self._db.is_closed()

    def basename(self) -> str:
        path = self.get_path()
        return os.path.basename(path) if path else 'no name'
