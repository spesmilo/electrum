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
from abc import ABC, abstractmethod
from enum import IntEnum
from collections import defaultdict
from collections.abc import MutableMapping
from typing import Any, Optional, Tuple, Union, Iterator, Iterable, List, Sequence
from .logging import Logger


_FLEX_KEY = str | int | None

_RaiseKeyError = object() # singleton for no-default behavior

class StorageReadWriteError(Exception): pass

class StorageEncryptionVersion(IntEnum):
    PLAINTEXT = 0
    USER_PASSWORD = 1
    XPUB_PASSWORD = 2


def normalize_key(x: Any) -> _FLEX_KEY:
    if isinstance(x, int):
        return int(x)
    elif isinstance(x, str):
        return x
    else:
        raise Exception(f"key {x=}")

def locked(func):
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return func(self, *args, **kwargs)
    return wrapper


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


def to_default(obj):
    """Convert user-defined classes to python built-in types.
    Also convert bytes to hex.
    Built-in containers keep their type: it is up to the storage to serialize them
    (e.g. json has no tuples or sets, see json_db.to_json_data).
    StoredDict/StoredList objects are converted to dict/list, even when nested in the
    value (e.g. db upgrades build new values out of stored ones).
    """
    if obj is None or isinstance(obj, (str, int, float)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (StoredDict, StoredList)):
        obj = obj.dump()
    if hasattr(obj, 'as_str') and callable(obj.as_str):
        return obj.as_str()
    if hasattr(obj, 'as_dict') and callable(obj.as_dict):
        obj = obj.as_dict()
    if hasattr(obj, 'as_tuple') and callable(obj.as_tuple):
        obj = obj.as_tuple()
    if isinstance(obj, dict):
        return dict([(key_to_str(k), to_default(v)) for k, v in obj.items()])
    if isinstance(obj, list):
        return [to_default(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(to_default(x) for x in obj)
    if isinstance(obj, (set, frozenset)):
        return frozenset(to_default(x) for x in obj)
    raise Exception('unsupported type', type(obj))



class BaseDB(Logger, ABC):
    """Backend of a StoredDict tree.

    The wrappers (StoredDict, StoredList, StoredObject) hold no data. They address the
    backend with the path of a container (its keys from the root, whose own key is '')
    and, where relevant, a key in it. Values are built-in python objects (see to_default):
    scalars, or dict/list/tuple/set containers of them. How they are serialized is up to
    the backend (e.g. JsonDB stores tuples and sets as lists).

    Hints: get_hint(path) returns a handle for the container at path, which the wrappers
    pass back as the first argument of every access to that container, so that the
    backend does not have to walk the path each time. A hint is valid only while its
    container is in place: the backend increments _structure_version whenever a
    container is removed or replaced, and the wrappers then ask for a new hint
    (see BaseStoredObject.hint).

    Locking: the backend takes self.lock in every mutation. The wrappers take it too,
    around operations that read then write, and around dump().
    """

    def __init__(self, path: Optional[str]):
        Logger.__init__(self)
        self.path = path
        self.lock = threading.RLock()
        # whether reads convert values to their registered types (see stored_at).
        # Db upgrades turn it off, as they work on the raw containers.
        self._should_convert = True
        # incremented whenever a container is removed or replaced (see BaseStoredObject.hint)
        self._structure_version = 0

    def get_path(self) -> Optional[str]:
        return self.path

    # --- containers

    @abstractmethod
    def get_hint(self, path: Sequence[_FLEX_KEY]) -> Any:
        """Handle for the container at path (see the class docstring).
        The wrappers compare hints by identity: a container that replaces another one
        at the same path must get a different hint."""
        pass

    @abstractmethod
    def get(self, hint, path: Sequence[_FLEX_KEY], key: _FLEX_KEY) -> Any:
        """Value under key in the container at path.
        Raises KeyError (dict) or IndexError (list) if there is none."""
        pass

    # dicts

    @abstractmethod
    def iter_keys(self, hint, path: Sequence[_FLEX_KEY]) -> Iterator[str]:
        pass

    @abstractmethod
    def dict_len(self, hint, path: Sequence[_FLEX_KEY]) -> int:
        pass

    @abstractmethod
    def dict_contains(self, hint, path: Sequence[_FLEX_KEY], key: str) -> bool:
        pass

    @abstractmethod
    def put(self, hint, path: Sequence[_FLEX_KEY], key: str, value) -> None:
        """Store value under key, adding the key if needed.
        A container value replaces the previous one whole."""
        pass

    @abstractmethod
    def replace(self, hint, path: Sequence[_FLEX_KEY], key: str, value) -> None:
        """Like put, for a key that exists (used by StoredObject attribute writes)."""
        pass

    @abstractmethod
    def remove(self, hint, path: Sequence[_FLEX_KEY], key: str) -> None:
        """Delete key. Raises KeyError if there is none."""
        pass

    @abstractmethod
    def clear(self, hint, path: Sequence[_FLEX_KEY]) -> None:
        pass

    # lists

    @abstractmethod
    def list_len(self, hint, path: Sequence[_FLEX_KEY]) -> int:
        pass

    @abstractmethod
    def list_append(self, hint, path: Sequence[_FLEX_KEY], item) -> None:
        pass

    @abstractmethod
    def list_index(self, hint, path: Sequence[_FLEX_KEY], item) -> int:
        """Index of the first element equal to item. Raises ValueError if there is none."""
        pass

    @abstractmethod
    def list_remove(self, hint, path: Sequence[_FLEX_KEY], item) -> None:
        """Remove the first element equal to item. Raises ValueError if there is none."""
        pass

    @abstractmethod
    def list_clear(self, hint, path: Sequence[_FLEX_KEY]) -> None:
        pass

    # --- persistence

    @abstractmethod
    def write(self) -> None:
        """Persist the changes made so far."""
        pass

    @abstractmethod
    def write_and_force_consolidation(self) -> None:
        """Persist the whole content, so that it can be loaded without replaying changes."""
        pass

    @abstractmethod
    def set_modified(self, b: bool) -> None:
        pass

    @abstractmethod
    def set_data(self, json_str: str) -> None:
        """Replace the whole content with the given json text."""
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def is_closed(self) -> bool:
        pass

    # --- file and encryption

    @abstractmethod
    def file_exists(self) -> bool:
        pass

    @abstractmethod
    def supports_file_encryption(self) -> bool:
        pass

    @abstractmethod
    def is_encrypted(self) -> bool:
        pass

    @abstractmethod
    def is_encrypted_with_user_pw(self) -> bool:
        pass

    @abstractmethod
    def is_encrypted_with_hw_device(self) -> bool:
        pass

    @abstractmethod
    def get_encryption_version(self) -> StorageEncryptionVersion:
        pass

    @abstractmethod
    def set_password(self, password: Optional[str], enc_version: Optional[StorageEncryptionVersion] = None) -> None:
        pass

    @abstractmethod
    def check_password(self, password: Optional[str]) -> None:
        pass

    @abstractmethod
    def decrypt(self, password: str) -> None:
        pass


class BaseStoredObject:

    _db: BaseDB = None
    _key: _FLEX_KEY = None
    _parent: Optional['BaseStoredObject'] = None
    _lock: threading.RLock = None
    _path = None
    _hint = None  # (object, structure_version)

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
        return value

    @property
    def hint(self):
        # cached object returned by the db (performance optimization)
        # The cache is dropped if a subtree was removed or replaced since it was filled,
        # so that a reference to a removed subtree raises instead of writing into it.
        version = self._db._structure_version
        if self._hint is None or self._hint[1] != version:
            self._hint = (self._db.get_hint(self._path), version)
        return self._hint[0]

    def db_get(self, key):
        value = self._db.get(self.hint, self._path, key)
        value = self._to_stored_dict_or_list(key, value)
        if not self.should_convert():
            return value
        value = self._convert_value(key, value)
        # set db for StoredObject, because it is not set in the constructor
        if isinstance(value, StoredObject):
            value.set_db(self._db)
            value.set_parent(key=key, parent=self)
        return value

    def _convert_key(self, key: str) -> _FLEX_KEY:
        """Maybe convert key from str to python type (typically int or IntEnum)"""
        if self._key_converters:
            if func := self._key_converters.get('self'):
                key = func(key)
        assert isinstance(key, _FLEX_KEY), f"unexpected type for {key=!r} at {self._path}"
        return key

    def _convert_value(self, key, v) -> Any:
        reg = self.get_constructor(key)
        if reg:
            if isinstance(v, (StoredDict, StoredList)):
                v = v.dump()
            _type, constructor = reg
            if _type == dict:
                v = constructor(**v)
            elif _type == tuple:
                v = constructor(*v)
            else:
                v = constructor(v)
        return v

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
    """for dataclasses"""

    def __setattr__(self, key: str, value):
        assert isinstance(key, str), repr(key)
        if not key.startswith('_') and self._path:
            with self.lock:
                if value != getattr(self, key):
                    self._db.replace(self.hint, self._path, key, to_default(value))
                object.__setattr__(self, key, value)
                return
        object.__setattr__(self, key, value)

    def as_dict(self):
        d = dict(vars(self))
        # don't expose/store private stuff
        d = {k: v for k, v in d.items()
             if not k.startswith('_')}
        return d


class StoredDict(BaseStoredObject, MutableMapping):
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

    def should_convert(self):
        return self._db._should_convert

    @locked
    def dump(self) -> dict:
        data = {}
        for k, v in self.items():
            if isinstance(v, (StoredDict, StoredList)):
                v = v.dump()
            data[k] = v
        return data

    def __getitem__(self, key: _FLEX_KEY) -> Any:
        key = key_to_str(key)
        return self.db_get(key)

    @locked
    def __setitem__(self, key: _FLEX_KEY, value: Any) -> None:
        key = key_to_str(key)
        if isinstance(value, StoredObject):
            # side effect
            value.set_db(self._db)
            value.set_parent(key=key, parent=self)
        # convert to python
        value = to_default(value)
        self._db.put(self.hint, self._path, key, value)

    @locked
    def __delitem__(self, key: _FLEX_KEY) -> None:
        key = key_to_str(key)
        self._db.remove(self.hint, self._path, key)

    def __iter__(self) -> Iterator[_FLEX_KEY]:
        for k in self._db.iter_keys(self.hint, self._path):
            yield self._convert_key(k)

    def __len__(self) -> int:
        return self._db.dict_len(self.hint, self._path)

    # ---- Dict-like extras ----

    def __contains__(self, key: object) -> bool:
        key = key_to_str(key)
        return self._db.dict_contains(self.hint, self._path, key)

    @locked
    def get(self, key: _FLEX_KEY, default: Any = None, add_if_missing=False) -> Any:
        # If add_if_missing is True, create DB entry if it does not exist.
        # This will return StoredDict/StoredList if default is dict/list
        # note: we test membership instead of catching KeyError, so that an
        # error raised while converting the value is not mistaken for a missing key
        if key not in self:
            if not add_if_missing:
                return default
            self[key] = default
        return self[key]

    @locked
    def clear(self) -> None:
        self._db.clear(self.hint, self._path)

    @locked
    def pop(self, key: _FLEX_KEY, default: Any = _RaiseKeyError) -> Any:
        # This will return dict/list
        if key not in self:
            if default is _RaiseKeyError:
                raise KeyError(key)
            return default
        v = self[key]
        if isinstance(v, (StoredList, StoredDict)):
            v = v.dump()
        del self[key]
        return v

    def as_dict(self) -> dict:
        """used by db upgrades and by util.MyEncoder"""
        return self.dump()

    @locked
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

    def should_convert(self):
        return self._db._should_convert

    def _get_list_item(self, key: int):
        key = int(key)
        return self.db_get(key)

    def __getitem__(self, s: Union[int, slice]) -> Any:
        n = len(self)
        if isinstance(s, slice):
            return [self._get_list_item(i) for i in range(*s.indices(n))]
        if isinstance(s, int):
            if s < 0:
                s += n
            if not 0 <= s < n:
                raise IndexError('list index out of range')
            return self._get_list_item(s)
        raise TypeError(f'list indices must be integers or slices, not {type(s).__name__}')

    def __len__(self):
        return self._db.list_len(self.hint, self._path)

    def __iter__(self) -> Iterator[str]:
        for i in range(self._db.list_len(self.hint, self._path)):
            yield self._get_list_item(i)

    def __eq__(self, other):
        # compare by content, like a list (and StoredDict, via Mapping.__eq__).
        # tuples are accepted too, as they are stored as lists.
        if isinstance(other, (list, tuple, StoredList)):
            return list(self) == list(other)
        return NotImplemented

    @locked
    def append(self, value):
        value = to_default(value)
        self._db.list_append(self.hint, self._path, value)

    @locked
    def clear(self):
        self._db.list_clear(self.hint, self._path)
        assert len(self) == 0

    def index(self, item) -> int:
        item = to_default(item)
        return self._db.list_index(self.hint, self._path, item)

    @locked
    def remove(self, item):
        item = to_default(item)
        self._db.list_remove(self.hint, self._path, item)

    @locked
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

    def __init__(self, path: str, init_db: bool = True, allow_partial_writes: bool = False):
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
