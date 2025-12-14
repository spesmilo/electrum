import threading
from typing import Any, Optional, Tuple, Union, Iterator, Iterable, List, Sequence
from .logging import Logger

from .lrucache import LRUCache

FLEX_KEY = str | int | None
_RaiseKeyError = object() # singleton for no-default behavior


def key_to_str(x: FLEX_KEY) -> str:
    if isinstance(x, int):
        return str(int(x))
    elif isinstance(x, str):
        return x
    else:
        raise Exception(f"key {x=}")

registered_names = {}
registered_keys = {}

def _parse_path(path):
    path2 = path.split('/')
    name, suffix = path2[0], path2[1:]
    n = len(suffix)
    assert suffix == n * ['*']
    return name, n

def register_name(path, _type, func):
    name, n = _parse_path(path)
    registered_names[name] = n, _type, func

def register_key(path, func):
    name, n = _parse_path(path)
    registered_keys[name] = n + 1, func


def stored_at(path, _type=dict):
    """ decorator that indicates the storage key of a stored object"""
    def decorator(func):
        register_name(path, _type, func)
        return func
    return decorator


def _convert_dict_key(path: List[str], key:str) -> FLEX_KEY:
    """Maybe convert key from str to python type (typically int or IntEnum)"""
    #assert all(isinstance(x, str) for x in path), repr(path)
    n = len(path)
    for i, name in enumerate(path):
        if name in registered_keys:
            level, func = registered_keys[name]
            if level == n - i:
                key = func(key)
                break
    assert isinstance(key, FLEX_KEY), f"unexpected type for {key=!r} at {path=}"
    return key


def _convert_dict_value(path: List[str], v) -> Any:
    #assert all(isinstance(x, str) for x in path), repr(path)
    n = len(path)
    for i, key in enumerate(path):
        if key in registered_names:
            level, _type, constructor = registered_names[key]
            if level == n - i - 1:
                if _type == dict:
                    v = constructor(**v)
                elif _type == tuple:
                    v = constructor(*v)
                else:
                    v = constructor(v)
                break
    return v


def json_default(obj):
    if isinstance(obj, (set, frozenset)):
        return list(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    if hasattr(obj, 'as_str') and callable(obj.as_str):
        return obj.as_str()
    if hasattr(obj, 'as_dict') and callable(obj.as_dict):
        return obj.as_dict()
    if hasattr(obj, 'as_tuple') and callable(obj.as_tuple):
        return obj.as_tuple()
    return obj


class BaseDB(Logger):

    def __init__(self):
        Logger.__init__(self)

    def get_stored_dict(self):
        return StoredDict(self, key='', parent=None)


class BaseStoredObject:

    _db: BaseDB = None
    _key: FLEX_KEY = None
    _parent: Optional['BaseStoredObject'] = None
    _lock: threading.RLock = None
    #_path = None

    def set_db(self, db):
        self._db = db
        self._lock = self._db.lock if self._db else threading.RLock()

    def set_parent(self, *, key: FLEX_KEY, parent: Optional['BaseStoredObject']) -> None:
        assert (key == "") == (parent is None), f"{key=!r}, {parent=!r}"
        assert isinstance(key, FLEX_KEY), repr(key)
        self._key = key
        self._parent = parent

    @property
    def lock(self):
        return self._lock

    @property
    def path(self) -> Sequence[FLEX_KEY] | None:
        #if self._path is not None:
        #    return self._path
        # return None iff we are pruned from root
        x = self
        s = [x._key]
        while x._parent is not None:
            x = x._parent
            s = [x._key] + s
        if x._key != '':
            #s = []
            return None
        else:
            assert self._db is not None
        return s
        #self._path = s
        #return self._path


class StoredObject(BaseStoredObject):
    """for attr.s objects """

    def __setattr__(self, key: str, value):
        assert isinstance(key, str), repr(key)
        if not key.startswith('_') and self.path:
            if value != getattr(self, key):
                self._db.replace(self.path, key, value)
        object.__setattr__(self, key, value)

    def as_dict(self):
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

    def __init__(self, db: BaseDB, key: FLEX_KEY, parent):
        BaseStoredObject.__init__(self)
        self._db = db
        self._lock = db.lock
        self._parent = parent
        self._key = key_to_str(key)
        self._should_convert = True
        self._cache = LRUCache(maxsize=100)

    def should_convert(self):
        return self._parent._should_convert if self._parent is not None else self._should_convert

    def get_dict(self, key) -> 'StoredDict':
        # side effect: creates db entry if it does not exist
        key = key_to_str(key)
        if not self._db.contains(self.path, key):
            self._db.put(self.path, key, {})
        return StoredDict(self._db, key=key, parent=self)

    def __getitem__(self, key: FLEX_KEY) -> Any:
        key = key_to_str(key)
        if cached := self._cache.get(key):
            return cached
        value = self._db.get(self.path, key)
        if not self.should_convert():
            if isinstance(value, dict):
                return StoredDict(self._db, key=key, parent=self)
            return value
        value = _convert_dict_value(self.path + [key], value)
        # set db for StoredObject, because it is not set in the constructor
        if isinstance(value, StoredObject):
            value.set_db(self._db)
            value.set_parent(key=key, parent=self)
        elif isinstance(value, list):
            value = StoredList(self._db, key=key, parent=self)
        elif isinstance(value, dict):
            value = StoredDict(self._db, key=key, parent=self)
        self._cache[key] = value
        return value

    def __setitem__(self, key: FLEX_KEY, value: Any) -> None:
        key = key_to_str(key)
        if isinstance(value, StoredList):
            # fixme: this only happens during db upgrade?
            value = value[:]
            assert isinstance(value, list)
        if isinstance(value, StoredDict):
            raise Exception('trying to set StoredDict')
        self._db.put(self.path, key, value)
        if key in self._cache:
            del self._cache[key]

    def __delitem__(self, key: FLEX_KEY) -> None:
        key = key_to_str(key)
        self._db.remove(self.path, key)
        if key in self._cache:
            del self._cache[key]

    def __iter__(self) -> Iterator[str]:
        return self._db.iter_keys(self.path)

    def __len__(self) -> int:
        return self._db.dict_len(self.path)

    # ---- Dict-like extras ----

    def __contains__(self, key: object) -> bool:
        key = key_to_str(key)
        assert isinstance(key, str)
        return self._db.contains(self.path, key)

    def keys(self) -> Iterable[str]:
        for k in self._db.iter_keys(self.path):
            yield _convert_dict_key(self.path, k)

    def values(self) -> Iterator[Any]:
        for k in self.keys():
            yield self[k]

    def items(self) -> Iterator[Tuple[str, Any]]:
        for k in self.keys():
            yield (k, self[k])

    def get(self, key: FLEX_KEY, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def clear(self) -> None:
        self._db.clear(self.path)
        self._cache.clear()

    def pop(self, key: FLEX_KEY, default: Any = _RaiseKeyError) -> Any:
        try:
            v = self[key]
        except KeyError:
            if default is _RaiseKeyError:
                raise
            return default
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
        def f(v):
            if isinstance(v, StoredDict):
                return v.as_dict()
            elif isinstance(v, StoredList):
                return v[::]
            else:
                return v
        return dict([(k, f(v)) for k, v in self.items()])

    def setdefault(self, key: FLEX_KEY, default = None, /):
        assert isinstance(key, FLEX_KEY), repr(key)
        if key not in self:
            self.__setitem__(key, default)
        return self[key]


class StoredList(BaseStoredObject):

    def __init__(self, db: BaseDB, key: FLEX_KEY, parent):
        self._db = db
        self._lock = db.lock
        self._parent = parent
        self._key = key_to_str(key)

    def __getitem__(self, s: slice) -> Any:
        return self._db.get_list_item(self.path, s)

    def __len__(self):
        return self._db.list_len(self.path)

    def __iter__(self) -> Iterator[str]:
        return self._db.list_iter(self.path)

    def append(self, item):
        self._db.list_append(self.path, item)

    def clear(self):
        self._db.list_clear(self.path)
        assert len(self) == 0

    def index(self, item) -> int:
        return self._db.list_index(self.path, item)

    def remove(self, item):
        self._db.list_remove(self.path, item)
