import threading
from typing import Any, Optional, Tuple, Union, Iterator, Iterable, List, Sequence
from .logging import Logger


Key = Union[str, int]
_FLEX_KEY = str | int | None
_RaiseKeyError = object() # singleton for no-default behavior


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


def key_to_str(x: Key) -> str:
    if isinstance(x, int):
        return str(int(x))
    elif isinstance(x, str):
        return x
    else:
        raise Exception(f"key {x=}")

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

def _is_stored_list(path, key):
    return key in ['imported_addresses', 'receiving', 'change', 'txids', 'qt-console-history'] or path[-1] in ['addr_history', 'active_forwardings']


def _convert_dict_key(path: List[str]) -> _FLEX_KEY:
    """Maybe convert key from str to python type (typically int or IntEnum)"""
    #assert all(isinstance(x, str) for x in path), repr(path)
    key = path[-1]
    parent_key = path[-2] if len(path) > 1 else None
    gp_key = path[-3] if len(path) > 2 else None
    if parent_key and parent_key in registered_dict_keys:
        convert_key = registered_dict_keys[parent_key]
    elif gp_key and gp_key in registered_parent_keys:
        convert_key = registered_parent_keys.get(gp_key)
    else:
        convert_key = None
    if convert_key:
        key = convert_key(key)
    assert isinstance(key, _FLEX_KEY), f"unexpected type for {key=!r} at {path=}"
    return key

def _convert_dict_value(path: List[str], v) -> Any:
    #assert all(isinstance(x, str) for x in path), repr(path)
    key = path[-1]
    parent_key = path[-2] if len(path) > 1 else None
    if parent_key in registered_dicts:
        constructor, _type = registered_dicts[parent_key]
        if _type == dict:
            v = constructor(**v)
        elif _type == tuple:
            v = constructor(*v)
        else:
            v = constructor(v)
    elif key in registered_names:
        constructor, _type = registered_names[key]
        if _type == dict:
            v = constructor(**v)
        else:
            v = constructor(v)
    # recursive call. fixme: is this required?
    if isinstance(v, dict):
        v = _convert_dict(path, v)
    return v

def _convert_dict(path: List[str], data: dict):
    # recursively convert json dict to StoredDict
    #assert all(isinstance(x, str) for x in path), repr(path)
    d = {}
    for k, v in list(data.items()):
        child_path = path + [k]
        k = _convert_dict_key(child_path)
        v = _convert_dict_value(child_path, v)
        d[k] = v
    return d


class BaseDB(Logger):

    def __init__(self):
        Logger.__init__(self)

    def get_stored_dict(self):
        return StoredDict(self, key='', parent=None)


class BaseStoredObject:

    _db: BaseDB = None
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


class StoredObject(BaseStoredObject):
    """for attr.s objects """

    def __setattr__(self, key: str, value):
        assert isinstance(key, str), repr(key)
        if self.path and not key.startswith('_'):
            if value != getattr(self, key):
                self._db.replace(self.path, key, value)
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

    def __init__(self, db: BaseDB, key: Key, parent):
        BaseStoredObject.__init__(self)
        self._db = db
        self._lock = db.lock
        self._parent = parent
        self._key = key_to_str(key)
        self._should_convert = True

    def should_convert(self):
        return self._parent._should_convert if self._parent is not None else self._should_convert

    def get_dict(self, key) -> 'StoredDict':
        # side effect: creates db entry if it does not exist
        key = key_to_str(key)
        if not self._db.contains(self.path, key):
            self._db.put(self.path, key, {})
        return StoredDict(self._db, key=key, parent=self)

    def __getitem__(self, key: Key) -> Any:
        key = key_to_str(key)
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
            if _is_stored_list(self.path, key):
                return StoredList(self._db, key=key, parent=self)
        elif isinstance(value, dict):
            return StoredDict(self._db, key=key, parent=self)
        return value

    def __setitem__(self, key: Key, value: Any) -> None:
        key = key_to_str(key)
        self._db.put(self.path, key, value, _is_stored_list(self.path, key))

    def __delitem__(self, key: Key) -> None:
        key = key_to_str(key)
        self._db.remove(self.path, key)

    def __iter__(self) -> Iterator[str]:
        return self._db.iter_keys(self.path)

    def __len__(self) -> int:
        return sum(1 for _ in self.keys())

    # ---- Dict-like extras ----

    def __contains__(self, key: object) -> bool:
        key = key_to_str(key)
        assert isinstance(key, str)
        return self._db.contains(self.path, key)

    def keys(self) -> Iterable[str]:
        for k in self._db.iter_keys(self.path):
            yield _convert_dict_key(self.path + [k])

    def values(self) -> Iterator[Any]:
        for k in self.keys():
            yield self[k]

    def items(self) -> Iterator[Tuple[str, Any]]:
        for k in self.keys():
            yield (k, self[k])

    def get(self, key: Key, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def clear(self) -> None:
        self._db.clear(self.path)

    def pop(self, key: Key, default: Any = _RaiseKeyError) -> Any:
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


class StoredList(BaseStoredObject):

    def __init__(self, db: BaseDB, key: Key, parent):
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
