from __future__ import annotations

import json
import threading
import os
from typing import Any, Optional, Tuple, Union, Iterator, Iterable
import plyvel
from contextlib import contextmanager

from .stored_dict import BaseDB, _FLEX_KEY

# Todo:
# - simplify path: first element is unused


def locked(func):
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return func(self, *args, **kwargs)
    return wrapper


class JsonCodec:
    """Default value codec: JSON (utf-8)."""
    @staticmethod
    def dumps(value: Any) -> bytes:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def loads(data: bytes) -> Any:
        if data == b'()':
            return ()
        return json.loads(data.decode("utf-8"))


def _to_bytes_key(k: _FLEX_KEY) -> bytes:
    if isinstance(k, int):
        k = str(int(k))
    return k.encode("utf-8")

def _to_str_key(k: bytes) -> str:
    return k.decode("utf-8")


# bump this if key/value encoding changes
STORAGE_VERSION = str(0).encode('utf-8')
VERSION_FILENAME = 'ELECTRUM_LEVELDB_VERSION'



class LevelDB(BaseDB):

    def __init__(
            self,
            path: str,
            init_db: bool = True,
    ):
        assert path # in-memory only is only allowed with JsonDB
        BaseDB.__init__(self, path)
        self.lock = threading.RLock()
        self.delimiter = "/"
        self.codec = JsonCodec
        if init_db:
            self.init_db()
            #self._debug()

    def is_encrypted(self):
        return False

    def file_exists(self):
        return os.path.exists(self.path)

    def supports_file_encryption(self):
        return False

    def is_encrypted_with_hw_device(self):
        return False

    def is_encrypted_with_user_pw(self):
        return False

    def init_db(self):
        # if path exists, check version file
        version_file = os.path.join(self.path, VERSION_FILENAME)
        if os.path.exists(self.path):
            if not os.path.exists(version_file):
                raise Exception('Not an Electrum DB')
            with open(version_file, "rb") as f:
                v = f.read()
                # no upgrades support for the moment
                if v != STORAGE_VERSION:
                    raise Exception('Unsupported DB version')
        # create DB
        # according to the docs, setting write_buffer_size
        # to zero forces levelDB to write directly to disk
        self.db = plyvel.DB(
            self.path,
            create_if_missing=True,
            write_buffer_size=0,
        )
        # create version file
        if not os.path.exists(version_file):
            with open(version_file, "wb") as f:
                f.write(STORAGE_VERSION)
        # set permissions
        self._set_permissions()

    def _set_permissions(self):
        os.chmod(self.path, 0o700)
        for path, dirs, files in os.walk(self.path):
            for x in files: os.chmod(os.path.join(path, x), 0o600)
            for x in dirs: os.chmod(os.path.join(path, x), 0o700)

    def _debug(self):
        for k, v in self.db.iterator():
            self.logger.info(f"{k} -> {v}")

    def close(self) -> None:
        if self.db is not None:
            self.logger.info('closing database')
            self.db.close()
            self.db = None

    def is_closed(self):
        return self.db is None

    def set_modified(self, b):
        # fixme: callers should not have to do that
        pass

    def __enter__(self) -> "LevelDB":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def write(self):
        pass

    def write_and_force_consolidation(self):
        # called after password update.
        # remove remnants encrypted with old passwordd
        self.db.compact_range()

    def _prefix_bytes(self, path) -> bytes:
        assert path[0] == ''
        d = self.delimiter.encode("utf-8")
        p = d.join([_to_bytes_key(x) for x in path])
        if not p:
            return b""
        # Ensure exactly one trailing delimiter for internal prefix usage
        if p.endswith(d):
            p = p[:-len(d)]
        return p

    def _full_key(self, path, key: _FLEX_KEY) -> bytes:
        return self._prefix_bytes(path + [key])

    def _child_prefix(self, path, key: _FLEX_KEY) -> bytes:
        d = self.delimiter.encode("utf-8")
        return self._full_key(path, key) + d

    def _has_children(self, path, key: _FLEX_KEY) -> bool:
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        pfx = self._child_prefix(path, key)
        it = db.iterator(prefix=pfx, include_value=False)
        try:
            next(it)
            return True
        except StopIteration:
            return False

    def iter_keys(self, hint, path) -> Iterator[str]:
        """
        Iterate unique top-level keys at this view's prefix.
        """
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        d = self.delimiter.encode("utf-8")
        pb = self._prefix_bytes(path) + d
        seen = set()
        for k, _v in db.iterator(prefix=pb):
            rel = k[len(pb):] if pb else k
            first = rel.split(d, 1)[0]
            if first not in seen:
                seen.add(first)
                yield _to_str_key(first)

    @locked
    def remove(self, hint, path, key):
        self._delete_subtree(path, key, wb=None)

    def _delete_subtree(self, path, key: _FLEX_KEY, wb: Optional[plyvel.WriteBatch] = None) -> None:
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        pfx = self._child_prefix(path, key)
        it = db.iterator(prefix=pfx, include_value=False)
        deleter = wb.delete if wb is not None else db.delete
        for k in it:
            deleter(k)
        # delete scalar at node itself, if present
        k = self._full_key(path, key)
        deleter(k)
        if wb is None:
            r = db.get(k)
            assert r is None, r

    @locked
    def clear(self, hint, path) -> None:
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        pb = self._prefix_bytes(path)
        with db.write_batch() as wb:
            for k, _v in db.iterator(prefix=pb):
                if k == pb:
                    # do not delete the dict itself
                    continue
                wb.delete(k)

    def get_hint(self, path):
        return path

    @locked
    def get(self, path, key: _FLEX_KEY) -> Any:
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        raw = db.get(self._full_key(path, key))
        if raw is None:
            raise KeyError((path, key, self._full_key(path, key)))
        r = self.codec.loads(raw)
        # internally we store tuples as non-empty lists
        if type(r) is list and len(r) > 0:
            r = tuple(r)
        return r

    @contextmanager
    def write_batch(self):
        assert self._write_batch is None
        self._write_batch = self.db.write_batch(transaction=True)
        with self._write_batch:
            try:
                yield
            finally:
                self._write_batch = None

    def _flatten_into_batch(self, base_key: bytes, value: Any, wb: plyvel.WriteBatch) -> None:
        d = self.delimiter.encode("utf-8")
        if isinstance(value, dict):
            wb.put(base_key, self.codec.dumps({}))
            for k, v in value.items():
                child_key = base_key + d + _to_bytes_key(k)
                self._flatten_into_batch(child_key, v, wb)
        elif isinstance(value, list):
            wb.put(base_key, self.codec.dumps([]))
            for k, v in enumerate(value):
                child_key = base_key + d + _to_bytes_key(k)
                self._flatten_into_batch(child_key, v, wb)
        elif isinstance(value, tuple):
            wb.put(base_key, b'()')
            for k, v in enumerate(value):
                child_key = base_key + d + _to_bytes_key(k)
                self._flatten_into_batch(child_key, v, wb)
        else:
            wb.put(base_key, self.codec.dumps(value))

    def _do_put(self, wb, path, key: _FLEX_KEY, value: Any):
        # delete any pre-existing dict
        self._delete_subtree(path, key, wb=wb)
        if isinstance(value, (list, dict, tuple)):
            base = self._full_key(path, key)
            # do not store marker at "key"; only descendants
            self._flatten_into_batch(base, value, wb)
        else:
            wb.put(self._full_key(path, key), self.codec.dumps(value))

    @locked
    def put(self, hint, path, key: _FLEX_KEY, value: Any) -> None:
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        if len(path) > 1 and db.get(self._prefix_bytes(path)) is None:
            raise KeyError("Dangling dict or list")
        if not self._write_batch:
            wb = self.db.write_batch()
            with wb:
                self._do_put(wb, path, key, value)
        else:
            self._do_put(self._write_batch, path, key, value)

    @locked
    def replace(self, hint, path, key: _FLEX_KEY, value: Any) -> None:
        # called by StoredObject in setattr
        self.put(hint, path, key, value)

    @locked
    def dict_contains(self, hint, path, key: object) -> bool:
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        if db.get(self._full_key(path, key)) is not None:
            return True
        return False #self._has_children(path, key)


    # list methods

    @locked
    def list_append(self, hint, path, item):
        n = self.list_len(hint, path)
        self.put(hint, path, str(n), item)

    @locked
    def list_clear(self, hint, path):
        path, key = path[:-1], path[-1]
        #self._delete_subtree(path, key, wb=None)
        self.put(hint, path, key, [])

    @locked
    def dict_len(self, hint, path):
        # fixme: slow
        return len(list(self.iter_keys(hint, path)))

    @locked
    def list_len(self, hint, path):
        return len(list(self.iter_keys(hint, path)))

    @locked
    def list_index(self, hint, path, item):
        for k in self.iter_keys(hint, path):
            v = self.get(path, k)
            if item == v:
                return int(k)
        raise KeyError(item)

    @locked
    def list_remove(self, hint, path, item):
        k = self.list_index(hint, path, item)
        n = self.list_len(hint, path)
        for i in range(k, n-1):
            self.put(hint, path, str(i), self.get(path, str(i+1)))
        self.remove(hint, path, str(n-1))
