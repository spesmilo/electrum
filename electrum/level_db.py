from __future__ import annotations

import json
import threading
from typing import Any, Optional, Tuple, Union, Iterator, Iterable
import plyvel

from .stored_dict import BaseDB, FLEX_KEY, key_to_str, json_default

# Todo:
# - simplify path: first element is unused
# - maybe stored_dict should 'have' a storage? -> wallet does not need to see it
# json_db slowness
# fix race (lock)


class JsonCodec:
    """Default value codec: JSON (utf-8)."""
    @staticmethod
    def dumps(value: Any) -> bytes:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=json_default).encode("utf-8")

    @staticmethod
    def loads(data: bytes) -> Any:
        return json.loads(data.decode("utf-8"))


def _to_bytes_key(k: str) -> bytes:
    return k.encode("utf-8")

def _to_str_key(k: bytes) -> str:
    return k.decode("utf-8")


# bump this if key/value encoding changes
STORAGE_VERSION = str(0).encode('utf-8')


class LevelDB(BaseDB):

    def __init__(
        self,
        path: str,
    ):
        BaseDB.__init__(self)
        self.lock = threading.RLock()
        self.delimiter = "/"
        self.codec = JsonCodec
        # according to the docs, setting write_buffer_size
        # to zero forces levelDB to write directly to disk
        self.db = plyvel.DB(
            path,
            create_if_missing=True,
            write_buffer_size=0,
        )
        # STORAGE_VERSION is not part of the dict because it does not start with the delimiter
        v = self.db.get(b'STORAGE_VERSION')
        if v is None:
            self.db.put(b'STORAGE_VERSION', STORAGE_VERSION)
        else:
            assert v == STORAGE_VERSION
        # print for debugging
        #self._debug()

    def _debug(self):
        for k, v in self.db.iterator():
            self.logger.info(f"{k} -> {v}")

    def close(self) -> None:
        if self.db is not None:
            self.logger.info('closing database')
            self.db.close()
            self.db = None

    def set_modified(self, b):
        # fixme: callers should not have to do that
        pass

    def __enter__(self) -> "LevelDB":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def write(self):
        pass

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

    def _full_key(self, path, key: FLEX_KEY) -> bytes:
        return self._prefix_bytes(path + [key])

    def _child_prefix(self, path, key: FLEX_KEY) -> bytes:
        d = self.delimiter.encode("utf-8")
        return self._full_key(path, key) + d

    def _has_children(self, path, key: FLEX_KEY) -> bool:
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

    def iter_keys(self, path) -> Iterator[str]:
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

    def remove(self, path, key):
        self._delete_subtree(path, key, wb=None)

    def _delete_subtree(self, path, key: FLEX_KEY, wb: Optional[plyvel.WriteBatch] = None) -> None:
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

    def clear(self, path) -> None:
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        pb = self._prefix_bytes(path)
        with db.write_batch() as wb:
            for k, _v in db.iterator(prefix=pb):
                wb.delete(k)

    def get(self, path, key: FLEX_KEY) -> Any:
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        raw = db.get(self._full_key(path, key))
        if raw is None:
            raise KeyError((path, key, self._full_key(path, key)))
        return self.codec.loads(raw) # json to python

    def _flatten_into_batch(self, base_key: bytes, value: Any, wb: plyvel.WriteBatch) -> None:
        d = self.delimiter.encode("utf-8")
        if isinstance(value, dict):
            wb.put(base_key, self.codec.dumps({}))
            for k, v in value.items():
                k = key_to_str(k)
                child_key = base_key + d + _to_bytes_key(k)
                self._flatten_into_batch(child_key, v, wb)
        elif isinstance(value, list):
            wb.put(base_key, self.codec.dumps([]))
            for k, v in enumerate(value):
                k = key_to_str(k)
                child_key = base_key + d + _to_bytes_key(k)
                self._flatten_into_batch(child_key, v, wb)
        else:
            wb.put(base_key, self.codec.dumps(value))

    def put(self, path, key: FLEX_KEY, value: Any) -> None:
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        with db.write_batch() as wb:
            # delete any pre-existing dict
            self._delete_subtree(path, key, wb=wb)
            if isinstance(value, (list, dict)):
                base = self._full_key(path, key)
                # do not store marker at "key"; only descendants
                self._flatten_into_batch(base, value, wb)
            else:
                wb.put(self._full_key(path, key), self.codec.dumps(value))

    def replace(self, path, key: FLEX_KEY, value: Any) -> None:
        # called by StoredObject in setattr
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        fullkey = self._full_key(path[:-1], path[-1])
        d = self.codec.loads(db.get(fullkey))
        d[key] = value
        db.put(fullkey, self.codec.dumps(d))

    def contains(self, path, key: object) -> bool:
        db = self.db
        if db is None:
            raise RuntimeError("DB is closed")
        if db.get(self._full_key(path, key)) is not None:
            return True
        return self._has_children(path, key)


    # list methods

    def get_list_item(self, path, s: slice):
        n = self.list_len(path)
        if type(s) is slice:
            start = 0 if s.start is None else s.start if s.start >= 0 else n + s.start
            stop = n-1 if s.stop is None else s.stop if s.stop >= 0 else n + s.stop
            step = 1 if s.step is None else s.step
            return [self.get(path, str(i)) for i in range(start, stop, step)]
        elif type(s) is int:
            s = n + s if s < 0 else s
            return self.get(path, str(s))
        else:
            raise Exception()

    def list_append(self, path, item):
        n = self.list_len(path)
        self.put(path, str(n), item)

    def list_clear(self, path):
        path, key = path[:-1], path[-1]
        #self._delete_subtree(path, key, wb=None)
        self.put(path, key, [])

    def dict_len(self, path):
        # fixme: slow
        return len(list(self.iter_keys(path)))

    def list_len(self, path):
        return len(list(self.iter_keys(path)))

    def list_iter(self, path):
        for i in range(self.list_len(path)):
            yield self.get(path, str(i))

    def list_index(self, path, item):
        for k in self.iter_keys(path):
            v = self.get(path, k)
            if item == v:
                return int(k)
        raise KeyError(item)

    def list_remove(self, path, item):
        k = self.list_index(path, item)
        n = self.list_len(path)
        for i in range(k, n-1):
            self.put(path, str(i), self.get(path, str(i+1)))
        self.remove(path, str(n-1))
