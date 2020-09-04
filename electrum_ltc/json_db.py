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

from . import util
from .logging import Logger

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

    def convert_key(self, key):
        """Convert int keys to str keys, as only those are allowed in json."""
        # NOTE: this is evil. really hard to keep in mind and reason about. :(
        #       e.g.: imagine setting int keys everywhere, and then iterating over the dict:
        #             suddenly the keys are str...
        return str(int(key)) if isinstance(key, int) else key

    @locked
    def __setitem__(self, key, v):
        key = self.convert_key(key)
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
        if isinstance(v, dict) or isinstance(v, str):
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
        key = self.convert_key(key)
        dict.__delitem__(self, key)
        if self.db:
            self.db.set_modified(True)

    @locked
    def __getitem__(self, key):
        key = self.convert_key(key)
        return dict.__getitem__(self, key)

    @locked
    def __contains__(self, key):
        key = self.convert_key(key)
        return dict.__contains__(self, key)

    @locked
    def pop(self, key, v=_RaiseKeyError):
        key = self.convert_key(key)
        if v is _RaiseKeyError:
            r = dict.pop(self, key)
        else:
            r = dict.pop(self, key, v)
        if self.db:
            self.db.set_modified(True)
        return r

    @locked
    def get(self, key, default=None):
        key = self.convert_key(key)
        return dict.get(self, key, default)




class JsonDB(Logger):

    def __init__(self, data):
        Logger.__init__(self)
        self.lock = threading.RLock()
        self.data = data
        self._modified = False

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
        except:
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
    def dump(self):
        return json.dumps(self.data, indent=4, sort_keys=True, cls=JsonDBJsonEncoder)

    def _should_convert_to_stored_dict(self, key) -> bool:
        return True
