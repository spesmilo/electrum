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
        else:
            v = copy.deepcopy(v)
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
