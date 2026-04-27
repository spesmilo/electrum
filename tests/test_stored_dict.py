import tempfile
import threading
from unittest import mock
import sys
import os
import json
import time
from io import StringIO
import asyncio
from pathlib import Path
import dataclasses

import jsonpatch

from electrum.stored_dict import DictStorage, StoredDict, StoredObject, stored_at



from . import ElectrumTestCase


@stored_at('/test_lock/*')
@dataclasses.dataclass
class _LockObj(StoredObject):
    x: int


class TestStorage(ElectrumTestCase):

    def setUp(self):
        super(TestStorage, self).setUp()
        self.path = os.path.join(self.electrum_path, "somewallet")

        self._saved_stdout = sys.stdout
        self._stdout_buffer = StringIO()
        sys.stdout = self._stdout_buffer

    def tearDown(self):
        super(TestStorage, self).tearDown()
        # Restore the "real" stdout
        sys.stdout = self._saved_stdout

    def test_db_roundtrip(self):
        sd = DictStorage(self.path)
        # list containing list and dict
        some_list = [[1, 2], {"c": "d"} ]
        sd['1'] = some_list
        self.assertEqual(sd['1'].dump(), some_list)
        # dict containing list and dict
        some_dict = {"a": [1, 2], "b": {"c":"d"} }
        sd['2'] = some_dict
        self.assertEqual(sd['2'].dump(), some_dict)
        # simple tuple.
        some_tuple = (1, 2, 3)
        sd['3'] = some_tuple
        self.assertEqual(sd['3'], some_tuple)
        # complex tuple
        complex_tuple = (1, 2, [3, 4])
        sd['4'] = complex_tuple
        self.assertEqual(sd['4'], complex_tuple)

    def test_db_iterators(self):
        sd = DictStorage(self.path)
        sd['a'] = [0, 1, 2, 3, 4]
        sl = sd.get('a')
        self.assertEqual(len(sl), 5)
        for i, v in enumerate(sl):
            self.assertEqual(i, v)

    def test_mutations_take_the_db_lock(self):
        # the db primitives must be entered with the db lock held, so that a mutation
        # (which reads, then writes) is atomic with respect to other threads
        sd = DictStorage(None)
        sd['l'] = []
        sd['test_lock'] = {'k': {'x': 1}}
        o = sd['test_lock']['k']
        db = sd._db
        seen = []
        def checked(name):
            orig = getattr(db, name)
            def f(*args, **kwargs):
                seen.append((name, sd.lock._is_owned()))
                return orig(*args, **kwargs)
            return f
        names = ('put', 'remove', 'clear', 'list_append', 'list_remove', 'list_clear')
        with mock.patch.multiple(db, **{name: checked(name) for name in names}):
            sd['a'] = 1
            sd['l'].append(2)
            sd['l'].remove(2)
            sd['l'].clear()
            o.x = 2
            sd.pop('a')
            sd.get('b', {}, add_if_missing=True)
            sd.setdefault('c', 1)
            sd['b'].clear()
        self.assertEqual(set(names), {name for name, owned in seen})
        self.assertEqual([], [name for name, owned in seen if not owned])

    def test_concurrent_writes_stay_consistent(self):
        # whatever the interleaving: no thread fails, and the patches replay to the in-memory data
        sd = DictStorage(None)
        sd['l'] = []
        sd['d'] = {}
        errors = []
        def worker(i):
            try:
                for n in range(500):
                    sd['l'].append([i, n])
                    sd['d'][str(n % 7)] = [i, n]
                    sd['d'].pop(str((n + 3) % 7), None)
            except Exception as e:
                errors.append(repr(e))
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual([], errors)
        self.assertEqual(2000, len(sd['l']))
        patches = [json.loads(p) for p in sd._db.pending_changes]
        self.assertEqual(sd._db.json_data, jsonpatch.JsonPatch(patches).apply({}))

    def test_list_indexing(self):
        # a StoredList indexes and slices like a list: slice bounds are clipped,
        # and an out of range index raises (it must not wrap around twice)
        sd = DictStorage(None)
        sd['l'] = [0, 1, 2, 3]
        l = sd['l']
        self.assertEqual(3, l[-1])
        self.assertEqual([1, 2], l[1:3])
        self.assertEqual([3, 1], l[::-2])
        self.assertEqual([0, 1, 2, 3], l[-10:10])
        for i in (4, -5):
            with self.assertRaises(IndexError):
                l[i]
        with self.assertRaises(TypeError):
            l['a']

    def test_partial_writes_are_off_by_default(self):
        # the default must match the config default: a write is a full write, nothing is appended
        sd = DictStorage(self.path)
        sd['a'] = 1
        sd.write()
        sd.close()
        sd = DictStorage(self.path)
        sd['b'] = 2
        sd.write()
        with open(self.path) as f:
            self.assertEqual({'a': 1, 'b': 2}, json.loads(f.read()))  # a single json object

    async def test_dangling_dict(self):
        storage = DictStorage(self.path)
        storage['a'] = {'b': {'c': 0}}
        storage.write()
        a = storage.get('a')
        b = a['b']
        self.assertEqual(type(b), StoredDict)
        b2 = a.pop('b')
        self.assertEqual(type(b2), dict)
        # replace item. this must not been written to db
        with self.assertRaises(KeyError):
            b['c'] = 42
        storage.write()
        storage.close()
        storage = DictStorage(self.path)
        self.assertEqual(storage.dump(), {'a':{}})

