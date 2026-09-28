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

from electrum.stored_dict import DictStorage, StoredDict, StoredObject, StorageReadWriteError, register_key, stored_at, to_default
from electrum.json_db import to_json_data
from electrum.wallet_db import WalletDB



from . import ElectrumTestCase


@stored_at('/test_cache/*')
@dataclasses.dataclass
class _CachedObj(StoredObject):
    x: int


@stored_at('/test_strict/*')
def _strict_obj(**kwargs):
    return kwargs['required']  # raises KeyError for a malformed entry


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
        # the json storage stores tuples as lists, so they read back as StoredList
        some_tuple = (1, 2, 3)
        sd['3'] = some_tuple
        self.assertEqual(sd['3'].dump(), list(some_tuple))
        # complex tuple: the third element is a StoredList
        complex_tuple = (1, 2, [3, 4])
        sd['4'] = complex_tuple
        self.assertEqual(sd['4'].dump(), list(complex_tuple))
        self.assertEqual(sd['4'][2].dump(), complex_tuple[2])

    def test_db_iterators(self):
        sd = DictStorage(self.path)
        sd['a'] = [0, 1, 2, 3, 4]
        sl = sd.get('a')
        self.assertEqual(len(sl), 5)
        for i, v in enumerate(sl):
            self.assertEqual(i, v)

    def test_key_conversion(self):
        # dicts registered with register_key convert their keys (typically str -> int)
        # consistently in __iter__, keys() and items()
        register_key('/test_int_keys', int)
        sd = DictStorage(None)
        sd['test_int_keys'] = {1: 'a', 2: 'b'}
        d = sd['test_int_keys']
        self.assertEqual([1, 2], list(d))
        self.assertEqual([1, 2], list(d.keys()))
        self.assertEqual({1: 'a', 2: 'b'}, dict(d.items()))
        self.assertIn(1, d)
        self.assertIn('1', d)
        self.assertEqual('b', d[2])

    async def test_dict_views(self):
        # keys(), values() and items() are live views, as for a regular dict
        storage = DictStorage(self.path)
        storage['a'] = {'k1': 1, 'k2': 2, 'k3': 3}
        a = storage.get('a')
        keys = a.keys()
        self.assertEqual(3, len(keys))
        self.assertEqual(['k1', 'k2', 'k3'], list(keys))
        self.assertEqual(list(keys), list(keys))  # not exhausted by iterating
        self.assertEqual([1, 2, 3], list(a.values()))
        self.assertIn(('k2', 2), a.items())
        a['k4'] = 4
        self.assertEqual(4, len(keys))  # the view is live
        storage['b'] = {}
        self.assertFalse(storage.get('b').keys())
        # equality with a regular dict
        self.assertEqual({'k1': 1, 'k2': 2, 'k3': 3, 'k4': 4}, a)
        self.assertNotEqual({'k1': 1}, a)
        # update() from another StoredDict
        b = storage.get('b')
        b.update(a)
        self.assertEqual(a.dump(), b.dump())

    def test_get_does_not_hide_conversion_errors(self):
        sd = DictStorage(None)
        sd['test_strict'] = {'good': {'required': 1}, 'bad': {}}
        d = sd['test_strict']
        self.assertEqual(1, d.get('good'))
        self.assertIsNone(d.get('missing'))
        self.assertEqual(2, d.get('missing2', 2))
        # an error raised while converting an entry must not look like a missing key,
        # and must not get the entry overwritten with the default
        with self.assertRaises(KeyError):
            d.get('bad')
        with self.assertRaises(KeyError):
            d.get('bad', {}, add_if_missing=True)
        self.assertEqual({}, sd._db.json_data['test_strict']['bad'])
        with self.assertRaises(KeyError):
            d.pop('bad', None)
        self.assertIn('bad', d)

    def test_object_cache(self):
        # converted values are cached: reads return the same object, until the value is replaced
        sd = DictStorage(None)
        sd['test_cache'] = {'k': {'x': 1}}
        d = sd['test_cache']
        self.assertIs(d, sd['test_cache'])
        o = d['k']
        self.assertIsInstance(o, _CachedObj)
        self.assertIs(o, d['k'])
        self.assertIs(o, list(d.values())[0])
        o.x = 2  # attribute writes still go through to the db
        self.assertEqual({'k': {'x': 2}}, sd._db.json_data['test_cache'])
        d['k'] = {'x': 3}  # replacing the value drops the cached object
        self.assertIsNot(o, d['k'])
        self.assertEqual(3, d['k'].x)
        new = _CachedObj(x=4)
        d['k2'] = new  # an object we store is the object we read back
        self.assertIs(new, d['k2'])
        del d['k2']
        self.assertNotIn('k2', d)
        sd['test_cache'] = {'k': {'x': 5}}  # replacing the whole dict drops the cache of its wrapper
        self.assertEqual(5, d['k'].x)
        self.assertEqual(5, sd['test_cache']['k'].x)

    def test_write_batch(self):
        # test that batches are written atomically
        sd = DictStorage(self.path)
        with sd.write_batch():
            sd['a'] = 0
        self.assertEqual(len(sd), 1)
        with sd.write_batch():
            sd['a'] = 1
        self.assertEqual(len(sd), 1)
        try:
            with sd.write_batch():
                sd['b'] = 1
                raise Exception('blah')
        except Exception as e:
            pass
        self.assertEqual(sd._db._write_batch, False)
        # at this point, the StoredDict length is 2
        self.assertEqual(len(sd), 2)
        # the changes of the failed batch are in memory but not written: the db refuses to write
        with self.assertRaises(StorageReadWriteError):
            sd.write()
        sd.close()
        # check that changes have not been written to disk
        sd = DictStorage(self.path)
        self.assertEqual(len(sd), 1)
        # a write requested during a batch is deferred to the end of the batch
        with sd.write_batch():
            sd['c'] = 1
            sd.write()
            self.assertEqual(1, len(DictStorage(self.path)))
        self.assertEqual(2, len(DictStorage(self.path)))

    def test_tuples_and_sets(self):
        # to_default keeps built-in containers: it is up to the storage to serialize them
        self.assertEqual((1, (2, 3)), to_default((1, (2, 3))))
        self.assertEqual(frozenset({1, 2}), to_default({1, 2}))
        # the json storage stores them as lists, in a deterministic order for sets,
        # so that a value compares equal to what a reload gives
        self.assertEqual([1, [2, 3]], to_json_data((1, (2, 3))))
        self.assertEqual(to_json_data({(1, 'a'), (2, 'b')}), to_json_data(frozenset({(2, 'b'), (1, 'a')})))
        sd = DictStorage(self.path)
        sd['t'] = {'k': (1, True)}
        sd['l'] = [(1, 2)]
        sd.write()
        sd.close()
        sd = DictStorage(self.path, allow_partial_writes=True)
        sd['t']['k'] = (1, True)  # the same value: no patch
        self.assertEqual([], sd._db.pending_changes)
        self.assertEqual(0, sd['l'].index((1, 2)))
        sd['l'].remove((1, 2))
        self.assertEqual(0, len(sd['l']))

    def test_nested_wrappers_can_be_stored(self):
        # to_default converts StoredDict/StoredList, even when nested in a value,
        # so that a value built out of stored ones can be stored (as db upgrades do)
        sd = DictStorage(None)
        sd['d'] = {'k': [1, 2], 'l': [{'a': 1}]}
        d = sd['d']
        self.assertEqual({'k': [1, 2], 'l': [{'a': 1}]}, to_default(d))
        self.assertEqual([[1, 2]], to_default([d['k']]))
        sd['e'] = {'copy': d, 'items': (d['k'], d['l'][0])}
        sd['m'] = []
        sd['m'].append(d['l'])
        self.assertEqual({'copy': {'k': [1, 2], 'l': [{'a': 1}]}, 'items': [[1, 2], {'a': 1}]}, sd._db.json_data['e'])
        self.assertEqual([[{'a': 1}]], sd._db.json_data['m'])

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

    def test_list_equality(self):
        # a StoredList compares by content with lists and tuples, like a StoredDict does with dicts
        sd = DictStorage(None)
        sd['l'] = [1, [2, 3], {'a': 4}]
        l = sd['l']
        self.assertEqual([1, [2, 3], {'a': 4}], l)
        self.assertEqual(l, (1, [2, 3], {'a': 4}))  # tuples are stored as lists
        self.assertNotEqual([1, [2, 3]], l)
        self.assertNotEqual(l, 'not a list')
        # so that WalletDB.put detects a no-op for a list, and does not mark the db as modified
        db = WalletDB(DictStorage(None))
        db.put('frozen_addresses', ['a', 'b'])
        db.storage._db._modified = False
        self.assertFalse(db.put('frozen_addresses', ['a', 'b']))
        self.assertFalse(db.storage._db._modified)
        self.assertTrue(db.put('frozen_addresses', ['a']))

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
        storage.close()
        storage = DictStorage(self.path, allow_partial_writes=True)  # reopen, so that later writes are appended
        a = storage.get('a')
        b = a['b']
        self.assertEqual(b['c'], 0)  # read through b, so that its hint is cached
        b2 = a.pop('b')
        self.assertEqual(type(b2), dict)
        with self.assertRaises(KeyError):
            b['c'] = 42
        storage.write()
        storage.close()
        storage = DictStorage(self.path)
        self.assertEqual(storage.dump(), {'a': {}})

