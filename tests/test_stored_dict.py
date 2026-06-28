import tempfile
import sys
import os
import json
import time
from io import StringIO
import asyncio
from pathlib import Path

from electrum.stored_dict import DictStorage, StoredDict



from . import ElectrumTestCase


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
        # complex tuple: the third element is a StoredDict
        complex_tuple = (1, 2, [3, 4])
        sd['4'] = complex_tuple
        with self.assertRaises(AssertionError):
            self.assertEqual(sd['4'], complex_tuple)
        self.assertEqual(sd['4'][2].dump(), complex_tuple[2])

    def test_db_iterators(self):
        sd = DictStorage(self.path)
        sd['a'] = [0, 1, 2, 3, 4]
        sl = sd.get('a')
        self.assertEqual(len(sl), 5)
        for i, v in enumerate(sl):
            self.assertEqual(i, v)

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
        # at this point, the StoredDict length is 1
        self.assertEqual(len(sd), 1)
        sd.close()
        # check that changes have not been written to disk
        sd = DictStorage(self.path)
        self.assertEqual(len(sd), 1)

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

