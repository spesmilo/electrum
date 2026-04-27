import tempfile
import sys
import os
import json
import time
from io import StringIO
import asyncio
from pathlib import Path

from electrum.stored_dict import WalletStorage, StoredDict



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
        sd = WalletStorage(self.path)
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
        sd = WalletStorage(self.path)
        sd['a'] = [0, 1, 2, 3, 4]
        sl = sd.get('a')
        self.assertEqual(len(sl), 5)
        for i, v in enumerate(sl):
            self.assertEqual(i, v)

    async def test_dangling_dict(self):
        storage = WalletStorage(self.path)
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
        storage = WalletStorage(self.path)
        self.assertEqual(storage.dump(), {'a':{}})

