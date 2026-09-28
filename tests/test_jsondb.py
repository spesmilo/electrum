import contextlib
import copy
import traceback
import json
import os
from typing import Any

import jsonpatch
from jsonpatch import JsonPatchException
from jsonpointer import JsonPointerException

from . import ElectrumTestCase

from electrum.json_db import JsonDB
from electrum.stored_dict import DictStorage
from electrum.util import WalletFileException

class TestJsonpatch(ElectrumTestCase):

    async def test_op_replace(self):
        data1 = {'foo': 'bar', 'numbers': [1, 3, 4, 8], 'dictlevelA1': {'secret1': 2, 'secret2': 4, 'secret3': 6}}
        patches = [{"op": "replace", "path": "/dictlevelA1/secret2", "value": 2222}]
        jpatch = jsonpatch.JsonPatch(patches)
        data2 = jpatch.apply(data1)
        self.assertEqual(
            {'foo': 'bar', 'numbers': [1, 3, 4, 8], 'dictlevelA1': {'secret1': 2, 'secret2': 2222, 'secret3': 6}},
            data2
        )

    @contextlib.contextmanager
    def _customAssertRaises(self, *args, **kwargs):
        with self.assertRaises(*args, **kwargs) as ctx:
            try:
                yield ctx
            except Exception as e:
                # save original traceback now, as assertRaises will destroy most of it imminently:
                ctx._customctx_original_tb = "".join(traceback.format_exception(e))
                raise

    async def test_patch_does_not_leak_privatekeys(self):
        data1 = {
            'dictlevelB1': 'secret77',
            'dictlevelC1': [1, "secret99", 4, 8],
            'dictlevelA1': {"dictlevelA2_aa": "secret11", "dictlevelA2_bb": "secret12", "dictlevelA2_cc": "secret13"}}
        def fail_if_leaking_secret(ctx) -> None:
            self.assertNotIn("secret", str(ctx.exception))
            self.assertNotIn("secret", repr(ctx.exception))
            self.assertNotIn("secret", ctx._customctx_original_tb)
            self.assertNotIn("dictlevel", str(ctx.exception))
            self.assertNotIn("dictlevel", repr(ctx.exception))
            self.assertNotIn("dictlevel", ctx._customctx_original_tb)
            self.assertIn("redacted", str(ctx.exception))  # injected by our monkeypatching
            self.assertIn("redacted", repr(ctx.exception))  # injected by our monkeypatching
        # op "replace"
        with self.subTest(msg="replace_dict_inner_key_missing"):
            patches = [{"op": "replace", "path": "/dictlevelA1/dictlevelX2", "value": "nakamoto_secret"}]
            jpatch = jsonpatch.JsonPatch(patches)
            with self._customAssertRaises(JsonPatchException) as ctx:
                data2 = jpatch.apply(data1)
            fail_if_leaking_secret(ctx)
        with self.subTest(msg="replace_dict_outer_key_missing"):
            patches = [{"op": "replace", "path": "/dictlevelX1/dictlevelX2", "value": "nakamoto_secret"}]
            jpatch = jsonpatch.JsonPatch(patches)
            with self._customAssertRaises(JsonPointerException) as ctx:
                data2 = jpatch.apply(data1)
            fail_if_leaking_secret(ctx)
        # op "remove"
        with self.subTest(msg="remove_dict_inner_key_missing"):
            patches = [{"op": "remove", "path": "/dictlevelA1/dictlevelX2"}]
            jpatch = jsonpatch.JsonPatch(patches)
            with self._customAssertRaises(JsonPatchException) as ctx:
                data2 = jpatch.apply(data1)
            fail_if_leaking_secret(ctx)
        with self.subTest(msg="remove_dict_outer_key_missing"):
            patches = [{"op": "remove", "path": "/dictlevelX1/dictlevelX2"}]
            jpatch = jsonpatch.JsonPatch(patches)
            with self._customAssertRaises(JsonPointerException) as ctx:
                data2 = jpatch.apply(data1)
            fail_if_leaking_secret(ctx)
        # op "add"
        with self.subTest(msg="add_dict_inner_key_missing"):
            patches = [{"op": "add", "path": "/dictlevelA1/dictlevelX2/dictlevelX3/dictlevelX4", "value": "nakamoto_secret"}]
            jpatch = jsonpatch.JsonPatch(patches)
            with self._customAssertRaises(JsonPointerException) as ctx:
                data2 = jpatch.apply(data1)
            fail_if_leaking_secret(ctx)
        with self.subTest(msg="add_dict_outer_key_missing"):
            patches = [{"op": "add", "path": "/dictlevelX1/dictlevelX2/dictlevelX3/dictlevelX4", "value": "nakamoto_secret"}]
            jpatch = jsonpatch.JsonPatch(patches)
            with self._customAssertRaises(JsonPointerException) as ctx:
                data2 = jpatch.apply(data1)
            fail_if_leaking_secret(ctx)


class TestJsonDB(ElectrumTestCase):

    async def test_jsonpatch_replace_after_remove(self):
        data = { 'a':{} }
        # op "add"
        patches = [{"op": "add", "path": "/a/b", "value": "42"}]
        jpatch = jsonpatch.JsonPatch(patches)
        data = jpatch.apply(data)
        self.assertEqual(data, {'a': {"b": "42"}})
        # remove
        patches = [{"op": "remove", "path": "/a/b"}]
        jpatch = jsonpatch.JsonPatch(patches)
        data = jpatch.apply(data)
        self.assertEqual(data, {'a': {}})
        # replace
        patches = [{"op": "replace", "path": "/a/b", "value": "43"}]
        jpatch = jsonpatch.JsonPatch(patches)
        with self.assertRaises(JsonPatchException):
            data = jpatch.apply(data)

    async def test_jsondb_partial_write_round_test(self):
        wallet_path = os.path.join(self.electrum_path, "somewallet")
        storage = DictStorage(wallet_path, allow_partial_writes=True)
        storage['a'] = [1, 2, 3]
        storage._db.write_and_force_consolidation()
        storage['a'].append(4)
        storage._db._append_pending_changes()
        storage = DictStorage(wallet_path, allow_partial_writes=True)
        self.assertEqual(len(storage['a']), 4)

    async def test_jsondb_list_clear(self):
        wallet_path = os.path.join(self.electrum_path, "somewallet")
        storage = DictStorage(wallet_path, allow_partial_writes=True)
        storage['a'] = [1, 2, 3]
        storage._db.write()
        storage['a'].clear()
        storage._db.write()
        storage = DictStorage(wallet_path, allow_partial_writes=True)
        self.assertEqual(len(storage['a']), 0)

    @staticmethod
    def _load_json_db(s: str) -> dict:
        db = JsonDB(None)
        db.set_data(s)
        return json.loads(json.dumps(db.json_data))

    async def test_json_db_maybe_load_incomplete_data_with_control_characters(self):
        # user-supplied text such as tx labels can contain arbitrary characters, such as "}"
        raw_json_db = '{"a": {"b": "c1"}, "d": "e"},\n{"op": "replace", "path": "/a/b", "value": "user_supp}}}lied_text"}'
        raw_json_db = raw_json_db[:-4]  # truncate some characters, to trigger maybe_load_incomplete_data()
        self.assertEqual({"a": {"b": "c1"}, "d": "e"}, self._load_json_db(raw_json_db))

    async def test_json_db_load_arbitrarily_truncated_data(self):
        # a file cut at any offset after the main object must recover to a valid prefix state;
        # a cut inside the main object must raise WalletFileException
        base = {'labels': {'tx1': 'nasty } { label'}, 'nested': {'a': [1, {'b': '}}}'}]}}
        patches = [
            {'op': 'add', 'path': '/labels/tx2', 'value': 'user_supp}}}lied {{{ text'},
            {'op': 'replace', 'path': '/labels/tx1', 'value': 'fake ,\\n{ separator'},
        ]
        # the valid prefix states: base with 0, 1, ..., len(patches) patches applied
        states = [base]
        for p in patches:
            states.append(jsonpatch.JsonPatch([p]).apply(states[-1]))
        s = json.dumps(base)
        for p in patches:
            s += ',\n' + json.dumps(p)
        self.assertEqual(states[-1], self._load_json_db(s))
        main_len = len(json.dumps(base))
        for i in range(1, len(s)):
            if i < main_len:  # main object truncated: unrecoverable
                with self.assertRaises(WalletFileException):
                    self._load_json_db(s[:i])
            else:  # main object intact: must recover
                self.assertIn(self._load_json_db(s[:i]), states)

    async def test_jsondb_pointer_escaping(self):
        # keys containing '/' or '~' must be escaped per RFC 6901 in emitted patches
        data = {'labels': {'some/label~key': 'hello'}, 'x1/': {'type': 'bip32'}}
        wallet_path = os.path.join(self.electrum_path, "somewallet")
        storage = DictStorage(wallet_path)
        storage.update(copy.deepcopy(data))
        storage._db.write_and_force_consolidation()
        storage['labels']['some/label~key'] = 'world'
        storage.pop('x1/')
        patches = json.loads('[' + ','.join(storage._db.pending_changes) + ']')
        self.assertEqual({'/labels/some~1label~0key', '/x1~1'}, {p['path'] for p in patches})
        data = jsonpatch.JsonPatch(patches).apply(data)
        self.assertEqual({'labels': {'some/label~key': 'world'}}, data)
