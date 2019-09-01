import json
import unittest


from .. import address
from .. import slp


script_tests_json = r'''
[
 {
  "msg": "OK: minimal GENESIS",
  "script": "6a04534c500001010747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: typical MINT without baton",
  "script": "6a04534c50000101044d494e5420ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: typical 1-output SEND",
  "script": "6a04534c500001010453454e44208888888888888888888888888888888888888888888888888888888888888888080000000000000042",
  "code": null
 },
 {
  "msg": "OK: typical 2-output SEND",
  "script": "6a04534c500001010453454e44208888888888888888888888888888888888888888888888888888888888888888080000000000000042080000000000000063",
  "code": null
 },
 {
  "msg": "Script ending mid-PUSH (one byte short) must be SLP-invalid",
  "script": "6a04534c500001010747454e455349534c004c004c004c0001004c000800000000000064",
  "code": 1
 },
 {
  "msg": "Script ending mid-PUSH (no length) must be SLP-invalid",
  "script": "6a04534c500001010747454e455349534c004c004c004c0001004c004c",
  "code": 1
 },
 {
  "msg": "Script ending mid-PUSH (length is one byte short) must be SLP-invalid",
  "script": "6a04534c500001010747454e455349534c004c004c004c0001004c004d00",
  "code": 1
 },
 {
  "msg": "(must be invalid: forbidden opcode): uses opcode OP_0",
  "script": "6a04534c500001010747454e455349534c00004c004c0001004c00080000000000000064",
  "code": 2
 },
 {
  "msg": "(must be invalid: forbidden opcode): uses opcode OP_1",
  "script": "6a04534c5000510747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": 2
 },
 {
  "msg": "(must be invalid: forbidden opcode): uses opcode OP_1NEGATE",
  "script": "6a04534c50004f0747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": 2
 },
 {
  "msg": "(must be invalid: forbidden opcode): uses opcode 0x50",
  "script": "6a04534c5000500747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": 2
 },
 {
  "msg": "(not SLP): p2pkh address script",
  "script": "76a914ffffffffffffffffffffffffffffffffffffffff88ac",
  "code": 3
 },
 {
  "msg": "(not SLP): empty op_return",
  "script": "6a",
  "code": 3
 },
 {
  "msg": "(not SLP): first push is 9-byte 'yours.org'",
  "script": "6a09796f7572732e6f7267",
  "code": 3
 },
 {
  "msg": "(not SLP): first push is 4-byte '\\x00BET'",
  "script": "6a0400424554",
  "code": 3
 },
 {
  "msg": "(not SLP): first push is 4-byte '\\x00SLP'",
  "script": "6a0400534c5001010747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": 3
 },
 {
  "msg": "(not SLP): first push is 3-byte 'SLP'",
  "script": "6a03534c5001010747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": 3
 },
 {
  "msg": "(not SLP): first push is 5-byte 'SLP\\x00\\x00'",
  "script": "6a05534c50000001010747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": 3
 },
 {
  "msg": "(not SLP): first push is 7-byte '\\xef\\xbb\\xbfSLP\\x00' (UTF8 byte order mark + 'SLP\\x00')",
  "script": "6a07efbbbf534c500001010747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": 3
 },
 {
  "msg": "OK: lokad pushed using PUSHDATA1",
  "script": "6a4c04534c500001010747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: lokad pushed using PUSHDATA2",
  "script": "6a4d0400534c500001010747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: lokad pushed using PUSHDATA4",
  "script": "6a4e04000000534c500001010747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: 2 bytes for token_type=1",
  "script": "6a04534c50000200010747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": null
 },
 {
    "msg": "(unsupported token type, must be token_type=1): 2 bytes for token_type=2",
    "script": "6a04534c50000200020747454e455349534c004c004c004c0001004c00080000000000000064",
    "code": 255
 },
 {
  "msg": "(must be invalid: wrong size): 3 bytes for token_type",
  "script": "6a04534c5000030000010747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): 0 bytes for token_type",
  "script": "6a04534c50004c000747454e455349534c004c004c004c0001004c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: too short): stopped after lokad ID",
  "script": "6a04534c5000",
  "code": 12
 },
 {
  "msg": "(must be invalid: too short): stopped after token_type",
  "script": "6a04534c50000101",
  "code": 12
 },
 {
  "msg": "(must be invalid: too short): stopped after transaction_type GENESIS",
  "script": "6a04534c500001010747454e45534953",
  "code": 12
 },
 {
  "msg": "(must be invalid: too short): stopped after transaction_type MINT",
  "script": "6a04534c50000101044d494e54",
  "code": 12
 },
 {
  "msg": "(must be invalid: too short): stopped after transaction_type SEND",
  "script": "6a04534c500001010453454e44",
  "code": 12
 },
 {
  "msg": "(must be invalid: bad value): transaction_type 'INIT'",
  "script": "6a04534c5000010104494e49544c004c004c004c0001004c00080000000000000064",
  "code": 11
 },
 {
  "msg": "(must be invalid: bad value): transaction_type 'TRAN'",
  "script": "6a04534c50000101045452414e208888888888888888888888888888888888888888888888888888888888888888080000000000000042",
  "code": 11
 },
 {
  "msg": "(must be invalid: bad value): transaction_type 'send'",
  "script": "6a04534c500001010473656e64208888888888888888888888888888888888888888888888888888888888888888080000000000000042",
  "code": 11
 },
 {
  "msg": "(must be invalid: bad value): transaction_type = 7-byte '\\xef\\xbb\\xbfSEND' (UTF8 byte order mark + 'SEND')",
  "script": "6a04534c5000010107efbbbf53454e44208888888888888888888888888888888888888888888888888888888888888888080000000000000042",
  "code": 11
 },
 {
  "msg": "(must be invalid: bad value): transaction_type = 10-byte UTF16 'SEND' (incl. BOM)",
  "script": "6a04534c500001010afffe530045004e004400208888888888888888888888888888888888888888888888888888888888888888080000000000000042",
  "code": 11
 },
 {
  "msg": "(must be invalid: bad value): transaction_type = 20-byte UTF32 'SEND' (incl. BOM)",
  "script": "6a04534c5000010114fffe000053000000450000004e00000044000000208888888888888888888888888888888888888888888888888888888888888888080000000000000042",
  "code": 11
 },
 {
  "msg": "OK: 8-character ticker 'NAKAMOTO' ascii",
  "script": "6a04534c500001010747454e45534953084e414b414d4f544f4c004c004c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: 9-character ticker 'Satoshi_N' ascii",
  "script": "6a04534c500001010747454e45534953095361746f7368695f4e4c004c004c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: 2-character ticker '\u4e2d\u672c' ('nakamoto' kanji) -- 6 bytes utf8",
  "script": "6a04534c500001010747454e4553495306e4b8ade69cac4c004c004c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: 4-character ticker '\u30ca\u30ab\u30e2\u30c8' ('nakamoto' katakana) -- 12 bytes utf8",
  "script": "6a04534c500001010747454e455349530ce3838ae382abe383a2e383884c004c004c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "(must be invalid: wrong size): Genesis with 0-byte decimals",
  "script": "6a04534c500001010747454e455349534c004c004c004c004c004c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): Genesis with 2-byte decimals",
  "script": "6a04534c500001010747454e455349534c004c004c004c000200004c00080000000000000064",
  "code": 10
 },
 {
  "msg": "OK: Genesis with 32-byte dochash",
  "script": "6a04534c500001010747454e455349534c004c004c0020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01004c00080000000000000064",
  "code": null
 },
 {
  "msg": "(must be invalid: wrong size): Genesis with 31-byte dochash",
  "script": "6a04534c500001010747454e455349534c004c004c001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01004c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): Genesis with 33-byte dochash",
  "script": "6a04534c500001010747454e455349534c004c004c0021ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01004c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): Genesis with 64-byte dochash",
  "script": "6a04534c500001010747454e455349534c004c004c0040ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01004c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): Genesis with 20-byte dochash",
  "script": "6a04534c500001010747454e455349534c004c004c0014ffffffffffffffffffffffffffffffffffffffff01004c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): SEND with 0-byte token_id",
  "script": "6a04534c500001010453454e444c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): SEND with 31-byte token_id",
  "script": "6a04534c500001010453454e441fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): SEND with 33-byte token_id",
  "script": "6a04534c500001010453454e4421ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): MINT with 0-byte token_id",
  "script": "6a04534c50000101044d494e544c004c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): MINT with 31-byte token_id",
  "script": "6a04534c50000101044d494e541fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): MINT with 32-byte token_id",
  "script": "6a04534c50000101044d494e5421ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4c00080000000000000064",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): SEND with a 7-byte amount",
  "script": "6a04534c500001010453454e442088888888888888888888888888888888888888888888888888888888888888880800000000000000630700000000000042080000000000000063",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): SEND with a 9-byte amount",
  "script": "6a04534c500001010453454e4420888888888888888888888888888888888888888888888888888888888888888808000000000000006309000000000000000042080000000000000063",
  "code": 10
 },
 {
  "msg": "(must be invalid: wrong size): SEND with a 0-byte amount",
  "script": "6a04534c500001010453454e442088888888888888888888888888888888888888888888888888888888888888880800000000000000634c00080000000000000063",
  "code": 10
 },
 {
  "msg": "OK: Genesis with decimals=9",
  "script": "6a04534c500001010747454e455349534c004c004c004c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "(must be invalid: bad value): Genesis with decimals=10",
  "script": "6a04534c500001010747454e455349534c004c004c004c00010a4c00080000000000000064",
  "code": 11
 },
 {
  "msg": "OK: Genesis with mint_baton_vout=255",
  "script": "6a04534c500001010747454e455349534c004c004c004c00010001ff080000000000000064",
  "code": null
 },
 {
  "msg": "OK: Genesis with mint_baton_vout=95",
  "script": "6a04534c500001010747454e455349534c004c004c004c000100015f080000000000000064",
  "code": null
 },
 {
  "msg": "OK: Genesis with mint_baton_vout=2",
  "script": "6a04534c500001010747454e455349534c004c004c004c0001000102080000000000000064",
  "code": null
 },
 {
  "msg": "(must be invalid: bad value): Genesis with mint_baton_vout=1",
  "script": "6a04534c500001010747454e455349534c004c004c004c0001000101080000000000000064",
  "code": 11
 },
 {
  "msg": "(must be invalid: bad value): Genesis with mint_baton_vout=0",
  "script": "6a04534c500001010747454e455349534c004c004c004c0001000100080000000000000064",
  "code": 11
 },
 {
  "msg": "OK: MINT with mint_baton_vout=255",
  "script": "6a04534c50000101044d494e5420ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff01ff080000000000000064",
  "code": null
 },
 {
  "msg": "OK: MINT with mint_baton_vout=95",
  "script": "6a04534c50000101044d494e5420ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff015f080000000000000064",
  "code": null
 },
 {
  "msg": "OK: MINT with mint_baton_vout=2",
  "script": "6a04534c50000101044d494e5420ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0102080000000000000064",
  "code": null
 },
 {
  "msg": "(must be invalid: bad value): MINT with mint_baton_vout=1",
  "script": "6a04534c50000101044d494e5420ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0101080000000000000064",
  "code": 11
 },
 {
  "msg": "(must be invalid: bad value): MINT with mint_baton_vout=0",
  "script": "6a04534c50000101044d494e5420ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0100080000000000000064",
  "code": 11
 },
 {
  "msg": "(must be invalid: wrong number of params) GENESIS with extra token amount",
  "script": "6a04534c500001010747454e455349534c004c004c004c0001004c00080000000000000064080000000000000064",
  "code": 12
 },
 {
  "msg": "(must be invalid: wrong number of params) MINT with extra token amount",
  "script": "6a04534c50000101044d494e5420ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4c00080000000000000064080000000000000064",
  "code": 12
 },
 {
  "msg": "OK: SEND with 19 token output amounts",
  "script": "6a04534c500001010453454e44208888888888888888888888888888888888888888888888888888888888888888080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001",
  "code": null
 },
 {
  "msg": "(must be invalid: too many parameters): SEND with 20 token output amounts",
  "script": "6a04534c500001010453454e44208888888888888888888888888888888888888888888888888888888888888888080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001080000000000000001",
  "code": 21
 },
 {
  "msg": "OK: all output amounts 0",
  "script": "6a04534c500001010453454e44208888888888888888888888888888888888888888888888888888888888888888080000000000000000080000000000000000",
  "code": null
 },
 {
  "msg": "OK: three inputs of max value (2**64-1) whose sum overflows a 64-bit int",
  "script": "6a04534c500001010453454e4420888888888888888888888888888888888888888888888888888888888888888808ffffffffffffffff08ffffffffffffffff08ffffffffffffffff",
  "code": null
 },
 {
  "msg": "OK: using opcode PUSHDATA1 for 8-byte push",
  "script": "6a04534c500001010747454e455349534c004c004c004c0001004c004c080000000000000064",
  "code": null
 },
 {
  "msg": "OK: using opcode PUSHDATA2 for empty push",
  "script": "6a04534c500001010747454e455349534c004d00004c004c0001004c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: using opcode PUSHDATA4 for empty push",
  "script": "6a04534c500001010747454e455349534c004e000000004c004c0001004c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: ticker is bad utf8 E08080 (validators must not require decodeable strings)",
  "script": "6a04534c500001010747454e4553495303e080804c004c004c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: ticker is bad utf8 C0 (validators must not require decodeable strings)",
  "script": "6a04534c500001010747454e4553495301c04c004c004c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: name is bad utf8 E08080 (validators must not require decodeable strings)",
  "script": "6a04534c500001010747454e455349534c0003e080804c004c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: name is bad utf8 C0 (validators must not require decodeable strings)",
  "script": "6a04534c500001010747454e455349534c0001c04c004c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: url is bad utf8 E08080 (validators must not require decodeable strings)",
  "script": "6a04534c500001010747454e455349534c004c0003e080804c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: url is bad utf8 C0 (validators must not require decodeable strings)",
  "script": "6a04534c500001010747454e455349534c004c0001c04c0001094c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: genesis with 300-byte name 'UUUUU...' (op_return over 223 bytes, validators must not refuse this)",
  "script": "6a04534c500001010747454e455349534c004d2c015555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555554c004c0001004c00080000000000000064",
  "code": null
 },
 {
  "msg": "OK: genesis with 300-byte document url 'UUUUU...' (op_return over 223 bytes, validators must not refuse this)",
  "script": "6a04534c500001010747454e455349534c004c004d2c015555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555554c0001004c00080000000000000064",
  "code": null
 }
]
'''

errorcodes = {
    # no-error maps to None

    # various script format errors
    ('Bad OP_RETURN', 'Script error'): 1,
    # disallowed opcodes
    ('Bad OP_RETURN', 'Non-push opcode'): 2,
    ('Bad OP_RETURN', 'OP_1NEGATE to OP_16 not allowed'): 2,
    ('Bad OP_RETURN', 'OP_0 not allowed'): 2,

    # not OP_RETURN script / not SLP
    # (note in some implementations, parsers should never be given such non-SLP scripts in the first place. In such implementations, error code 3 tests may be skipped.)
    ('Bad OP_RETURN', 'No OP_RETURN'): 3,
    ('Empty OP_RETURN', ): 3,
    ('Not SLP',): 3,

    # 10- field bytesize is wrong
    ('Field has wrong length', ): 10,
    ('Ticker too long', ): 10,
    ('Token document hash is incorrect length',): 10,
    ('token_id is wrong length',): 10,

    # 11- improper value
    ('Too many decimals',): 11,
    ('Bad transaction type',): 11,
    ('Mint baton cannot be on vout=0 or 1',): 11,

    # 12- missing field / too few fields
    ('Missing output amounts', ): 12,
    ('Missing token_type', ): 12,
    ('Missing SLP command', ): 12,
    ('GENESIS with incorrect number of parameters', ): 12,
    ('SEND with too few parameters', ): 12,
    ('MINT with incorrect number of parameters', ): 12,

    # specific
    ('More than 19 output amounts',): 21,

    #SlpUnsupportedSlpTokenType : 255 below
    }

class SLPTests(unittest.TestCase):
    def test_opreturn_parse(self):
        testlist = json.loads(script_tests_json)

        print("Starting %d tests on SLP's OP_RETURN parser"%len(testlist))
        for d in testlist:
            description = d['msg']
            scripthex = d['script']
            code = d['code']
            if scripthex is None:
                continue
            if hasattr(code, '__iter__'):
                expected_codes = tuple(code)
            else:
                expected_codes = (code, )

            with self.subTest(description=description, script=scripthex):
                sco = address.ScriptOutput(bytes.fromhex(scripthex))
                try:
                    slp_sco = slp.ScriptOutput(sco.script)
                except Exception as e:
                    if isinstance(e, slp.InvalidOutputMessage):
                        emsg = e.args
                        if errorcodes[emsg] not in expected_codes:
                            raise AssertionError("Invalidity reason %r (code: %d) not in expected reasons %r"%(emsg, errorcodes[emsg], expected_codes))
                    elif isinstance(e, slp.UnsupportedSlpTokenType):
                        if 255 not in expected_codes:
                            raise AssertionError("UnsupportedSlpTokenType exception raised (code 255) but not in expected reasons (%r)"%(expected_codes,))
                    else:
                        raise
                else:
                    # no exception
                    if None not in expected_codes:
                        raise AssertionError("Script was found valid but should have been invalid, for a reason code in %r."%(expected_codes,))

    def test_opreturn_build(self):
        testlist = json.loads(script_tests_json)

        print("Starting %d tests on SLP's OP_RETURN builder"%len(testlist))
        ctr = 0
        for d in testlist:
            description = d['msg']
            scripthex = d['script']
            code = d['code']
            if code is not None:
                # we are only interested in "None" tests, that is, ones
                # that are expected to parse as valid
                continue
            if scripthex is None:
                continue
            if hasattr(code, '__iter__'):
                expected_codes = tuple(code)
            else:
                expected_codes = (code, )

            def check_is_equal_message(msg1, msg2):
                print("ScriptHex = ", scripthex)
                print("Testing ", msg1.chunks, "vs", msg2.chunks)
                seen = {'chunks'}
                for k in msg1.valid_properties:
                    if k.startswith('_') or k in seen:
                        continue
                    try:
                        v = getattr(msg1, k, None)
                    except:
                        continue
                    if v is not None and not callable(v):
                        #print("kw=",k)
                        self.assertEqual(v, getattr(msg2, k, None))
                        seen.add(k)
                for k in msg2.valid_properties:
                    if k.startswith('_') or k in seen:
                        continue
                    try:
                        v = getattr(msg2, k, None)
                    except:
                        continue
                    if v is not None and not callable(v):
                        #print("kw=",k)
                        self.assertEqual(v, getattr(msg1, k, None))
                        seen.add(k)

            with self.subTest(description=description, script=scripthex):
                sco = address.ScriptOutput(bytes.fromhex(scripthex))
                slp_sco = slp.ScriptOutput(sco.script)  # should not raise
                _type = slp_sco.message.transaction_type
                if _type == 'GENESIS':
                    try:
                        outp = slp.Build.GenesisOpReturnOutput_V1(
                            ticker = slp_sco.message.ticker.decode('utf-8'),
                            token_name = slp_sco.message.token_name.decode('utf-8'),
                            token_document_url = slp_sco.message.token_doc_url and slp_sco.message.token_doc_url.decode('utf-8'),
                            token_document_hash_hex = slp_sco.message.token_doc_hash and slp_sco.message.token_doc_hash.decode('utf-8'),
                            decimals = slp_sco.message.decimals,
                            baton_vout = slp_sco.message.mint_baton_vout,
                            initial_token_mint_quantity = slp_sco.message.initial_token_mint_quantity,
                            token_type = slp_sco.message.token_type,
                        )
                    except (UnicodeError, slp.OPReturnTooLarge):
                        # some of the test data doesn't decode to utf8 because it contains 0xff
                        # some of the test data has too-big op_return
                        continue
                    check_is_equal_message(slp_sco.message, outp[1].message)
                elif _type == 'MINT':
                    try:
                        outp = slp.Build.MintOpReturnOutput_V1(
                            token_id_hex = slp_sco.message.token_id_hex,
                            baton_vout = slp_sco.message.mint_baton_vout,
                            token_mint_quantity = slp_sco.message.additional_token_quantity,
                            token_type = slp_sco.message.token_type
                        )
                    except (UnicodeError, slp.OPReturnTooLarge):
                        continue
                    check_is_equal_message(slp_sco.message, outp[1].message)
                elif _type == 'SEND':
                    try:
                        outp = slp.Build.SendOpReturnOutput_V1(
                            token_id_hex = slp_sco.message.token_id_hex,
                            output_qty_array = slp_sco.message.token_output[1:],
                            token_type = slp_sco.message.token_type
                        )
                    except (UnicodeError, slp.OPReturnTooLarge):
                        continue
                    check_is_equal_message(slp_sco.message, outp[1].message)
                elif _type == 'COMMIT':
                    continue
                else:
                    raise RuntimeError('Unexpected transation_type')
                ctr += 1

        print("Completed %d OP_RETURN *build* tests"%ctr)

