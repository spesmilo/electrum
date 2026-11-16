import hashlib
import hmac
import os
import pathlib
from unittest import mock

from electrum import logging as electrum_logging
from electrum.logging import (redact_log_text, read_recent_logs, set_file_logging, filter_log_for_sharing,
                              what_identifies_us_in_logs, log_sharing_key)
from electrum.simple_config import SimpleConfig

from . import ElectrumTestCase


def _line(logger: str, message: str, level: str = 'INFO') -> str:
    return f'20261116T015645.543541Z | {level:>8} | {logger} | {message}\n'


class TestFilterLogForSharing(ElectrumTestCase):

    def test_only_the_entries_about_lightning_payments_and_the_graph_are_kept(self):
        kept = [
            _line('lnworker.PaySession.[d9f3aa74-419e]', 'pay_to_node starting session'),
            _line('lnworker.LNWallet.[w]', 'sent htlc 1 over 800000x100x1: amount=1000 msat'),
            _line('lnrouter.LNPathFinder', 'found a path. cost=1'),
            _line('lnpeer.Peer.[w, 0322222222-1a2b3c4d]', 'Received INIT', 'DEBUG'),
            _line('channel_db.ChannelDB', 'Deleting 3 orphaned channels'),
            _line('gossip_catch_up', 'catch-up on gossip in the background every 120 minutes'),
            _line('lnworker.LNWallet.[w]', 'Exception in pay_to_node: PaymentFailure()', 'ERROR')
            + 'Traceback (most recent call last):\n  File "lnworker.py", line 1\nPaymentFailure\n',
        ]
        kept.append(_line('logging', 'Electrum version: 4.8.4 - https://electrum.org'))
        dropped = [
            _line('lnchannel.Channel.[w, 0x1x1]', "sign_next_commitment. psbt='cHNidP8BAN8CAAAAAVY'", 'DEBUG'),
            _line('interface.[myhome.example:50002]', 'connection established'),
            _line('gui.qml.qeinvoice', "outputs=[<TxOutput address=bc1q value=1>] message='rent'"),
            _line('wallet.Standard_Wallet.[w]', 'adding tx'),
            _line('lnwatcher.LNWatcher', 'sweeping'),
            _line('storage.WalletStorage', 'wallet path /data/wallets/w'),
        ]
        text = ''.join(kept[:3] + dropped[:3] + kept[3:] + dropped[3:])
        self.assertEqual(''.join(kept), filter_log_for_sharing(text))
        self.assertEqual('', filter_log_for_sharing('not a log line\n'))


KEY = bytes(range(32))


def label(kind: str, value: str, shown_as: str = None) -> str:
    """what the labels are: an HMAC-SHA256 of 'kind:value' with the key, the first 8 hex digits"""
    digest = hmac.new(KEY, f'{kind}:{value}'.encode(), hashlib.sha256).hexdigest()[:8]
    return f'<{shown_as or kind} {digest}>'


def redact(text: str, **kwargs) -> str:
    return redact_log_text(text, key=KEY, **kwargs)


class TestRedactLogText(ElectrumTestCase):

    NODE_ID = '03' + 'ab' * 32
    HASH = 'cd' * 32

    def test_what_identifies_the_user_is_replaced(self):
        invoice = 'lnbc1500n1pj9xyzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq'
        lnurl = ('LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQ'
                 'URZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS')
        xpub = ('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7us'
                'UDFdp6W1EGMcet8')
        psbt = 'cHNidP8BAN8CAAAAAVYaijTIyjVkVrTTgLtSyhbZ/qi9tGFAPpXdD2gtKKZ5AAAAAAD/////'
        for text, expected in (
            (f'pay_invoice {invoice} ok', f'pay_invoice {label("invoice", invoice)} ok'),
            (f'uri lightning:{invoice.upper()}', f'uri {label("invoice", "lightning:" + invoice.upper())}'),
            ('offer lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrc2qajx2enpw4k8g93pq',
             'offer ' + label('invoice', 'lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrc2qajx2enpw4k8g93pq')),
            (f'lnurl {lnurl}', f'lnurl {label("lnurl", lnurl)}'),
            ('to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq.', f'to {label("address", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")}.'),
            ('to bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080', f'to {label("address", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")}'),
            ('to 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', f'to {label("address", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")}'),
            (f'key {xpub}', f'key {label("key", xpub)}'),
            ('wif L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ',
             f'wif {label("key", "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ")}'),
            (f'RHASH={self.HASH}. txid {self.HASH.upper()}:1', f'RHASH={label("hash", self.HASH)}. txid {label("hash", self.HASH)}:1'),
            (f"payment_key='{self.HASH}{'ef' * 32}'", f"payment_key='{label('hash', self.HASH + 'ef' * 32)}'"),
            ("payment_hash=b'\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd"
             "\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd\\xcd', cltv_abs=600147",
             f"payment_hash={label('hash', self.HASH)}, cltv_abs=600147"),  # the same label as in hex
            ("flags=b'\\x00\\x01'", f"flags={label('bytes', '0001')}"),
            ("odd=b'\\x9'", "odd=" + label('bytes', "b'\\x9'")),  # not a valid literal
            (f"psbt='{psbt}'", f"psbt='{label('data', psbt)}'"),
            ('<TxOutput script=0014e8df018c7e326cc253faac7e46cdc51e68542c42 value=1>',
             f'<TxOutput script={label("hash", "0014e8df018c7e326cc253faac7e46cdc51e68542c42")} value=1>'),
            ('peer 203.0.113.7:9735, 203.0.113.7. and [2001:db8::1]:9735 and ::ffff:192.0.2.1',
             f'peer {label("ip", "203.0.113.7")}:9735, {label("ip", "203.0.113.7")}. and [{label("ip", "2001:db8::1")}]:9735 '
             f'and {label("ip", "::ffff:192.0.2.1")}'),
            ('tor ' + 'A' * 56 + '.ONION:9735', f'tor {label("onion", "A" * 56 + ".ONION")}:9735'),
            ("channels_with_funds: {(b'\\xeaV', b'\\x03\\xb6'): (499980692000, 5)}, have_direct_channel=False",
             'channels_with_funds: <balances>, have_direct_channel=False'),
            (_line('lnworker.PaySession.[d9f3aa74-419e]', 'waiting'),
             _line(f'lnworker.PaySession.[{label("payment", "d9f3aa74-419e")}]', 'waiting')),
            ('interface.[myhome.example:50002] | connected', f'interface.[{label("server", "myhome.example:50002")}] | connected'),
            # the nodes and channels of the network too: whom we pay and whom we have channels with
            (f'error reported by {self.NODE_ID}', f'error reported by {label("node", self.NODE_ID[:10])}'),
            ('route: 0322222222 -[700000x5x0 0+0ppm cltv 40]-> 0344444444',
             f'route: {label("node", "0322222222", "our node")} -[{label("channel", "700000x5x0", "our channel")} 0+0ppm cltv 40]-> '
             f'{label("node", "0344444444")}'),
            ('htlc failed at edge 3 of 4 (channel 700123x456x7)', f'htlc failed at edge 3 of 4 (channel {label("channel", "700123x456x7")})'),
            # the key of an htlc, with the short channel id in hex
            ("payment_key='0c35000000640001:0'", f"payment_key='{label('channel', '800000x100x1')}:0'"),
            # a peer, with a host name the user may have typed
            (f'handshake done for {self.NODE_ID}@myhome.duckdns.org:9735',
             f'handshake done for {label("node", self.NODE_ID[:10])}@{label("host", "myhome.duckdns.org")}:9735'),
            (f'adding peer {self.NODE_ID}@my_node.lan:9735',
             f'adding peer {label("node", self.NODE_ID[:10])}@{label("host", "my_node.lan")}:9735'),
            (f'handshake done for {self.NODE_ID}@mynode:9735',
             f'handshake done for {label("node", self.NODE_ID[:10])}@{label("host", "mynode")}:9735'),
            ('failed to connect lnd-700000x1x2.example.com TimeoutError()',
             f'failed to connect {label("host", "lnd-700000x1x2.example.com")} TimeoutError()'),
            (f'adding peer {self.NODE_ID}@203.0.113.7:9735 and later 203.0.113.7, failed to connect 2001:db8::1 x',
             f'adding peer {label("node", self.NODE_ID[:10])}@{label("ip", "203.0.113.7")}:9735 and later '
             f'{label("ip", "203.0.113.7")}, failed to connect {label("ip", "2001:db8::1")} x'),
            (f'handshake done for {self.NODE_ID}@myhome.example.:9735',
             f'handshake done for {label("node", self.NODE_ID[:10])}@{label("host", "myhome.example.")}:9735'),
            ('failed to connect node.example.com [Errno -2] Name or service not known',
             f'failed to connect {label("host", "node.example.com")} [Errno -2] Name or service not known'),
            ('catching up on gossip. peers (msgs/s, old updates): 03abcd 12 300 done, 02ef01 ? 0. unknown_ids=3',
             f'catching up on gossip. peers (msgs/s, old updates): {label("node", "03abcd")} 12 300 done, {label("node", "02ef01")} ? 0. '
             'unknown_ids=3'),
        ):
            self.assertEqual(expected, redact(text), msg=text)

    def test_the_same_value_gets_the_same_label_in_any_form(self):
        node_bytes = repr(bytes.fromhex(self.NODE_ID))
        scid_bytes = repr((800000).to_bytes(3, 'big') + (100).to_bytes(3, 'big') + (1).to_bytes(2, 'big'))
        text = f'{self.NODE_ID} {self.NODE_ID[:10]} {self.NODE_ID.upper()} node_id={node_bytes} 800000x100x1 scid={scid_bytes}'
        n, c = label('node', self.NODE_ID[:10]), label('channel', '800000x100x1')
        self.assertEqual(f'{n} {n} {n} node_id={n} {c} scid={c}', redact(text))

    def test_labels_depend_on_the_key(self):
        text = f'RHASH={self.HASH} route: 0211111111 -[800000x100x1 1+1ppm]-> 0322222222'
        self.assertEqual(redact(text), redact(text))
        self.assertNotEqual(redact(text), redact_log_text(text, key=bytes(32)))
        self.assertNotEqual(redact_log_text(text), redact_log_text(text))  # without a key, a new one each time
        self.assertEqual(redact(text), redact(redact(text)))  # labels are left as they are

    def test_what_is_about_the_payment_is_kept(self):
        for text in (
            'requesting channel graph since 2026-11-15T09:50:21, for 24915 seconds',
            _line('lnworker.LNGossip', 'amount_to_pay=164927000 msat. caught up on gossip in 90 seconds'),
            'Electrum version: 4.8.4. code=<OnionFailureCode.TEMPORARY_CHANNEL_FAILURE: 4103>',
            'gossip_db status. sync progress: (26556, 26556, 100). num_nodes=11496',
            'sent htlc 6: amount=1000 msat, fee=1 msat, cltv_abs=976054. fee 1000+1ppm cltv 144',
            _line('lnpeer.Peer.[LNGossip, ?-1a2b3c4d]', 'Received INIT'),
        ):
            self.assertEqual(text, redact(text), msg=text)

    def test_our_node_channels_and_wallets(self):
        our_node_id = '02' + '11' * 32
        text = (f'nodeID={our_node_id}. route: {our_node_id[:10]} -[800000x100x1 1000+1ppm]-> 0322222222 '
                f'-[800000x100x12]-> 0344444444, again 800000x100x1 and 800000x100x2 of wallet a, not of "wallet ab"')
        us, c1, c2 = label('node', our_node_id[:10], 'our node'), label('channel', '800000x100x1', 'our channel'), \
            label('channel', '800000x100x2', 'our channel')
        self.assertEqual(
            f'nodeID={us}. route: {us} -[{c1} 1000+1ppm]-> {label("node", "0322222222")} '
            f'-[{label("channel", "800000x100x12")}]-> {label("node", "0344444444")}, again {c1} and {c2} of '
            f'{label("wallet", "wallet a")}, not of "wallet ab"',
            redact(text, our_node_ids=[our_node_id], our_channels=['800000x100x1', '800000x100x2'],
                   wallet_names=['wallet a', 'ab']))

    def test_our_node_channels_and_wallets_are_found_where_the_log_says_they_are_ours(self):
        # e.g. in the logs of a wallet that is not loaded when they get shared
        text = (_line('lnworker.LNWallet.[savings]', 'sent htlc 6 over 800000x100x1: amount=1000 msat. '
                      'route: 0211111111 -[800000x100x1 1000+1ppm, own channel]-> 0322222222')
                + _line('lnworker.LNWallet.[savings]', 'htlc succeeded. route: 0211111111 -[800000x200x0 1000+1ppm]-> 0355555555')
                + _line('lnpeer.Peer.[savings, 0322222222-1a2b3c4d]', 'loaded wallet savings; 0211111111' + '22' * 28)
                + _line('storage', 'wallet path /data/files/wallets/default_wallet')
                + _line('lnpeer.Peer.[savings, 0322222222-1a2b3c4d]', 'channel_reestablish (800000x300x2): replayed 0')
                + _line('lnworker.LNWallet.[savings]', "creating bolt11 invoice with routing_hints: [('r', "
                        "[('0322222222', '16000000x1x2', 1000, 1, 144)])]")
                + _line('lnpeer.Peer.[LNGossip, 0322222222-1a2b3c4d]', 'query 700000x1x1'))
        w, us = label('wallet', 'savings'), label('node', '0211111111', 'our node')
        c1, c2 = label('channel', '800000x100x1', 'our channel'), label('channel', '800000x200x0', 'our channel')
        self.assertEqual(
            _line(f'lnworker.LNWallet.[{w}]', f'sent htlc 6 over {c1}: amount=1000 msat. '
                  f'route: {us} -[{c1} 1000+1ppm, own channel]-> {label("node", "0322222222")}')
            + _line(f'lnworker.LNWallet.[{w}]', f'htlc succeeded. route: {us} -[{c2} 1000+1ppm]-> {label("node", "0355555555")}')
            + _line(f'lnpeer.Peer.[{w}, {label("node", "0322222222")}-1a2b3c4d]', f'loaded wallet {w}; {us}')
            + _line('storage', f'wallet path /data/files/wallets/{label("wallet", "default_wallet")}')
            + _line(f'lnpeer.Peer.[{w}, {label("node", "0322222222")}-1a2b3c4d]',
                    f'channel_reestablish ({label("channel", "800000x300x2", "our channel")}): replayed 0')
            + _line(f'lnworker.LNWallet.[{w}]', f"creating bolt11 invoice with routing_hints: [('r', "
                    f"[('{label('node', '0322222222')}', '{label('channel', '16000000x1x2', 'our channel')}', 1000, 1, 144)])]")
            + _line(f'lnpeer.Peer.[LNGossip, {label("node", "0322222222")}-1a2b3c4d]', f'query {label("channel", "700000x1x1")}'),
            redact(text))

    def test_wallet_names_whatever_they_are(self):
        text = (_line('lnworker.LNWallet.[AK]', 'paying AK from AK; peer 192.168.1.100 and node@myhome.example:9735')
                + _line('lnpeer.Peer.[AK, 0322222222-1a2b3c4d]', 'Received INIT'))
        ak = label('wallet', 'AK')
        expected = (_line(f'lnworker.LNWallet.[{ak}]', f'paying AK from AK; peer {label("ip", "192.168.1.100")} and '
                          f'node@{label("host", "myhome.example")}:9735')
                    + _line(f'lnpeer.Peer.[{ak}, {label("node", "0322222222")}-1a2b3c4d]', 'Received INIT'))
        # (a short name only in logger names, where it is a name for sure)
        self.assertEqual(expected, redact(text))
        self.assertEqual(redact(text), redact(redact(text)))
        # names that are numbers, or words of the labels, do not break the labels
        text += _line('lnworker.LNWallet.[AK]', 'route: 0211111111 -[800000x100x1 1+1ppm]-> 0322222222')
        odd = redact(text, wallet_names=['100', '9735', 'node', 'host', 'our', 'wallet'])
        self.assertIn(label('node', '0211111111', 'our node'), odd)
        self.assertIn(label('ip', '192.168.1.100'), odd)
        self.assertIn(label('host', 'myhome.example'), odd)
        self.assertIn(f'lnworker.LNWallet.[{ak}]', odd)
        self.assertNotRegex(odd, r'<[^<>]*<')  # no label within a label
        self.assertEqual(odd, redact(odd, wallet_names=['100', '9735', 'node', 'host', 'our', 'wallet']))

    def test_wallet_names_with_commas_spaces_and_other_letters(self):
        for name in ('Alexey, savings', 'Лена, личный', '<w>', 'my savings', 'ab]cd'):
            with self.subTest(name=name):
                text = (_line(f'lnworker.LNWallet.[{name}]', 'x')
                        + _line(f'lnpeer.Peer.[{name}, 0322222222-1a2b3c4d]', 'y')
                        + _line('lnworker', f'File "/data/wallets/{name}.tmp", line 1'))
                w = label('wallet', name)
                expected = (_line(f'lnworker.LNWallet.[{w}]', 'x')
                            + _line(f'lnpeer.Peer.[{w}, {label("node", "0322222222")}-1a2b3c4d]', 'y')
                            + _line('lnworker', f'File "/data/wallets/{w}.tmp", line 1'))
                self.assertEqual(expected, redact(text))  # one label, the whole name, also if it is not loaded
                self.assertEqual(expected, redact(text, wallet_names=[name]))
                # also where only the lines of its peers name it
                peer_line = _line(f'lnpeer.Peer.[{name}, 0322222222-1a2b3c4d]', 'y')
                self.assertEqual(expected.splitlines(keepends=True)[1], redact(peer_line))

    def test_what_a_peer_sends_does_not_teach_names_nor_take_long(self):
        import time
        # e.g. the text of a warning, which is logged in full
        text = (_line('lnpeer.Peer.[AK, 0322222222-1a2b3c4d]', 'warning: x lnworker.LNWallet.[LNWallet] | y '
                      + 'Peer.[a, ' * 7000 + 'LNWallet.[a] ' * 5000)
                + _line('lnworker.LNWallet.[AK]', 'paying'))
        t0 = time.monotonic()
        shared = redact(text)
        self.assertLess(time.monotonic() - t0, 5)
        self.assertIn(f'lnworker.LNWallet.[{label("wallet", "AK")}] | paying', shared)

    def test_home_directory_is_replaced(self):
        home = os.path.expanduser('~')
        self.assertEqual('File "~/electrum/lnworker.py", line 1', redact(f'File "{home}/electrum/lnworker.py", line 1'))

    def test_large_text_is_redacted_in_reasonable_time(self):
        import time
        text = _line('lnworker.LNWallet.[w]', f'sent htlc 1 over 800000x100x1: RHASH={self.HASH} route: '
                     '0211111111 -[800000x100x1 1000+1ppm]-> 0322222222') * 20_000  # ~4 MB
        t0 = time.monotonic()
        redact(text)
        self.assertLess(time.monotonic() - t0, 30)


class TestLogSharingKey(ElectrumTestCase):

    def test_created_once_and_kept(self):
        config = SimpleConfig({'electrum_path': self.electrum_path})
        self.assertIsNone(config.LOGS_SHARING_KEY)
        key = log_sharing_key(config)
        self.assertEqual(32, len(key))
        self.assertEqual(key.hex(), config.LOGS_SHARING_KEY)
        self.assertEqual(key, log_sharing_key(SimpleConfig({'electrum_path': self.electrum_path})))
        config.LOGS_SHARING_KEY = 'garbage'
        self.assertNotEqual(key, log_sharing_key(config))


class TestWhatIdentifiesUs(ElectrumTestCase):

    def test_what_identifies_us_in_the_logs_comes_from_the_wallets(self):
        from electrum.lnutil import ShortChannelID
        chan = mock.Mock(short_channel_id=ShortChannelID.from_components(800000, 100, 1))
        chan.get_local_scid_alias.return_value = ShortChannelID.from_components(16000000, 1, 2)
        chan.get_remote_scid_alias.return_value = None
        backup = mock.Mock(short_channel_id=None)
        backup.get_local_scid_alias.return_value = None
        backup.get_remote_scid_alias.return_value = ShortChannelID.from_components(16000000, 3, 4)
        with_lightning = mock.Mock()
        with_lightning.basename.return_value = 'savings'
        with_lightning.lnworker.node_keypair.pubkey = bytes.fromhex('02' + '11' * 32)
        with_lightning.lnworker.channels = {b'1': chan}
        with_lightning.lnworker.channel_backups = {b'2': backup}
        without_lightning = mock.Mock(lnworker=None)
        without_lightning.basename.return_value = 'cold'
        self.assertEqual(
            {'our_node_ids': ['02' + '11' * 32], 'our_channels': ['800000x100x1', '16000000x1x2', '16000000x3x4'],
             'wallet_names': ['savings', 'cold']},
            what_identifies_us_in_logs([with_lightning, without_lightning]))
        self.assertEqual({'our_node_ids': [], 'our_channels': [], 'wallet_names': []}, what_identifies_us_in_logs([]))


class TestReadRecentLogs(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.log_dir = pathlib.Path(self.config.path) / 'logs'
        self.log_dir.mkdir()

    def _write(self, name: str, lines):
        with open(self.log_dir / name, 'w', encoding='utf-8') as f:
            f.write(''.join(line + '\n' for line in lines))

    def test_newest_files_come_last_and_the_text_starts_at_a_whole_line(self):
        self._write('electrum_log_20261114T000000Z_1.log', ['old-1', 'old-2'])
        self._write('electrum_log_20261115T000000Z_2.log.1', ['mid-1', 'mid-2'])  # rotated: older than .log
        self._write('electrum_log_20261115T000000Z_2.log', ['new-1', 'new-2'])
        self._write('something-else.txt', ['not a log'])
        self.assertEqual('old-1\nold-2\nmid-1\nmid-2\nnew-1\nnew-2\n', read_recent_logs(self.config, max_size=1000))
        self.assertEqual('mid-2\nnew-1\nnew-2\n', read_recent_logs(self.config, max_size=20))
        self.assertEqual('new-2\n', read_recent_logs(self.config, max_size=7))
        self.assertEqual('new-1\nnew-2\n', read_recent_logs(self.config, max_size=12))  # a whole file
        self.assertEqual('new-2\n', read_recent_logs(self.config, max_size=6))  # starts right at a line

    def test_a_file_cut_in_the_middle_of_a_line_does_not_continue_in_the_next_one(self):
        with open(self.log_dir / 'electrum_log_20261114T000000Z_1.log', 'w', encoding='utf-8') as f:
            f.write('old-1\nold-2 cut')
        self._write('electrum_log_20261115T000000Z_2.log', ['new-1'])
        self.assertEqual('old-1\nold-2 cut\nnew-1\n', read_recent_logs(self.config, max_size=1000))

    def test_no_logs(self):
        self.assertEqual('', read_recent_logs(self.config, max_size=1000))
        os.rmdir(self.log_dir)
        self.assertEqual('', read_recent_logs(self.config, max_size=1000))


class TestSetFileLogging(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        if electrum_logging.get_logfile_path() is not None:
            self.skipTest('the test process writes logs to a file already')
        self.addCleanup(set_file_logging, self.config, False)

    def test_file_logging_starts_and_stops_while_running(self):
        set_file_logging(self.config, True)
        path = electrum_logging.get_logfile_path()
        self.assertEqual(pathlib.Path(self.config.path) / 'logs', path.parent)
        logger = electrum_logging.get_logger('test_file_logging')
        logger.warning('written to the file')
        self.assertIn('Electrum version', path.read_text(encoding='utf-8'))  # (what the developers want to know)
        set_file_logging(self.config, True)  # again: nothing changes
        self.assertEqual(path, electrum_logging.get_logfile_path())
        set_file_logging(self.config, False)
        self.assertIsNone(electrum_logging.get_logfile_path())
        logger.warning('not written any more')
        with open(path, encoding='utf-8') as f:
            content = f.read()
        self.assertIn('written to the file', content)
        self.assertNotIn('not written any more', content)
        set_file_logging(self.config, False)  # again: nothing changes
        # switched on again within the same second: a new file, the first one is kept
        set_file_logging(self.config, True)
        self.assertNotEqual(path, electrum_logging.get_logfile_path())
        with open(path, encoding='utf-8') as f:
            self.assertEqual(content, f.read())

    def test_a_debug_build_always_writes_logs(self):
        set_file_logging(self.config, True)
        with mock.patch('electrum.util.is_android_debug_apk', return_value=True):
            set_file_logging(self.config, False)
        self.assertIsNotNone(electrum_logging.get_logfile_path())
