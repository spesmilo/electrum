import unittest

from electrum_ltc import interface

from . import SequentialTestCase


class TestInterface(SequentialTestCase):

    def test_match_host_name(self):
        self.assertTrue(interface._match_hostname('asd.fgh.com', 'asd.fgh.com'))
        self.assertFalse(interface._match_hostname('asd.fgh.com', 'asd.zxc.com'))
        self.assertTrue(interface._match_hostname('asd.fgh.com', '*.fgh.com'))
        self.assertFalse(interface._match_hostname('asd.fgh.com', '*fgh.com'))
        self.assertFalse(interface._match_hostname('asd.fgh.com', '*.zxc.com'))

    def test_check_host_name(self):
        i = interface.TcpConnection(server=':1:', queue=None, config_path=None)

        self.assertFalse(i.check_host_name(None, None))
        self.assertFalse(i.check_host_name(
            peercert={'subjectAltName': []}, name=''))
        self.assertTrue(i.check_host_name(
            peercert={'subjectAltName': [('DNS', 'foo.bar.com')]},
            name='foo.bar.com'))
        self.assertTrue(i.check_host_name(
            peercert={'subject': [('commonName', 'foo.bar.com')]},
            name='foo.bar.com'))
