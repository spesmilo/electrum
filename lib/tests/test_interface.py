import unittest

from lib import interface


class TestInterface(unittest.TestCase):

    def test_match_host_name(self):
        self.assertTrue(interface._match_hostname('asd.fgh.com', 'asd.fgh.com'))
        self.assertFalse(interface._match_hostname('asd.fgh.com', 'asd.zxc.com'))
        self.assertTrue(interface._match_hostname('asd.fgh.com', '*.fgh.com'))
        self.assertFalse(interface._match_hostname('asd.fgh.com', '*fgh.com'))
        self.assertFalse(interface._match_hostname('asd.fgh.com', '*.zxc.com'))

    def test_check_host_name(self):
        self.assertFalse(interface.check_host_name(None, None))
        self.assertFalse(interface.check_host_name(
            peercert={'subjectAltName': []}, name=''))
        self.assertTrue(interface.check_host_name(
            peercert={'subjectAltName': [('DNS', '*.bar.com')]},
            name='foo.bar.com'))
        self.assertTrue(interface.check_host_name(
            peercert={'subject': [('commonName', '*.bar.com')]},
            name='foo.bar.com'))
