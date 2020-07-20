from unittest import TestCase

from electrum.bitcoin import redeem_script_to_address
from electrum.constants import BitcoinVaultRegtest
from electrum.three_keys.script import TwoKeysScriptGenerator, ThreeKeysScriptGenerator, ThreeKeysError


class TestScripts(TestCase):
    def setUp(self) -> None:
        self.recovery_pub_key = '02ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c'
        self.instant_pub_key = '0263451a52f3d3ae6918969e1c5ce934743185578481ef8130336ad1726ba61ddb'

        self.random_2keys_pub_key = '02a3bcaf41515051185b05a6c1cda191a519d96797359ea2eca4efbf3af0389eb9'
        self.random_3keys_pub_key = '0322b4675430c8d89f42418bb4e61ad95ece3c89804f482a1be3e206ad86633116'

    def test_2keys_redeem_script(self):
        generator = TwoKeysScriptGenerator(recovery_pubkey=self.recovery_pub_key)
        redeem_script = generator.get_redeem_script([self.random_2keys_pub_key])
        self.assertEqual(
 '63516752682102a3bcaf41515051185b05a6c1cda191a519d96797359ea2eca4efbf3af0389eb92102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c52ae',
            redeem_script
        )

    def test_3keys_redeem_script(self):
        generator = ThreeKeysScriptGenerator(recovery_pubkey=self.recovery_pub_key, instant_pubkey=self.instant_pub_key)
        redeem_script = generator.get_redeem_script([self.random_3keys_pub_key])
        self.assertEqual(
'635167635267536868210322b4675430c8d89f42418bb4e61ad95ece3c89804f482a1be3e206ad86633116210263451a52f3d3ae6918969e1c5ce934743185578481ef8130336ad1726ba61ddb2102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c53ae',
            redeem_script
        )

    def test_address_generation_for_2keys(self):
        generator = TwoKeysScriptGenerator(recovery_pubkey=self.recovery_pub_key)
        redeem_script = generator.get_redeem_script([self.random_2keys_pub_key])
        address = redeem_script_to_address(
            txin_type='p2sh',
            scriptcode=redeem_script,
            net=BitcoinVaultRegtest
        )
        self.assertEqual(
            '2MzJp4FAYMQAdL8XLsvizG8d26vDSHdHH4g',
            address
        )

    def test_address_generation_for_3keys(self):
        generator = ThreeKeysScriptGenerator(recovery_pubkey=self.recovery_pub_key, instant_pubkey=self.instant_pub_key)
        redeem_script = generator.get_redeem_script([self.random_3keys_pub_key])
        address = redeem_script_to_address(
            txin_type='p2sh',
            scriptcode=redeem_script,
            net=BitcoinVaultRegtest
        )
        self.assertEqual(
            '2NDdnzhZXEjj8HGoY5AKQUfh2KtFpPv3z4u',
            address
        )

    def _test_errors(self, generator):
        pub_key = ['a', 'b', 'c']
        with self.assertRaises(ThreeKeysError) as err:
            generator.get_redeem_script(pub_key)
        self.assertTrue('Wrong input type! Expected list' in str(err.exception))

        pub_key = []
        with self.assertRaises(ThreeKeysError) as err:
            generator.get_redeem_script(pub_key)
        self.assertTrue('Wrong input type! Expected list' in str(err.exception))

        pub_key = 'abcdef'
        with self.assertRaises(ThreeKeysError) as err:
            generator.get_redeem_script(pub_key)
        self.assertTrue('Wrong input type! Expected list' in str(err.exception))

        with self.assertRaises(ThreeKeysError) as err:
            generator.get_script_sig([], [])
        self.assertTrue('Recovery/alert' in str(err.exception))

    def test_2keys_errors(self):
        generator = TwoKeysScriptGenerator(recovery_pubkey=self.recovery_pub_key)
        self._test_errors(generator)

    def test_3keys_errors(self):
        generator = ThreeKeysScriptGenerator(recovery_pubkey=self.recovery_pub_key, instant_pubkey=self.instant_pub_key)
        self._test_errors(generator)
