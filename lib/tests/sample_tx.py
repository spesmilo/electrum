# sample transactions, for testnet and mainnet
# list of samples, each sample will be tested depending on supplied parameters
# each sample is a dict of
#       raw - signed tx blob
#       tx - expected deserialization of 'raw'
#       raw_unsigned - unsigned tx blob
#       tx_unsigned - expected deserialization of 'raw_unsigned'
#       outputs - expected output of tx.get_outputs()
#       ouputaddresses - expected output of tx.get_output_addresses(), also used to test tx.has_address()
#       txid - the id of the complete (signed) tx - used to test Transaction.txid()
#       keypairs - key pairs for signing tx - BE CAREFUL ONLY USE TESTNET
#       inputvalues - the values of inputs
sample_tx_testnet = [
    {  # standard tx, from public testnet electron cash wallet to another testnet electron cash wallet
        'raw_unsigned': '0100000001f67f0082045b3da782a3c44ff677e8f6f711fc8bf744c85298f8f15883b0fce7000000005701ff4c53ff043587cf000000000000000000b5668482ecaab929ba9d04c358f171901398519b8c81b3ae860ed68ab0ecf01e023cc396f788f47edee48068fe79ec46cf4065d8cc3546a03648cad58aa281b56d00000000feffffff0210270000000000001976a9147adbcfb7469cee9efcede1353d205fdb32b0566988ac94560100000000001976a914e045289a6ba6806055b2e9aa96dd92ad83afc18888ac00000000',
        'tx_unsigned': {
            'inputs': [{
                'signatures': [None],
                'prevout_hash': 'e7fcb08358f1f89852c844f78bfc11f7f6e877f64fc4a382a73d5b0482007ff6',
                'scriptSig': '01ff4c53ff043587cf000000000000000000b5668482ecaab929ba9d04c358f171901398519b8c81b3ae860ed68ab0ecf01e023cc396f788f47edee48068fe79ec46cf4065d8cc3546a03648cad58aa281b56d00000000',
                'sequence': 4294967294,
                'x_pubkeys': [
                    'ff043587cf000000000000000000b5668482ecaab929ba9d04c358f171901398519b8c81b3ae860ed68ab0ecf01e023cc396f788f47edee48068fe79ec46cf4065d8cc3546a03648cad58aa281b56d00000000'
                ],
                'address': 'mx6w8bqyDQHZUJP6vAUVgXAoL6U1QnDgEJ',
                'num_sig': 1,
                'pubkeys': ['035996a16b51eed04a678aa0c5637a0d6d688ac2b6c2b36cc646af72381337c669'],
                'type': 'p2pkh',
                'prevout_n': 0
            }],
            'lockTime': 0,
            'version': 1,
            'outputs': [{
                'prevout_n': 0,
                'scriptPubKey': '76a9147adbcfb7469cee9efcede1353d205fdb32b0566988ac',
                'type': 0,
                'value': 10000,
                'address': 'mria4Djx9XZ3zJLYxSEfd7ShcJNdTHMmst'
            },{
                'prevout_n': 1,
                'scriptPubKey': '76a914e045289a6ba6806055b2e9aa96dd92ad83afc18888ac',
                'type': 0,
                'value': 87700,
                'address': 'n1xnWFMLF9xkcUxL3ZwQKbGkRNBpGKdFjt'
            }]
        },
        'keypairs': {'ff043587cf000000000000000000b5668482ecaab929ba9d04c358f171901398519b8c81b3ae860ed68ab0ecf01e023cc396f788f47edee48068fe79ec46cf4065d8cc3546a03648cad58aa281b56d00000000': 'cW66cr1e6sXF4T5QuAzU6UZbrVkMuPeuTWhodZX2MJ1kdBkr3r7A'},
        'inputvalues': [100000],
        'raw': '0100000001f67f0082045b3da782a3c44ff677e8f6f711fc8bf744c85298f8f15883b0fce7000000006b48304502210082422e8b395e44e60d116652465ff22157ee3abbb2529163aeabc0c57bee718c02206d2c19bda83b6c8e861ed9936eda93819364dafefa2a14517b7958b9d59d05124121035996a16b51eed04a678aa0c5637a0d6d688ac2b6c2b36cc646af72381337c669feffffff0210270000000000001976a9147adbcfb7469cee9efcede1353d205fdb32b0566988ac94560100000000001976a914e045289a6ba6806055b2e9aa96dd92ad83afc18888ac00000000',
        'outputs': [('mria4Djx9XZ3zJLYxSEfd7ShcJNdTHMmst', 10000),('n1xnWFMLF9xkcUxL3ZwQKbGkRNBpGKdFjt',87700)],
        'outputaddresses': ['mria4Djx9XZ3zJLYxSEfd7ShcJNdTHMmst','n1xnWFMLF9xkcUxL3ZwQKbGkRNBpGKdFjt'],
        'input_txs': ['01000000010607d3ce6eb8e892ef110d26643c962fd53d04ea4c4429ef0954e17ae9d9ef28000000006b483045022100cee875b264d8b201b197eb0b062793925add3d924d53904a22a42c9f6d60779502201a166c4bb0cd3eea7d8953acc450ff8bf1daeb5823d6931788e5b438b2bbc890412102ef9e36c431cdfa97033ffef9f19a7a9bd849f5db45054ecd4007a5893e17c6d3feffffff02a0860100000000001976a914b5ef2f37793fa1c0a7fff8363685ced547d46eee88ac3cba7a4d000000001976a91495b2610cb0759125b382e6cacef6542b7a592e9088ac00000000'],
    },
]

sample_tx_mainnet = [
    {
        'raw': '020000000121f8030318ce76131e8b3c8f45e0c520e6a8e06515766080edfada23658a5512000000006a47304402203422fad67115b00671af96510b73b87b71499dbd9b482c1bb5aa5da4533ff411022021a49b5448f463d6b54da24d86da872b9e9883fc5bfac2063c1cebde2c2da7264121028bbab2552f9568b687915d68a2ce55f682a81da4a63120b9d8d72db43cc657c1feffffff02802600000000000017a9143284a4e0b824fea4fad46dd764712459bdc49dca87e14d0900000000001976a914a306d546bbaa717f90d788cc8edc21f537cc4d2b88ac9c8b0700',
        'txid': 'c15f904d85e0773d46f5418237422fceb9762e718d21369dc7dfe0a078e7f3b5',
        'tx': {
            'inputs': [{
                'signatures': ['304402203422fad67115b00671af96510b73b87b71499dbd9b482c1bb5aa5da4533ff411022021a49b5448f463d6b54da24d86da872b9e9883fc5bfac2063c1cebde2c2da72641'],
                'prevout_hash': '12558a6523dafaed8060761565e0a8e620c5e0458f3c8b1e1376ce180303f821',
                'scriptSig': '47304402203422fad67115b00671af96510b73b87b71499dbd9b482c1bb5aa5da4533ff411022021a49b5448f463d6b54da24d86da872b9e9883fc5bfac2063c1cebde2c2da7264121028bbab2552f9568b687915d68a2ce55f682a81da4a63120b9d8d72db43cc657c1',
                'sequence': 4294967294,
                'x_pubkeys': ['028bbab2552f9568b687915d68a2ce55f682a81da4a63120b9d8d72db43cc657c1'],
                'address': '1331F4BdeChHwFr9njUB78c2LwF87EJjjT',
                'num_sig': 1,
                'pubkeys': ['028bbab2552f9568b687915d68a2ce55f682a81da4a63120b9d8d72db43cc657c1'],
                'type': 'p2pkh',
                'prevout_n': 0
            }],
            'lockTime': 494492,
            'version': 2,
            'outputs': [{
                'prevout_n': 0,
                'scriptPubKey': 'a9143284a4e0b824fea4fad46dd764712459bdc49dca87',
                'type': 0,
                'value': 9856,
                'address': '36J8cQV5WZVRxxZJ3DwRjeta1RH9QRR3FN'
            }, {
                'prevout_n': 1,
                'scriptPubKey': '76a914a306d546bbaa717f90d788cc8edc21f537cc4d2b88ac',
                'type': 0,
                'value': 609761,
                'address': '1Fs1L3PcASQC5AKyZ5ahdJFeJMN7MNSwXg'
            }]
        },
    },
    {
        'txid': 'b78209426e08bf64147de99ee84014daa212d8942d28dbe5c5e552d818579fe0',
        'raw': '02000000026540eb0223a46ccd7de94ac68cf29b81030c6388dd8feb87442f115610c88724010000008b4830450221008bf9e5a522d3e229e25a185178ccbd9ff957c87480ca70ada25dd1b1755b79d802200bbfc99d8ae21a35bb4141dea0529aea114e57fd08f5c13d559f6eed17ec2bd8414104dcab7b8f51749c30390e85cafa0f0a7d3c5ea596575f59d21b8bab966294a0527fc8de2cc96a9f5f806a5a969be6ff42326745acf0bd2d2f36b66c7977ef3323ffffffff37b3b68131907d3691018771efff9e090d6db30ea7247ecc76fb6085a5b98cd8020000008a473044022065b73305c421af4fafd62e720951155c09ed9db5058aec966690a58664e88dc402202b2c7fddbb4ed77cb66bcda1add2da5e96db53be0a8168357ab697b7fb0df7b24141040baa4271a82c5f1a09a5ea63d763697ca0545b6049c4dd8e8d099dd91f2da10eb11e829000a82047ac56969fb582433067a21c3171e569d1832c34fdd793cfc8ffffffff030000000000000000226a20e73f3eac9da99afe7dc7822828a705f07d271372411494e58391d08ceb0ce508e4412b01000000001976a9148b80536aa3c460258cda834b86a46787c9a2b0bf88ac51bf0700000000001976a914a62d57e0f658a7926959099f617a850206063dae88ac00000000',
        'tx': {
            'inputs': [{
                'signatures': ['30450221008bf9e5a522d3e229e25a185178ccbd9ff957c87480ca70ada25dd1b1755b79d802200bbfc99d8ae21a35bb4141dea0529aea114e57fd08f5c13d559f6eed17ec2bd841'],
                'prevout_hash': '2487c81056112f4487eb8fdd88630c03819bf28cc64ae97dcd6ca42302eb4065',
                'scriptSig': '4830450221008bf9e5a522d3e229e25a185178ccbd9ff957c87480ca70ada25dd1b1755b79d802200bbfc99d8ae21a35bb4141dea0529aea114e57fd08f5c13d559f6eed17ec2bd8414104dcab7b8f51749c30390e85cafa0f0a7d3c5ea596575f59d21b8bab966294a0527fc8de2cc96a9f5f806a5a969be6ff42326745acf0bd2d2f36b66c7977ef3323',
                'sequence': 4294967295,
                'x_pubkeys': ['04dcab7b8f51749c30390e85cafa0f0a7d3c5ea596575f59d21b8bab966294a0527fc8de2cc96a9f5f806a5a969be6ff42326745acf0bd2d2f36b66c7977ef3323'],
                'address': '1Dice5ycHmxDHUFVkdKGgrwsDDK1mPES3U',
                'num_sig': 1,
                'pubkeys': ['04dcab7b8f51749c30390e85cafa0f0a7d3c5ea596575f59d21b8bab966294a0527fc8de2cc96a9f5f806a5a969be6ff42326745acf0bd2d2f36b66c7977ef3323'],
                'type': 'p2pkh',
                'prevout_n': 1
            }, {
                'signatures': ['3044022065b73305c421af4fafd62e720951155c09ed9db5058aec966690a58664e88dc402202b2c7fddbb4ed77cb66bcda1add2da5e96db53be0a8168357ab697b7fb0df7b241'],
                'prevout_hash': 'd88cb9a58560fb76cc7e24a70eb36d0d099effef71870191367d903181b6b337',
                'scriptSig': '473044022065b73305c421af4fafd62e720951155c09ed9db5058aec966690a58664e88dc402202b2c7fddbb4ed77cb66bcda1add2da5e96db53be0a8168357ab697b7fb0df7b24141040baa4271a82c5f1a09a5ea63d763697ca0545b6049c4dd8e8d099dd91f2da10eb11e829000a82047ac56969fb582433067a21c3171e569d1832c34fdd793cfc8',
                'sequence': 4294967295,
                'x_pubkeys': ['040baa4271a82c5f1a09a5ea63d763697ca0545b6049c4dd8e8d099dd91f2da10eb11e829000a82047ac56969fb582433067a21c3171e569d1832c34fdd793cfc8'],
                'address': '1DiceuELb5GZktc3CMEv868DMtU3B5957x',
                'num_sig': 1,
                'pubkeys': ['040baa4271a82c5f1a09a5ea63d763697ca0545b6049c4dd8e8d099dd91f2da10eb11e829000a82047ac56969fb582433067a21c3171e569d1832c34fdd793cfc8'],
                'type': 'p2pkh',
                'prevout_n': 2
            }],
            'lockTime': 0,
            'version': 2,
            'outputs': [{
                'prevout_n': 0,
                'scriptPubKey': '6a20e73f3eac9da99afe7dc7822828a705f07d271372411494e58391d08ceb0ce508',
                'type': 2,
                'value': 0,
                'address': "j \xe7?>\xac\x9d\xa9\x9a\xfe}\xc7\x82((\xa7\x05\xf0}'\x13rA\x14\x94\xe5\x83\x91\xd0\x8c\xeb\x0c\xe5\x08"
            }, {
                'prevout_n': 1,
                'scriptPubKey': '76a9148b80536aa3c460258cda834b86a46787c9a2b0bf88ac',
                'type': 0,
                'value': 19612132,
                'address': '1DiceuELb5GZktc3CMEv868DMtU3B5957x'
            }, {
                'prevout_n': 2,
                'scriptPubKey': '76a914a62d57e0f658a7926959099f617a850206063dae88ac',
                'type': 0,
                'value': 507729,
                'address': '1G9fVMJ9o1PW2tpb4MpoDHN3A8urBa3LCb'
            }]
        },
    }
]