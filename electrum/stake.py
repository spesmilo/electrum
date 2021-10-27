import datetime
import itertools
import json
import secrets
import socket
import ssl

from .bitcoin import address_to_scripthash


class SocketConnector:
    def __init__(self, host, port, use_ssl=False, timeout=5):
        self._host = host
        self._port = port
        self._use_ssl = use_ssl
        self._timeout = timeout

        self._connection = self._create_connection()
        self._connection.connect((self._host, self._port))

    def _create_connection(self):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(self._timeout)
        if self._use_ssl:
            connection = ssl.wrap_socket(connection)

        return connection

    def _receive_data(self, convert_to_json=True):
        readed_bytes = bytearray()
        while readed_bytes[-1:] != b'\n':
            chunk = self._connection.recv(1024)
            readed_bytes.extend(chunk)

        if convert_to_json:
            return json.loads(readed_bytes)
        else:
            return readed_bytes.decode()

    def send_and_receive_data(self, data_string: str, convert_to_json=True):
        self._connection.send(f'{data_string}\n'.encode())

        return self._receive_data(convert_to_json=convert_to_json)


class StakeElectrumXAPIDataService:
    LIST_UNSPEND_METHOD_NAME = 'blockchain.scripthash.listunspent'
    TRANSACTION_GET_STAKE_METHOD_NAME = 'blockchain.transaction.get_stake'
    BLOCK_HEADER_METHOD_NAME = 'blockchain.block.header'
    BLOCK_TRANSACTION_METHOD_NAME = 'blockchain.transaction.get'

    def __init__(self, connector):
        self._connector = connector

    @staticmethod
    def generate_api_payload(method: str, params: list):
        return json.dumps(
            {
                'method': method,
                'params': params,
                'id': secrets.randbelow(100),
            }
        )

    @staticmethod
    def extract_timestamp_from_block_header_hash(block_hash):
        header_timestamp = int(block_hash[142:150], 16)

        return datetime.datetime.utcfromtimestamp(header_timestamp).strftime(
            '%Y-%m-%d %H:%M:%S'
        )  # TODO

    def get_detailed_data_for_tx(self, tx_hash):
        stake_data = self._connector.send_and_receive_data(
            data_string=self.generate_api_payload(
                method=self.BLOCK_TRANSACTION_METHOD_NAME, params=[tx_hash, 1]
            )
        )
        # etailed_stake_data = stake_data['result']['stakingInfo']
        no_staking_info = {
            'deposit_height': 0,
            'staking_period': 0,
            'staking_amount': 0,
            'accumulated_reward': 0,
            'fulfilled': True,
            'paid_out': False
        }
        detailed_stake_data = stake_data['result'].get('stakingInfo', no_staking_info)
        header_data = self._connector.send_and_receive_data(
            data_string=self.generate_api_payload(
                method=self.BLOCK_HEADER_METHOD_NAME,
                params=[int(detailed_stake_data['deposit_height'])],
            )
        )
        try:
            detailed_stake_data['timestamp'] = self.extract_timestamp_from_block_header_hash(
                block_hash=header_data['result']
            )

        except KeyError:  # todo: get normal tx and sent to UI as not stake yet
            detailed_stake_data['timestamp'] = 'Pending'
        return detailed_stake_data

    def get_tx_details(self, tx_hash):
        tx_data = self._connector.send_and_receive_data(
            data_string=self.generate_api_payload(
                method=self.BLOCK_TRANSACTION_METHOD_NAME,
                params=[tx_hash, 1]
            )
        )
        return tx_data

    def get_detailed_stakes_data_for_address(self, address: str):
        listunspent_data = self._connector.send_and_receive_data(
            data_string=self.generate_api_payload(
                method=self.LIST_UNSPEND_METHOD_NAME,
                params=[address_to_scripthash(addr=address)],
            )
        )

        stakes_data = [
            {'tx_hash': data['tx_hash']}
            for data in listunspent_data['result']
            if data['is_stake'] == 1
        ]
        detailed_stakes_data = [
            self.get_detailed_data_for_tx(tx_hash=data['tx_hash']) for data in stakes_data
        ]
        try:
            return [
                {**stake_data, **detailed_stake_data}
                for stake_data, detailed_stake_data in zip(stakes_data, detailed_stakes_data)
            ]
        except TypeError:
            print('Jeszcze nie uznany przez electrum X za stake')

    def get_detailed_stakes_data_for_addresses(self, addresses):
        try:  # todo przenieść do środka bo inaczej nie pokzuje stakeów prawidłowych
            return list(
                itertools.chain(
                    *[
                        self.get_detailed_stakes_data_for_address(address=address)
                        for address in addresses
                    ]
                )
            )
        except TypeError:
            print('prawdopodobnie jeszcze nie uznany za stake w electrumX')

connector = SocketConnector(
    host='electrumx.testnet.ec.stage.rnd.land', port=443, use_ssl=True  # TODO
)

stake_api = StakeElectrumXAPIDataService(connector=connector)
