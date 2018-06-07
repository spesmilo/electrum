import time
import queue
from . import util
from . import network
from . import bitcoin
from .i18n import _


class ElectrumX(network.Network):
    """ The ElectrumX class defines all ElectrumX specific API calls.

    See https://electrumx.readthedocs.io/en/latest/protocol-basics.html
    """

    def __init__(self, config=None):
        super().__init__(config)

        self.__hash2address = {}

    # Deprecated in favor of headers
    def get_chunk(self, index, callback=None):
        command = 'blockchain.block.get_chunk'
        invocation = lambda c: self._send([(command, [index])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    # TODO clean this method up. It should have no reference to interface.
    def request_header(self, interface, height):
        self._queue_request('blockchain.block.get_header', [height], interface)
        interface.request = height
        interface.req_time = time.time()

    def __map_scripthash_to_address(self, callback):
        """ This method takes a callback and wraps it in an other callback.
        The new callback modifies the response passed to the original callback
        by replacing the scripthash returned by the backend server with the
        address which initially yielded this scripthash
        """
        def replacing_callback(original_response):
            new_response = original_response.copy()
            params = new_response.pop('params')
            address = self.__hash2address[params[0]]
            new_response['params'] = [address]
            callback(new_response)
        return replacing_callback

    def subscribe_to_scripthashes(self, hashes, callback=None):
        command = 'blockchain.scripthash.subscribe'
        messages = [(command, [hash_]) for hash_ in hashes]
        invocation = lambda c: self._send(messages, c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def subscribe_to_addresses(self, addresses, callback=None):
        """ Converts the list of addresses to scripthashes and delegates to
        subscribe_to_scripthashes. """
        scripthashes = {
            bitcoin.address_to_scripthash(address): address
            for address in addresses}
        self.__hash2address.update(scripthashes)

        if not callback:
            callback = ElectrumX.__wait_for

        return self.subscribe_to_scripthashes(
            scripthashes,
            self.__map_scripthash_to_address(callback))

    # NOTE this method handles exceptions and a special edge case, counter to
    # what the other ElectrumX methods do. This is unexpected.
    def broadcast_transaction(self, transaction, callback=None):
        command = 'blockchain.transaction.broadcast'
        invocation = lambda c: self._send([(command, [str(transaction)])], c)

        if callback:
            invocation(callback)
            return

        try:
            out = ElectrumX.__wait_for(invocation)
        except BaseException as e:
            return False, "error: " + str(e)

        if out != transaction.txid():
            return False, "error: " + out

        return True, out

    def get_history_for_address(self, address, callback=None):
        scripthash = bitcoin.address_to_scripthash(address)
        self.__hash2address.update({scripthash: address})

        if not callback:
            callback = ElectrumX.__wait_for

        return self.get_history_for_scripthash(
            scripthash,
            self.__map_scripthash_to_address(callback))

    def get_history_for_scripthash(self, hash, callback=None):
        command = 'blockchain.scripthash.get_history'
        invocation = lambda c: self._send([(command, [hash])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def headers(self, start_height, count, callback=None):
        command = 'blockchain.block.headers'
        invocation = lambda c: self._send([(command, [start_height, count])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def subscribe_to_headers(self, callback=None):
        command = 'blockchain.headers.subscribe'
        invocation = lambda c: self._send([(command, [True])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def get_merkle_for_transaction(self, tx_hash, tx_height, callback=None):
        command = 'blockchain.transaction.get_merkle'
        invocation = lambda c: self._send([(command, [tx_hash, tx_height])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def subscribe_to_scripthash(self, scripthash, callback=None):
        command = 'blockchain.scripthash.subscribe'
        invocation = lambda c: self._send([(command, [scripthash])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def get_transaction(self, transaction_hash, callback=None):
        command = 'blockchain.transaction.get'
        invocation = lambda c: self._send([(command, [transaction_hash])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def get_transactions(self, transaction_hashes, callback=None):
        command = 'blockchain.transaction.get'
        messages = [(command, [tx_hash]) for tx_hash in transaction_hashes]
        invocation = lambda c: self._send(messages, c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def listunspent_for_scripthash(self, scripthash, callback=None):
        command = 'blockchain.scripthash.listunspent'
        invocation = lambda c: self._send([(command, [scripthash])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def get_balance_for_scripthash(self, scripthash, callback=None):
        command = 'blockchain.scripthash.get_balance'
        invocation = lambda c: self._send([(command, [scripthash])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def server_version(self, client_name, protocol_version, callback=None):
        command = 'server.version'
        invocation = lambda c: self._send([(command, [client_name, protocol_version])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    @staticmethod
    def __wait_for(it):
        """Wait for the result of calling lambda `it`."""
        q = queue.Queue()
        it(q.put)
        try:
            result = q.get(block=True, timeout=30)
        except queue.Empty:
            raise util.TimeoutException(_('Server did not answer'))

        if result.get('error'):
            raise Exception(result.get('error'))

        return result.get('result')

    @staticmethod
    def __with_default_synchronous_callback(invocation, callback):
        """ Use this method if you want to make the network request
        synchronous. """
        if not callback:
            return ElectrumX.__wait_for(invocation)

        invocation(callback)
