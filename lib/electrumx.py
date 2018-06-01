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

    def request_header(self, interface, height):
        self.queue_request('blockchain.block.get_header', [height], interface)
        interface.request = height
        interface.req_time = time.time()

    def map_scripthash_to_address(self, callback):
        def cb2(x):
            x2 = x.copy()
            p = x2.pop('params')
            addr = self.h2addr[p[0]]
            x2['params'] = [addr]
            callback(x2)
        return cb2

    def subscribe_to_addresses(self, addresses, callback):
        hash2address = {
            bitcoin.address_to_scripthash(address): address
            for address in addresses}
        self.h2addr.update(hash2address)
        msgs = [
            ('blockchain.scripthash.subscribe', [x])
            for x in hash2address.keys()]
        self.send(msgs, self.map_scripthash_to_address(callback))

    def request_address_history(self, address, callback):
        h = bitcoin.address_to_scripthash(address)
        self.h2addr.update({h: address})
        self.send(
            [('blockchain.scripthash.get_history', [h])],
            self.map_scripthash_to_address(callback))

    # NOTE this method handles exceptions and a special edge case, counter to
    # what the other ElectrumX methods do. This is unexpected.
    def broadcast_transaction(self, transaction, callback=None):
        command = 'blockchain.transaction.broadcast'
        invocation = lambda c: self.send([(command, [str(transaction)])], c)

        if callback:
            invocation(callback)

        try:
            out = ElectrumX.__wait_for(invocation)
        except BaseException as e:
            return False, "error: " + str(e)

        if out != transaction.txid():
            return False, "error: " + out

        return True, out

    def get_history_for_scripthash(self, hash, callback=None):
        command = 'blockchain.scripthash.get_history'
        invocation = lambda c: self.send([(command, [hash])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def subscribe_to_headers(self, callback=None):
        command = 'blockchain.headers.subscribe'
        invocation = lambda c: self.send([(command, [])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def subscribe_to_address(self, address, callback=None):
        command = 'blockchain.address.subscribe'
        invocation = lambda c: self.send([(command, [address])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def get_merkle_for_transaction(self, tx_hash, tx_height, callback=None):
        command = 'blockchain.transaction.get_merkle'
        invocation = lambda c: self.send([(command, [tx_hash, tx_height])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def subscribe_to_scripthash(self, scripthash, callback=None):
        command = 'blockchain.scripthash.subscribe'
        invocation = lambda c: self.send([(command, [scripthash])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def get_transaction(self, transaction_hash, callback=None):
        command = 'blockchain.transaction.get'
        invocation = lambda c: self.send([(command, [transaction_hash])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def get_transactions(self, transaction_hashes, callback=None):
        command = 'blockchain.transaction.get'
        messages = [(command, [tx_hash]) for tx_hash in transaction_hashes]
        invocation = lambda c: self.send(messages, c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def listunspent_for_scripthash(self, scripthash, callback=None):
        command = 'blockchain.scripthash.listunspent'
        invocation = lambda c: self.send([(command, [scripthash])], c)

        return ElectrumX.__with_default_synchronous_callback(
            invocation,
            callback)

    def get_balance_for_scripthash(self, scripthash, callback=None):
        command = 'blockchain.scripthash.get_balance'
        invocation = lambda c: self.send([(command, [scripthash])], c)

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
