import cbor
import hashlib
import json
import time
import logging
import collections
import collections.abc
import traceback
import random
import sys


# JadeError
from .jade_error import JadeError

# Low-level comms backends
from .jade_serial import JadeSerialImpl
from .jade_tcp import JadeTCPImpl

# Not used in electrum wallet
# Removed to reduce transitive dependencies
# from .jade_ble import JadeBleImpl


# Default serial connection
DEFAULT_SERIAL_DEVICE = '/dev/ttyUSB0'
DEFAULT_BAUD_RATE = 115200
DEFAULT_SERIAL_TIMEOUT = 120

# Default BLE connection
DEFAULT_BLE_DEVICE_NAME = 'Jade'
DEFAULT_BLE_SERIAL_NUMBER = None
DEFAULT_BLE_SCAN_TIMEOUT = 60

# 'jade' logger
logger = logging.getLogger('jade')
device_logger = logging.getLogger('jade-device')


# Helper to map bytes-like types into hex-strings
# to make for prettier message-logging
def _hexlify(data):
    if data is None:
        return None
    elif isinstance(data, bytes) or isinstance(data, bytearray):
        return data.hex()
    elif isinstance(data, list):
        return [_hexlify(item) for item in data]
    elif isinstance(data, dict):
        return {k: _hexlify(v) for k, v in data.items()}
    else:
        return data


# Simple http request function which can be used when a Jade response
# requires an external http call.
# The default implementation used in JadeAPI._jadeRpc() below.
# NOTE: Only available if the 'requests' dependency is available.

# NOTE: Removed entirely for electrum - so it is not used silently as a fallback.
# (hard error preferred in that case)
# Jade repo api will be improved to make enabling this function more explicit

# try:
#     import requests
#
#     def _http_request(params):
#         logger.debug('_http_request: {}'.format(params))
#
#         # Use the first non-onion url
#         url = [url for url in params['urls'] if not url.endswith('.onion')][0]
#         if params['method'] == 'GET':
#             assert 'data' not in params, 'Cannot pass body to requests.get'
#             f = requests.get(url)
#         elif params['method'] == 'POST':
#             data = json.dumps(params['data'])
#             f = requests.post(url, data)
#
#         logger.debug("http_request received reply: {}".format(f.text))
#
#         if f.status_code != 200:
#             logger.error("http error {} : {}".format(f.status_code, f.text))
#             raise ValueError(f.status_code)
#
#         assert params['accept'] == 'json'
#         f = f.json()
#
#         return {'body': f}
#
# except ImportError as e:
#     logger.warn(e)
#     logger.warn('Default _http_requests() function will not be available')
#

#
# High-Level Jade Client API
# Builds on a JadeInterface to provide a meaningful API
#
# Either:
#  a) use with JadeAPI.create_[serial|ble]() as jade:
# (recommended)
# or:
#  b) use JadeAPI.create_[serial|ble], then call connect() before
#     using, and disconnect() when finished
# (caveat cranium)
# or:
#  c) use ctor to wrap existing JadeInterface instance
# (caveat cranium)
#
class JadeAPI:
    def __init__(self, jade):
        assert jade is not None
        self.jade = jade

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        if (exc_type):
            logger.error("Exception causing JadeAPI context exit.")
            logger.error(exc_type)
            logger.error(exc)
            traceback.print_tb(tb)
        self.disconnect(exc_type is not None)

    @staticmethod
    def create_serial(device=None, baud=None, timeout=None):
        impl = JadeInterface.create_serial(device, baud, timeout)
        return JadeAPI(impl)

#    @staticmethod
#    def create_ble(device_name=None, serial_number=None,
#                   scan_timeout=None, loop=None):
#        impl = JadeInterface.create_ble(device_name, serial_number,
#                                        scan_timeout, loop)
#        return JadeAPI(impl)

    # Connect underlying interface
    def connect(self):
        self.jade.connect()

    # Disconnect underlying interface
    def disconnect(self, drain=False):
        self.jade.disconnect(drain)

    # Drain all output from the interface
    def drain(self):
        self.jade.drain()

    # Raise any returned error as an exception
    @staticmethod
    def _get_result_or_raise_error(reply):
        if 'error' in reply:
            e = reply['error']
            raise JadeError(e.get('code'), e.get('message'), e.get('data'))

        return reply['result']

    # Helper to call wrapper interface rpc invoker
    def _jadeRpc(self, method, params=None, inputid=None, http_request_fn=None, long_timeout=False):
        newid = inputid if inputid else str(random.randint(100000, 999999))
        request = self.jade.build_request(newid, method, params)
        reply = self.jade.make_rpc_call(request, long_timeout)
        result = self._get_result_or_raise_error(reply)

        # The Jade can respond with a request for interaction with a remote
        # http server. This is used for interaction with the pinserver but the
        # code below acts as a dumb proxy and simply makes the http request and
        # forwards the response back to the Jade.
        # Note: the function called to make the http-request can be passed in,
        # or it can default to the simple _http_request() function above, if available.
        if isinstance(result, collections.abc.Mapping) and 'http_request' in result:
            this_module = sys.modules[__name__]
            make_http_request = http_request_fn or getattr(this_module, '_http_request', None)
            assert make_http_request, 'Default _http_request() function not available'

            http_request = result['http_request']
            http_response = make_http_request(http_request['params'])
            return self._jadeRpc(
                http_request['on-reply'],
                http_response['body'],
                http_request_fn=make_http_request,
                long_timeout=long_timeout)

        return result

    # Get version information from the hw
    def get_version_info(self):
        return self._jadeRpc('get_version_info')

    # Add client entropy to the hw rng
    def add_entropy(self, entropy):
        params = {'entropy': entropy}
        return self._jadeRpc('add_entropy', params)

    # OTA new firmware
    def ota_update(self, fwcmp, fwlen, chunksize, cb):

        cmphasher = hashlib.sha256()
        cmphasher.update(fwcmp)
        cmphash = cmphasher.digest()
        cmplen = len(fwcmp)

        # Initiate OTA
        params = {'fwsize': fwlen,
                  'cmpsize': cmplen,
                  'cmphash': cmphash}

        result = self._jadeRpc('ota', params)
        assert result is True

        # Write binary chunks
        written = 0
        while written < cmplen:
            remaining = cmplen - written
            length = min(remaining, chunksize)
            chunk = bytes(fwcmp[written:written + length])
            result = self._jadeRpc('ota_data', chunk)
            assert result is True
            written += length

            if (cb):
                cb(written, cmplen)

        # All binary data uploaded
        return self._jadeRpc('ota_complete')

    # Run (debug) healthcheck on the hw
    def run_remote_selfcheck(self):
        return self._jadeRpc('debug_selfcheck', long_timeout=True)

    # Set the (debug) mnemonic
    def set_mnemonic(self, mnemonic, passphrase=None, temporary_wallet=False):
        params = {'mnemonic': mnemonic, 'passphrase': passphrase,
                  'temporary_wallet': temporary_wallet}
        return self._jadeRpc('debug_set_mnemonic', params)

    # Set the (debug) seed
    def set_seed(self, seed, temporary_wallet=False):
        params = {'seed': seed, 'temporary_wallet': temporary_wallet}
        return self._jadeRpc('debug_set_mnemonic', params)

    # Override the pinserver details on the hww
    def set_pinserver(self, urlA=None, urlB=None, pubkey=None, cert=None):
        params = {}
        if urlA is not None or urlB is not None:
            params['urlA'] = urlA
            params['urlB'] = urlB
        if pubkey is not None:
            params['pubkey'] = pubkey
        if cert is not None:
            params['certificate'] = cert
        return self._jadeRpc('update_pinserver', params)

    # Reset the pinserver details on the hww to their defaults
    def reset_pinserver(self, reset_details, reset_certificate):
        params = {'reset_details': reset_details,
                  'reset_certificate': reset_certificate}
        return self._jadeRpc('update_pinserver', params)

    # Trigger user authentication on the hw
    # Involves pinserver handshake
    def auth_user(self, network, http_request_fn=None):
        params = {'network': network}
        return self._jadeRpc('auth_user', params,
                             http_request_fn=http_request_fn,
                             long_timeout=True)

    # Get xpub given a path
    def get_xpub(self, network, path):
        params = {'network': network, 'path': path}
        return self._jadeRpc('get_xpub', params)

    # Get registered multisig wallets
    def get_registered_multisigs(self):
        return self._jadeRpc('get_registered_multisigs')

    # Register a multisig wallet
    def register_multisig(self, network, multisig_name, variant, sorted_keys, threshold, signers):
        params = {'network': network, 'multisig_name': multisig_name,
                  'descriptor': {'variant': variant, 'sorted': sorted_keys,
                                 'threshold': threshold, 'signers': signers}}
        return self._jadeRpc('register_multisig', params)

    # Get receive-address for parameters
    def get_receive_address(self, *args, recovery_xpub=None, csv_blocks=0,
                            variant=None, multisig_name=None):
        if multisig_name is not None:
            assert len(args) == 2
            keys = ['network', 'paths', 'multisig_name']
            args += (multisig_name,)
        elif variant is not None:
            assert len(args) == 2
            keys = ['network', 'path', 'variant']
            args += (variant,)
        else:
            assert len(args) == 4
            keys = ['network', 'subaccount', 'branch', 'pointer', 'recovery_xpub', 'csv_blocks']
            args += (recovery_xpub, csv_blocks)
        return self._jadeRpc('get_receive_address', dict(zip(keys, args)))

    # Sign a message
    def sign_message(self, path, message, use_ae_signatures=False,
                     ae_host_commitment=None, ae_host_entropy=None):
        if use_ae_signatures:
            # Anti-exfil protocol:
            # We send the signing request and receive the signer-commitment in
            # reply once the user confirms.
            # We can then request the actual signature passing the ae-entropy.
            params = {'path': path, 'message': message, 'ae_host_commitment': ae_host_commitment}
            signer_commitment = self._jadeRpc('sign_message', params)
            params = {'ae_host_entropy': ae_host_entropy}
            signature = self._jadeRpc('get_signature', params)
            return signer_commitment, signature
        else:
            # Standard EC signature, simple case
            params = {'path': path, 'message': message}
            return self._jadeRpc('sign_message', params)

    # Get a Liquid master blinding key
    def get_master_blinding_key(self):
        return self._jadeRpc('get_master_blinding_key')

    # Get a Liquid public blinding key for a given script
    def get_blinding_key(self, script):
        params = {'script': script}
        return self._jadeRpc('get_blinding_key', params)

    # Get the shared secret to unblind a tx, given the receiving script on
    # our side and the pubkey of the sender (sometimes called "nonce" in
    # Liquid).  Optionally fetch our blinding pubkey also.
    def get_shared_nonce(self, script, their_pubkey, include_pubkey=False):
        params = {'script': script, 'their_pubkey': their_pubkey, 'include_pubkey': include_pubkey}
        return self._jadeRpc('get_shared_nonce', params)

    # Get a "trusted" blinding factor to blind an output. Normally the blinding
    # factors are generated and returned in the `get_commitments` call, but
    # for the last output the VBF must be generated on the host side, so this
    # call allows the host to get a valid ABF to compute the generator and
    # then the "final" VBF. Nonetheless, this call is kept generic, and can
    # also generate VBFs, thus the "type" parameter.
    # `hash_prevouts` is computed as specified in BIP143 (double SHA of all
    #   the outpoints being spent as input. It's not checked right away since
    #   at this point Jade doesn't know anything about the tx we are referring
    #   to. It will be checked later during `sign_liquid_tx`.
    # `output_index` is the output we are trying to blind.
    # `type` can either be "ASSET" or "VALUE" to generate ABFs or VBFs.
    def get_blinding_factor(self, hash_prevouts, output_index, type):
        params = {'hash_prevouts': hash_prevouts,
                  'output_index': output_index,
                  'type': type}
        return self._jadeRpc('get_blinding_factor', params)

    # Generate the blinding factors and commitments for a given output.
    # Can optionally get a "custom" VBF, normally used for the last
    # input where the VBF is not random, but generated accordingly to
    # all the others.
    # `hash_prevouts` and `output_index` have the same meaning as in
    #   the `get_blinding_factor` call.
    # NOTE: the `asset_id` should be passed as it is normally displayed, so
    # reversed compared to the "consensus" representation.
    def get_commitments(self,
                        asset_id,
                        value,
                        hash_prevouts,
                        output_index,
                        vbf=None):
        params = {'asset_id': asset_id,
                  'value': value,
                  'hash_prevouts': hash_prevouts,
                  'output_index': output_index}
        if vbf is not None:
            params['vbf'] = vbf
        return self._jadeRpc('get_commitments', params)

    # Common code for sending btc- and liquid- tx-inputs and receiving the
    # signatures.  Handles standard EC and AE signing schemes.
    def _send_tx_inputs(self, base_id, inputs, use_ae_signatures):
        if use_ae_signatures:
            # Anti-exfil protocol:
            # We send one message per input (which includes host-commitment *but
            # not* the host entropy) and receive the signer-commitment in reply.
            # Once all n input messages are sent, we can request the actual signatures
            # (as the user has a chance to confirm/cancel at this point).
            # We request the signatures passing the ae-entropy for each one.
            # Send inputs one at a time, receiving 'signer-commitment' in reply
            signer_commitments = []
            host_ae_entropy_values = []
            for txinput in inputs:
                # ae-protocol - do not send the host entropy immediately
                txinput = txinput.copy()  # shallow copy
                host_ae_entropy_values.append(txinput.pop('ae_host_entropy', None))

                base_id += 1
                input_id = str(base_id)
                reply = self._jadeRpc('tx_input', txinput, input_id)
                signer_commitments.append(reply)

            # Request the signatures one at a time, sending the entropy
            signatures = []
            for (i, host_ae_entropy) in enumerate(host_ae_entropy_values, 1):
                base_id += 1
                sig_id = str(base_id)
                params = {'ae_host_entropy': host_ae_entropy}
                reply = self._jadeRpc('get_signature', params, sig_id)
                signatures.append(reply)

            assert len(signatures) == len(inputs)
            return list(zip(signer_commitments, signatures))
        else:
            # Legacy protocol:
            # We send one message per input - without expecting replies.
            # Once all n input messages are sent, the hw then sends all n replies
            # (as the user has a chance to confirm/cancel at this point).
            # Then receive all n replies for the n signatures.
            # NOTE: *NOT* a sequence of n blocking rpc calls.
            # NOTE: at some point this flow should be removed in favour of the one
            # above, albeit without passing anti-exfil entropy or commitment data.

            # Send all n inputs
            requests = []
            for txinput in inputs:
                base_id += 1
                msg_id = str(base_id)
                request = self.jade.build_request(msg_id, 'tx_input', txinput)
                self.jade.write_request(request)
                requests.append(request)
                time.sleep(0.1)

            # Receive all n signatures
            signatures = []
            for request in requests:
                reply = self.jade.read_response()
                self.jade.validate_reply(request, reply)
                signature = self._get_result_or_raise_error(reply)
                signatures.append(signature)

            assert len(signatures) == len(inputs)
            return signatures

    # Sign a Liquid txn
    def sign_liquid_tx(self, network, txn, inputs, commitments, change, use_ae_signatures=False):
        # 1st message contains txn and number of inputs we are going to send.
        # Reply ok if that corresponds to the expected number of inputs (n).
        base_id = 100 * random.randint(1000, 9999)
        params = {'network': network,
                  'txn': txn,
                  'num_inputs': len(inputs),
                  'trusted_commitments': commitments,
                  'use_ae_signatures': use_ae_signatures,
                  'change': change}

        reply = self._jadeRpc('sign_liquid_tx', params, str(base_id))
        assert reply

        # Send inputs and receive signatures
        return self._send_tx_inputs(base_id, inputs, use_ae_signatures)

    # Sign a txn
    def sign_tx(self, network, txn, inputs, change, use_ae_signatures=False):
        # 1st message contains txn and number of inputs we are going to send.
        # Reply ok if that corresponds to the expected number of inputs (n).
        base_id = 100 * random.randint(1000, 9999)
        params = {'network': network,
                  'txn': txn,
                  'num_inputs': len(inputs),
                  'use_ae_signatures': use_ae_signatures,
                  'change': change}

        reply = self._jadeRpc('sign_tx', params, str(base_id))
        assert reply

        # Send inputs and receive signatures
        return self._send_tx_inputs(base_id, inputs, use_ae_signatures)


#
# Mid-level interface to Jade
# Wraps either a serial or a ble connection
# Calls to send and receive bytes and cbor messages over the interface.
#
# Either:
#  a) use wrapped with JadeAPI
# (recommended)
# or:
#  b) use with JadeInterface.create_[serial|ble]() as jade:
#       ...
# or:
#  c) use JadeInterface.create_[serial|ble], then call connect() before
#     using, and disconnect() when finished
# (caveat cranium)
# or:
#  d) use ctor to wrap existing low-level implementation instance
# (caveat cranium)
#
class JadeInterface:
    def __init__(self, impl):
        assert impl is not None
        self.impl = impl

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        if (exc_type):
            logger.error("Exception causing JadeInterface context exit.")
            logger.error(exc_type)
            logger.error(exc)
            traceback.print_tb(tb)
        self.disconnect(exc_type is not None)

    @staticmethod
    def create_serial(device=None, baud=None, timeout=None):
        if device and JadeTCPImpl.isSupportedDevice(device):
            impl = JadeTCPImpl(device)
        else:
            impl = JadeSerialImpl(device or DEFAULT_SERIAL_DEVICE,
                                  baud or DEFAULT_BAUD_RATE,
                                  timeout or DEFAULT_SERIAL_TIMEOUT)
        return JadeInterface(impl)

#    @staticmethod
#    def create_ble(device_name=None, serial_number=None,
#                   scan_timeout=None, loop=None):
#        impl = JadeBleImpl(device_name or DEFAULT_BLE_DEVICE_NAME,
#                           serial_number or DEFAULT_BLE_SERIAL_NUMBER,
#                           scan_timeout or DEFAULT_BLE_SCAN_TIMEOUT,
#                           loop=loop)
#        return JadeInterface(impl)

    def connect(self):
        self.impl.connect()

    def disconnect(self, drain=False):
        if drain:
            self.drain()

        self.impl.disconnect()

    def drain(self):
        logger.warn("Draining interface...")
        drained = bytearray()
        finished = False

        while not finished:
            byte_ = self.impl.read(1)
            drained.extend(byte_)
            finished = byte_ == b''

            if finished or byte_ == b'\n' or len(drained) > 256:
                try:
                    device_logger.warn(drained.decode('utf-8'))
                except Exception as e:
                    # Dump the bytes raw and as hex if decoding as utf-8 failed
                    device_logger.warn("Raw:")
                    device_logger.warn(drained)
                    device_logger.warn("----")
                    device_logger.warn("Hex dump:")
                    device_logger.warn(drained.hex())

                # Clear and loop to continue collecting
                drained.clear()

    @staticmethod
    def build_request(input_id, method, params=None):
        request = {"method": method, "id": input_id}
        if params is not None:
            request["params"] = params
        return request

    @staticmethod
    def serialise_cbor_request(request):
        dump = cbor.dumps(request)
        len_dump = len(dump)
        if 'method' in request and 'ota_data' in request['method']:
            msg = 'Sending ota_data message {} as cbor of size {}'.format(request['id'], len_dump)
            logger.info(msg)
        else:
            logger.info('Sending: {} as cbor of size {}'.format(_hexlify(request), len_dump))
        return dump

    def write(self, bytes_):
        logger.debug("Sending: {} bytes".format(len(bytes_)))
        wrote = self.impl.write(bytes_)
        logger.debug("Sent: {} bytes".format(len(bytes_)))
        return wrote

    def write_request(self, request):
        msg = self.serialise_cbor_request(request)
        written = 0
        while written < len(msg):
            written += self.write(msg[written:])

    def read(self, n):
        logger.debug("Reading {} bytes...".format(n))
        bytes_ = self.impl.read(n)
        logger.debug("Received: {} bytes".format(len(bytes_)))
        return bytes_

    def read_cbor_message(self):
        while True:
            # 'self' is sufficiently 'file-like' to act as a load source.
            # Throws EOFError on end of stream/timeout/lost-connection etc.
            message = cbor.load(self)

            if isinstance(message, collections.abc.Mapping):
                # A message response (to a prior request)
                if 'id' in message:
                    logger.info("Received msg: {}".format(_hexlify(message)))
                    return message

                # A log message - handle as normal
                if 'log' in message:
                    response = message['log']
                    log_method = device_logger.error
                    try:
                        response = message['log'].decode("utf-8")
                        log_methods = {
                            'E': device_logger.error,
                            'W': device_logger.warn,
                            'I': device_logger.info,
                            'D': device_logger.debug,
                            'V': device_logger.debug,
                        }
                        if len(response) > 1 and response[1] == ' ':
                            lvl = response[0]
                            log_method = log_methods.get(lvl, device_logger.error)
                    except Exception as e:
                        logger.error('Error processing log message: {}'.format(e))
                    log_method('>> {}'.format(response))
                    continue

            # Unknown/unhandled/unexpected message
            logger.error("Unhandled message received")
            device_logger.error(message)

    def read_response(self, long_timeout=False):
        while True:
            try:
                return self.read_cbor_message()
            except EOFError as e:
                if not long_timeout:
                    raise

    @staticmethod
    def validate_reply(request, reply):
        assert isinstance(reply, dict) and 'id' in reply
        assert ('result' in reply) != ('error' in reply)
        assert reply['id'] == request['id'] or \
            reply['id'] == '00' and 'error' in reply

    def make_rpc_call(self, request, long_timeout=False):
        # Write outgoing request message
        assert isinstance(request, dict)
        assert 'id' in request and len(request['id']) > 0
        assert 'method' in request and len(request['method']) > 0
        assert len(request['id']) < 16 and len(request['method']) < 32
        self.write_request(request)

        # Read and validate incoming message
        reply = self.read_response(long_timeout)
        self.validate_reply(request, reply)

        return reply
