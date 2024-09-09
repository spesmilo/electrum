import cbor2 as cbor
import hashlib
import json
import time
import logging
import collections
import collections.abc
import traceback
import random
import socket
import sys

# JadeError
from .jade_error import JadeError

# Low-level comms backends
from .jade_serial import JadeSerialImpl
from .jade_tcp import JadeTCPImpl

# 'jade' logger
logger = logging.getLogger(__name__)
device_logger = logging.getLogger(f'{__name__}-device')

# BLE comms backend is optional
# It relies on the BLE dependencies being available
try:
    from .jade_ble import JadeBleImpl
except (ImportError, FileNotFoundError) as e:
    logger.warning(e)
    logger.warning('BLE scanning/connectivity will not be available')


# Default serial connection
DEFAULT_BAUD_RATE = 115200
DEFAULT_SERIAL_TIMEOUT = 120

# Default BLE connection
DEFAULT_BLE_DEVICE_NAME = 'Jade'
DEFAULT_BLE_SERIAL_NUMBER = None
DEFAULT_BLE_SCAN_TIMEOUT = 60


def _hexlify(data):
    """
    Helper to map bytes-like types into hex-strings
    to make for prettier message-logging.

    Parameters
    ----------
    data : any
        The object to hexlify.
        - bytes or bytearrays have 'hex()' method invoked
        - list and dicts (values) have this function mapped over them
        - Otherwise the input is returned unchanged
    """
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

# NOTE: Removed entirely for electrum - so it is not used silently as a fallback.
# (hard error preferred in that case)
# Jade repo api will be improved to make enabling this function more explicit
# try:
#     import requests
#
#     def _http_request(params):
#         """
#         Simple http request function which can be used when a Jade response
#         requires an external http call.
#         The default implementation used in JadeAPI._jadeRpc() below.
#         NOTE: Only available if the 'requests' dependency is available.
#
#         Callers can supply their own implementation of this call where it is required.
#
#         Parameters
#         ----------
#         data : dict
#             A dictionary structure describing the http call to make
#
#         Returns
#         -------
#         dict
#             with single key 'body', whose value is the json returned from the call
#
#         """
#         logger.debug('_http_request: {}'.format(params))
#
#         # Use the first non-onion url
#         url = [url for url in params['urls'] if not url.endswith('.onion')][0]
#
#         if params['method'] == 'GET':
#             assert 'data' not in params, 'Cannot pass body to requests.get'
#             def http_call_fn(): return requests.get(url)
#         elif params['method'] == 'POST':
#             data = json.dumps(params['data'])
#             def http_call_fn(): return requests.post(url, data)
#         else:
#             raise JadeError(1, "Only GET and POST methods supported", params['method'])
#
#         try:
#             f = http_call_fn()
#             logger.debug("http_request received reply: {}".format(f.text))
#
#             if f.status_code != 200:
#                 logger.error("http error {} : {}".format(f.status_code, f.text))
#                 raise ValueError(f.status_code)
#
#             assert params['accept'] == 'json'
#             f = f.json()
#         except Exception as e:
#             logging.error(e)
#             f = None
#
#         return {'body': f}
#
# except ImportError as e:
#     logger.info(e)
#     logger.info('Default _http_requests() function will not be available')

def generate_dump():
    while True:
        try:
            with socket.create_connection(("localhost", 4444)) as s:
                output = b""
                while b"Open On-Chip Debugger" not in output:
                    data = s.recv(1024)
                    if not data:
                        continue
                    output += data

                s.sendall(b"esp gcov dump\n")

                output = b""
                while b"Targets disconnected." not in output:
                    data = s.recv(1024)
                    if not data:
                        continue
                    output += data
                s.sendall(b"resume\n")
                time.sleep(1)
            return
        except ConnectionRefusedError:
            pass


class JadeAPI:
    """
    High-Level Jade Client API
    Builds on a JadeInterface to provide a meaningful API

    Either:
    a) use with JadeAPI.create_[serial|ble]() as jade:
    (recommended)
    or:
    b) use JadeAPI.create_[serial|ble], then call connect() before
    using, and disconnect() when finished
    (caveat cranium)
    or:
    c) use ctor to wrap existing JadeInterface instance
    (caveat cranium)
    """

    def __init__(self, jade):
        assert jade is not None
        self.jade = jade

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        if (exc_type):
            logger.info("Exception causing JadeAPI context exit.")
            logger.info(exc_type)
            logger.info(exc)
            traceback.print_tb(tb)
        self.disconnect(exc_type is not None)

    @staticmethod
    def create_serial(device=None, baud=None, timeout=None):
        """
        Create a JadeAPI object using the serial interface described.

        Parameters
        ----------
        device : str, optional
            The device identifier for the serial device.
            Underlying implementation will default (to /dev/ttyUSB0)

        baud : int, optional
            The communication baud rate.
            Underlying implementation will default (to 115200)

        timeout : int, optional
            The serial read timeout when awaiting messages.
            Underlying implementation will default (to 120s)

        Returns
        -------
        JadeAPI
            API object configured to use given serial parameters.
            NOTE: the api instance has not yet tried to contact the hw
            - caller must call 'connect()' before trying to use the Jade.
        """
        impl = JadeInterface.create_serial(device, baud, timeout)
        return JadeAPI(impl)

    @staticmethod
    def create_ble(device_name=None, serial_number=None,
                   scan_timeout=None, loop=None):
        """
        Create a JadeAPI object using the BLE interface described.
        NOTE: raises JadeError if BLE dependencies not installed.

        Parameters
        ----------
        device_name : str, optional
            The device name of the desired BLE device.
            Underlying implementation will default (to 'Jade')

        serial_number : int, optional
            The serial number of the desired BLE device
            - used to disambiguate multiple beacons with the same 'device name'
            Underlying implementation will connect to the first beacon it scans
            with the matching 'device name'.

        scan_timeout : int, optional
            The timeout when scanning for devices which match the device name/serial number.
            Underlying implementation will default (to 60s)

        loop : optional
            The asynchio event loop to use, if required.
            Underlying implementation will default (to asyncio.get_event_loop())

        Returns
        -------
        JadeAPI
            API object configured to use given BLE parameters.
            NOTE: the api instance has not yet tried to contact the hw
            - caller must call 'connect()' before trying to use the Jade.

        Raises
        ------
        JadeError if BLE backend not available (ie. BLE dependencies not installed)
        """
        impl = JadeInterface.create_ble(device_name, serial_number,
                                        scan_timeout, loop)
        return JadeAPI(impl)

    def connect(self):
        """
        Try to connect the underlying transport interface (eg. serial, ble, etc.)
        Raises an exception on failure.
        """
        self.jade.connect()

    def disconnect(self, drain=False):
        """
        Disconnect the underlying transport (eg. serial, ble, etc.)

        Parameters
        ----------
        drain : bool, optional
            When true log any/all remaining messages/data, otherwise silently discard.
            NOTE: can prevent disconnection if data is arriving constantly.
            Defaults to False.
        """
        self.jade.disconnect(drain)

    def drain(self):
        """
        Log any/all outstanding messages/data.
        NOTE: can run indefinitely if data is arriving constantly.
        """
        self.jade.drain()

    @staticmethod
    def _get_result_or_raise_error(reply):
        """
        Raise any error message returned from a Jade rpc call as an exception.

        Parameters
        ----------
        reply : dict
            Dictionary representing a reply from a Jade rpc call.

        Returns
        -------
        dict
            Any nested 'result' structure, if the reply is not an error.

        Raises
        ------
        JadeError
            If the reply represented an error, including all details received.
        """
        if 'error' in reply:
            e = reply['error']
            raise JadeError(e.get('code'), e.get('message'), e.get('data'))

        return reply['result']

    def _jadeRpc(self, method, params=None, inputid=None, http_request_fn=None, long_timeout=False):
        """
        Helper to make a request/reply rpc call over the underlying transport interface.
        NOTE: interface must be 'connected'.

        If the call returns an 'http_request' structure, this is handled here and the http
        call is made, and the result is passed into the rpc method given in 'on reply', by
        calling this function recursively.

        Parameters
        ----------
        method : str
            rpc method to invoke

        params : dict, optional
            any parameters to pass to the rpc method
            Defaults to None.

        inputid : str, optional
            Any specific 'id' to use in the rpc message.
            Defaults to a using a pseudo-random id generated in-situ.

        http_request_fn : function, optional
            A function which accepts a dict (containing a description of the http request), makes
            the described http call, and returns the body data in an element called 'body'.
            Defaults to _http_request() above.

        long_timeout : bool, optional
            Whether the rpc call should use an indefinitely long timeout, rather than that set on
            construction.
            (Useful if the call involves a non-trivial user interaction with the device.)
            Defaults to False.

        Returns
        -------
        dict
            The reply from the rpc call.
            NOTE: will return the last/final reply after a sequence of calls, where 'http_request'
            was returned and remote data was fetched and passed into s subsequent call.
        """
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

    def ping(self):
        """
        RPC call to test the connection to Jade and that Jade is powered on and receiving data, and
        return whether the main task is currently handling a message, handling user menu navigation
        or is idle.

        NOTE: unlike all other calls this is not queued and handled in fifo order - this message is
        handled immediately and the response sent as quickly as possible.  This call does not block.
        If this call is made in parallel with Jade processing other messages, the replies may be
        out of order (although the message 'id' should still be correct).  Use with caution.

        Returns
        -------
        0 if the main task is currently idle
        1 if the main task is handling a client message
        2 if the main task is handling user ui menu navigation
        """
        return self._jadeRpc('ping')

    def get_version_info(self, nonblocking=False):
        """
        RPC call to fetch summary details pertaining to the hardware unit and running firmware.

        Parameters
        ----------
        nonblocking : bool
            If True message will be handled immediately (see also ping()) *experimental feature*

        Returns
        -------
        dict
            Contains keys for various info describing the hw and running fw
        """
        params = {'nonblocking': True} if nonblocking else None
        return self._jadeRpc('get_version_info', params)

    def add_entropy(self, entropy):
        """
        RPC call to add client entropy into the unit RNG entropy pool.

        Parameters
        ----------
        entropy : bytes
            Bytes to fold into the hw entropy pool.

        Returns
        -------
        bool
            True on success
        """
        params = {'entropy': entropy}
        return self._jadeRpc('add_entropy', params)

    def set_epoch(self, epoch=None):
        """
        RPC call to set the current time epoch value, required for TOTP use.
        NOTE: The time is lost on each power-down and must be reset on restart/reconnect before
        TOTP can be used.

        Parameters
        ----------
        epoch : int, optional
            Current epoch value, in seconds.  Defaults to int(time.time()) value.

        Returns
        -------
        bool
            True on success
        """
        params = {'epoch': epoch if epoch is not None else int(time.time())}
        return self._jadeRpc('set_epoch', params)

    def logout(self):
        """
        RPC call to logout of any wallet loaded on the Jade unit.
        Any key material is freed and zero'd.
        Call always returns true.

        Returns
        -------
        bool
            True
        """
        return self._jadeRpc('logout')

    def ota_update(self, fwcmp, fwlen, chunksize, fwhash=None, patchlen=None, cb=None,
                   gcov_dump=False):
        """
        RPC call to attempt to update the unit's firmware.

        Parameters
        ----------
        fwcmp : bytes
            The compressed firmware image to upload to the Jade unit.  Can be a full firmware or
            and incremental diff to be applied to the currently running firmware image.
        fwlen : int
            The size of the new complete (uncompressed) firmware image (after any delta is applied).
        chunksize : int
            The size of the chunks used to upload the compressed firmware.  Each chunk is uploaded
            and ack'd by the hw unit.
            The maximum supported chunk size is given in the version info data, under the key
            'JADE_OTA_MAX_CHUNK'.
        fwhash: 32-bytes, optional
            The sha256 hash of the full uncompressed final firmware image.  In the case of a full
            firmware upload this should be the hash of the uncompressed file.  In the case of a
            delta update this is the hash of the expected final image - ie. the existing firmware
            with the uploaded delta applied.  ie. it is a verification of the fw image Jade will try
            to boot. Optional for backward-compatibility - may become mandatory in a future release.
        patchlen: int, optional
            If the compressed firmware bytes are an incremental diff to be applied to the running
            firmware image, this is the size of that patch when uncompressed.
            Defaults to None, implying the compressed data is a full firmware image upload.
            (Compare with fwlen - the size of the final fw image.)
        cb : function, optional
            Callback function accepting two integers - the amount of compressed firmware sent thus
            far, and the total length of the compressed firmware to send.
            If passed, this function is invoked each time a fw chunk is successfully uploaded and
            ack'd by the hw, to notify of upload progress.
            Defaults to None, and nothing is called to report upload progress.

        Returns
        -------
        bool
            True if no errors were reported - on next restart the hw unit will attempt to boot the
            new firmware.
        """

        # Compute the sha256 hash of the compressed file being uploaded
        cmphasher = hashlib.sha256()
        cmphasher.update(fwcmp)
        cmphash = cmphasher.digest()
        cmplen = len(fwcmp)

        # Initiate OTA
        ota_method = 'ota'
        params = {'fwsize': fwlen,
                  'cmpsize': cmplen,
                  'cmphash': cmphash}

        if fwhash is not None:
            params['fwhash'] = fwhash

        if patchlen is not None:
            ota_method = 'ota_delta'
            params['patchsize'] = patchlen

        result = self._jadeRpc(ota_method, params)
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

        if gcov_dump:
            self.run_remote_gcov_dump()

        # All binary data uploaded
        return self._jadeRpc('ota_complete')

    def run_remote_selfcheck(self):
        """
        RPC call to run in-built tests.
        NOTE: Only available in a DEBUG build of the firmware.

        Returns
        -------
        int
            Time in ms for the internal tests to run, as measured on the hw.
            ie. excluding any messaging overhead
        """
        return self._jadeRpc('debug_selfcheck', long_timeout=True)

    def run_remote_gcov_dump(self):
        """
        RPC call to run in-built gcov-dump.
        NOTE: Only available in a DEBUG build of the firmware.

        Returns
        -------
        bool
            Always True.
        """
        result = self._jadeRpc('debug_gcov_dump', long_timeout=True)
        time.sleep(0.5)
        generate_dump()
        time.sleep(2)
        return result

    def capture_image_data(self, check_qr=False):
        """
        RPC call to capture raw image data from the camera.
        See also scan_qr() below.
        NOTE: Only available in a DEBUG build of the firmware.

        Parameters
        ----------
        check_qr : bool, optional
            If True only images which contain a valid qr code are captured and returned.
            If False, any image is considered valid and is returned.
            Defaults to False

        Returns
        -------
        bytes
            Raw image data from the camera framebuffer
        """
        params = {'check_qr': check_qr}
        return self._jadeRpc('debug_capture_image_data', params)

    def scan_qr(self, image):
        """
        RPC call to scan a passed image and return any data extracted from any qr image.
        Exercises the camera image capture, but ignores result and uses passed image instead.
        See also capture_image_data() above.
        NOTE: Only available in a DEBUG build of the firmware.

        Parameters
        ----------
        image : bytes
            The image data (as obtained from capture_image_data() above).

        Returns
        -------
        bytes
            String or byte data obtained from the image (via qr code)
        """
        params = {'image': image}
        return self._jadeRpc('debug_scan_qr', params)

    def clean_reset(self):
        """
        RPC call to clean/reset memory and storage, as much as is practical.
        NOTE: Only available in a DEBUG build of the firmware.

        Returns
        -------
        bool
            True on success.
        """
        return self._jadeRpc('debug_clean_reset')

    def set_mnemonic(self, mnemonic, passphrase=None, temporary_wallet=False):
        """
        RPC call to set the wallet mnemonic (in RAM only - flash storage is untouched).
        NOTE: Only available in a DEBUG build of the firmware.

        Parameters
        ----------
        mnemonic : str
            The wallet mnemonic to set.

        passphrase : str, optional
            Any bip39 passphrase to apply.
            Defaults to None.

        temporary_wallet : bool, optional
            Whether to treat this wallet/mnemonic as an 'Emergency Restore' temporary wallet, as
            opposed to one successfully loaded from the flash storage.
            NOTE: in either case the wallet is only set in RAM, and flash storage is not affected.
            Defaults to False.

        Returns
        -------
        bool
            True on success.
        """
        params = {'mnemonic': mnemonic, 'passphrase': passphrase,
                  'temporary_wallet': temporary_wallet}
        return self._jadeRpc('debug_set_mnemonic', params)

    def set_seed(self, seed):
        """
        RPC call to set the wallet seed.
        NOTE: Only available in a DEBUG build of the firmware.
        NOTE: Setting a seed always sets a 'temporary' wallet.

        Parameters
        ----------
        seed : bytes
            The wallet seed to set as a temporary wallet (cannot be persisted in flash).

        Returns
        -------
        bool
            True on success.
        """
        params = {'seed': seed}
        return self._jadeRpc('debug_set_mnemonic', params)

    def get_bip85_bip39_entropy(self, num_words, index, pubkey):
        """
        RPC call to fetch encrypted bip85-bip39 entropy.
        NOTE: Only available in a DEBUG build of the firmware.

        Parameters
        ----------
        num_words : int
            The number of words the entropy is required to produce.

        index : int
            The index to use in the bip32 path to calculate the entropy.

        pubkey: 33-bytes
            The host ephemeral pubkey to use to generate a shared ecdh secret to use as an AES key
            to encrypt the returned entropy.

        Returns
        -------
        dict
            pubkey - 33-bytes, Jade's ephemeral pubkey used to generate a shared ecdh secret used as
            an AES key to encrypt the returned entropy
            encrypted - bytes, the requested bip85 bip39 entropy, AES encrypted with the first key
            derived from the ecdh shared secret, prefixed with the iv
            hmac - 32-bytes, the hmac of the encrypted buffer, using the second key derived from the
            ecdh shared secret
        """
        params = {'num_words': num_words,
                  'index': index,
                  'pubkey': pubkey}
        return self._jadeRpc('get_bip85_bip39_entropy', params)

    def set_pinserver(self, urlA=None, urlB=None, pubkey=None, cert=None):
        """
        RPC call to explicitly set (override) the details of the blind pinserver used to
        authenticate the PIN entered on the Jade unit.
        This data is recorded in the hw flash, and returned to the caller when authenticating
        (in auth_user(), below).

        Parameters
        ----------
        urlA : str, optional
            The primary url of the pinserver to use.

        urlB : str, optional
            Any secondary url of the pinserver to use.

        pubkey : bytes, optional
            The public key used to verify pinserver signed payloads.

        cert : bytes, optional
            Any additional certificate required to verify the pinserver identity.

        Returns
        -------
        bool
            True on success.
        """
        params = {}
        if urlA is not None or urlB is not None:
            params['urlA'] = urlA
            params['urlB'] = urlB
        if pubkey is not None:
            params['pubkey'] = pubkey
        if cert is not None:
            params['certificate'] = cert
        return self._jadeRpc('update_pinserver', params)

    def reset_pinserver(self, reset_details, reset_certificate):
        """
        RPC call to reset any formerly overridden pinserver details to their defaults.

        Parameters
        ----------
        reset_details : bool, optional
            If set, any overridden urls and pubkey are reset to their defaults.

        reset_certificate : bool, optional
            If set, any additional certificate is reset (to None).

        Returns
        -------
        bool
            True on success.
        """
        params = {'reset_details': reset_details,
                  'reset_certificate': reset_certificate}
        return self._jadeRpc('update_pinserver', params)

    def auth_user(self, network, http_request_fn=None, epoch=None):
        """
        RPC call to authenticate the user on the hw device, for using with the network provided.

        Parameters
        ----------
        network : str
            The name of the network intended for use - eg. 'mainnet', 'liquid', 'testnet' etc.
            This is verified against the networks allowed on the hardware.

        http_request_fn : function, optional
            Optional http-request function to pass http requests to the Jade pinserver.
            Default behaviour is to use the '_http_request()' function which defers to the
            'requests' module.
            If the 'reqests' module is not available, no default http-request function is created,
            and one must be supplied here.

        epoch : int, optional
            Current epoch value, in seconds.  Defaults to int(time.time()) value.

        Returns
        -------
        bool
            True is returned immediately if the hw is already unlocked for use on the given network.
            True if the PIN is entered and verified with the remote blind pinserver.
            False if the PIN entered was incorrect.
        """
        params = {'network': network, 'epoch': epoch if epoch is not None else int(time.time())}
        return self._jadeRpc('auth_user', params,
                             http_request_fn=http_request_fn,
                             long_timeout=True)

    def register_otp(self, otp_name, otp_uri):
        """
        RPC call to register a new OTP record on the hw device.

        Parameters
        ----------
        otp_name : str
            An identifying name for this OTP record

        otp_uri : str
            The uri of this OTP record - must begin 'otpauth://'

        Returns
        -------
        bool
            True if the OTP uri was validated and persisted on the hw
        """
        params = {'name': otp_name, 'uri': otp_uri}
        return self._jadeRpc('register_otp', params)

    def get_otp_code(self, otp_name, value_override=None):
        """
        RPC call to fetch a new OTP code from the hw device.

        Parameters
        ----------
        otp_name : str
            An identifying name for the OTP record to use

        value_override : int
            An overriding HOTP counter or TOTP timestamp to use.
            NOTE: Only available in a DEBUG build of the firmware.

        Returns
        -------
        bool
            True if the OTP uri was validated and persisted on the hw
        """
        params = {'name': otp_name}
        if value_override is not None:
            params['override'] = value_override
        return self._jadeRpc('get_otp_code', params)

    def get_xpub(self, network, path):
        """
        RPC call to fetch an xpub for the given bip32 path for the given network.

        Parameters
        ----------
        network : str
            Network to which the xpub applies - eg. 'mainnet', 'liquid', 'testnet', etc.

        path : [int]
            bip32 path for which the xpub should be generated.

        Returns
        -------
        str
            base58 encoded xpub
        """
        params = {'network': network, 'path': path}
        return self._jadeRpc('get_xpub', params)

    def get_registered_multisigs(self):
        """
        RPC call to fetch brief summaries of any multisig wallets registered to this signer.

        Returns
        -------
        dict
            Brief description of registered multisigs, keyed by registration name.
            Each entry contains keys:
                variant - str, script type, eg. 'sh(wsh(multi(k)))'
                sorted - boolean, whether bip67 key sorting is applied
                threshold - int, number of signers required,N
                num_signers - total number of signatories, M
                master_blinding_key - 32-bytes, any liquid master blinding key for this wallet
        """
        return self._jadeRpc('get_registered_multisigs')

    def get_registered_multisig(self, multisig_name, as_file=False):
        """
        RPC call to fetch details of a named multisig wallet registered to this signer.
        NOTE: the multisig wallet must have been registered with firmware v1.0.23 or later
        for the full signer details to be persisted and available.

        Parameters
        ----------
        multisig_name : string
            Name of multsig registration record to return.

        as_file : string, optional
            If true the flat file format is returned, otherwise structured json is returned.
            Defaults to false.

        Returns
        -------
        dict
            Description of registered multisig wallet identified by registration name.
            Contains keys:
                is_file is true:
                    multisig_file - str, the multisig file as produced by several wallet apps.
                    eg:
                        Name: MainWallet
                        Policy: 2 of 3
                        Format: P2WSH
                        Derivation: m/48'/0'/0'/2'

                        B237FE9D: xpub6E8C7BX4c7qfTsX7urnXggcAyFuhDmYLQhwRwZGLD9maUGWPinuc9k96ej...
                        249192D2: xpub6EbXynW6xjYR3crcztum6KzSWqDJoAJQoovwamwVnLaCSHA6syXKPnJo6U...
                        67F90FFC: xpub6EHuWWrYd8bp5FS1XAZsMPkmCqLSjpULmygWqAqWRCCjSWQwz6ntq5KnuQ...

                is_file is false:
                    multisig_name - str, name of multisig registration
                    variant - str, script type, eg. 'sh(wsh(multi(k)))'
                    sorted - boolean, whether bip67 key sorting is applied
                    threshold - int, number of signers required,N
                    master_blinding_key - 32-bytes, any liquid master blinding key for this wallet
                    signers - dict containing keys:
                        fingerprint - 4 bytes, origin fingerprint
                        derivation - [int], bip32 path from origin to signer xpub provided
                        xpub - str, base58 xpub of signer
                        path - [int], any fixed path to always apply after the xpub - usually empty.

        """
        params = {'multisig_name': multisig_name,
                  'as_file': as_file}
        return self._jadeRpc('get_registered_multisig', params)

    def register_multisig(self, network, multisig_name, variant, sorted_keys, threshold, signers,
                          master_blinding_key=None):
        """
        RPC call to register a new multisig wallet, which must contain the hw signer.
        A registration name is provided - if it already exists that record is overwritten.

        Parameters
        ----------
        network : string
            Network to which the multisig should apply - eg. 'mainnet', 'liquid', 'testnet', etc.

        multisig_name : string
            Name to use to identify this multisig wallet registration record.
            If a registration record exists with the name given, that record is overwritten.

        variant : str
            The script type - one of 'sh(multi(k))', 'wsh(multi(k))', 'sh(wsh(multi(k)))'

        sorted_keys : bool
            Whether this is a 'sortedmulti()' wallet - ie. whether to apply bip67 sorting to the
            pubkeys when generating redeem scripts.

        threshold : int
            Number of signers required.

        signers : [dict]
            Description of signers - should include keys:
                - 'fingerprint' - 4 bytes, origin fingerprint
                - 'derivation' - [int], bip32 path from origin to signer xpub provided
                - 'xpub' - str, base58 xpub of signer - will be verified for hw unit signer
                - 'path' - [int], any fixed path to always apply after the xpub - usually empty.

        master_blinding_key : 32-bytes, optional
            The master blinding key to use for this multisig wallet on liquid.
            Optional, defaults to None.
            Logically mandatory when 'network' indicates a liquid network and the Jade is to be
            used to generate confidential addresses, blinding keys, blinding nonces, asset blinding
            factors or output commitments.

        Returns
        -------
        bool
            True on success, implying the mutisig wallet can now be used.
        """
        params = {'network': network, 'multisig_name': multisig_name,
                  'descriptor': {'variant': variant, 'sorted': sorted_keys,
                                 'threshold': threshold, 'signers': signers,
                                 'master_blinding_key': master_blinding_key}}
        return self._jadeRpc('register_multisig', params)

    def register_multisig_file(self, multisig_file):
        """
        RPC call to register a new multisig wallet, which must contain the hw signer.
        A registration file is provided - as produced my several wallet apps.

        Parameters
        ----------
        multisig_file : string
            The multisig file as produced by several wallet apps.
            eg:
                Name: MainWallet
                Policy: 2 of 3
                Format: P2WSH
                Derivation: m/48'/0'/0'/2'

                B237FE9D: xpub6E8C7BX4c7qfTsX7urnXggcAyFuhDmYLQhwRwZGLD9maUGWPinuc9k96ejhEQ1DCk...
                249192D2: xpub6EbXynW6xjYR3crcztum6KzSWqDJoAJQoovwamwVnLaCSHA6syXKPnJo6U3bVeGde...
                67F90FFC: xpub6EHuWWrYd8bp5FS1XAZsMPkmCqLSjpULmygWqAqWRCCjSWQwz6ntq5KnuQnL23No2...

    Returns
    -------
    bool
        True on success, implying the mutisig wallet can now be used.
    """
        params = {'multisig_file': multisig_file}
        return self._jadeRpc('register_multisig', params)

    def get_registered_descriptors(self):
        """
        RPC call to fetch brief summaries of any descriptor wallets registered to this signer.

        Returns
        -------
        dict
            Brief description of registered descriptor, keyed by registration name.
            Each entry contains keys:
                descriptor_len - int, length of descriptor output script
                num_datavalues - int, total number of substitution placeholders passed with script
                master_blinding_key - 32-bytes, any liquid master blinding key for this wallet
        """
        return self._jadeRpc('get_registered_descriptors')

    def get_registered_descriptor(self, descriptor_name):
        """
        RPC call to fetch details of a named descriptor wallet registered to this signer.

        Parameters
        ----------
        descriptor_name : string
            Name of descriptor registration record to return.

        Returns
        -------
        dict
            Description of registered descriptor wallet identified by registration name.
            Contains keys:
                descriptor_name - str, name of descritpor registration
                descriptor - str, descriptor output script, may contain substitution placeholders
                datavalues - dict containing placeholders for substitution into script
        """
        params = {'descriptor_name': descriptor_name}
        return self._jadeRpc('get_registered_descriptor', params)

    def register_descriptor(self, network, descriptor_name, descriptor_script, datavalues=None):
        """
        RPC call to register a new descriptor wallet, which must contain the hw signer.
        A registration name is provided - if it already exists that record is overwritten.

        Parameters
        ----------
        network : string
            Network to which the descriptor should apply - eg. 'mainnet', 'liquid', 'testnet', etc.

        descriptor_name : string
            Name to use to identify this descriptor wallet registration record.
            If a registration record exists with the name given, that record is overwritten.

        Returns
        -------
        bool
            True on success, implying the descriptor wallet can now be used.
        """
        params = {'network': network, 'descriptor_name': descriptor_name,
                  'descriptor': descriptor_script, 'datavalues': datavalues}
        return self._jadeRpc('register_descriptor', params)

    def get_receive_address(self, *args, recovery_xpub=None, csv_blocks=0,
                            variant=None, multisig_name=None, descriptor_name=None,
                            confidential=None):
        """
        RPC call to generate, show, and return an address for the given path.
        The call has three forms.

        Parameters
        ----------
        network: str
            Network to which the address should apply - eg. 'mainnet', 'liquid', 'testnet', etc.

        Then either:

        1. Blockstream Green (multisig shield) addresses
            subaccount : int
                Blockstream Green subaccount

            branch : int
                Blockstream Green derivation branch

            pointer : int
                Blockstream Green address pointer

            recovery_xpub : str, optional
                xpub of recovery key for 2of3 subaccounts.  Otherwise should be omitted.
                Defaults to None (ie. not a 2of3 subaccount).

            csv_blocks : int, optional
                Number of blocks to include in csv redeem script, if this is a csv-enabled account.
                Otherwise should be omitted.
                Defaults to 0 (ie. does not apply/not a csv-enabled account.)

        2. Generic single-sig addresses
            path: [int]
                bip32 path for which the xpub should be generated.

            variant: str
                The script type - one of 'pkh(k)', 'wpkh(k)', 'sh(wpkh(k))'

        3. Generic multisig addresses
            paths: [[int]]
                bip32 path suffixes, one for each signer, applied as a suffix to the registered
                signer path. Usually these path suffixes will all be identical.

            multisig_name : str
                The name of the registered multisig wallet record used to generate the address.

        4. Descriptor wallet addresses
            branch : int
                Multi-path derivation branch, usually 0.

            pointer : int
                Path index to descriptor

            descriptor_name : str
                The name of the registered descriptor wallet record used to generate the address.

        Returns
        -------
        str
            The address generated for the given parameters.

        """
        if multisig_name is not None:
            assert len(args) == 2
            keys = ['network', 'paths', 'multisig_name']
            args += (multisig_name,)
        elif descriptor_name is not None:
            assert len(args) == 3
            keys = ['network', 'branch', 'pointer', 'descriptor_name']
            args += (descriptor_name,)
        elif variant is not None:
            assert len(args) == 2
            keys = ['network', 'path', 'variant']
            args += (variant,)
        else:
            assert len(args) == 4
            keys = ['network', 'subaccount', 'branch', 'pointer', 'recovery_xpub', 'csv_blocks']
            args += (recovery_xpub, csv_blocks)

        params = dict(zip(keys, args))
        if confidential is not None:
            params['confidential'] = confidential

        return self._jadeRpc('get_receive_address', params)

    def sign_message(self, path, message, use_ae_signatures=False,
                     ae_host_commitment=None, ae_host_entropy=None):
        """
        RPC call to format and sign the given message, using the given bip32 path.
        Supports RFC6979 and anti-exfil signatures.

        Parameters
        ----------
        path : [int]
            bip32 path for which the signature should be generated.

        message : str
            Message string to format and sign.

        ae_host_commitment : 32-bytes, optional
            The host-commitment to use for Antil-Exfil signatures

        ae_host_entropy : 32-bytes, optional
            The host-entropy to use for Antil-Exfil signatures

        Returns
        -------
        1. Legacy/RFC6979 signatures
        str
            base64-encoded signature

        2. Anti-exfil signatures
        (bytes, str)
            signer-commitment, base64-encoded signature
        """
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

    def sign_message_file(self, message_file):
        """
        RPC call to format and sign the given message, using the given bip32 path.
        A message file is provided - as produced by eg. Specter wallet.
        Supports RFC6979 only.

        Parameters
        ----------
        message_file : str
            Message file to parse and produce signature for.
            eg:  'signmessage m/84h/0h/0h/0/0 ascii:this is a test message'

        Returns
        -------
        str
            base64-encoded RFC6979 signature
        """
        params = {'message_file': message_file}
        return self._jadeRpc('sign_message', params)

    def get_identity_pubkey(self, identity, curve, key_type, index=0):
        """
        RPC call to fetch a pubkey for the given identity (slip13/slip17).
        NOTE: this api returns an uncompressed public key

        Parameters
        ----------
        identity : str
            Identity string to format and sign. For example ssh://satoshi@bitcoin.org

        curve : str
            Name of curve to use - currently only 'nist256p1' is supported

        key_type : str
            Key derivation type - must be either 'slip-0013' for an identity pubkey, or 'slip-0017'
            for an ecdh pubkey.

        index : int, optional
            Index number (if require multiple keys/sigs per identity)
            Defaults to 0

        Returns
        -------
        65-bytes
            Uncompressed public key for the given identity and index.
            Consistent with 'sign_identity' or 'get_identity_shared_key', depending on the
            'key_type'.

        """
        params = {'identity': identity, 'curve': curve, 'type': key_type, 'index': index}
        return self._jadeRpc('get_identity_pubkey', params)

    def get_identity_shared_key(self, identity, curve, their_pubkey, index=0):
        """
        RPC call to fetch a SLIP-0017 shared ecdh key for the identity and counterparty public key.
        NOTE: this api takes an uncompressed public key

        Parameters
        ----------
        identity : str
            Identity string to format and sign. For example ssh://satoshi@bitcoin.org

        curve : str
            Name of curve to use - currently only 'nist256p1' is supported

        their_pubkey : 65-bytes
            The counterparty's uncompressed public key

        index : int, optional
            Index number (if require multiple keys/sigs per identity)
            Defaults to 0

        Returns
        -------
        32-bytes
            The shared ecdh key for the given identity and cpty public key
            Consistent with 'get_identity_pubkey' with 'key_type=slip-0017'
        """
        params = {'identity': identity, 'curve': curve, 'index': index,
                  'their_pubkey': their_pubkey}
        return self._jadeRpc('get_identity_shared_key', params)

    def sign_identity(self, identity, curve, challenge, index=0):
        """
        RPC call to authenticate the given identity through a challenge.
        Supports RFC6979.
        Returns the signature and the associated SLIP-0013 pubkey
        NOTE: this api returns an uncompressed public key

        Parameters
        ----------
        identity : str
            Identity string to format and sign. For example ssh://satoshi@bitcoin.org

        curve : str
            Name of curve to use - currently only 'nist256p1' is supported

        challenge : bytes
            Challenge bytes to sign

        index : int, optional
            Index number (if require multiple keys/sigs per identity)
            Defaults to 0

        Returns
        -------
        dict
            Contains keys:
            pubkey - 65-bytes, the uncompressed SLIP-0013 public key, consistent with
            'get_identity_pubkey' with 'key_type=slip-0013'
            signature - 65-bytes, RFC6979 deterministic signature, prefixed with 0x00
        """
        params = {'identity': identity, 'curve': curve, 'index': index, 'challenge': challenge}
        return self._jadeRpc('sign_identity', params)

    def sign_attestation(self, challenge):
        """
        RPC call to sign passed challenge with embedded hw RSA-4096 key, such that the caller
        can check the authenticity of the hardware unit.  eg. whether it is a genuine
        Blockstream production Jade unit.
        Caller must have the public key of the external verifying authority they wish to validate
        against (eg. Blockstream's Jade verification public key).
        NOTE: only supported by ESP32S3-based hardware units.

        Parameters
        ----------
        challenge : bytes
            Challenge bytes to sign

        Returns
        -------
        dict
            Contains keys:
            signature - 512-bytes, hardware RSA signature of the SHA256 hash of the passed
                        challenge bytes.
            pubkey_pem - str, PEM export of RSA pubkey of the hardware unit, to verify the returned
            RSA signature.
            ext_signature - bytes, RSA signature of the verifying authority over the returned
            pubkey_pem data.
            (Caller can verify this signature with the public key of the verifying authority.)
        """
        params = {'challenge': challenge}
        return self._jadeRpc('sign_attestation', params)

    def get_master_blinding_key(self, only_if_silent=False):
        """
        RPC call to fetch the master (SLIP-077) blinding key for the hw signer.
        May block temporarily to request the user's permission to export.  Passing 'only_if_silent'
        causes the call to return the 'denied' error if it would normally ask the user.
        NOTE: the master blinding key of any registered multisig wallets can be obtained from
        the result of `get_registered_multisigs()`.

        Parameters
        ----------
        only_if_silent : boolean, optional
            If True Jade will return the denied error if it would normally ask the user's permission
            to export the master blinding key.  Passing False (or letting default) may block while
            asking the user to confirm the export on Jade.

        Returns
        -------
        32-bytes
            SLIP-077 master blinding key
        """
        params = {'only_if_silent': only_if_silent}
        return self._jadeRpc('get_master_blinding_key', params)

    def get_blinding_key(self, script, multisig_name=None):
        """
        RPC call to fetch the public blinding key for the hw signer.

        Parameters
        ----------
        script : bytes
            The script for which the public blinding key is required.

        multisig_name : str, optional
            The name of any registered multisig wallet for which to fetch the blinding key.
            Defaults to None

        Returns
        -------
        33-bytes
            Public blinding key for the passed script.
        """
        params = {'script': script, 'multisig_name': multisig_name}
        return self._jadeRpc('get_blinding_key', params)

    def get_shared_nonce(self, script, their_pubkey, include_pubkey=False, multisig_name=None):
        """
        RPC call to get the shared secret to unblind a tx, given the receiving script and
        the pubkey of the sender (sometimes called "blinding nonce" in Liquid).
        Optionally fetch the hw signer's public blinding key also.

        Parameters
        ----------
        script : bytes
            The script for which the blinding nonce is required.

        their_pubkey : 33-bytes
            The counterparty public key.

        include_pubkey : bool, optional
            Whether to also return the wallet's public blinding key.
            Defaults to False.

        multisig_name : str, optional
            The name of any registered multisig wallet for which to fetch the blinding nonce.
            Defaults to None

        Returns
        -------
        1. include_pubkey is False
        33-bytes
            Public blinding nonce for the passed script and counterparty public key.

        2. include_pubkey is True
        dict
            Contains keys:
            shared_nonce - 32-bytes, public blinding nonce for the passed script as above.
            blinding_key - 33-bytes, public blinding key for the passed script.
        """
        params = {'script': script, 'their_pubkey': their_pubkey,
                  'include_pubkey': include_pubkey, 'multisig_name': multisig_name}
        return self._jadeRpc('get_shared_nonce', params)

    def get_blinding_factor(self, hash_prevouts, output_index, bftype, multisig_name=None):
        """
        RPC call to get deterministic blinding factors to blind an output.
        Predicated on the host calculating the 'hash_prevouts' value correctly.
        Can fetch abf, vbf, or both together.

        Parameters
        ----------

        hash_prevouts : 32-bytes
            This value should be computed by the host as specified in bip143.
            It is not verified by Jade, since at this point Jade does not have the tx in question.

        output_index : int
            The index of the output we are trying to blind

        bftype : str
            Can be "ASSET", "VALUE", or "ASSET_AND_VALUE", to generate abf, vbf, or both.

        multisig_name : str, optional
            The name of any registered multisig wallet for which to fetch the blinding factor.
            Defaults to None

        Returns
        -------
        32-bytes or 64-bytes
            The blinding factor for "ASSET" and "VALUE" requests, or both concatenated abf|vbf
            ie. the first 32 bytes being abf, the second 32 bytes being vbf.
        """
        params = {'hash_prevouts': hash_prevouts,
                  'output_index': output_index,
                  'type': bftype,
                  'multisig_name': multisig_name}
        return self._jadeRpc('get_blinding_factor', params)

    def get_commitments(self,
                        asset_id,
                        value,
                        hash_prevouts,
                        output_index,
                        vbf=None,
                        multisig_name=None):
        """
        RPC call to generate deterministic blinding factors and commitments for a given output.
        Can optionally get a "custom" VBF, normally used for the last input where the vbf is not
        computed here, but generated on the host according to all the other values.
        The commitments generated here should be passed back into `sign_liquid_tx()`.

        Parameters
        ----------
        asset_id : 32-bytes
            asset_id as usually displayed - ie. reversed compared to network/consensus order

        value : int
            value in 'satoshi' or equivalent atomic integral unit

        hash_prevouts : 32-bytes
            This value is computed as specified in bip143.
            It is verified immediately since at this point Jade doesn't have the tx in question.
            It will be checked later during `sign_liquid_tx()`.

        output_index : int
            The index of the output we are trying to blind

        vbf : 32-bytes, optional
            The vbf to use, in preference to deterministically generating one in this call.

        multisig_name : str, optional
            The name of any registered multisig wallet for which to fetch the blinding factor.
            Defaults to None

        Returns
        -------
        dict
            Containing the blinding factors and output commitments.
        """
        params = {'asset_id': asset_id,
                  'value': value,
                  'hash_prevouts': hash_prevouts,
                  'output_index': output_index,
                  'vbf': vbf,
                  'multisig_name': multisig_name}
        return self._jadeRpc('get_commitments', params)

    def _send_tx_inputs(self, base_id, inputs, use_ae_signatures):
        """
        Helper call to send the tx inputs to Jade for signing.
        Handles legacy RFC6979 signatures, as well as the Anti-Exfil protocol.

        Parameters
        ----------
        base_id : int
            The ids of the messages sent will be increments from this base id.

        inputs : [dict]
            The tx inputs - see `sign_tx()` / `sign_liquid_tx()` for details.

        use_ae_signatures : bool
            Whether to use the anti-exfil protocol to generate the signatures

        Returns
        -------
        1. if use_ae_signatures is False
        [bytes]
            An array of signatures corresponding to the array of inputs passed.
            The signatures are in DER format with the sighash appended.
            'None' placeholder elements are used for inputs not requiring a signature.

        2. if use_ae_signatures is True
        [(32-bytes, bytes)]
            An array of pairs of signer-commitments and signatures corresponding to the inputs.
            The signatures are in DER format with the sighash appended.
            (None, None) placeholder elements are used for inputs not requiring a signature.
        """
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
                txinput = txinput.copy() if txinput else {}  # shallow copy
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
                if txinput is None:
                    txinput = {}

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

    def sign_liquid_tx(self, network, txn, inputs, commitments, change, use_ae_signatures=False,
                       asset_info=None, additional_info=None):
        """
        RPC call to sign a liquid transaction.

        Parameters
        ----------
        network : str
            Network to which the txn should apply - eg. 'liquid', 'liquid-testnet', etc.

        txn : bytes
            The transaction to sign

        inputs : [dict]
            The tx inputs.
                If signing this input, should contain keys:
                is_witness, bool - whether this is a segwit input
                script, bytes- the redeem script
                path, [int] - the bip32 path to sign with
                value_commitment, 33-bytes - The value commitment of the input

                This is optional if signing this input:
                sighash, int - The sighash to use, defaults to 0x01 (SIGHASH_ALL)

                These are only required for Anti-Exfil signatures:
                ae_host_commitment, 32-bytes - The host-commitment for Anti-Exfil signatures
                ae_host_entropy, 32-bytes - The host-entropy for Anti-Exfil signatures

                These are only required for advanced transactions, eg. swaps, and only when the
                inputs need unblinding.
                Not needed for vanilla send-payment/redeposit etc:
                abf, 32-bytes - asset blinding factor
                asset_id, 32-bytes - the unblinded asset-id
                asset_generator, 33-bytes - the (blinded) asset-generator
                vbf, 32-bytes - the value blinding factor
                value, int - the unblinded sats value of the input

                If not signing this input a null or an empty dict can be passed.

        commitments : [dict]
            An array sized for the number of outputs.
            Unblinded outputs should have a 'null' placeholder element.
            The commitments as retrieved from `get_commitments()`, with the addition of:
                'blinding_key', <bytes> - the output's public blinding key
                    (as retrieved from `get_blinding_key()`)

        change : [dict]
            An array sized for the number of outputs.
            Outputs which are not to this wallet should have a 'null' placeholder element.
            The output scripts for the elements with data will be verified by Jade.
            Unless the element also contains 'is_change': False, these outputs will automatically
            be approved and not be verified by the user.
            Populated elements should contain sufficient data to generate the wallet address.
            See `get_receive_address()`

        use_ae_signatures : bool, optional
            Whether to use the anti-exfil protocol to generate the signatures.
            Defaults to False.

        asset_info : [dict], optional
            Any asset-registry data relevant to the assets being transacted, such that Jade can
            display a meaningful name, issuer, ticker etc. rather than just asset-id.
            At the very least must contain 'asset_id', 'contract' and 'issuance_prevout' items,
            exactly as in the registry data.  NOTE: asset_info for the network policy-asset is
            not required.
            Defaults to None.

        additional_info: dict, optional
            Extra data about the transaction.  Only required for advanced transactions, eg. swaps.
            Not needed for vanilla send-payment/redeposit etc:
            tx_type, str: 'swap' indicates the tx represents an asset-swap proposal or transaction.
            wallet_input_summary, dict:  a list of entries containing 'asset_id' (32-bytes) and
            'satoshi' (int) showing net movement of assets out of the wallet (ie. sum of wallet
            inputs per asset, minus any change outputs).
            wallet_output_summary, dict:  a list of entries containing 'asset_id' (32-bytes) and
            'satoshi' (int) showing net movement of assets into the wallet (ie. sum of wallet
            outputs per asset, excluding any change outputs).

        Returns
        -------
        1. if use_ae_signatures is False
        [bytes]
            An array of signatures corresponding to the array of inputs passed.
            The signatures are in DER format with the sighash appended.
            'None' placeholder elements are used for inputs not requiring a signature.

        2. if use_ae_signatures is True
        [(32-bytes, bytes)]
            An array of pairs of signer-commitments and signatures corresponding to the inputs.
            The signatures are in DER format with the sighash appended.
            (None, None) placeholder elements are used for inputs not requiring a signature.
        """
        # 1st message contains txn and number of inputs we are going to send.
        # Reply ok if that corresponds to the expected number of inputs (n).
        base_id = 100 * random.randint(1000, 9999)
        params = {'network': network,
                  'txn': txn,
                  'num_inputs': len(inputs),
                  'trusted_commitments': commitments,
                  'use_ae_signatures': use_ae_signatures,
                  'change': change,
                  'asset_info': asset_info,
                  'additional_info': additional_info}

        reply = self._jadeRpc('sign_liquid_tx', params, str(base_id))
        assert reply

        # Send inputs and receive signatures
        return self._send_tx_inputs(base_id, inputs, use_ae_signatures)

    def sign_tx(self, network, txn, inputs, change, use_ae_signatures=False):
        """
        RPC call to sign a btc transaction.

        Parameters
        ----------
        network : str
            Network to which the txn should apply - eg. 'mainnet', 'testnet', etc.

        txn : bytes
            The transaction to sign

        inputs : [dict]
            The tx inputs.   Should contain keys:
                One of these is required:
                input_tx, bytes - The prior transaction which created the utxo of this input
                satoshi, int - The satoshi amount of this input - can be used in place of
                    'input_tx' for a tx with a single segwit input

                These are only required if signing this input:
                is_witness, bool - whether this is a segwit input
                script, bytes- the redeem script
                path, [int] - the bip32 path to sign with

                This is optional if signing this input:
                sighash, int - The sighash to use, defaults to 0x01 (SIGHASH_ALL)

                These are only required for Anti-Exfil signatures:
                ae_host_commitment, 32-bytes - The host-commitment for Anti-Exfil signatures
                ae_host_entropy, 32-bytes - The host-entropy for Anti-Exfil signatures

        change : [dict]
            An array sized for the number of outputs.
            Outputs which are not to this wallet should have a 'null' placeholder element.
            The output scripts for the elements with data will be verified by Jade.
            Unless the element also contains 'is_change': False, these outputs will automatically
            be approved and not be verified by the user.
            Populated elements should contain sufficient data to generate the wallet address.
            See `get_receive_address()`

        use_ae_signatures : bool
            Whether to use the anti-exfil protocol to generate the signatures

        Returns
        -------
        1. if use_ae_signatures is False
        [bytes]
            An array of signatures corresponding to the array of inputs passed.
            The signatures are in DER format with the sighash appended.
            'None' placeholder elements are used for inputs not requiring a signature.

        2. if use_ae_signatures is True
        [(32-bytes, bytes)]
            An array of pairs of signer-commitments and signatures corresponding to the inputs.
            The signatures are in DER format with the sighash appended.
            (None, None) placeholder elements are used for inputs not requiring a signature.
        """
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

    def sign_psbt(self, network, psbt):
        """
        RPC call to sign a passed psbt as required

        Parameters
        ----------
        network : str
            Network to which the txn should apply - eg. 'mainnet', 'testnet', etc.

        psbt : bytes
            The psbt formatted as bytes

        Returns
        -------
        bytes
            The psbt, updated with any signatures required from the hw signer
        """
        # Send PSBT message
        params = {'network': network, 'psbt': psbt}
        msgid = str(random.randint(100000, 999999))
        request = self.jade.build_request(msgid, 'sign_psbt', params)
        self.jade.write_request(request)

        # Read replies until we have them all, collate data and return.
        # NOTE: we send 'get_extended_data' messages to request more 'chunks' of the reply data.
        psbt_out = bytearray()
        while True:
            reply = self.jade.read_response()
            self.jade.validate_reply(request, reply)
            psbt_out.extend(self._get_result_or_raise_error(reply))

            if 'seqnum' not in reply or reply['seqnum'] == reply['seqlen']:
                break

            newid = str(random.randint(100000, 999999))
            params = {'origid': msgid,
                      'orig': 'sign_psbt',
                      'seqnum': reply['seqnum'] + 1,
                      'seqlen': reply['seqlen']}
            request = self.jade.build_request(newid, 'get_extended_data', params)
            self.jade.write_request(request)

        return psbt_out


class JadeInterface:
    """
    Mid-level interface to Jade
    Wraps either a serial or a ble connection
    Calls to send and receive bytes and cbor messages over the interface.

    Either:
     a) use wrapped with JadeAPI
    (recommended)
    or:
     b) use with JadeInterface.create_[serial|ble]() as jade:
          ...
    or:
     c) use JadeInterface.create_[serial|ble], then call connect() before
        using, and disconnect() when finished
    (caveat cranium)
    or:
     d) use ctor to wrap existing low-level implementation instance
    (caveat cranium)
    """

    def __init__(self, impl):
        assert impl is not None
        self.impl = impl

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        if (exc_type):
            logger.info("Exception causing JadeInterface context exit.")
            logger.info(exc_type)
            logger.info(exc)
            traceback.print_tb(tb)
        self.disconnect(exc_type is not None)

    @staticmethod
    def create_serial(device=None, baud=None, timeout=None):
        """
        Create a JadeInterface object using the serial interface described.

        Parameters
        ----------
        device : str, optional
            The device identifier for the serial device.
            Underlying implementation will default (to /dev/ttyUSB0)

        baud : int, optional
            The communication baud rate.
            Underlying implementation will default (to 115200)

        timeout : int, optional
            The serial read timeout when awaiting messages.
            Underlying implementation will default (to 120s)

        Returns
        -------
        JadeInterface
            Interface object configured to use given serial parameters.
            NOTE: the instance has not yet tried to contact the hw
            - caller must call 'connect()' before trying to use the Jade.
        """
        if device and JadeTCPImpl.isSupportedDevice(device):
            impl = JadeTCPImpl(device, timeout or DEFAULT_SERIAL_TIMEOUT)
        else:
            impl = JadeSerialImpl(device,
                                  baud or DEFAULT_BAUD_RATE,
                                  timeout or DEFAULT_SERIAL_TIMEOUT)
        return JadeInterface(impl)

    @staticmethod
    def create_ble(device_name=None, serial_number=None,
                   scan_timeout=None, loop=None):
        """
        Create a JadeInterface object using the BLE interface described.
        NOTE: raises JadeError if BLE dependencies not installed.

        Parameters
        ----------
        device_name : str, optional
            The device name of the desired BLE device.
            Underlying implementation will default (to 'Jade')

        serial_number : int, optional
            The serial number of the desired BLE device
            - used to disambiguate multiple beacons with the same 'device name'
            Underlying implementation will connect to the first beacon it scans
            with the matching 'device name'.

        scan_timeout : int, optional
            The timeout when scanning for devices which match the device name/serial number.
            Underlying implementation will default (to 60s)

        loop : optional
            The asynchio event loop to use, if required.
            Underlying implementation will default (to asyncio.get_event_loop())

        Returns
        -------
        JadeInterface
            Interface object configured to use given BLE parameters.
            NOTE: the instance has not yet tried to contact the hw
            - caller must call 'connect()' before trying to use the Jade.

        Raises
        ------
        JadeError if BLE backend not available (ie. BLE dependencies not installed)
        """
        this_module = sys.modules[__name__]
        if not hasattr(this_module, "JadeBleImpl"):
            raise JadeError(1, "BLE support not installed", None)

        impl = JadeBleImpl(device_name or DEFAULT_BLE_DEVICE_NAME,
                           serial_number or DEFAULT_BLE_SERIAL_NUMBER,
                           scan_timeout or DEFAULT_BLE_SCAN_TIMEOUT,
                           loop=loop)
        return JadeInterface(impl)

    def connect(self):
        """
        Try to connect the underlying transport interface (eg. serial, ble, etc.)
        Raises an exception on failure.
        """
        self.impl.connect()

    def disconnect(self, drain=False):
        """
        Disconnect the underlying transport (eg. serial, ble, etc.)

        Parameters
        ----------
        drain : bool, optional
            When true log any/all remaining messages/data, otherwise silently discard.
            NOTE: can prevent disconnection if data is arriving constantly.
            Defaults to False.
        """
        if drain:
            self.drain()

        self.impl.disconnect()

    def drain(self):
        """
        Log any/all outstanding messages/data.
        NOTE: can run indefinitely if data is arriving constantly.
        """
        logger.warning("Draining interface...")
        drained = bytearray()
        finished = False

        while not finished:
            byte_ = self.impl.read(1)
            drained.extend(byte_)
            finished = byte_ == b''

            if finished or byte_ == b'\n' or len(drained) > 256:
                try:
                    device_logger.warning(drained.decode('utf-8'))
                except Exception as e:
                    # Dump the bytes raw and as hex if decoding as utf-8 failed
                    device_logger.warning("Raw:")
                    device_logger.warning(drained)
                    device_logger.warning("----")
                    device_logger.warning("Hex dump:")
                    device_logger.warning(drained.hex())

                # Clear and loop to continue collecting
                drained.clear()

    @staticmethod
    def build_request(input_id, method, params=None):
        """
        Build a request dict from passed parameters

        Parameters
        ----------
        input_id : str
            The id of the request message to construct

        method : str
            rpc method to invoke

        params : dict, optional
            any parameters to pass to the rpc method
            Defaults to None.

        Returns
        -------
        dict
            The request object as a dict
        """
        request = {"method": method, "id": input_id}
        if params is not None:
            request["params"] = params
        return request

    @staticmethod
    def serialise_cbor_request(request):
        """
        Method to format a request dict as a cbor message

        Parameters
        ----------
        request : dict
            The request dict

        Returns
        -------
        bytes
            The request formatted as cbor message bytes
        """
        dump = cbor.dumps(request)
        len_dump = len(dump)
        if 'method' in request and 'ota_data' in request['method']:
            msg = 'Sending ota_data message {} as cbor of size {}'.format(request['id'], len_dump)
            logger.info(msg)
        else:
            logger.info('Sending: {} as cbor of size {}'.format(_hexlify(request), len_dump))
        return dump

    def write(self, bytes_):
        """
        Write bytes over the underlying interface

        Parameters
        ----------
        bytes_ : bytes
            The bytes to write

        Returns
        -------
        int
            The number of bytes written
        """
        logger.debug("Sending: {} bytes".format(len(bytes_)))
        wrote = self.impl.write(bytes_)
        logger.debug("Sent: {} bytes".format(len(bytes_)))
        return wrote

    def write_request(self, request):
        """
        Write a request dict over the underlying interface, formatted as cbor.

        Parameters
        ----------
        request : dict
            The request dict to write
        """
        msg = self.serialise_cbor_request(request)
        written = 0
        while written < len(msg):
            written += self.write(msg[written:])

    def read(self, n):
        """
        Try to read bytes from the underlying interface.

        Returns
        -------
        bytes
            The bytes received
        """
        logger.debug("Reading {} bytes...".format(n))
        bytes_ = self.impl.read(n)
        logger.debug("Received: {} bytes".format(len(bytes_)))
        return bytes_

    def read_cbor_message(self):
        """
        Try to read a single cbor (response) message from the underlying interface.
        Respects the any read timeout.
        If any 'log' messages are received, logs them locally at the nearest corresponding level
        and awaits the next message.  Returns when it receives what appears to be a reply message.

        Returns
        -------
        dict
            The message received, as a dict
        """
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
                            'W': device_logger.warning,
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
        """
        Try to read a single cbor (response) message from the underlying interface.
        If any 'log' messages are received, logs them locally at the nearest corresponding level
        and awaits the next message.  Returns when it receives what appears to be a reply message.
        If `long_timeout` is false, any read-timeout is respected.  If True, the call will block
        indefinitely awaiting a response message.

        Parameters
        ----------
        long_timeout : bool
            Whether to wait indefinitely for the next (response) message.

        Returns
        -------
        dict
            The message received, as a dict
        """
        while True:
            try:
                return self.read_cbor_message()
            except EOFError as e:
                if not long_timeout:
                    raise

    @staticmethod
    def validate_reply(request, reply):
        """
        Helper to minimally validate a reply message, in the context of a request.
        Asserts if the reply does contain the expected minimal fields.
        """
        assert isinstance(reply, dict) and 'id' in reply
        assert ('result' in reply) != ('error' in reply)
        assert reply['id'] == request['id'] or \
            reply['id'] == '00' and 'error' in reply

    def make_rpc_call(self, request, long_timeout=False):
        """
        Method to send a request over the underlying interface, and await a response.
        The request is minimally validated before it is sent, and the response is similarly
        validated before being returned.
        Any read-timeout is respected unless 'long_timeout' is passed, in which case the call
        blocks indefinitely awaiting a response.

        Parameters
        ----------
        long_timeout : bool
            Whether to wait indefinitely for the response.

        Returns
        -------
        dict
            The (minimally validated) response message received, as a dict
        """
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
