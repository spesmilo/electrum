# ----------------------------------------------------------------------------------
# Electrum plugin for the Digital Bitbox hardware wallet by Shift Devices AG
# digitalbitbox.com
#

try:
    import electrum
    from electrum.bitcoin import TYPE_ADDRESS, var_int, msg_magic, Hash, verify_message, pubkey_from_signature, point_to_ser, public_key_to_p2pkh, EncodeAES, DecodeAES, MyVerifyingKey
    from electrum.i18n import _
    from electrum.keystore import Hardware_KeyStore
    from ..hw_wallet import HW_PluginBase
    from electrum.util import print_error

    import time
    import hid
    import json
    import math
    import binascii
    import struct
    import hashlib
    from ecdsa.ecdsa import generator_secp256k1
    from ecdsa.util import sigencode_der
    from ecdsa.curves import SECP256k1
    DIGIBOX = True
except ImportError as e:
    DIGIBOX = False



# ----------------------------------------------------------------------------------
# USB HID interface
#

def to_hexstr(s):
    return binascii.hexlify(s).decode('ascii')

class DigitalBitbox_Client():

    def __init__(self, hidDevice):
        self.dbb_hid = hidDevice
        self.opened = True
        self.password = None
        self.isInitialized = False
        self.setupRunning = False
        self.usbReportSize = 64 # firmware > v2.0.0


    def close(self):
        if self.opened:
            try:
                self.dbb_hid.close()
            except:
                pass
        self.opened = False


    def timeout(self, cutoff):
        pass


    def label(self):
        return " "


    def is_pairable(self):
        return True


    def is_initialized(self):
        return self.dbb_has_password()


    def is_paired(self):
        return self.password is not None


    def get_xpub(self, bip32_path):
        if self.check_device_dialog():
            msg = b'{"xpub": "%s"}' % bip32_path.encode('utf8')
            reply = self.hid_send_encrypt(msg)
            return reply['xpub']
        return None


    def dbb_has_password(self):
        reply = self.hid_send_plain(b'{"ping":""}')
        if 'ping' not in reply:
            raise Exception('Device communication error. Please unplug and replug your Digital Bitbox.')
        if reply['ping'] == 'password':
            return True
        return False


    def stretch_key(self, key):
        import pbkdf2, hmac
        return binascii.hexlify(pbkdf2.PBKDF2(key, b'Digital Bitbox', iterations = 20480, macmodule = hmac, digestmodule = hashlib.sha512).read(64))


    def backup_password_dialog(self):
        msg = _("Enter the password used when the backup was created:")
        while True:
            password = self.handler.get_passphrase(msg, False)
            if password is None:
                return None
            if len(password) < 4:
                msg = _("Password must have at least 4 characters.\r\n\r\nEnter password:")
            elif len(password) > 64:
                msg = _("Password must have less than 64 characters.\r\n\r\nEnter password:")
            else:
                return password.encode('utf8')


    def password_dialog(self, msg):
        while True:
            password = self.handler.get_passphrase(msg, False)
            if password is None:
                return False
            if len(password) < 4:
                msg = _("Password must have at least 4 characters.\r\n\r\nEnter password:")
            elif len(password) > 64:
                msg = _("Password must have less than 64 characters.\r\n\r\nEnter password:")
            else:
                self.password = password.encode('utf8')
                return True


    def check_device_dialog(self):
        # Set password if fresh device
        if self.password is None and not self.dbb_has_password():
            if not self.setupRunning:
                return False # A fresh device cannot connect to an existing wallet
            msg = _("An uninitialized Digital Bitbox is detected. " \
                    "Enter a new password below.\r\n\r\n REMEMBER THE PASSWORD!\r\n\r\n" \
                    "You cannot access your coins or a backup without the password.\r\n" \
                    "A backup is saved automatically when generating a new wallet.")
            if self.password_dialog(msg):
                reply = self.hid_send_plain(b'{"password":"' + self.password + '"}')
            else:
                return False

        # Get password from user if not yet set
        msg = _("Enter your Digital Bitbox password:")
        while self.password is None:
            if not self.password_dialog(msg):
                return False
            reply = self.hid_send_encrypt(b'{"led":"blink"}')
            if 'error' in reply:
                self.password = None
                if reply['error']['code'] == 109:
                    msg = _("Incorrect password entered.\r\n\r\n"  \
                            + reply['error']['message'] + "\r\n\r\n" \
                            "Enter your Digital Bitbox password:")
                else:
                    # Should never occur
                    msg = _("Unexpected error occurred.\r\n\r\n"  \
                            + reply['error']['message'] + "\r\n\r\n" \
                            "Enter your Digital Bitbox password:")

        # Initialize device if not yet initialized
        if not self.setupRunning:
            self.isInitialized = True # Wallet exists. Electrum code later checks if the device matches the wallet
        elif not self.isInitialized:
            reply = self.hid_send_encrypt(b'{"device":"info"}')
            if reply['device']['id'] != "":
                self.recover_or_erase_dialog() # Already seeded
            else:
                self.seed_device_dialog() # Seed if not initialized

        return self.isInitialized


    def recover_or_erase_dialog(self):
        msg = _("The Digital Bitbox is already seeded. Choose an option:\n")
        choices = [
            (_("Create a wallet using the current seed")),
            (_("Load a wallet from the micro SD card (the current seed is overwritten)")),
            (_("Erase the Digital Bitbox"))
        ]
        try:
            reply = self.handler.win.query_choice(msg, choices)
        except Exception:
            return # Back button pushed
        if reply == 2:
            self.dbb_erase()
        elif reply == 1:
            if not self.dbb_load_backup():
                return
        else:
            pass # Use existing seed
        self.isInitialized = True


    def seed_device_dialog(self):
        msg = _("Choose how to initialize your Digital Bitbox:\n")
        choices = [
            (_("Generate a new random wallet")),
            (_("Load a wallet from the micro SD card"))
        ]
        try:
            reply = self.handler.win.query_choice(msg, choices)
        except Exception:
            return # Back button pushed
        if reply == 0:
            self.dbb_generate_wallet()
        else:
            if not self.dbb_load_backup(show_msg=False):
                return
        self.isInitialized = True


    def dbb_generate_wallet(self):
        key = self.stretch_key(self.password)
        filename = b"Electrum-" + time.strftime("%Y-%m-%d-%H-%M-%S") + ".pdf"
        msg = b'{"seed":{"source": "create", "key": "%s", "filename": "%s", "entropy": "%s"}}' % (key, filename, b'Digital Bitbox Electrum Plugin')
        reply = self.hid_send_encrypt(msg)
        if 'error' in reply:
            raise Exception(reply['error']['message'])


    def dbb_erase(self):
        self.handler.show_message(_("Are you sure you want to erase the Digital Bitbox?\r\n\r\n" \
                                    "To continue, touch the Digital Bitbox's light for 3 seconds.\r\n\r\n" \
                                    "To cancel, briefly touch the light or wait for the timeout."))
        hid_reply = self.hid_send_encrypt(b'{"reset":"__ERASE__"}')
        self.handler.clear_dialog()
        if 'error' in hid_reply:
            raise Exception(hid_reply['error']['message'])
        else:
            self.password = None
            raise Exception('Device erased')


    def dbb_load_backup(self, show_msg=True):
        backups = self.hid_send_encrypt(b'{"backup":"list"}')
        if 'error' in backups:
            raise Exception(backups['error']['message'])
        try:
            f = self.handler.win.query_choice(_("Choose a backup file:"), backups['backup'])
        except Exception:
            return False # Back button pushed
        key = self.backup_password_dialog()
        if key is None:
            raise Exception('Canceled by user')
        key = self.stretch_key(key)
        if show_msg:
            self.handler.show_message(_("Loading backup...\r\n\r\n" \
                                        "To continue, touch the Digital Bitbox's light for 3 seconds.\r\n\r\n" \
                                        "To cancel, briefly touch the light or wait for the timeout."))
        msg = b'{"seed":{"source": "backup", "key": "%s", "filename": "%s"}}' % (key, backups['backup'][f].encode('utf8'))
        hid_reply = self.hid_send_encrypt(msg)
        self.handler.clear_dialog()
        if 'error' in hid_reply:
            raise Exception(hid_reply['error']['message'])
        return True


    def hid_send_frame(self, data):
        HWW_CID = 0xFF000000
        HWW_CMD = 0x80 + 0x40 + 0x01
        data_len = len(data)
        seq = 0;
        idx = 0;
        write = []
        while idx < data_len:
            if idx == 0:
                # INIT frame
                write = data[idx : idx + min(data_len, self.usbReportSize - 7)]
                self.dbb_hid.write(b'\0' + struct.pack(">IBH", HWW_CID, HWW_CMD, data_len & 0xFFFF) + write + b'\xEE' * (self.usbReportSize - 7 - len(write)))
            else:
                # CONT frame
                write = data[idx : idx + min(data_len, self.usbReportSize - 5)]
                self.dbb_hid.write(b'\0' + struct.pack(">IB", HWW_CID, seq) + write + b'\xEE' * (self.usbReportSize - 5 - len(write)))
                seq += 1
            idx += len(write)


    def hid_read_frame(self):
        # INIT response
        read = bytearray(self.dbb_hid.read(self.usbReportSize))
        cid = ((read[0] * 256 + read[1]) * 256 + read[2]) * 256 + read[3]
        cmd = read[4]
        data_len = read[5] * 256 + read[6]
        data = read[7:]
        idx = len(read) - 7;
        while idx < data_len:
            # CONT response
            read = bytearray(self.dbb_hid.read(self.usbReportSize))
            data += read[5:]
            idx += len(read) - 5
        return data


    def hid_send_plain(self, msg):
        reply = ""
        try:
            serial_number = self.dbb_hid.get_serial_number_string()
            if "v2.0." in serial_number or "v1." in serial_number:
                hidBufSize = 4096
                self.dbb_hid.write('\0' + msg + '\0' * (hidBufSize - len(msg)))
                r = bytearray()
                while len(r) < hidBufSize:
                    r += bytearray(self.dbb_hid.read(hidBufSize))
            else:
                self.hid_send_frame(msg)
                r = self.hid_read_frame()
            r = r.rstrip(b' \t\r\n\0')
            r = r.replace(b"\0", b'')
            reply = json.loads(r)
        except Exception as e:
            print_error('Exception caught ' + str(e))
        return reply


    def hid_send_encrypt(self, msg):
        reply = ""
        try:
            secret = Hash(self.password)
            msg = EncodeAES(secret, msg)
            reply = self.hid_send_plain(msg)
            if 'ciphertext' in reply:
                reply = DecodeAES(secret, ''.join(reply["ciphertext"]))
                reply = json.loads(reply)
            if 'error' in reply:
                self.password = None
        except Exception as e:
            print_error('Exception caught ' + str(e))
        return reply



# ----------------------------------------------------------------------------------
#
#

class DigitalBitbox_KeyStore(Hardware_KeyStore):
    hw_type = 'digitalbitbox'
    device = 'DigitalBitbox'


    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        self.force_watching_only = False
        self.maxInputs = 14 # maximum inputs per single sign command


    def get_derivation(self):
        return str(self.derivation)


    def give_error(self, message, clear_client = False):
        if clear_client:
            self.client = None
        raise Exception(message)


    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(_('Encryption and decryption are currently not supported for %s') % self.device)


    def sign_message(self, sequence, message, password):
        sig = None
        try:
            message = message.encode('utf8')
            inputPath = self.get_derivation() + "/%d/%d" % sequence
            msg_hash = Hash(msg_magic(message))
            inputHash = to_hexstr(msg_hash)
            hasharray = []
            hasharray.append({'hash': inputHash, 'keypath': inputPath})
            hasharray = json.dumps(hasharray)

            msg = b'{"sign":{"meta":"sign message", "data":%s}}' % hasharray.encode('utf8')

            dbb_client = self.plugin.get_client(self)

            if not dbb_client.is_paired():
                raise Exception("Could not sign message.")

            reply = dbb_client.hid_send_encrypt(msg)
            self.handler.show_message(_("Signing message ...\r\n\r\n" \
                                        "To continue, touch the Digital Bitbox's blinking light for 3 seconds.\r\n\r\n" \
                                        "To cancel, briefly touch the blinking light or wait for the timeout."))
            reply = dbb_client.hid_send_encrypt(msg) # Send twice, first returns an echo for smart verification (not implemented)
            self.handler.clear_dialog()

            if 'error' in reply:
                raise Exception(reply['error']['message'])

            if 'sign' not in reply:
                raise Exception("Could not sign message.")

            if 'recid' in reply['sign'][0]:
                # firmware > v2.1.1
                sig = bytes([27 + int(reply['sign'][0]['recid'], 16) + 4]) + binascii.unhexlify(reply['sign'][0]['sig'])
                pk, compressed = pubkey_from_signature(sig, msg_hash)
                pk = point_to_ser(pk.pubkey.point, compressed)
                addr = public_key_to_p2pkh(pk)
                if verify_message(addr, sig, message) is False:
                    raise Exception("Could not sign message")
            elif 'pubkey' in reply['sign'][0]:
                # firmware <= v2.1.1
                for i in range(4):
                    sig = bytes([27 + i + 4]) + binascii.unhexlify(reply['sign'][0]['sig'])
                    try:
                        addr = public_key_to_p2pkh(binascii.unhexlify(reply['sign'][0]['pubkey']))
                        if verify_message(addr, sig, message):
                            break
                    except Exception:
                        continue
                else:
                    raise Exception("Could not sign message")


        except BaseException as e:
            self.give_error(e)
        return sig


    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return

        try:
            p2shTransaction = False
            derivations = self.get_tx_derivations(tx)
            inputhasharray = []
            hasharray = []
            pubkeyarray = []

            # Build hasharray from inputs
            for i, txin in enumerate(tx.inputs()):
                if txin['type'] == 'coinbase':
                    self.give_error("Coinbase not supported") # should never happen

                if txin['type'] in ['p2sh']:
                    p2shTransaction = True

                for x_pubkey in txin['x_pubkeys']:
                    if x_pubkey in derivations:
                        index = derivations.get(x_pubkey)
                        inputPath = "%s/%d/%d" % (self.get_derivation(), index[0], index[1])
                        inputHash = Hash(binascii.unhexlify(tx.serialize_preimage(i)))
                        hasharray_i = {'hash': to_hexstr(inputHash), 'keypath': inputPath}
                        hasharray.append(hasharray_i)
                        inputhasharray.append(inputHash)
                        break
                else:
                    self.give_error("No matching x_key for sign_transaction") # should never happen

            # Sanity check
            if p2shTransaction:
                for txinput in tx.inputs():
                    if txinput['type'] != 'p2sh':
                        self.give_error("P2SH / regular input mixed in same transaction not supported") # should never happen

            # Build pubkeyarray from outputs (unused because echo for smart verification not implemented)
            if not p2shTransaction:
                for _type, address, amount in tx.outputs():
                    assert _type == TYPE_ADDRESS
                    info = tx.output_info.get(address)
                    if info is not None:
                        index, xpubs, m = info
                        changePath = self.get_derivation() + "/%d/%d" % index
                        changePubkey = self.derive_pubkey(index[0], index[1])
                        pubkeyarray_i = {'pubkey': changePubkey, 'keypath': changePath}
                        pubkeyarray.append(pubkeyarray_i)

            # Build sign command
            dbb_signatures = []
            steps = math.ceil(1.0 * len(hasharray) / self.maxInputs)
            for step in range(int(steps)):
                hashes = hasharray[step * self.maxInputs : (step + 1) * self.maxInputs]

                msg = ('{"sign": {"meta":"%s", "data":%s, "checkpub":%s} }' % \
                       (to_hexstr(Hash(tx.serialize())), json.dumps(hashes), json.dumps(pubkeyarray))).encode('utf8')

                dbb_client = self.plugin.get_client(self)

                if not dbb_client.is_paired():
                    raise Exception("Could not sign transaction.")

                reply = dbb_client.hid_send_encrypt(msg)
                if 'error' in reply:
                    raise Exception(reply['error']['message'])

                if 'echo' not in reply:
                    raise Exception("Could not sign transaction.")

                if steps > 1:
                    self.handler.show_message(_("Signing large transaction. Please be patient ...\r\n\r\n" \
                                                "To continue, touch the Digital Bitbox's blinking light for 3 seconds. " \
                                                "(Touch " + str(step + 1) + " of " + str(int(steps)) + ")\r\n\r\n" \
                                                "To cancel, briefly touch the blinking light or wait for the timeout.\r\n\r\n"))
                else:
                    self.handler.show_message(_("Signing transaction ...\r\n\r\n" \
                                                "To continue, touch the Digital Bitbox's blinking light for 3 seconds.\r\n\r\n" \
                                                "To cancel, briefly touch the blinking light or wait for the timeout."))

                reply = dbb_client.hid_send_encrypt(msg) # Send twice, first returns an echo for smart verification (not implemented)
                self.handler.clear_dialog()

                if 'error' in reply:
                    raise Exception(reply['error']['message'])

                if 'sign' not in reply:
                    raise Exception("Could not sign transaction.")

                dbb_signatures.extend(reply['sign'])

            # Fill signatures
            if len(dbb_signatures) != len(tx.inputs()):
                raise Exception("Incorrect number of transactions signed.") # Should never occur
            for i, txin in enumerate(tx.inputs()):
                num = txin['num_sig']
                for pubkey in txin['pubkeys']:
                    signatures = list(filter(None, txin['signatures']))
                    if len(signatures) == num:
                        break # txin is complete
                    ii = txin['pubkeys'].index(pubkey)
                    signed = dbb_signatures[i]
                    if 'recid' in signed:
                        # firmware > v2.1.1
                        recid = int(signed['recid'], 16)
                        s = binascii.unhexlify(signed['sig'])
                        h = inputhasharray[i]
                        pk = MyVerifyingKey.from_signature(s, recid, h, curve = SECP256k1)
                        pk = to_hexstr(point_to_ser(pk.pubkey.point, True))
                    elif 'pubkey' in signed:
                        # firmware <= v2.1.1
                        pk = signed['pubkey']
                    if pk != pubkey:
                        continue
                    sig_r = int(signed['sig'][:64], 16)
                    sig_s = int(signed['sig'][64:], 16)
                    sig = sigencode_der(sig_r, sig_s, generator_secp256k1.order())
                    txin['signatures'][ii] = to_hexstr(sig) + '01'
                    tx._inputs[i] = txin
        except BaseException as e:
            self.give_error(e, True)
        else:
            print_error("Transaction is_complete", tx.is_complete())
            tx.raw = tx.serialize()


class DigitalBitboxPlugin(HW_PluginBase):

    libraries_available = DIGIBOX
    keystore_class = DigitalBitbox_KeyStore
    client = None
    DEVICE_IDS = [
                   (0x03eb, 0x2402) # Digital Bitbox
                 ]

    def __init__(self, parent, config, name):
        HW_PluginBase.__init__(self, parent, config, name)
        if self.libraries_available:
            self.device_manager().register_devices(self.DEVICE_IDS)


    def get_dbb_device(self, device):
        dev = hid.device()
        dev.open_path(device.path)
        return dev


    def create_client(self, device, handler):
        if device.interface_number == 0 or device.usage_page == 0xffff:
            self.handler = handler
            client = self.get_dbb_device(device)
            if client is not None:
                client = DigitalBitbox_Client(client)
            return client
        else:
            return None


    def setup_device(self, device_info, wizard):
        devmgr = self.device_manager()
        device_id = device_info.device.id_
        client = devmgr.client_by_id(device_id)
        client.handler = self.create_handler(wizard)
        client.setupRunning = True
        client.get_xpub("m/44'/0'")


    def get_xpub(self, device_id, derivation, wizard):
        devmgr = self.device_manager()
        client = devmgr.client_by_id(device_id)
        client.handler = self.create_handler(wizard)
        client.check_device_dialog()
        xpub = client.get_xpub(derivation)
        return xpub


    def get_client(self, keystore, force_pair=True):
        devmgr = self.device_manager()
        handler = keystore.handler
        with devmgr.hid_lock:
            client = devmgr.client_for_keystore(self, handler, keystore, force_pair)
        if client is not None:
            client.check_device_dialog()
        return client
