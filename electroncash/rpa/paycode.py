#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
# This file (c) 2020 Jonald Fyookball
# With tweaks from Calin Culianu
# Part of the Electron Cash SPV Wallet
# License: MIT

'''
This implements the functionality for RPA (Reusable Payment Address) aka Paycodes
'''

from decimal import Decimal as PyDecimal

from . import addr
from .. import bitcoin
from .. import transaction
from ..address import Address, Base58
from ..bitcoin import COIN, TYPE_ADDRESS, sha256
from ..plugins import run_hook
from ..transaction import Transaction, OPReturn
from ..util import print_msg


def _satoshis(amount):
    # satoshi conversion must not be performed by the parser
    return int(COIN * PyDecimal(amount)) if amount not in ['!', None] else amount


def _resolver(wallet, x, nocheck):
    if x is None:
        return None
    out = wallet.contacts.resolve(x)
    if out.get('type') == 'openalias' and nocheck is False and out.get('validated') is False:
        raise BaseException('cannot verify alias', x)
    return out['address']


def _mktx(wallet, config, outputs, fee=None, change_addr=None, domain=None, nocheck=False,
          unsigned=False, password=None, locktime=None, op_return=None, op_return_raw=None):
    if op_return and op_return_raw:
        raise ValueError('Both op_return and op_return_raw cannot be specified together!')

    domain = None if domain is None else map(lambda x: _resolver(wallet, x, nocheck), domain)
    final_outputs = []
    if op_return:
        final_outputs.append(OPReturn.output_for_stringdata(op_return))
    elif op_return_raw:
        try:
            op_return_raw = op_return_raw.strip()
            tmp = bytes.fromhex(op_return_raw).hex()
            assert tmp == op_return_raw.lower()
            op_return_raw = tmp
        except Exception as e:
            raise ValueError("op_return_raw must be an even number of hex digits") from e
        final_outputs.append(OPReturn.output_for_rawhex(op_return_raw))

    for address, amount in outputs:
        address = _resolver(wallet, address, nocheck)
        amount = _satoshis(amount)
        final_outputs.append((TYPE_ADDRESS, address, amount))

    coins = wallet.get_spendable_coins(domain, config)
    tx = wallet.make_unsigned_transaction(coins, final_outputs, config, fee, change_addr)
    if locktime is not None:
        tx.locktime = locktime
    if not unsigned:
        run_hook('sign_tx', wallet, tx)
        wallet.sign_transaction(tx, password)
    return tx


def _calculate_paycode_shared_secret(private_key, public_key, outpoint):
    """private key is expected to be an integer.
    public_key is expected to be bytes.
    outpoint is expected to be a string.
    returns the paycode shared secret as bytes"""

    from ..bitcoin import Point
    from ..bitcoin import curve_secp256k1 as curve

    # Public key is expected to be compressed.  Change into a point object.
    pubkey_point = bitcoin.ser_to_point(public_key)
    ecdsa_point = Point(curve, pubkey_point.x(), pubkey_point.y())

    # Multiply the public and private points together
    ecdh_product = ecdsa_point * private_key
    ecdh_x = int(ecdh_product.x())
    ecdh_x_bytes = ecdh_x.to_bytes(33, byteorder="big")

    # Get the hash of the product
    sha_ecdh_x_bytes = sha256(ecdh_x_bytes)
    sha_ecdh_x_as_int = int.from_bytes(sha_ecdh_x_bytes, byteorder="big")

    # Hash the outpoint string
    hash_of_outpoint = sha256(outpoint)
    hash_of_outpoint_as_int = int.from_bytes(hash_of_outpoint, byteorder="big")

    # Sum the ECDH hash and the outpoint Hash
    grand_sum = sha_ecdh_x_as_int + hash_of_outpoint_as_int

    # Hash the final result
    nbytes = (len("%x" % grand_sum) + 1) // 2
    grand_sum_bytes = grand_sum.to_bytes(nbytes, byteorder="big")
    shared_secret = sha256(grand_sum_bytes)

    return shared_secret


def _generate_address_from_pubkey_and_secret(parent_pubkey, secret):
    """parent_pubkey and secret are expected to be bytes
    This function generates a receiving address based on CKD."""

    new_pubkey = bitcoin.CKD_pub(parent_pubkey, secret, 0)[0]

    use_uncompressed = False

    # Currently, just uses compressed keys, but if this ever changes to require uncompressed points:
    if use_uncompressed:
        pubkey_point = bitcoin.ser_to_point(new_pubkey)
        uncompressed = "04" + hex(pubkey_point.x())[2:] + hex(pubkey_point.y())[2:]
        new_pubkey = bytes.fromhex(uncompressed)

    return Address.from_pubkey(new_pubkey)


def _generate_privkey_from_secret(parent_privkey, secret):
    """parent_privkey and secret are expected to be bytes
    This function generates a receiving address based on CKD."""

    return bitcoin.CKD_priv(parent_privkey, secret, 0)[0].hex()


def generate_paycode(wallet, prefix_size="08"):
    """prefix size should be either 0x04 , 0x08, 0x0C, 0x10"""

    # Fields of the paycode
    version = "01"
    scanpubkey = wallet.derive_pubkeys(0, 0)
    spendpubkey = wallet.derive_pubkeys(0, 1)
    expiry = "00000000"

    # Concatenate
    payloadstring = version + prefix_size + scanpubkey + spendpubkey + expiry

    # Convert to bytes
    payloadbytes = bytes.fromhex(payloadstring)

    # Generate paycode "address" via rpa.addr function
    prefix = "paycode"
    return addr.encode_full(prefix, addr.PUBKEY_TYPE, payloadbytes)


def generate_transaction_from_paycode(wallet, config, amount, rpa_paycode=None, fee=None, from_addr=None,
                                      change_addr=None, nocheck=False, unsigned=False, password=None, locktime=None,
                                      op_return=None, op_return_raw=None):
    if not wallet.is_schnorr_enabled():
        print_msg("You must enable schnorr signing on this wallet for RPA.  Exiting.")
        return 0

    # Initialize variable for the final return value.
    final_raw_tx = 0

    # Decode the paycode
    rprefix, addr_hash = addr.decode(rpa_paycode)
    paycode_hex = addr_hash.hex()

    # Parse paycode
    paycode_field_version = paycode_hex[0:2]
    paycode_field_prefix_size = paycode_hex[2:4]
    paycode_field_scan_pubkey = paycode_hex[4:70]
    paycode_field_spend_pubkey = paycode_hex[70:136]
    paycode_field_expiry = paycode_hex[136:144]
    paycode_field_checksum = paycode_hex[144: 154]

    # Initialize a few variables for the transaction
    tx_fee = _satoshis(fee)
    domain = from_addr.split(',') if from_addr else None

    # Initiliaze a few variables for grinding
    tx_matches_paycode_prefix = False
    grind_nonce = 0
    grinding_version = "1"

    if paycode_field_prefix_size == "04":
        prefix_chars = 1
    elif paycode_field_prefix_size == "08":
        prefix_chars = 2
    elif paycode_field_prefix_size == "0C":
        prefix_chars = 3
    elif paycode_field_prefix_size == "10":
        prefix_chars = 4
    else:
        raise ValueError("Invalid prefix size. Must be 4,8,12, or 16 bits.")

    print_msg("Attempting to grind a matching prefix.  This may take a few minutes.  Please be patient.")

    # While loop for grinding.  Keep grinding until txid prefix matches paycode scanpubkey prefix.
    while not tx_matches_paycode_prefix:

        # Construct the transaction, initially with a dummy destination
        rpa_dummy_address = wallet.dummy_address().to_string(Address.FMT_CASHADDR)
        unsigned = True
        tx = _mktx(wallet, config, [(rpa_dummy_address, amount)], tx_fee, change_addr, domain, nocheck, unsigned,
                   password, locktime, op_return, op_return_raw)

        # Calculate ndata for grinding.  Ndata is passed through the stack as an input into RFC 6979
        grind_nonce_string = str(grind_nonce)
        grinding_message = rpa_paycode + grind_nonce_string + grinding_version
        ndata = sha256(grinding_message)

        # Use the first input (input zero) for our shared secret
        input_zero = tx._inputs[0]

        # Fetch our own private key for the coin
        bitcoin_addr = input_zero["address"]
        private_key_wif_format = wallet.export_private_key(bitcoin_addr, password)
        private_key_int_format = int.from_bytes(Base58.decode_check(private_key_wif_format)[1:33], byteorder="big")

        # Grab the outpoint  (the colon is intentionally ommitted from the string)
        outpoint_string = str(input_zero["prevout_hash"]) + str(input_zero["prevout_n"])

        # Format the pubkey in preparation to get the shared secret
        scanpubkey_bytes = bytes.fromhex(paycode_field_scan_pubkey)

        # Calculate shared secret
        shared_secret = _calculate_paycode_shared_secret(private_key_int_format, scanpubkey_bytes, outpoint_string)

        # Get the real destination for the transaction
        rpa_destination_address = _generate_address_from_pubkey_and_secret(bytes.fromhex(paycode_field_spend_pubkey),
                                                                           shared_secret).to_string(
            Address.FMT_CASHADDR)

        # Swap the dummy destination for the real destination
        tx.rpa_paycode_swap_dummy_for_destination(rpa_dummy_address, rpa_destination_address)

        # Sort the inputs and outputs deterministically
        tx.BIP_LI01_sort()

        # Now we need to sign the transaction after the outputs are known
        wallet.sign_transaction(tx, password, ndata=ndata)

        # Generate the raw transaction
        raw_tx_string = tx.as_dict()["hex"]

        # Get the TxId for this raw Tx.
        double_hash_tx = bytearray(sha256(sha256(bytes.fromhex(raw_tx_string))))
        double_hash_tx.reverse()
        txid = double_hash_tx.hex()

        # Check if we got a successful match.  If so, exit.
        if txid[0:prefix_chars].upper() == paycode_field_scan_pubkey[2:prefix_chars + 2].upper():
            print_msg("Grinding successful after ", grind_nonce, " iterations.")
            print_msg("Transaction Id: ", txid)
            print_msg("prefix is ", txid[0:prefix_chars].upper())
            final_raw_tx = raw_tx_string
            tx_matches_paycode_prefix = True  # <<-- exit

        # Increment the nonce
        grind_nonce += 1

    return final_raw_tx


def extract_private_key_from_transaction(wallet, raw_tx, password=None):
    # Initialize return value.  Will return 0 if no private key can be found.
    retval = 0

    # Deserialize the raw transaction
    unpacked_tx = Transaction.deserialize(Transaction(raw_tx))

    # Get a list of output addresses (we will need this for later to check if our key matches)
    output_addresses = []
    outputs = unpacked_tx["outputs"]
    for i in outputs:
        output_addresses.append(i['address'].to_string(Address.FMT_CASHADDR))

    # Variables for looping
    number_of_inputs = len(unpacked_tx["inputs"])
    input_index = 0
    process_inputs = True

    # Process each input until we find one that creates the shared secret to get a private key for an output
    while process_inputs:

        # Grab the outpoint
        single_input = unpacked_tx["inputs"][input_index]
        prevout_hash = single_input["prevout_hash"]
        prevout_n = str(single_input["prevout_n"])  # n is int. convert to str.
        outpoint_string = prevout_hash + prevout_n

        # Get the pubkey of the sender from the scriptSig.
        scriptSig = bytes.fromhex(single_input["scriptSig"])
        d = {}
        parsed_scriptSig = transaction.parse_scriptSig(d, scriptSig)
        sender_pubkey = bytes.fromhex(d["pubkeys"][0])

        # We need the private key that corresponds to the scanpubkey.
        # In this implementation, this is the one that goes with receiving address 0
        scanpubkey = wallet.derive_pubkeys(0, 0)

        # Fetch our own private (scan) key out of the wallet.
        scan_bitcoin_addr = Address.from_pubkey(scanpubkey)
        scan_private_key_wif_format = wallet.export_private_key(scan_bitcoin_addr, password)
        scan_private_key_int_format = int.from_bytes(Base58.decode_check(scan_private_key_wif_format)[1:33],
                                                     byteorder="big")

        # Calculate shared secret
        shared_secret = _calculate_paycode_shared_secret(scan_private_key_int_format, sender_pubkey, outpoint_string)

        # Get the spendpubkey for our paycode.
        # In this implementation, simply: receiving address 1.
        spendpubkey = wallet.derive_pubkeys(0, 1)

        # Get the destination address for the transaction
        destination = _generate_address_from_pubkey_and_secret(bytes.fromhex(spendpubkey), shared_secret).to_string(
            Address.FMT_CASHADDR)

        # Fetch our own private (spend) key out of the wallet.
        spendpubkey = wallet.derive_pubkeys(0, 1)
        spend_bitcoin_addr = Address.from_pubkey(spendpubkey)
        spend_private_key_wif_format = wallet.export_private_key(spend_bitcoin_addr, password)
        spend_private_key_int_format = int.from_bytes(Base58.decode_check(spend_private_key_wif_format)[1:33],
                                                      byteorder="big")

        # Generate the private key for the money being received via paycode
        privkey = _generate_privkey_from_secret(bytes.fromhex(hex(spend_private_key_int_format)[2:]), shared_secret)

        # Check the address matches
        if destination in output_addresses:
            process_inputs = False
            retval = privkey

        # Increment the input
        input_index += 1

        # If this was the last input, stop.
        if input_index >= number_of_inputs:
            process_inputs = False

    return retval
