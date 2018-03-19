import functools
import datetime
import sys
import struct
import traceback
sys.path.insert(0, "lib/ln")
from .ln import rpc_pb2

from jsonrpclib import Server
from google.protobuf import json_format
import binascii
import ecdsa.util
import hashlib
from .bitcoin import EC_KEY, MySigningKey
from ecdsa.curves import SECP256k1
from . import bitcoin
from . import transaction
from . import keystore

import queue

import threading
import json
import base64

import asyncio

from concurrent.futures import TimeoutError

WALLET = None
NETWORK = None
CONFIG = None
locked = set()

machine = "148.251.87.112"
#machine = "127.0.0.1"

def WriteDb(json):
    req = rpc_pb2.WriteDbRequest()
    json_format.Parse(json, req)
    print("writedb unimplemented", req.dbData)
    m = rpc_pb2.WriteDbResponse()
    msg = json_format.MessageToJson(m)
    return msg


def ConfirmedBalance(json):
    request = rpc_pb2.ConfirmedBalanceRequest()
    json_format.Parse(json, request)
    m = rpc_pb2.ConfirmedBalanceResponse()
    confs = request.confirmations
    #witness = request.witness  # bool

    m.amount = sum(WALLET.get_balance())
    msg = json_format.MessageToJson(m)
    return msg


def NewAddress(json):
    request = rpc_pb2.NewAddressRequest()
    json_format.Parse(json, request)
    m = rpc_pb2.NewAddressResponse()
    if request.type == rpc_pb2.WITNESS_PUBKEY_HASH:
        m.address = WALLET.get_unused_address()
    elif request.type == rpc_pb2.NESTED_PUBKEY_HASH:
        assert False, "cannot handle nested-pubkey-hash address type generation yet"
    elif request.type == rpc_pb2.PUBKEY_HASH:
        assert False, "cannot handle pubkey_hash generation yet"
    else:
        assert False, "unknown address type"
    msg = json_format.MessageToJson(m)
    return msg


#def FetchRootKey(json):
#    request = rpc_pb2.FetchRootKeyRequest()
#    json_format.Parse(json, request)
#    m = rpc_pb2.FetchRootKeyResponse()
#    m.rootKey = WALLET.keystore.get_private_key([151,151,151,151], None)[0]
#    msg = json_format.MessageToJson(m)
#    return msg


cl = rpc_pb2.ListUnspentWitnessRequest

assert rpc_pb2.WITNESS_PUBKEY_HASH is not None


def ListUnspentWitness(json):
    req = cl()
    json_format.Parse(json, req)
    confs = req.minConfirmations #TODO regard this

    unspent = WALLET.get_utxos()
    m = rpc_pb2.ListUnspentWitnessResponse()
    for utxo in unspent:
        # print(utxo)
        # example:
        # {'prevout_n': 0,
        #  'address': 'sb1qt52ccplvtpehz7qvvqft2udf2eaqvfsal08xre',
        #  'prevout_hash': '0d4caccd6e8a906c8ca22badf597c4dedc6dd7839f3cac3137f8f29212099882',
        #  'coinbase': False,
        #  'height': 326,
        #  'value': 400000000}

        global locked
        if (utxo["prevout_hash"], utxo["prevout_n"]) in locked:
            print("SKIPPING LOCKED OUTPOINT", utxo["prevout_hash"])
            continue
        towire = m.utxos.add()
        towire.addressType = rpc_pb2.WITNESS_PUBKEY_HASH
        towire.redeemScript = b""
        towire.pkScript = b""
        towire.witnessScript = bytes(bytearray.fromhex(
            bitcoin.address_to_script(utxo["address"])))
        towire.value = utxo["value"]
        towire.outPoint.hash = utxo["prevout_hash"]
        towire.outPoint.index = utxo["prevout_n"]
    return json_format.MessageToJson(m)

def LockOutpoint(json):
    req = rpc_pb2.LockOutpointRequest()
    json_format.Parse(json, req)
    global locked
    locked.add((req.outpoint.hash, req.outpoint.index))


def UnlockOutpoint(json):
    req = rpc_pb2.UnlockOutpointRequest()
    json_format.Parse(json, req)
    global locked
    # throws KeyError if not existing. Use .discard() if we do not care
    locked.remove((req.outpoint.hash, req.outpoint.index))

def ListTransactionDetails(json):
    global WALLET
    global NETWORK
    m = rpc_pb2.ListTransactionDetailsResponse()
    for tx_hash, height, conf, timestamp, delta, balance in WALLET.get_history():
        if height == 0:
          print("WARNING", tx_hash, "has zero height!")
        detail = m.details.add()
        detail.hash = tx_hash
        detail.value = delta
        detail.numConfirmations = conf
        detail.blockHash = NETWORK.blockchain().get_hash(height)
        detail.blockHeight = height
        detail.timestamp = timestamp
        detail.totalFees = 1337 # TODO
    return json_format.MessageToJson(m)

def FetchInputInfo(json):
    req = rpc_pb2.FetchInputInfoRequest()
    json_format.Parse(json, req)
    has = req.outPoint.hash
    idx = req.outPoint.index
    txoinfo = WALLET.txo.get(has, {})
    m = rpc_pb2.FetchInputInfoResponse()
    if has in WALLET.transactions:
        tx = WALLET.transactions[has]
        m.mine = True
    else:
        tx = WALLET.get_input_tx(has)
        print("did not find tx with hash", has)
        print("tx", tx)

        m.mine = False
        return json_format.MessageToJson(m)
    outputs = tx.outputs()
    assert {bitcoin.TYPE_SCRIPT: "SCRIPT", bitcoin.TYPE_ADDRESS: "ADDRESS",
            bitcoin.TYPE_PUBKEY: "PUBKEY"}[outputs[idx][0]] == "ADDRESS"
    scr = transaction.Transaction.pay_script(outputs[idx][0], outputs[idx][1])
    m.txOut.value = outputs[idx][2]  # type, addr, val
    m.txOut.pkScript = bytes(bytearray.fromhex(scr))
    msg = json_format.MessageToJson(m)
    return msg

def SendOutputs(json):
    global NETWORK, WALLET, CONFIG

    req = rpc_pb2.SendOutputsRequest()
    json_format.Parse(json, req)

    m = rpc_pb2.SendOutputsResponse()

    elecOutputs = [(bitcoin.TYPE_SCRIPT, binascii.hexlify(txout.pkScript).decode("utf-8"), txout.value) for txout in req.outputs]

    print("ignoring feeSatPerByte", req.feeSatPerByte) # TODO

    tx = None
    try:
        #                outputs,     password, config, fee
        tx = WALLET.mktx(elecOutputs, None,     CONFIG, 1000)
    except Exception as e:
        m.success = False
        m.error = str(e)
        m.resultHash = ""
        return json_format.MessageToJson(m)

    suc, has = NETWORK.broadcast(tx)
    if not suc:
        m.success = False
        m.error = "electrum/lightning/SendOutputs: Could not broadcast: " + str(has)
        m.resultHash = ""
        return json_format.MessageToJson(m)
    m.success = True
    m.error = ""
    m.resultHash = tx.txid()
    return json_format.MessageToJson(m)

def isSynced():
    global NETWORK
    local_height, server_height = NETWORK.get_status_value("updated")
    synced = server_height != 0 and NETWORK.is_up_to_date() and local_height >= server_height
    return synced, local_height, server_height

def IsSynced(json):
    m = rpc_pb2.IsSyncedResponse()
    m.synced, localHeight, _ = isSynced()
    block = NETWORK.blockchain().read_header(localHeight)
    m.lastBlockTimeStamp = block["timestamp"]
    return json_format.MessageToJson(m)

def SignMessage(json):
    req = rpc_pb2.SignMessageRequest()
    json_format.Parse(json, req)
    m = rpc_pb2.SignMessageResponse()

    pri = privKeyForPubKey(req.pubKey)

    m.signature = pri.sign(bitcoin.Hash(req.messageToBeSigned), ecdsa.util.sigencode_der)
    m.error = ""
    m.success = True
    return json_format.MessageToJson(m)

def LEtobytes(x, l):
    if l == 2:
        fmt = "<H"
    elif l == 4:
        fmt = "<I"
    elif l == 8:
        fmt = "<Q"
    else:
        assert False, "invalid format for LEtobytes"
    return struct.pack(fmt, x)


def toint(x):
    if len(x) == 1:
        return ord(x)
    elif len(x) == 2:
        fmt = ">H"
    elif len(x) == 4:
        fmt = ">I"
    elif len(x) == 8:
        fmt = ">Q"
    else:
        assert False, "invalid length for toint(): " + str(len(x))
    return struct.unpack(fmt, x)[0]

class TxSigHashes(object):
    def __init__(self, hashOutputs=None, hashSequence=None, hashPrevOuts=None):
        self.hashOutputs = hashOutputs
        self.hashSequence = hashSequence
        self.hashPrevOuts = hashPrevOuts


class Output(object):
    def __init__(self, value=None, pkScript=None):
        assert value is not None and pkScript is not None
        self.value = value
        self.pkScript = pkScript


class InputScript(object):
    def __init__(self, scriptSig, witness):
        assert witness is None or type(witness[0]) is type(bytes([]))
        assert type(scriptSig) is type(bytes([]))
        self.scriptSig = scriptSig
        self.witness = witness


def tweakPrivKey(basePriv, commitTweak):
    tweakInt = int.from_bytes(commitTweak, byteorder="big")
    tweakInt += basePriv.secret # D is secret
    tweakInt %= SECP256k1.generator.order()
    return EC_KEY(tweakInt.to_bytes(32, 'big'))

def singleTweakBytes(commitPoint, basePoint):
    m = hashlib.sha256()
    m.update(bytearray.fromhex(commitPoint))
    m.update(bytearray.fromhex(basePoint))
    return m.digest()

def deriveRevocationPrivKey(revokeBasePriv, commitSecret):
    revokeTweakBytes = singleTweakBytes(revokeBasePriv.get_public_key(True),
                                        commitSecret.get_public_key(True))
    revokeTweakInt = int.from_bytes(revokeTweakBytes, byteorder="big")

    commitTweakBytes = singleTweakBytes(commitSecret.get_public_key(True),
                                        revokeBasePriv.get_public_key(True))
    commitTweakInt = int.from_bytes(commitTweakBytes, byteorder="big")

    revokeHalfPriv = revokeTweakInt * revokeBasePriv.secret # D is secret
    commitHalfPriv = commitTweakInt * commitSecret.secret

    revocationPriv = revokeHalfPriv + commitHalfPriv
    revocationPriv %= SECP256k1.generator.order()

    return EC_KEY(revocationPriv.to_bytes(32, byteorder="big"))


def maybeTweakPrivKey(signdesc, pri):
    if len(signdesc.singleTweak) > 0:
        pri2 = tweakPrivKey(pri, signdesc.singleTweak)
    elif len(signdesc.doubleTweak) > 0:
        pri2 = deriveRevocationPrivKey(pri, EC_KEY(signdesc.doubleTweak))
    else:
        pri2 = pri

    if pri2 != pri:
        have_keys = WALLET.storage.get("lightning_extra_keys", [])
        if pri2.secret not in have_keys:
            WALLET.storage.put("lightning_extra_keys", have_keys + [pri2.secret])
            WALLET.storage.write()
            print("saved new tweaked key", pri2.secret)

    return pri2


def isWitnessPubKeyHash(script):
    if len(script) != 2:
        return False
    haveop0 = (transaction.opcodes.OP_0 == script[0][0])
    haveopdata20 = (20 == script[1][0])
    return haveop0 and haveopdata20

#// calcWitnessSignatureHash computes the sighash digest of a transaction's
#// segwit input using the new, optimized digest calculation algorithm defined
#// in BIP0143: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki.
#// This function makes use of pre-calculated sighash fragments stored within
#// the passed HashCache to eliminate duplicate hashing computations when
#// calculating the final digest, reducing the complexity from O(N^2) to O(N).
#// Additionally, signatures now cover the input value of the referenced unspent
#// output. This allows offline, or hardware wallets to compute the exact amount
#// being spent, in addition to the final transaction fee. In the case the
#// wallet if fed an invalid input amount, the real sighash will differ causing
#// the produced signature to be invalid.


def calcWitnessSignatureHash(original, sigHashes, hashType, tx, idx, amt):
    assert len(original) != 0
    decoded = transaction.deserialize(binascii.hexlify(tx).decode("utf-8"))
    if idx > len(decoded["inputs"]) - 1:
        raise Exception("invalid inputIndex")
    txin = decoded["inputs"][idx]
    #tohash = transaction.Transaction.serialize_witness(txin)
    sigHash = LEtobytes(decoded["version"], 4)
    if toint(hashType) & toint(sigHashAnyOneCanPay) == 0:
        sigHash += bytes(bytearray.fromhex(sigHashes.hashPrevOuts))[::-1]
    else:
        sigHash += b"\x00" * 32

    if toint(hashType) & toint(sigHashAnyOneCanPay) == 0 and toint(hashType) & toint(sigHashMask) != toint(sigHashSingle) and toint(hashType) & toint(sigHashMask) != toint(sigHashNone):
        sigHash += bytes(bytearray.fromhex(sigHashes.hashSequence))[::-1]
    else:
        sigHash += b"\x00" * 32

    sigHash += bytes(bytearray.fromhex(txin["prevout_hash"]))[::-1]
    sigHash += LEtobytes(txin["prevout_n"], 4)
    # byte 72

    subscript = list(transaction.script_GetOp(original))
    if isWitnessPubKeyHash(subscript):
        sigHash += b"\x19"
        sigHash += bytes([transaction.opcodes.OP_DUP])
        sigHash += bytes([transaction.opcodes.OP_HASH160])
        sigHash += b"\x14"  # 20 bytes
        assert len(subscript) == 2, subscript
        opcode, data, length = subscript[1]
        sigHash += data
        sigHash += bytes([transaction.opcodes.OP_EQUALVERIFY])
        sigHash += bytes([transaction.opcodes.OP_CHECKSIG])
    else:
        # For p2wsh outputs, and future outputs, the script code is
        # the original script, with all code separators removed,
        # serialized with a var int length prefix.

        assert len(sigHash) == 104, len(sigHash)
        sigHash += bytes(bytearray.fromhex(bitcoin.var_int(len(original))))
        assert len(sigHash) == 105, len(sigHash)

        sigHash += original

    sigHash += LEtobytes(amt, 8)
    sigHash += LEtobytes(txin["sequence"], 4)

    if toint(hashType) & toint(sigHashSingle) != toint(sigHashSingle) and toint(hashType) & toint(sigHashNone) != toint(sigHashNone):
        sigHash += bytes(bytearray.fromhex(sigHashes.hashOutputs))[::-1]
    elif toint(hashtype) & toint(sigHashMask) == toint(sigHashSingle) and idx < len(decoded["outputs"]):
        raise Exception("TODO 1")
    else:
        raise Exception("TODO 2")

    sigHash += LEtobytes(decoded["lockTime"], 4)
    sigHash += LEtobytes(toint(hashType), 4)

    return transaction.Hash(sigHash)

#// RawTxInWitnessSignature returns the serialized ECDA signature for the input
#// idx of the given transaction, with the hashType appended to it. This
#// function is identical to RawTxInSignature, however the signature generated
#// signs a new sighash digest defined in BIP0143.
# func RawTxInWitnessSignature(tx *MsgTx, sigHashes *TxSigHashes, idx int,
#  amt int64, subScript []byte, hashType SigHashType,
#  key *btcec.PrivateKey) ([]byte, error) {


def rawTxInWitnessSignature(tx, sigHashes, idx, amt, subscript, hashType, key):
    digest = calcWitnessSignatureHash(
        subscript, sigHashes, hashType, tx, idx, amt)
    return key.sign(digest, sigencode=ecdsa.util.sigencode_der) + hashType

# WitnessSignature creates an input witness stack for tx to spend BTC sent
# from a previous output to the owner of privKey using the p2wkh script
# template. The passed transaction must contain all the inputs and outputs as
# dictated by the passed hashType. The signature generated observes the new
# transaction digest algorithm defined within BIP0143.
def witnessSignature(tx, sigHashes, idx, amt, subscript, hashType, privKey, compress):
    sig = rawTxInWitnessSignature(
        tx, sigHashes, idx, amt, subscript, hashType, privKey)

    pkData = bytes(bytearray.fromhex(
        privKey.get_public_key(compressed=compress)))

    return sig, pkData


sigHashMask = b"\x1f"

sigHashAll = b"\x01"
sigHashNone = b"\x02"
sigHashSingle = b"\x03"
sigHashAnyOneCanPay = b"\x80"

test = rpc_pb2.ComputeInputScriptResponse()

test.witnessScript.append(b"\x01")
test.witnessScript.append(b"\x02")


def SignOutputRaw(json):
    req = rpc_pb2.SignOutputRawRequest()
    json_format.Parse(json, req)

    #assert len(req.signDesc.pubKey) in [33, 0]
    assert len(req.signDesc.doubleTweak) in [32, 0]
    assert len(req.signDesc.sigHashes.hashPrevOuts) == 64
    assert len(req.signDesc.sigHashes.hashSequence) == 64
    assert len(req.signDesc.sigHashes.hashOutputs) == 64

    m = rpc_pb2.SignOutputRawResponse()

    m.signature = signOutputRaw(req.tx, req.signDesc)

    msg = json_format.MessageToJson(m)
    return msg


def signOutputRaw(tx, signDesc):
    pri = derivePrivKey(signDesc.keyDescriptor)
    assert pri is not None
    pri2 = maybeTweakPrivKey(signDesc, pri)
    sig = rawTxInWitnessSignature(tx, signDesc.sigHashes, signDesc.inputIndex,
                                  signDesc.output.value, signDesc.witnessScript, sigHashAll, pri2)
    return sig[:len(sig) - 1]

async def PublishTransaction(json):
    req = rpc_pb2.PublishTransactionRequest()
    json_format.Parse(json, req)
    global NETWORK
    tx = transaction.Transaction(binascii.hexlify(req.tx).decode("utf-8"))
    suc, has = NETWORK.broadcast(tx)
    m = rpc_pb2.PublishTransactionResponse()
    m.success = suc
    m.error = str(has) if not suc else ""
    if m.error:
        print("PublishTransaction", m.error)
        if "Missing inputs" in m.error:
            print("inputs", tx.inputs())
    return json_format.MessageToJson(m)


def ComputeInputScript(json):
    req = rpc_pb2.ComputeInputScriptRequest()
    json_format.Parse(json, req)

    #assert len(req.signDesc.pubKey) in [33, 0]
    assert len(req.signDesc.doubleTweak) in [32, 0]
    assert len(req.signDesc.sigHashes.hashPrevOuts) == 64
    assert len(req.signDesc.sigHashes.hashSequence) == 64
    assert len(req.signDesc.sigHashes.hashOutputs) == 64
    # singleTweak , witnessScript variable length

    try:
        inpscr = computeInputScript(req.tx, req.signDesc)
    except:
        print("catched!")
        traceback.print_exc()
        return None

    m = rpc_pb2.ComputeInputScriptResponse()

    m.witnessScript.append(inpscr.witness[0])
    m.witnessScript.append(inpscr.witness[1])
    m.scriptSig = inpscr.scriptSig

    msg = json_format.MessageToJson(m)
    return msg


def fetchPrivKey(str_address, keyLocatorFamily, keyLocatorIndex):
    pri = None

    if str_address is not None:
        pri, redeem_script = WALLET.export_private_key(str_address, None)

        if redeem_script:
            print("ignoring redeem script", redeem_script)

        typ, pri, compressed = bitcoin.deserialize_privkey(pri)
        if keyLocatorFamily == 0 and keyLocatorIndex == 0: return EC_KEY(pri)

        ks = keystore.BIP32_KeyStore({})
        der = "m/0'/"
        xtype = 'p2wpkh'
        ks.add_xprv_from_seed(pri, xtype, der)
    else:
        ks = WALLET.keystore

    if keyLocatorFamily != 0 or keyLocatorIndex != 0:
        pri = ks.get_private_key([1017, keyLocatorFamily, keyLocatorIndex], password=None)[0]
        pri = EC_KEY(pri)

    assert pri is not None

    return pri


def computeInputScript(tx, signdesc):
    typ, str_address = transaction.get_address_from_output_script(
        signdesc.output.pkScript)
    assert typ != bitcoin.TYPE_SCRIPT

    assert len(signdesc.keyDescriptor.pubKey) == 0
    pri = fetchPrivKey(str_address, signdesc.keyDescriptor.keyLocator.family, signdesc.keyDescriptor.keyLocator.index)

    isNestedWitness = False  # because NewAddress only does native addresses

    witnessProgram = None
    ourScriptSig = None

    if isNestedWitness:
        pub = pri.get_public_key()

        scr = bitcoin.hash_160(pub)

        witnessProgram = b"\x00\x14" + scr

        # \x14 is OP_20
        ourScriptSig = b"\x16\x00\x14" + scr
    else:
        # TODO TEST
        witnessProgram = signdesc.output.pkScript
        ourScriptSig = b""
        print("set empty ourScriptSig")
        print("witnessProgram", witnessProgram)

    # If a tweak (single or double) is specified, then we'll need to use
    # this tweak to derive the final private key to be used for signing
    # this output.
    pri2 = maybeTweakPrivKey(signdesc, pri)

    #
    # Generate a valid witness stack for the input.
    # TODO(roasbeef): adhere to passed HashType
    witnessScript, pkData = witnessSignature(tx, signdesc.sigHashes,
                                             signdesc.inputIndex, signdesc.output.value, witnessProgram,
                                             sigHashAll, pri2, True)
    return InputScript(witness=(witnessScript, pkData), scriptSig=ourScriptSig)

from collections import namedtuple
QueueItem = namedtuple("QueueItem", ["methodName", "args"])

class LightningRPC:
    def __init__(self):
        super(LightningRPC, self).__init__()
        self.queue = queue.Queue()
        self.subscribers = []
    # overridden
    async def run(self, netAndWalLock):
      while asyncio.get_event_loop().is_running():
        try:
            qitem = self.queue.get(block=False)
        except queue.Empty:
            await asyncio.sleep(5)
            pass
        else:
            def lightningRpcNetworkRequestThreadTarget(qitem):
                applyMethodName = lambda x: functools.partial(x, qitem.methodName)
                client = Server("http://" + machine + ":8090")
                argumentStrings = [str(x) for x in qitem.args]
                lightningSessionKey = base64.b64encode(privateKeyHash[:6]).decode("ascii")
                resolvedMethod = getattr(client, qitem.methodName)
                try:
                    result = resolvedMethod(lightningSessionKey, *argumentStrings)
                except BaseException as e:
                    traceback.print_exc()
                    for i in self.subscribers: applyMethodName(i)(e)
                    raise
                toprint = result
                try:
                    assert result["stderr"] == "" and result["returncode"] == 0, "LightningRPC detected error: " + result["stderr"]
                    toprint = json.loads(result["stdout"])
                    for i in self.subscribers: applyMethodName(i)(toprint)
                except BaseException as e:
                    traceback.print_exc()
                    for i in self.subscribers: applyMethodName(i)(e)
                if self.console:
                    self.console.new_lightning_result.emit(json.dumps(toprint, indent=4))
            threading.Thread(target=lightningRpcNetworkRequestThreadTarget, args=(qitem, )).start()
    def setConsole(self, console):
        self.console = console
    def subscribe(self, notifyFunction):
        self.subscribers.append(notifyFunction)
    def clearSubscribers():
        self.subscribers = []

def lightningCall(rpc, methodName):
    def fun(*args):
        rpc.queue.put(QueueItem(methodName, args))
    return fun

class LightningUI():
    def __init__(self, lightningGetter):
        self.rpc = lightningGetter
    def __getattr__(self, nam):
        synced, local, server = isSynced()
        if not synced:
            return lambda *args: "Not synced yet: local/server: {}/{}".format(local, server)
        return lightningCall(self.rpc(), nam)

privateKeyHash = None

class LightningWorker:
    def __init__(self, wallet, network, config):
        global privateKeyHash
        super(LightningWorker, self).__init__()
        self.server = None
        self.wallet = wallet
        self.network = network
        self.config = config
        ks = self.wallet().keystore
        assert hasattr(ks, "xprv"), "Wallet must have xprv, can't be e.g. imported"
        try:
            xprv = ks.get_master_private_key(None)
        except:
            raise BaseException("Could not get master private key, is the wallet password protected?")
        xprv, xpub = bitcoin.bip32_private_derivation(xprv, "m/", "m/152/152/152/152")
        tupl = bitcoin.deserialize_xprv(xprv)
        privKey = tupl[-1]
        assert type(privKey) is type(bytes([]))
        privateKeyHash = bitcoin.Hash(privKey)

        deser = bitcoin.deserialize_xpub(wallet().keystore.xpub)
        assert deser[0] == "p2wpkh", deser
        self.subscribers = []

    async def run(self, netAndWalLock):
        global WALLET, NETWORK
        global CONFIG

        wasAlreadyUpToDate = False

        while asyncio.get_event_loop().is_running():
            WALLET = self.wallet()
            NETWORK = self.network()
            CONFIG = self.config()

            writer = None
            print("OPENING CONNECTION")
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(machine, 1080), 5)
                writer.write(b"MAGIC")
                writer.write(privateKeyHash[:6])
                await asyncio.wait_for(writer.drain(), 5)
                while asyncio.get_event_loop().is_running():
                    print(datetime.datetime.now(), "READING REQUEST")
                    obj = await readJson(reader)
                    if not obj: continue
                    if "id" not in obj:
                        print("Invoice update?", obj)
                        for i in self.subscribers: i(obj)
                        continue
                    print(datetime.datetime.now(), "making reply")
                    await asyncio.wait_for(readReqAndReply(obj, writer, netAndWalLock), 10)
            except:
                traceback.print_exc()
                await asyncio.sleep(5)
                continue
    def subscribe(self, notifyFunction):
        self.subscribers.append(functools.partial(notifyFunction, "LightningWorker"))

async def readJson(reader):
    data = b""
    while asyncio.get_event_loop().is_running():
      newlines = sum(1 if x == b"\n"[0] else 0 for x in data)
      if newlines > 1: print("Too many newlines in Electrum/lightning.py!", data)
      try:
        return json.loads(data)
      except ValueError:
        try:
            data += await asyncio.wait_for(reader.read(1), 1)
        except TimeoutError:
            continue

async def readReqAndReply(obj, writer, netAndWalLock):
    methods = [
    # SecretKeyRing
    DerivePrivKey,
    DeriveNextKey,
    DeriveKey,
    ScalarMult
    # Signer / BlockchainIO
    ,ConfirmedBalance
    ,NewAddress
    ,ListUnspentWitness
    ,WriteDb
    ,FetchInputInfo
    ,ComputeInputScript
    ,SignOutputRaw
    ,PublishTransaction
    ,LockOutpoint
    ,UnlockOutpoint
    ,ListTransactionDetails
    ,SendOutputs
    ,IsSynced
    ,SignMessage]
    result = None
    found = False
    try:
        for method in methods:
            if method.__name__ == obj["method"]:
                params = obj["params"][0]
                print("calling method", obj["method"], "with", params)
                netAndWalLock.acquire()
                if asyncio.iscoroutinefunction(method):
                    result = await method(params)
                else:
                    result = method(params)
                netAndWalLock.release()
                found = True
                break
    except BaseException as e:
        traceback.print_exc()
        print("exception while calling method", obj["method"])
        writer.write(json.dumps({"id":obj["id"],"error": {"code": -32002, "message": traceback.format_exc()}}).encode("ascii") + b"\n")
        await writer.drain()
    else:
        if not found:
            # TODO assumes obj has id
            writer.write(json.dumps({"id":obj["id"],"error": {"code": -32601, "message": "invalid method"}}).encode("ascii") + b"\n")
        else:
            print("result was", result)
            if result is None:
                result = "{}"
            try:
                assert type({}) is type(json.loads(result))
            except:
                traceback.print_exc()
                print("wrong method implementation")
                writer.write(json.dumps({"id":obj["id"],"error": {"code": -32000, "message": "wrong return type in electrum-lightning-hub"}}).encode("ascii") + b"\n")
            else:
                writer.write(json.dumps({"id":obj["id"],"result": result}).encode("ascii") + b"\n")
        await writer.drain()

def privKeyForPubKey(pubKey):
    global globalIdx
    priv_keys = WALLET.storage.get("lightning_extra_keys", [])
    for i in priv_keys:
        candidate = EC_KEY(i.to_bytes(32, "big"))
        if pubkFromECKEY(candidate) == pubKey:
            return candidate

    attemptKeyIdx = globalIdx - 1
    while attemptKeyIdx >= 0:
      attemptPrivKey = fetchPrivKey(None, 9000, attemptKeyIdx)
      attempt = pubkFromECKEY(attemptPrivKey)
      if attempt == pubKey:
        return attemptPrivKey
      attemptKeyIdx -= 1

    adr = bitcoin.pubkey_to_address('p2wpkh', binascii.hexlify(pubKey).decode("utf-8"))
    pri, redeem_script = WALLET.export_private_key(adr, None)

    if redeem_script:
        print("ignoring redeem script", redeem_script)

    typ, pri, compressed = bitcoin.deserialize_privkey(pri)
    return EC_KEY(pri)
    
    #assert False, "could not find private key for pubkey {} hex={}".format(pubKey, binascii.hexlify(pubKey).decode("ascii"))

def derivePrivKey(keyDesc):
    keyDescFam = keyDesc.keyLocator.family
    keyDescIdx = keyDesc.keyLocator.index
    keyDescPubKey = keyDesc.pubKey
    privKey = None

    if len(keyDescPubKey) != 0:
        return privKeyForPubKey(keyDescPubKey)

    return fetchPrivKey(None, keyDescFam, keyDescIdx)

def DerivePrivKey(json):
    req = rpc_pb2.DerivePrivKeyRequest()
    json_format.Parse(json, req)

    m = rpc_pb2.DerivePrivKeyResponse()

    m.privKey = derivePrivKey(req.keyDescriptor).secret.to_bytes(32, "big")

    msg = json_format.MessageToJson(m)
    return msg

globalIdx = 0

def DeriveNextKey(json):
    global globalIdx
    req = rpc_pb2.DeriveNextKeyRequest()
    json_format.Parse(json, req)

    family = req.keyFamily

    m = rpc_pb2.DeriveNextKeyResponse()

    # lnd leaves these unset:
    # source: https://github.com/lightningnetwork/lnd/pull/769/files#diff-c954f5135a8995b1a3dfa298101dd0efR160
    #m.keyDescriptor.keyLocator.family = 
    #m.keyDescriptor.keyLocator.index = 

    m.keyDescriptor.pubKey = pubkFromECKEY(fetchPrivKey(None, 9000, globalIdx))
    globalIdx += 1

    msg = json_format.MessageToJson(m)
    return msg

def DeriveKey(json):
    req = rpc_pb2.DeriveKeyRequest()
    json_format.Parse(json, req)

    family = req.keyLocator.family
    idx =  req.keyLocator.index

    m = rpc_pb2.DeriveKeyResponse()

    #lnd sets these to parameter values
    m.keyDescriptor.keyLocator.family = family
    m.keyDescriptor.keyLocator.index = index

    m.keyDescriptor.pubKey = pubkFromECKEY(fetchPrivKey(None, family, index))

    msg = json_format.MessageToJson(m)
    return msg

#// ScalarMult performs a scalar multiplication (ECDH-like operation) between
#// the target key descriptor and remote public key. The output returned will be
#// the sha256 of the resulting shared point serialized in compressed format. If
#// k is our private key, and P is the public key, we perform the following
#// operation:
#//
#//  sx := k*P s := sha256(sx.SerializeCompressed())
def ScalarMult(json):
    req = rpc_pb2.ScalarMultRequest()
    json_format.Parse(json, req)

    privKey = derivePrivKey(req.keyDescriptor)

    point = bitcoin.ser_to_point(req.pubKey)

    point = point * privKey.secret

    c = hashlib.sha256()
    c.update(bitcoin.point_to_ser(point, True))

    m = rpc_pb2.ScalarMultResponse()

    m.hashResult = c.digest()

    msg = json_format.MessageToJson(m)
    return msg

def pubkFromECKEY(eckey):
    return bytes(bytearray.fromhex(eckey.get_public_key(True))) #compressed=True
