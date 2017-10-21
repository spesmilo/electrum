import sys
import struct
import traceback
sys.path.insert(0, "lib/ln")
from .ln import rpc_pb2
import os
from . import keystore, bitcoin, daemon, interface
import socket

import concurrent.futures as futures
import time
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer
import json as jsonm
from google.protobuf import json_format
import binascii

WALLET = None
NETWORK = None

def SetHdSeed(json):
  print("set hdseed unimplemented")
  m = rpc_pb2.SetHdSeedResponse()
  msg = json_format.MessageToJson(m)
  return msg
def ConfirmedBalance(json):
  global pubk
  request = rpc_pb2.ConfirmedBalanceRequest()
  json_format.Parse(json, request)
  m = rpc_pb2.ConfirmedBalanceResponse()
  confs = request.confirmations
  witness = request.witness # bool

  WALLET.synchronize()
  WALLET.wait_until_synchronized()

  m.amount = sum(WALLET.get_balance())
  msg = json_format.MessageToJson(m)
  return msg
def NewAddress(json):
  request = rpc_pb2.NewAddressRequest()
  json_format.Parse(json, request)
  m = rpc_pb2.NewAddressResponse()
  if request.type == rpc_pb2.NewAddressRequest.WITNESS_PUBKEY_HASH:
    m.address = WALLET.get_unused_address()
  elif request.type == rpc_pb2.NewAddressRequest.NESTED_PUBKEY_HASH:
    assert False
  elif request.type == rpc_pb2.NewAddressRequest.PUBKEY_HASH:
    assert False
  else:
    assert False
  msg = json_format.MessageToJson(m)
  return msg
def FetchRootKey(json):
  global K_compressed
  request = rpc_pb2.FetchRootKeyRequest()
  json_format.Parse(json, request)
  m = rpc_pb2.FetchRootKeyResponse()
  m.rootKey = K_compressed # TODO this should actually be a private key
  msg = json_format.MessageToJson(m)
  return msg

cl = rpc_pb2.ListUnspentWitnessRequest
def ListUnspentWitness(json):
  global pubk
  req = cl()
  json_format.Parse(json, req)
  confs = req.minConfirmations

  WALLET.synchronize()
  WALLET.wait_until_synchronized()

  unspent = WALLET.get_utxos()
  m = rpc_pb2.ListUnspentWitnessResponse()
  for utxo in unspent:
    print(utxo)
    #example:
    # {'prevout_n': 0,
    #  'address': 'sb1qt52ccplvtpehz7qvvqft2udf2eaqvfsal08xre',
    #  'prevout_hash': '0d4caccd6e8a906c8ca22badf597c4dedc6dd7839f3cac3137f8f29212099882',
    #  'coinbase': False,
    #  'height': 326,
    #  'value': 400000000}


    towire = m.utxos.add()
    towire.value = utxo["value"]
    towire.outPoint.hash = utxo["prevout_hash"]
    towire.outPoint.index = utxo["prevout_n"]
  #m.utxos[0].value =
  return json_format.MessageToJson(m)

i = 0

def NewRawKey(json):
  global i
  addresses = WALLET.get_unused_addresses()
  res = rpc_pb2.NewRawKeyResponse()
  i = i + 1
  if i > len(addresses)-1:
    i = 0
  pubk = addresses[i]
  res.publicKey = bytes(bytearray.fromhex(WALLET.get_public_keys(pubk)[0]))
  return json_format.MessageToJson(res)

def FetchInputInfo(json):
  print(json)
  req = rpc_pb2.FetchInputInfoRequest()
  json_format.Parse(json, req)
  has = req.outPoint.hash
  idx = req.outPoint.index
  print(list(WALLET.txo.values())[:10])
  txoinfo = WALLET.txo.get(has, {})
  print("txoinfo", has, txoinfo)
  m = rpc_pb2.FetchInputInfoResponse()
  if has in WALLET.transactions:
    tx = WALLET.transactions[has]
  else:
    res = q(has, 'blockchain.transaction.get')
    print(res)
    assert res
    tx = transaciton.Transaction(res)
    print("did not find tx with hash", has)
    print(tx)
    assert False
  outputs = tx.outputs()
  print("output:")
  print(outputs[idx])
  assert {bitcoin.TYPE_SCRIPT: "SCRIPT", bitcoin.TYPE_ADDRESS: "ADDRESS", bitcoin.TYPE_PUBKEY: "PUBKEY"}[outputs[idx][0]] == "ADDRESS"
  scr = transaction.Transaction.pay_script(outputs[idx][0], outputs[idx][1])
  print("scr")
  print(scr)
  #q(has, "blockchain.transaction.get")
  m.txOut.value = outputs[idx][2] # type, addr, val
  #m.txOut.value = 10
  #m.txOut.pkScript = b"lol"
  m.txOut.pkScript = bytes(bytearray.fromhex(scr))
  msg = json_format.MessageToJson(m)
  #raise Exception(msg)
  return msg

def q(pubk, cmd='blockchain.address.get_balance'):
  #print(NETWORK.synchronous_get(('blockchain.address.get_balance', [pubk]), timeout=1))
  # create an INET, STREAMing socket
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # now connect to the web server on port 80 - the normal http port
  s.connect(("localhost", 50001))
  i = interface.Interface("localhost:50001:garbage", s)
  i.queue_request(cmd, [pubk], 42) # 42 is id
  i.send_requests()
  time.sleep(.1)
  res = i.get_responses()
  assert len(res) == 1
  print(res[0][1])
  return res[0][1]["result"]

def serve(config, port):
  server = SimpleJSONRPCServer(('localhost', int(port)))
  server.register_function(FetchRootKey)
  server.register_function(ConfirmedBalance)
  server.register_function(NewAddress)
  server.register_function(ListUnspentWitness)
  server.register_function(SetHdSeed)
  server.register_function(NewRawKey)
  server.register_function(FetchInputInfo)
  server.register_function(ComputeInputScript)
  server.serve_forever()

def test_lightning(wallet, networ, config, port):
  global WALLET, NETWORK, pubk, K_compressed
  WALLET = wallet
  assert networ is None

  from . import network

  assert len(bitcoin.DEFAULT_SERVERS) == 1, bitcoin.DEFAULT_SERVERS
  networ = network.Network(config)
  networ.start()
  wallet.start_threads(networ)
  wallet.synchronize()
  print("WAITING!!!!")
  wallet.wait_until_synchronized()
  print("done")

  NETWORK = networ
  print("utxos", WALLET.get_utxos())

  deser = bitcoin.deserialize_xpub(wallet.keystore.xpub)
  assert deser[0] == "segwit", deser

  pubk = wallet.get_unused_address()
  K_compressed = bytes(bytearray.fromhex(wallet.get_public_keys(pubk)[0]))
  #adr = bitcoin.public_key_to_p2wpkh(K_compressed)

  assert len(K_compressed) == 33, len(K_compressed)

  assert wallet.pubkeys_to_address(binascii.hexlify(K_compressed).decode("utf-8")) in wallet.get_addresses()
  #print(q(pubk, 'blockchain.address.listunspent'))

  serve(config, port)

def LEtobytes(x,l):
  if l == 2:
    fmt = "<H"
  elif l == 4:
    fmt = "<I"
  elif l == 8:
    fmt = "<Q"
  else:
    assert False
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
    assert False, len(x)
  return struct.unpack(fmt, x)[0]

class SignDescriptor(object):
  def __init__(self, pubKey=None, sigHashes=None, inputIndex=None, singleTweak=None,hashType=None,doubleTweak=None,witnessScript=None,output=None):
    self.pubKey = pubKey
    self.sigHashes = sigHashes
    self.inputIndex = inputIndex
    self.singleTweak = singleTweak
    self.hashType = hashType
    self.doubleTweak = doubleTweak
    self.witnessScript = witnessScript
    self.output = output
  def __str__(self):
      return '%s(%s)' % (
          type(self).__name__,
          ', '.join('%s=%s' % item for item in vars(self).items())
      )

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

from .bitcoin import EC_KEY, public_key_to_p2pkh
from . import bitcoin
from .transaction import decode_script
from . import transaction

def maybeTweakPrivKey(signdesc, pri):
  if len(signdesc.singleTweak) > 0:
    return tweakPrivKey(pri, signdesc.singleTweak)
  elif len(signdesc.doubleTweak) > 0:
    return deriveRevocationPrivKey(pri, signdesc.doubleTweak)
  else:
    return pri

def isWitnessPubKeyHash(script):
  if len(script) != 2: return False
  haveop0 = transaction.opcodes.OP_0 == script[0][0]
  haveopdata20 = 20 == script[1][0]
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
def calcWitnessSignatureHash(subscript, sigHashes, hashType, tx, idx, amt):
  #correct = "".join(map(lambda x: chr(int(x)), "1 0 0 0 217 43 73 76 147 7 70 63 188 219 20 47 234 97 195 13 216 87 117 11 107 76 81 144 254 102 255 191 72 130 26 154 59 177 48 41 206 123 31 85 158 245 231 71 252 172 67 159 20 85 162 236 124 95 9 183 34 144 121 94 112 102 80 68 211 171 158 20 224 139 71 93 77 94 74 135 98 70 57 191 79 168 32 75 105 235 123 26 235 34 171 178 162 172 163 27 1 0 0 0 25 118 169 20 157 152 5 36 153 45 228 145 20 188 199 140 125 173 247 140 169 123 131 107 136 172 0 228 11 84 2 0 0 0 255 255 255 255 49 104 166 12 84 134 136 136 201 54 92 173 174 23 215 5 206 240 150 172 65 238 5 213 166 63 170 11 195 67 37 187 0 0 0 0 1 0 0 0".split(" ")))
  print("calcWitnessSignatureHash. here is transaction:")
  print(tx)
  decoded = transaction.deserialize(binascii.hexlify(tx).decode("utf-8"))
  if idx > len(decoded["inputs"])-1:
    raise Exception("invalid inputIndex")
  txin = decoded["inputs"][idx]
  #tohash = transaction.Transaction.serialize_witness(txin)
  sigHash = LEtobytes(decoded["version"],4)
  if toint(hashType) & toint(sigHashAnyOneCanPay) == 0:
    sigHash += bytes(bytearray.fromhex(sigHashes.hashPrevOuts))
  else:
    sigHash += b"\x00" * 32
  #assert correct[:len(sigHash)] == sigHash, "\n" + sigHash.encode("hex") + "\n" + correct[:len(sigHash)].encode("hex")

  if toint(hashType) & toint(sigHashAnyOneCanPay) == 0 and toint(hashType) & toint(sigHashMask) != toint(sigHashSingle) and toint(hashType) & toint(sigHashMask) != toint(sigHashNone):
    sigHash += bytes(bytearray.fromhex(sigHashes.hashSequence))
  else:
    sigHash += b"\x00" * 32
  #assert correct[:len(sigHash)] == sigHash, "\n" + sigHash.encode("hex") + "\n" + correct[:len(sigHash)].encode("hex")

  #assert txin["prevout_hash"] == "1ba3aca2b2ab22eb1a7beb694b20a84fbf394662874a5e4d5d478be0149eabd3"
  sigHash += bytes(bytearray.fromhex(txin["prevout_hash"]))[::-1]
  sigHash += LEtobytes(txin["prevout_n"],4)

  #assert correct[:len(sigHash)] == sigHash, "\n" + sigHash.encode("hex") + "\n" + correct[:len(sigHash)].encode("hex")

  if isWitnessPubKeyHash(subscript):
    sigHash += b"\x19"
    sigHash += bytes([transaction.opcodes.OP_DUP])
    sigHash += bytes([transaction.opcodes.OP_HASH160])
    sigHash += b"\x14" # 20 bytes
    opcode, data, length = subscript[1]
    sigHash += data
    sigHash += bytes([transaction.opcodes.OP_EQUALVERIFY])
    sigHash += bytes([transaction.opcodes.OP_CHECKSIG])
  else:
		# // For p2wsh outputs, and future outputs, the script code is
		# // the original script, with all code separators removed,
		# // serialized with a var int length prefix.
    raise Exception("TODO")
  #assert correct[:len(sigHash)] == sigHash, "\n" + sigHash.encode("hex") + "\n" + correct[:len(sigHash)].encode("hex")

  sigHash += LEtobytes(amt, 8)
  sigHash += LEtobytes(txin["sequence"], 4)

  #assert correct[:len(sigHash)] == sigHash, "\n" + sigHash.encode("hex") + "\n" + correct[:len(sigHash)].encode("hex")

  if toint(hashType) & toint(sigHashSingle) != toint(sigHashSingle) and toint(hashType) & toint(sigHashNone) != toint(sigHashNone):
    sigHash += bytes(bytearray.fromhex(sigHashes.hashOutputs))
  elif toint(hashtype) & toint(sigHashMask) == toint(sigHashSingle) and idx < len(decoded["outputs"]):
    raise Exception("TODO")
  else:
    raise Exception("TODO")

  sigHash += LEtobytes(decoded["lockTime"], 4)
  sigHash += LEtobytes(toint(hashType), 4)

  #assert correct[:len(sigHash)] == sigHash, "\n" + sigHash.encode("hex") + "\n" + correct[:len(sigHash)].encode("hex")

  #assert sigHash == correct, [ord(x) for x in sigHash]
  return transaction.Hash(sigHash)

#// RawTxInWitnessSignature returns the serialized ECDA signature for the input
#// idx of the given transaction, with the hashType appended to it. This
#// function is identical to RawTxInSignature, however the signature generated
#// signs a new sighash digest defined in BIP0143.
#func RawTxInWitnessSignature(tx *MsgTx, sigHashes *TxSigHashes, idx int,
#	amt int64, subScript []byte, hashType SigHashType,
#	key *btcec.PrivateKey) ([]byte, error) {
def rawTxInWitnessSignature(tx, sigHashes, idx, amt, subscript, hashType, key):
  parsed = list(transaction.script_GetOp(subscript))
  digest = calcWitnessSignatureHash(parsed, sigHashes, hashType, tx, idx, amt)
  #assert digest == ''.join(map(lambda x: chr(int(x)), "33 236 33 111 254 94 205 8 151 34 154 141 176 156 16 118 34 2 183 224 53 72 53 155 60 72 96 110 24 220 112 24".split(" ")))
  number = string_to_number(digest)
  signkey = MySigningKey.from_secret_exponent(key.secret, curve=ecdsa.curves.SECP256k1)
  sig = signkey.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der) + hashType
  return sig

from ecdsa.util import string_to_number
import ecdsa.curves
from .bitcoin import MySigningKey
import hashlib

#// WitnessSignature creates an input witness stack for tx to spend BTC sent
#// from a previous output to the owner of privKey using the p2wkh script
#// template. The passed transaction must contain all the inputs and outputs as
#// dictated by the passed hashType. The signature generated observes the new
#// transaction digest algorithm defined within BIP0143.
def witnessSignature(tx, sigHashes, idx, amt, subscript, hashType, privKey, compress):
  sig = rawTxInWitnessSignature(tx, sigHashes, idx, amt, subscript, hashType, privKey)
  #ref = ''.join(map(lambda x: chr(int(x)),"48 68 2 32 62 85 194 71 180 244 2 87 141 53 208 147 25 47 181 82 25 88 118 216 45 70 168 14 65 144 142 71 205 4 105 209 2 32 17 185 10 179 229 150 236 161 45 49 199 206 16 79 105 228 13 185 39 231 184 62 199 137 80 190 249 211 70 248 95 40 1".split(" ")))

  #assert sig == ref, "\n" + str([ord(x) for x in ref]) + "\n" + str([ord(x) for x in sig])

  pkData = bytes(bytearray.fromhex(privKey.get_public_key(compressed=compress)))

  return sig, pkData

sigHashMask = b"\x1f"

sigHashAll = b"\x01"
sigHashNone = b"\x02"
sigHashSingle = b"\x03"
sigHashAnyOneCanPay = b"\x80"

test = rpc_pb2.ComputeInputScriptResponse()

test.witnessScript.append(b"\x01")
test.witnessScript.append(b"\x02")

def ComputeInputScript(json):
  req = rpc_pb2.ComputeInputScriptRequest()
  json_format.Parse(json, req)

  assert len(req.signDesc.pubKey) in [33, 0]
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

def computeInputScript(tx, signdesc):
    print("pkScript")
    print(signdesc.output.pkScript)
    typ, str_address = transaction.get_address_from_output_script(signdesc.output.pkScript)
    assert typ != bitcoin.TYPE_SCRIPT
    try:
      base58 = bitcoin.hash160_to_b58_address(bitcoin.hash_160(bytearray.fromhex(str_address[2:])),0)
      print("base58:")
      print(base58)
    except:
      print("(not hex)")
    print("getting private key for {}".format(str_address))

    isNestedWitness = True # TODO should not be hardcoded

    # TODO FIXME privkey should be retrieved from wallet using str_address and signer_key
    pri, redeem_script = WALLET.export_private_key(str_address, None)
    typ, pri, compressed = bitcoin.deserialize_privkey(pri)
    pri = EC_KEY(pri)
    print("ignoring redeem script", redeem_script)

    witnessProgram = None
    ourScriptSig = None

    if isNestedWitness:
      pub = pri.get_public_key()

      scr = bitcoin.hash_160(pub)

      #refwitnessprogram = "".join(map(lambda x: chr(int(x)), "0 20 157 152 5 36 153 45 228 145 20 188 199 140 125 173 247 140 169 123 131 107".split(" ")))
      witnessProgram = b"\x00\x14" + scr
      #assert refwitnessprogram == witnessProgram, (refwitnessprogram.encode("hex"), witnessProgram.encode("hex"))

      #referenceScriptSig = ''.join(map(chr,[22,0,20,157,152,5,36,153,45,228,145,20,188,199,140,125,173,247,140,169,123,131,107]))
      # \x14 is OP_20
      ourScriptSig = b"\x16\x00\x14" + scr
      #assert ourScriptSig == referenceScriptSig, (decode_script(referenceProgram), scr, decode_script(ourProgram))
    else:
      #TODO TEST
      witnessProgram = signdesc.output.pkScript

    #  // If a tweak (single or double) is specified, then we'll need to use
    #  // this tweak to derive the final private key to be used for signing
    #  // this output.
    pri2 = maybeTweakPrivKey(signdesc, pri)
    #  if err != nil {
    #    return nil, err
    #  }
    #
    #  // Generate a valid witness stack for the input.
    #  // TODO(roasbeef): adhere to passed HashType
    witnessScript, pkData = witnessSignature(tx, signdesc.sigHashes,
      signdesc.inputIndex, signdesc.output.value, witnessProgram,
      sigHashAll, pri2, True)
    print([type(witnessScript), type(pkData), type(ourScriptSig)])
    return InputScript(witness = (witnessScript, pkData), scriptSig = ourScriptSig)

if __name__ == '__main__':
  serve()
