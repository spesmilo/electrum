import sys
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
  m.txOut.value = 10
  m.txOut.pkScript = b"lol"
  msg = json_format.MessageToJson(m)
  raise Exception(msg)
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

  assert bitcoin.deserialize_xpub(wallet.keystore.xpub)[0] == "segwit"

  pubk = wallet.get_unused_address()
  K_compressed = bytes(bytearray.fromhex(wallet.get_public_keys(pubk)[0]))
  #adr = bitcoin.public_key_to_p2wpkh(K_compressed)

  assert len(K_compressed) == 33, len(K_compressed)

  assert wallet.pubkeys_to_address(binascii.hexlify(K_compressed).decode("utf-8")) in wallet.get_addresses()
  #print(q(pubk, 'blockchain.address.listunspent'))

  serve(config, port)

if __name__ == '__main__':
  serve()

