from btchip import btchip
from btchip.btchipComm import *
from btchip.bitcoinTransaction import *
from btchip.bitcoinVarint import *
from btchip.btchipException import *
from btchip.btchipHelpers import *
from btchip.btchipKeyRecovery import *
from binascii import hexlify, unhexlify

from .oceanTransaction import oceanTransaction
import struct

class btchip_ocean(btchip.btchip):
        
        def getTrustedInput(self, transaction, index):
                result = {}
                # Header
                apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x00, 0x00 ]
                params = bytearray.fromhex("%.8x" % (index))
                params.extend(struct.pack('<I',transaction.version))
                params.extend(struct.pack('<B',transaction.flag))
                writeVarint(len(transaction.inputs), params)
                
                
                apdu.append(len(params))
                apdu.extend(params)
                self.dongle.exchange(bytearray(apdu))
                # Each input
                for trinput in transaction.inputs:
                        apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00 ]
                        params = bytearray(trinput.prev_hash)
                        params.extend(struct.pack('<I',trinput.prev_idx))
                        writeVarint(len(trinput.script), params)
                        apdu.append(len(params))
                        apdu.extend(params)
                        self.dongle.exchange(bytearray(apdu))
                        offset = 0
                        while True:
                                blockLength = 251
                                if ((offset + blockLength) < len(trinput.script)):
                                        dataLength = blockLength
                                else:
                                        dataLength = len(trinput.script) - offset
                                params=bytearray(trinput.script[offset : offset + dataLength])
                                #Append the sequence data if we have finished sending the script data.
                                if ((offset + dataLength) == len(trinput.script)):
                                        params.extend(struct.pack('<I', trinput.sequence))
                                apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, len(params) ]
                                apdu.extend(params)
                                self.dongle.exchange(bytearray(apdu))
                                offset += dataLength
                                if (offset >= len(trinput.script)):
                                        break
                # Number of outputs
                apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00 ]
                params = []
                writeVarint(len(transaction.outputs), params)
                apdu.append(len(params))
                apdu.extend(params)
                self.dongle.exchange(bytearray(apdu))
                # Each output
                indexOutput = 0
                for troutput in transaction.outputs:
                        apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00 ]
                        params = bytearray(troutput.asset)        
                        params.extend(bytearray(troutput.value))
                        params.extend(bytearray(troutput.nonce))
                        writeVarint(len(troutput.script), params)
                        apdu.append(len(params))
                        apdu.extend(params)
                        self.dongle.exchange(bytearray(apdu))
                        offset = 0
                        while (offset < len(troutput.script)):
                                blockLength = 255
                                if ((offset + blockLength) < len(troutput.script)):
                                        dataLength = blockLength
                                else:
                                        dataLength = len(troutput.script) - offset
                                apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, dataLength ]
                                script_part=troutput.script[offset : offset + dataLength]
                                apdu.extend(script_part)
                                self.dongle.exchange(bytearray(apdu))
                                offset += dataLength
                # LockTime
                tl_bytes=struct.pack('<I',transaction.lockTime)
                apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, len(tl_bytes)]
                apdu.extend(tl_bytes)
                response = self.dongle.exchange(bytearray(apdu))
                result['trustedInput'] = True
                result['value'] = response
                return result

        def finalizeInput(self, outputAddress, amount, fees, changePath, rawTx=None):
                alternateEncoding = False
                donglePath = parse_bip32_path(changePath)
                if self.needKeyCache:
                        self.resolvePublicKeysInPath(changePath)                
                result = {}
                outputs = None
                if rawTx is not None:
                        try:
                                fullTx = oceanTransaction(bytes(rawTx))
                                outputs = fullTx.serializeOutputs()
                                if len(donglePath) != 0:
                                        apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, 0xFF, 0x00 ]
                                        params = []
                                        params.extend(donglePath)
                                        apdu.append(len(params))
                                        apdu.extend(params)
                                        response = self.dongle.exchange(bytearray(apdu))
                                        
 
                                offset = 0
                                while (offset < len(outputs)):
                                        blockLength = self.scriptBlockLength
                                        if ((offset + blockLength) < len(outputs)):
                                                dataLength = blockLength
                                                p1 = 0x00
                                        else:
                                                dataLength = len(outputs) - offset
                                                p1 = 0x80
                                        apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, \
                                                 p1, 0x00, dataLength ]
                                        apdu.extend(outputs[offset : offset + dataLength])
                                        response = self.dongle.exchange(bytearray(apdu))
                                        offset += dataLength
                                alternateEncoding = True
                        except:
                                pass
                if not alternateEncoding:
                        apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE, 0x02, 0x00 ]
                        params = []
                        params.extend(bytearray(len(outputAddress)))
                        assert isinstance(outputAddress, bytes)
                        params.extend(bytearray(outputAddress))
                        writeHexAmountBE(btc_to_satoshi(str(amount)), params)
                        writeHexAmountBE(btc_to_satoshi(str(fees)), params)
                        params.extend(donglePath)
                        apdu.append(len(params))
                        apdu.extend(params)
                        response = self.dongle.exchange(bytearray(apdu))
                result['confirmationNeeded'] = response[1 + response[0]] != 0x00
                result['confirmationType'] = response[1 + response[0]]
                if result['confirmationType'] == 0x02:
                        result['keycardData'] = response[1 + response[0] + 1:]
                if result['confirmationType'] == 0x03:
                        offset = 1 + response[0] + 1 
                        keycardDataLength = response[offset]
                        offset = offset + 1
                        result['keycardData'] = response[offset : offset + keycardDataLength]
                        offset = offset + keycardDataLength
                        result['secureScreenData'] = response[offset:]
                if result['confirmationType'] == 0x04:
                        offset = 1 + response[0] + 1
                        keycardDataLength = response[offset]
                        result['keycardData'] = response[offset + 1 : offset + 1 + keycardDataLength]                        
                if outputs == None:
                        result['outputData'] = response[1 : 1 + response[0]]
                else:
                        result['outputData'] = outputs
                return result























                
                alternateEncoding = False
                donglePath = parse_bip32_path(changePath)
                if self.needKeyCache:
                        self.resolvePublicKeysInPath(changePath)                
                result = {}
                outputs = None
                if rawTx is not None:
                        try:
                                fullTx = oceanTransaction(bytes(rawTx))
                                outputs = fullTx.serializeOutputs()
                                if len(donglePath) != 0:
                                        apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, 0xFF, 0x00 ]
                                        params = []
                                        params.extend(donglePath)
                                        apdu.append(len(params))
                                        apdu.extend(params)
                                        response = self.dongle.exchange(bytearray(apdu))
                                        
                                offset = 0
                                while (offset < len(outputs)):
                                        blockLength = self.scriptBlockLength
                                        if ((offset + blockLength) < len(outputs)):
                                                dataLength = blockLength
                                                p1 = 0x00
                                        else:
                                                dataLength = len(outputs) - offset
                                                p1 = 0x80
                                        apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, \
                                                p1, 0x00, dataLength ]
                                        apdu.extend(outputs[offset : offset + dataLength])
                                        response = self.dongle.exchange(bytearray(apdu))
                                        offset += dataLength
                                alternateEncoding = True
                        except:
                                pass
                if not alternateEncoding:
                        apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE, 0x02, 0x00 ]
                        params = []
                        params.append(len(outputAddress))
                        params.extend(bytearray(outputAddress))
                        writeHexAmountBE(btc_to_satoshi(str(amount)), params)
                        writeHexAmountBE(btc_to_satoshi(str(fees)), params)
                        params.extend(donglePath)
                        apdu.append(len(params))
                        apdu.extend(params)
                        response = self.dongle.exchange(bytearray(apdu))
                result['confirmationNeeded'] = response[1 + response[0]] != 0x00
                result['confirmationType'] = response[1 + response[0]]
                if result['confirmationType'] == 0x02:
                        result['keycardData'] = response[1 + response[0] + 1:]
                if result['confirmationType'] == 0x03:
                        offset = 1 + response[0] + 1 
                        keycardDataLength = response[offset]
                        offset = offset + 1
                        result['keycardData'] = response[offset : offset + keycardDataLength]
                        offset = offset + keycardDataLength
                        result['secureScreenData'] = response[offset:]
                if result['confirmationType'] == 0x04:
                        offset = 1 + response[0] + 1
                        keycardDataLength = response[offset]
                        result['keycardData'] = response[offset + 1 : offset + 1 + keycardDataLength]                        
                if outputs == None:
                        result['outputData'] = response[1 : 1 + response[0]]
                else:
                        result['outputData'] = outputs
                return result
