# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: types.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import descriptor_pb2 as google_dot_protobuf_dot_descriptor__pb2
from . import exchange_pb2 as exchange__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0btypes.proto\x1a google/protobuf/descriptor.proto\x1a\x0e\x65xchange.proto\"\x80\x01\n\nHDNodeType\x12\r\n\x05\x64\x65pth\x18\x01 \x02(\r\x12\x13\n\x0b\x66ingerprint\x18\x02 \x02(\r\x12\x11\n\tchild_num\x18\x03 \x02(\r\x12\x12\n\nchain_code\x18\x04 \x02(\x0c\x12\x13\n\x0bprivate_key\x18\x05 \x01(\x0c\x12\x12\n\npublic_key\x18\x06 \x01(\x0c\">\n\x0eHDNodePathType\x12\x19\n\x04node\x18\x01 \x02(\x0b\x32\x0b.HDNodeType\x12\x11\n\taddress_n\x18\x02 \x03(\r\"\xe8\x03\n\x08\x43oinType\x12\x11\n\tcoin_name\x18\x01 \x01(\t\x12\x15\n\rcoin_shortcut\x18\x02 \x01(\t\x12\x17\n\x0c\x61\x64\x64ress_type\x18\x03 \x01(\r:\x01\x30\x12\x11\n\tmaxfee_kb\x18\x04 \x01(\x04\x12\x1c\n\x11\x61\x64\x64ress_type_p2sh\x18\x05 \x01(\r:\x01\x35\x12\x1d\n\x15signed_message_header\x18\x08 \x01(\t\x12\x1a\n\x12\x62ip44_account_path\x18\t \x01(\r\x12\x0e\n\x06\x66orkid\x18\x0c \x01(\r\x12\x10\n\x08\x64\x65\x63imals\x18\r \x01(\r\x12\x18\n\x10\x63ontract_address\x18\x0e \x01(\x0c\x12\x1c\n\nxpub_magic\x18\x10 \x01(\r:\x08\x37\x36\x30\x36\x37\x33\x35\x38\x12\x0e\n\x06segwit\x18\x12 \x01(\x08\x12\x14\n\x0c\x66orce_bip143\x18\x13 \x01(\x08\x12\x12\n\ncurve_name\x18\x14 \x01(\t\x12\x17\n\x0f\x63\x61shaddr_prefix\x18\x15 \x01(\t\x12\x15\n\rbech32_prefix\x18\x16 \x01(\t\x12\x0e\n\x06\x64\x65\x63red\x18\x17 \x01(\x08\x12\x1e\n\x16xpub_magic_segwit_p2sh\x18\x19 \x01(\r\x12 \n\x18xpub_magic_segwit_native\x18\x1a \x01(\r\x12\x17\n\x0fnanoaddr_prefix\x18\x1b \x01(\t\"[\n\x18MultisigRedeemScriptType\x12 \n\x07pubkeys\x18\x01 \x03(\x0b\x32\x0f.HDNodePathType\x12\x12\n\nsignatures\x18\x02 \x03(\x0c\x12\t\n\x01m\x18\x03 \x01(\r\"\x9f\x02\n\x0bTxInputType\x12\x11\n\taddress_n\x18\x01 \x03(\r\x12\x11\n\tprev_hash\x18\x02 \x02(\x0c\x12\x12\n\nprev_index\x18\x03 \x02(\r\x12\x12\n\nscript_sig\x18\x04 \x01(\x0c\x12\x1c\n\x08sequence\x18\x05 \x01(\r:\n4294967295\x12\x33\n\x0bscript_type\x18\x06 \x01(\x0e\x32\x10.InputScriptType:\x0cSPENDADDRESS\x12+\n\x08multisig\x18\x07 \x01(\x0b\x32\x19.MultisigRedeemScriptType\x12\x0e\n\x06\x61mount\x18\x08 \x01(\x04\x12\x13\n\x0b\x64\x65\x63red_tree\x18\t \x01(\r\x12\x1d\n\x15\x64\x65\x63red_script_version\x18\n \x01(\r\"\x9e\x02\n\x0cTxOutputType\x12\x0f\n\x07\x61\x64\x64ress\x18\x01 \x01(\t\x12\x11\n\taddress_n\x18\x02 \x03(\r\x12\x0e\n\x06\x61mount\x18\x03 \x02(\x04\x12&\n\x0bscript_type\x18\x04 \x02(\x0e\x32\x11.OutputScriptType\x12+\n\x08multisig\x18\x05 \x01(\x0b\x32\x19.MultisigRedeemScriptType\x12\x16\n\x0eop_return_data\x18\x06 \x01(\x0c\x12(\n\x0c\x61\x64\x64ress_type\x18\x07 \x01(\x0e\x32\x12.OutputAddressType\x12$\n\rexchange_type\x18\x08 \x01(\x0b\x32\r.ExchangeType\x12\x1d\n\x15\x64\x65\x63red_script_version\x18\t \x01(\r\"W\n\x0fTxOutputBinType\x12\x0e\n\x06\x61mount\x18\x01 \x02(\x04\x12\x15\n\rscript_pubkey\x18\x02 \x02(\x0c\x12\x1d\n\x15\x64\x65\x63red_script_version\x18\x03 \x01(\r\"\xc2\x02\n\x0fTransactionType\x12\x0f\n\x07version\x18\x01 \x01(\r\x12\x1c\n\x06inputs\x18\x02 \x03(\x0b\x32\x0c.TxInputType\x12%\n\x0b\x62in_outputs\x18\x03 \x03(\x0b\x32\x10.TxOutputBinType\x12\x1e\n\x07outputs\x18\x05 \x03(\x0b\x32\r.TxOutputType\x12\x11\n\tlock_time\x18\x04 \x01(\r\x12\x12\n\ninputs_cnt\x18\x06 \x01(\r\x12\x13\n\x0boutputs_cnt\x18\x07 \x01(\r\x12\x12\n\nextra_data\x18\x08 \x01(\x0c\x12\x16\n\x0e\x65xtra_data_len\x18\t \x01(\r\x12\x0e\n\x06\x65xpiry\x18\n \x01(\r\x12\x14\n\x0coverwintered\x18\x0b \x01(\x08\x12\x18\n\x10version_group_id\x18\x0c \x01(\r\x12\x11\n\tbranch_id\x18\r \x01(\r\"%\n\x12RawTransactionType\x12\x0f\n\x07payload\x18\x01 \x02(\x0c\"q\n\x14TxRequestDetailsType\x12\x15\n\rrequest_index\x18\x01 \x01(\r\x12\x0f\n\x07tx_hash\x18\x02 \x01(\x0c\x12\x16\n\x0e\x65xtra_data_len\x18\x03 \x01(\r\x12\x19\n\x11\x65xtra_data_offset\x18\x04 \x01(\r\"\\\n\x17TxRequestSerializedType\x12\x17\n\x0fsignature_index\x18\x01 \x01(\r\x12\x11\n\tsignature\x18\x02 \x01(\x0c\x12\x15\n\rserialized_tx\x18\x03 \x01(\x0c\"g\n\x0cIdentityType\x12\r\n\x05proto\x18\x01 \x01(\t\x12\x0c\n\x04user\x18\x02 \x01(\t\x12\x0c\n\x04host\x18\x03 \x01(\t\x12\x0c\n\x04port\x18\x04 \x01(\t\x12\x0c\n\x04path\x18\x05 \x01(\t\x12\x10\n\x05index\x18\x06 \x01(\r:\x01\x30\"2\n\nPolicyType\x12\x13\n\x0bpolicy_name\x18\x01 \x01(\t\x12\x0f\n\x07\x65nabled\x18\x02 \x01(\x08\"\xa4\x02\n\x0c\x45xchangeType\x12\x39\n\x18signed_exchange_response\x18\x01 \x01(\x0b\x32\x17.SignedExchangeResponse\x12%\n\x14withdrawal_coin_name\x18\x02 \x01(\t:\x07\x42itcoin\x12\x1c\n\x14withdrawal_address_n\x18\x03 \x03(\r\x12\x18\n\x10return_address_n\x18\x04 \x03(\r\x12>\n\x16withdrawal_script_type\x18\x05 \x01(\x0e\x32\x10.InputScriptType:\x0cSPENDADDRESS\x12:\n\x12return_script_type\x18\x06 \x01(\x0e\x32\x10.InputScriptType:\x0cSPENDADDRESS*\xe6\x02\n\x0b\x46\x61ilureType\x12\x1d\n\x19\x46\x61ilure_UnexpectedMessage\x10\x01\x12\x1a\n\x16\x46\x61ilure_ButtonExpected\x10\x02\x12\x17\n\x13\x46\x61ilure_SyntaxError\x10\x03\x12\x1b\n\x17\x46\x61ilure_ActionCancelled\x10\x04\x12\x17\n\x13\x46\x61ilure_PinExpected\x10\x05\x12\x18\n\x14\x46\x61ilure_PinCancelled\x10\x06\x12\x16\n\x12\x46\x61ilure_PinInvalid\x10\x07\x12\x1c\n\x18\x46\x61ilure_InvalidSignature\x10\x08\x12\x11\n\rFailure_Other\x10\t\x12\x1a\n\x16\x46\x61ilure_NotEnoughFunds\x10\n\x12\x1a\n\x16\x46\x61ilure_NotInitialized\x10\x0b\x12\x17\n\x13\x46\x61ilure_PinMismatch\x10\x0c\x12\x19\n\x15\x46\x61ilure_FirmwareError\x10\x63*\x87\x01\n\x10OutputScriptType\x12\x10\n\x0cPAYTOADDRESS\x10\x00\x12\x13\n\x0fPAYTOSCRIPTHASH\x10\x01\x12\x11\n\rPAYTOMULTISIG\x10\x02\x12\x11\n\rPAYTOOPRETURN\x10\x03\x12\x10\n\x0cPAYTOWITNESS\x10\x04\x12\x14\n\x10PAYTOP2SHWITNESS\x10\x05*l\n\x0fInputScriptType\x12\x10\n\x0cSPENDADDRESS\x10\x00\x12\x11\n\rSPENDMULTISIG\x10\x01\x12\x0c\n\x08\x45XTERNAL\x10\x02\x12\x10\n\x0cSPENDWITNESS\x10\x03\x12\x14\n\x10SPENDP2SHWITNESS\x10\x04*U\n\x0bRequestType\x12\x0b\n\x07TXINPUT\x10\x00\x12\x0c\n\x08TXOUTPUT\x10\x01\x12\n\n\x06TXMETA\x10\x02\x12\x0e\n\nTXFINISHED\x10\x03\x12\x0f\n\x0bTXEXTRADATA\x10\x04*F\n\x11OutputAddressType\x12\t\n\x05SPEND\x10\x00\x12\x0c\n\x08TRANSFER\x10\x01\x12\n\n\x06\x43HANGE\x10\x02\x12\x0c\n\x08\x45XCHANGE\x10\x03*\x94\t\n\x11\x42uttonRequestType\x12\x17\n\x13\x42uttonRequest_Other\x10\x01\x12\"\n\x1e\x42uttonRequest_FeeOverThreshold\x10\x02\x12\x1f\n\x1b\x42uttonRequest_ConfirmOutput\x10\x03\x12\x1d\n\x19\x42uttonRequest_ResetDevice\x10\x04\x12\x1d\n\x19\x42uttonRequest_ConfirmWord\x10\x05\x12\x1c\n\x18\x42uttonRequest_WipeDevice\x10\x06\x12\x1d\n\x19\x42uttonRequest_ProtectCall\x10\x07\x12\x18\n\x14\x42uttonRequest_SignTx\x10\x08\x12\x1f\n\x1b\x42uttonRequest_FirmwareCheck\x10\t\x12\x19\n\x15\x42uttonRequest_Address\x10\n\x12\x1f\n\x1b\x42uttonRequest_FirmwareErase\x10\x0b\x12*\n&ButtonRequest_ConfirmTransferToAccount\x10\x0c\x12+\n\'ButtonRequest_ConfirmTransferToNodePath\x10\r\x12\x1d\n\x19\x42uttonRequest_ChangeLabel\x10\x0e\x12 \n\x1c\x42uttonRequest_ChangeLanguage\x10\x0f\x12\"\n\x1e\x42uttonRequest_EnablePassphrase\x10\x10\x12#\n\x1f\x42uttonRequest_DisablePassphrase\x10\x11\x12\'\n#ButtonRequest_EncryptAndSignMessage\x10\x12\x12 \n\x1c\x42uttonRequest_EncryptMessage\x10\x13\x12\"\n\x1e\x42uttonRequest_ImportPrivateKey\x10\x14\x12(\n$ButtonRequest_ImportRecoverySentence\x10\x15\x12\x1e\n\x1a\x42uttonRequest_SignIdentity\x10\x16\x12\x16\n\x12\x42uttonRequest_Ping\x10\x17\x12\x1b\n\x17\x42uttonRequest_RemovePin\x10\x18\x12\x1b\n\x17\x42uttonRequest_ChangePin\x10\x19\x12\x1b\n\x17\x42uttonRequest_CreatePin\x10\x1a\x12\x1c\n\x18\x42uttonRequest_GetEntropy\x10\x1b\x12\x1d\n\x19\x42uttonRequest_SignMessage\x10\x1c\x12\x1f\n\x1b\x42uttonRequest_ApplyPolicies\x10\x1d\x12\x1e\n\x1a\x42uttonRequest_SignExchange\x10\x1e\x12!\n\x1d\x42uttonRequest_AutoLockDelayMs\x10\x1f\x12\x1c\n\x18\x42uttonRequest_U2FCounter\x10 \x12\"\n\x1e\x42uttonRequest_ConfirmEosAction\x10!\x12\"\n\x1e\x42uttonRequest_ConfirmEosBudget\x10\"\x12\x1d\n\x19\x42uttonRequest_ConfirmMemo\x10#*\x7f\n\x14PinMatrixRequestType\x12 \n\x1cPinMatrixRequestType_Current\x10\x01\x12!\n\x1dPinMatrixRequestType_NewFirst\x10\x02\x12\"\n\x1ePinMatrixRequestType_NewSecond\x10\x03:4\n\x07wire_in\x12!.google.protobuf.EnumValueOptions\x18\xd2\x86\x03 \x01(\x08:5\n\x08wire_out\x12!.google.protobuf.EnumValueOptions\x18\xd3\x86\x03 \x01(\x08::\n\rwire_debug_in\x12!.google.protobuf.EnumValueOptions\x18\xd4\x86\x03 \x01(\x08:;\n\x0ewire_debug_out\x12!.google.protobuf.EnumValueOptions\x18\xd5\x86\x03 \x01(\x08\x42)\n\x1a\x63om.keepkey.deviceprotocolB\x0bKeepKeyType')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'types_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:
  google_dot_protobuf_dot_descriptor__pb2.EnumValueOptions.RegisterExtension(wire_in)
  google_dot_protobuf_dot_descriptor__pb2.EnumValueOptions.RegisterExtension(wire_out)
  google_dot_protobuf_dot_descriptor__pb2.EnumValueOptions.RegisterExtension(wire_debug_in)
  google_dot_protobuf_dot_descriptor__pb2.EnumValueOptions.RegisterExtension(wire_debug_out)

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\032com.keepkey.deviceprotocolB\013KeepKeyType'
  _FAILURETYPE._serialized_start=2538
  _FAILURETYPE._serialized_end=2896
  _OUTPUTSCRIPTTYPE._serialized_start=2899
  _OUTPUTSCRIPTTYPE._serialized_end=3034
  _INPUTSCRIPTTYPE._serialized_start=3036
  _INPUTSCRIPTTYPE._serialized_end=3144
  _REQUESTTYPE._serialized_start=3146
  _REQUESTTYPE._serialized_end=3231
  _OUTPUTADDRESSTYPE._serialized_start=3233
  _OUTPUTADDRESSTYPE._serialized_end=3303
  _BUTTONREQUESTTYPE._serialized_start=3306
  _BUTTONREQUESTTYPE._serialized_end=4478
  _PINMATRIXREQUESTTYPE._serialized_start=4480
  _PINMATRIXREQUESTTYPE._serialized_end=4607
  _HDNODETYPE._serialized_start=66
  _HDNODETYPE._serialized_end=194
  _HDNODEPATHTYPE._serialized_start=196
  _HDNODEPATHTYPE._serialized_end=258
  _COINTYPE._serialized_start=261
  _COINTYPE._serialized_end=749
  _MULTISIGREDEEMSCRIPTTYPE._serialized_start=751
  _MULTISIGREDEEMSCRIPTTYPE._serialized_end=842
  _TXINPUTTYPE._serialized_start=845
  _TXINPUTTYPE._serialized_end=1132
  _TXOUTPUTTYPE._serialized_start=1135
  _TXOUTPUTTYPE._serialized_end=1421
  _TXOUTPUTBINTYPE._serialized_start=1423
  _TXOUTPUTBINTYPE._serialized_end=1510
  _TRANSACTIONTYPE._serialized_start=1513
  _TRANSACTIONTYPE._serialized_end=1835
  _RAWTRANSACTIONTYPE._serialized_start=1837
  _RAWTRANSACTIONTYPE._serialized_end=1874
  _TXREQUESTDETAILSTYPE._serialized_start=1876
  _TXREQUESTDETAILSTYPE._serialized_end=1989
  _TXREQUESTSERIALIZEDTYPE._serialized_start=1991
  _TXREQUESTSERIALIZEDTYPE._serialized_end=2083
  _IDENTITYTYPE._serialized_start=2085
  _IDENTITYTYPE._serialized_end=2188
  _POLICYTYPE._serialized_start=2190
  _POLICYTYPE._serialized_end=2240
  _EXCHANGETYPE._serialized_start=2243
  _EXCHANGETYPE._serialized_end=2535
# @@protoc_insertion_point(module_scope)
