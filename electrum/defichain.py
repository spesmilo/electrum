import struct
from enum import IntEnum
from typing import Dict, List, Optional, Set

from . import bitcoin
from .util import bfh

# Taken from CustomTxType enum in `ain` master(8dfa88a7bc9e23e68017eccf757bf4c3bd8e720e) branch.
# The ABI might change, in this case this struct should be changed appropriately
class CustomTxType(IntEnum):
    TXNone = 0,
    Reject = 1, # Invalid TX type. Returned by GuessCustomTxType on invalid custom TX.

    # masternodes:
    CreateMasternode       = ord('C'),
    ResignMasternode       = ord('R'),
    UpdateMasternode       = ord('m'),
    SetForcedRewardAddress = ord('F'),
    RemForcedRewardAddress = ord('f'),
    # custom tokens:
    CreateToken           = ord('T'),
    MintToken             = ord('M'),
    UpdateToken           = ord('N'), # previous type, only DAT flag triggers
    UpdateTokenAny        = ord('n'), # new type of token's update with any flags/fields possible
    # dex orders - just not to overlap in future
    # CreateOrder         = ord('O'),
    # DestroyOrder        = ord('E'),
    # MatchOrders         = ord('A'),
    #poolpair
    CreatePoolPair        = ord('p'),
    UpdatePoolPair        = ord('u'),
    PoolSwap              = ord('s'),
    PoolSwapV2            = ord('i'),
    AddPoolLiquidity      = ord('l'),
    RemovePoolLiquidity   = ord('r'),
    # accounts
    UtxosToAccount        = ord('U'),
    AccountToUtxos        = ord('b'),
    AccountToAccount      = ord('B'),
    AnyAccountsToAccounts = ord('a'),
    #set governance variable
    SetGovVariable        = ord('G'),
    SetGovVariableHeight  = ord('j'),
    # Auto auth TX
    AutoAuthPrep          = ord('A'),
    # oracles
    AppointOracle       = ord('o'),
    RemoveOracleAppoint = ord('h'),
    UpdateOracleAppoint = ord('t'),
    SetOracleData       = ord('y'),
    # ICX
    ICXCreateOrder   = ord('1'),
    ICXMakeOffer     = ord('2'),
    ICXSubmitDFCHTLC = ord('3'),
    ICXSubmitEXTHTLC = ord('4'),
    ICXClaimDFCHTLC  = ord('5'),
    ICXCloseOrder    = ord('6'),
    ICXCloseOffer    = ord('7'),
    # Loans
    SetLoanCollateralToken = ord('c'),
    SetLoanToken           = ord('g'),
    UpdateLoanToken        = ord('x'),
    LoanScheme             = ord('L'),
    DefaultLoanScheme      = ord('d'),
    DestroyLoanScheme      = ord('D'),
    Vault                  = ord('V'),
    CloseVault             = ord('e'),
    UpdateVault            = ord('v'),
    DepositToVault         = ord('S'),
    WithdrawFromVault      = ord('J'),
    TakeLoan               = ord('X'),
    PaybackLoan            = ord('H'),
    AuctionBid             = ord('I')

    def hex(self) -> str:
        return bytes([self]).hex()

class CustomTxBaseMeta(type):
    must_be_declared = ["tx_ending", "used_addresses"]

    def __new__(cls, name, bases, body):
        if name != "CustomTxBase":
            for func in CustomTxBaseMeta.must_be_declared:
                if func not in body:
                    raise NotImplementedError(f"Any subclass of CustomTxBase must implement `{func}`")
        return super().__new__(cls, name, bases, body)

class CustomTxBase(metaclass=CustomTxBaseMeta):
    """
    All subclasses of this class must implement the following methods:
    ["tx_ending"]
    """
    # Equivalent to 'DfTx' sequence of ascii values.
    # It's written reversed, cause .hex() on bytes object causes bytes sequence to be reversed
    DFTX_MARKER = 0x78546644

    def __init__(self, tx_type: int):
        self.opcode = bitcoin.opcodes.OP_RETURN
        self.tx_type = tx_type

    def tx_ending(self) -> str:
        raise NotImplementedError("Any subclass of CustomTxBase must implement `tx_ending`")

    def used_addresses(self) -> Set[str]:
        raise NotImplementedError("Any subclass of CustomTxBase must implement `used_addresses`")

    def serialize_scriptpubkey(self) -> bytes:
        scriptpubkey = bitcoin.construct_script([CustomTxBase.DFTX_MARKER], False)
        scriptpubkey += bitcoin.construct_script([self.tx_type])
        scriptpubkey += bitcoin.construct_script([self.tx_ending()], False)

        script_len = int(len(scriptpubkey) / 2)
        scriptpubkey = \
                bitcoin.construct_script([self.opcode]) + \
                bitcoin._op_push(script_len) + \
                scriptpubkey
        return bfh(scriptpubkey)

class AccountToAccount(CustomTxBase):
    def __init__(self, addr_from: str, addrs_to: Dict[str, Dict[int, int]]):
        """
        Used to represent AccountToAccount custom transaction
        Arguments:
            addr_from: Address to send tokens from (must be in script form, not in defichain/bitcoin
                       addresses form, use `bitcoin.address_to_script` to convert.
            addrs_to:  Map of addresses to send tokens to, format is the following:
                       {`address_script`: {`token_id`: `amount`}}
        """
        super().__init__(CustomTxType["AccountToAccount"])
        self.addr_from = addr_from
        self.addrs_to = addrs_to

    def tx_ending(self) -> str:
        script = bitcoin.construct_script([self.addr_from])
        script += bitcoin.construct_script([len(self.addrs_to)], False)
        for addr_to, payments in self.addrs_to.items():
            script += bitcoin.construct_script([addr_to])
            script += bitcoin.construct_script([len(payments)], False)
            for token_id, amount in payments.items():
                script += bitcoin.construct_script(
                    [struct.pack('<I', token_id), struct.pack('<Q', amount)],
                    False
                )
        return script

    @classmethod
    def decode_from_vds(cls, vds: 'BCDataStream') -> 'AccountToAccount':
        addr_from = vds.read_bytes(vds.read_compact_size()).hex()
        # addr_from = vds.read_string()
        addr_map_len = vds.read_bytes(1)[0]
        addrs_to = {}

        for _ in range(addr_map_len):
            addr_to = vds.read_bytes(vds.read_compact_size()).hex()
            # addr_to = vds.read_string()
            amounts_len = vds.read_bytes(1)[0]
            amounts = {}

            for _ in range(amounts_len):
                token_id = vds.read_uint32()
                amounts[token_id] = vds.read_uint64()
            addrs_to[addr_to] = amounts

        return cls(addr_from, addrs_to)

    def used_addresses(self) -> Set[str]:
        return set([self.addr_from, *self.addrs_to.keys()])

implemented_txns = {
    # masternodes:
    CustomTxType.CreateMasternode: None,
    CustomTxType.ResignMasternode: None,
    CustomTxType.UpdateMasternode: None,
    CustomTxType.SetForcedRewardAddress: None,
    CustomTxType.RemForcedRewardAddress: None,
    # custom tokens:
    CustomTxType.CreateToken: None,
    CustomTxType.MintToken: None,
    CustomTxType.UpdateToken: None, # previous type, only DAT flag triggers
    CustomTxType.UpdateTokenAny: None, # new type of token's update with any flags/fields possible
    # dex orders - just not to overlap in future
    # CustomTxType.CreateOrder: None,
    # CustomTxType.DestroyOrder: None,
    # CustomTxType.MatchOrders: None,
    # poolpair
    CustomTxType.CreatePoolPair: None,
    CustomTxType.UpdatePoolPair: None,
    CustomTxType.PoolSwap: None,
    CustomTxType.PoolSwapV2: None,
    CustomTxType.AddPoolLiquidity: None,
    CustomTxType.RemovePoolLiquidity: None,
    # accounts
    CustomTxType.UtxosToAccount: None,
    CustomTxType.AccountToUtxos: None,
    CustomTxType.AccountToAccount: AccountToAccount,
    CustomTxType.AnyAccountsToAccounts: None,
    #set governance variable
    CustomTxType.SetGovVariable: None,
    CustomTxType.SetGovVariableHeight: None,
    # Auto auth TX
    CustomTxType.AutoAuthPrep: None,
    # oracles
    CustomTxType.AppointOracle: None,
    CustomTxType.RemoveOracleAppoint: None,
    CustomTxType.UpdateOracleAppoint: None,
    CustomTxType.SetOracleData: None,
    # ICX
    CustomTxType.ICXCreateOrder: None,
    CustomTxType.ICXMakeOffer: None,
    CustomTxType.ICXSubmitDFCHTLC: None,
    CustomTxType.ICXSubmitEXTHTLC: None,
    CustomTxType.ICXClaimDFCHTLC: None,
    CustomTxType.ICXCloseOrder: None,
    CustomTxType.ICXCloseOffer: None,
    # Loans
    CustomTxType.SetLoanCollateralToken: None,
    CustomTxType.SetLoanToken: None,
    CustomTxType.UpdateLoanToken: None,
    CustomTxType.LoanScheme: None,
    CustomTxType.DefaultLoanScheme: None,
    CustomTxType.DestroyLoanScheme: None,
    CustomTxType.Vault: None,
    CustomTxType.CloseVault: None,
    CustomTxType.UpdateVault: None,
    CustomTxType.DepositToVault: None,
    CustomTxType.WithdrawFromVault: None,
    CustomTxType.TakeLoan: None,
    CustomTxType.PaybackLoan: None,
    CustomTxType.AuctionBid: None
}

def try_deserialize_scriptpubkey(scriptpubkey: bytes) -> Optional['CustomTxBase']:
    from .transaction import BCDataStream
    vds = BCDataStream()
    vds.write(scriptpubkey)
    len_script = len(scriptpubkey) - 1

    push_data_opcode = None
    if len_script < bitcoin.opcodes.OP_PUSHDATA1:
        pass
    elif len_script <= 0xff:
        push_data_opcode = bitcoin.opcodes.OP_PUSHDATA1
    elif len_script <= 0xffff:
        push_data_opcode = bitcoin.opcodes.OP_PUSHDATA2
    else:
        push_data_opcode = bitcoin.opcodes.OP_PUSHDATA4

    try:
        assert vds.read_bytes(1)[0] == bitcoin.opcodes.OP_RETURN
        if push_data_opcode is not None:
            assert vds.read_bytes(1)[0] == push_data_opcode
            if push_data_opcode == bitcoin.opcodes.OP_PUSHDATA1:
                script_len = vds.read_bytes(1)[0]
            elif push_data_opcode == bitcoin.opcodes.OP_PUSHDATA2:
                script_len = vds.read_bytes(2)[0]
            elif push_data_opcode == bitcoin.opcodes.OP_PUSHDATA4:
                script_len = vds.read_bytes(4)[0]

        assert vds.read_uint32() == CustomTxBase.DFTX_MARKER
        tx_type = vds.read_bytes(1)[0]
        tx_cls = implemented_txns.get(tx_type)

        if tx_cls is None: return None

        return tx_cls.decode_from_vds(vds)
    except:
        return None
