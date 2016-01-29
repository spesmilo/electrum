from ..ledger.client import ledger_client_class
from ..ledger.plugin import LedgerCompatiblePlugin, LedgerCompatibleWallet
from electrum.wallet import BIP44_Wallet


class LedgerWallet(LedgerCompatibleWallet):
    wallet_type = 'ledger'
    device = 'ledger'
    restore_wallet_class = BIP44_Wallet
    max_change_outputs = 1


class LedgerPlugin(LedgerCompatiblePlugin):
    firmware_URL = 'https://www.ledgerwallet.com'
    libraries_URL = 'https://github.com/LedgerHQ/btchip-python'
    wallet_class = LedgerWallet
    try:
        from btchip.btchipComm import getDongle, DongleWait
        from btchip.btchip import btchip
        from btchip.btchipUtils import compress_public_key,format_transaction, get_regular_input_script
        from btchip.bitcoinTransaction import bitcoinTransaction
        from btchip.btchipPersoWizard import StartBTChipPersoDialog
        from btchip.btchipFirmwareWizard import checkFirmware, updateFirmware
        from btchip.btchipException import BTChipException
        client_class = ledger_client_class(btchip)
        libraries_available = True
    except ImportError:
        libraries_available = False
