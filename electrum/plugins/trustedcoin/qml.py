from typing import TYPE_CHECKING

from electrum.i18n import _
from electrum.plugin import hook
from electrum.util import UserFacingException

from electrum.gui.qml.qewallet import QEWallet
from .common_qt import TrustedcoinPluginQObject

from .trustedcoin import TrustedCoinPlugin, TrustedCoinException

if TYPE_CHECKING:
    from electrum.gui.qml import ElectrumQmlApplication
    from electrum.wallet import Abstract_Wallet
    from electrum.wizard import NewWalletWizard


class Plugin(TrustedCoinPlugin):
    def __init__(self, *args):
        super().__init__(*args)

    @hook
    def load_wallet(self, wallet: 'Abstract_Wallet'):
        if not isinstance(wallet, self.wallet_class):
            return
        self.logger.debug(f'plugin enabled for wallet "{str(wallet)}"')
        if wallet.can_sign_without_server():
            self.so._canSignWithoutServer = True
            self.so.canSignWithoutServerChanged.emit()

            msg = ' '.join([
                _('This wallet was restored from seed, and it contains two master private keys.'),
                _('Therefore, two-factor authentication is disabled.')
            ])
            self.logger.info(msg)
        self.start_request_thread(wallet)

    @hook
    def init_qml(self, app: 'ElectrumQmlApplication'):
        self.logger.debug(f'init_qml hook called, gui={str(type(app))}')
        self._app = app
        wizard = self._app.daemon.newWalletWizard
        # important: TrustedcoinPluginQObject needs to be parented, as keeping a ref
        # in the plugin is not enough to avoid gc
        # Note: storing the trustedcoin qt helper in the plugin is different from the desktop client,
        # which stores the helper in the wizard object. As the mobile client only shows a single wizard
        # at a time, this is ok for now.
        self.so = TrustedcoinPluginQObject(self, wizard, self._app)
        # extend wizard
        self.extend_wizard(wizard)

    # wizard support functions

    def extend_wizard(self, wizard: 'NewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'trustedcoin_start': {
                'gui': '../../../../plugins/trustedcoin/qml/Disclaimer',
            },
            'trustedcoin_choose_seed': {
                'gui': '../../../../plugins/trustedcoin/qml/ChooseSeed',
            },
            'trustedcoin_create_seed': {
                'gui': 'WCCreateSeed',
            },
            'trustedcoin_confirm_seed': {
                'gui': 'WCConfirmSeed',
            },
            'trustedcoin_have_seed': {
                'gui': 'WCHaveSeed',
            },
            'trustedcoin_keep_disable': {
                'gui': '../../../../plugins/trustedcoin/qml/KeepDisable',
            },
            'trustedcoin_tos': {
                'gui': '../../../../plugins/trustedcoin/qml/Terms',
            },
            'trustedcoin_show_confirm_otp': {
                'gui': '../../../../plugins/trustedcoin/qml/ShowConfirmOTP',
            }
        }
        wizard.navmap_merge(views)

    # running wallet functions

    def prompt_user_for_otp(self, wallet, tx, on_success, on_failure):
        self.logger.debug('prompt_user_for_otp')
        self.on_success = on_success
        self.on_failure = on_failure if on_failure else lambda x: self.logger.error(x)
        self.wallet = wallet
        self.tx = tx
        qewallet = QEWallet.getInstanceFor(wallet)
        qewallet.request_otp(self.on_otp)

    def on_otp(self, otp):
        if not otp:
            self.on_failure(_('No auth code'))
            return

        self.logger.debug(f'on_otp {otp} for tx {repr(self.tx)}')

        try:
            self.wallet.on_otp(self.tx, otp)
        except UserFacingException as e:
            self.on_failure(_('Invalid one-time password.'))
        except TrustedCoinException as e:
            if e.status_code == 400:  # invalid OTP
                self.on_failure(_('Invalid one-time password.'))
            else:
                self.on_failure(_('Service Error') + ':\n' + str(e))
        except Exception as e:
            self.on_failure(_('Error') + ':\n' + str(e))
        else:
            self.on_success(self.tx)

    def billing_info_retrieved(self, wallet):
        self.logger.info('billing_info_retrieved')
        qewallet = QEWallet.getInstanceFor(wallet)
        qewallet.billingInfoChanged.emit()
        self.so.updateBillingInfo(wallet)
