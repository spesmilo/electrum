from electrum.i18n import _
from electrum.logging import get_logger
from electrum.keystore import bip39_is_checksum_valid
from electrum.simple_config import SimpleConfig
from electrum.gui.qt.util import (EnterButton, Buttons, CloseButton, OkButton, CancelButton, WindowModalDialog, WWLabel, PasswordLineEdit)
from electrum.gui.qt.qrcodewidget import QRCodeWidget, QRDialog
from electrum.gui.qt.wizard.wallet import WCScriptAndDerivation, WCHWUnlock, WCHWUninitialized, WCHWXPub, WalletWizardComponent
from electrum.plugin import hook
from PyQt5.QtCore import Qt, pyqtSignal, QRegExp
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtWidgets import (QPushButton, QLabel, QVBoxLayout, QHBoxLayout, QWidget, QGridLayout, QComboBox, QLineEdit, QTextEdit, QTabWidget)

from functools import partial
from os import urandom
import textwrap
import threading

#satochip
from .satochip import SatochipPlugin
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase

#pysatochip
from pysatochip.CardConnector import CardConnector, UnexpectedSW12Error, CardError, CardNotPresentError, WrongPinError
from pysatochip.Satochip2FA import Satochip2FA, SERVER_LIST
from pysatochip.version import SATOCHIP_PROTOCOL_MAJOR_VERSION, SATOCHIP_PROTOCOL_MINOR_VERSION

# Seed import wizard msg
PASSPHRASE_HELP_SHORT =_(
    "A passphrase is an optional feature that allows you to extend your seed with additional entropy. "
    "A passphrase is not a PIN.")
PASSPHRASE_NOT_PIN = _(
    "If set, you will need your passphrase "
    "along with your BIP39 seed to restore your wallet from a backup. "
    "If you are not sure, leave this field empty!")

_logger = get_logger(__name__)

MSG_USE_2FA= _("Do you want to use 2-Factor-Authentication (2FA)?\n\nWith 2FA, any transaction must be confirmed on a second device such as your smartphone. First you have to install the Satochip-2FA android app on google play. Then you have to pair your 2FA device with your Satochip by scanning the qr-code on the next screen. \n\nWARNING: be sure to backup a copy of the qr-code in a safe place, in case you have to reinstall the app!")

class Plugin(SatochipPlugin, QtPluginBase):
    icon_unpaired = "satochip_unpaired.png"
    icon_paired = "satochip.png"

    def create_handler(self, window):
        return Satochip_Handler(window)

    def requires_settings(self):
        # Return True to add a Settings button.
        return True

    def settings_widget(self, window):
        # Return a button that when pressed presents a settings dialog.
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        # Return a settings dialog.
        d = WindowModalDialog(window, _("Email settings"))
        vbox = QVBoxLayout(d)

        d.setMinimumSize(500, 200)
        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))
        d.show()

    def show_settings_dialog(self, window, keystore):
        # When they click on the icon for Satochip we come here.
        def connect():
            device_id = self.choose_device(window, keystore)
            return device_id
        def show_dialog(device_id):
            if device_id:
                SatochipSettingsDialog(window, self, keystore, device_id).exec_()
        keystore.thread.add(connect, on_success=show_dialog)

    @hook
    def init_wallet_wizard(self, wizard: 'QENewWalletWizard'):
        self.extend_wizard(wizard)

    # insert satochip pages in new wallet wizard
    def extend_wizard(self, wizard: 'QENewWalletWizard'):
        super().extend_wizard(wizard)
        views = {
            'satochip_start': {'gui': WCScriptAndDerivation},
            'satochip_xpub': {'gui': WCHWXPub},
            'satochip_not_setup': {'gui': WCSatochipSetupParams},
            'satochip_do_setup': {'gui': WCSatochipSetup},
            'satochip_not_seeded': {'gui': WCSatochipImportSeedParams},
            'satochip_import_seed': {'gui': WCSatochipImportSeed},
            'satochip_unlock': {'gui': WCHWUnlock}
        }
        wizard.navmap_merge(views)

class Satochip_Handler(QtHandlerBase):

    def __init__(self, win):
        super(Satochip_Handler, self).__init__(win, 'Satochip')

class SatochipSettingsDialog(WindowModalDialog):
    '''This dialog doesn't require a device be paired with a wallet.

    We want users to be able to wipe a device even if they've forgotten
    their PIN.'''

    def __init__(self, window, plugin, keystore, device_id):
        title = _("{} Settings").format(plugin.device)
        super(SatochipSettingsDialog, self).__init__(window, title)
        self.setMaximumWidth(540)

        devmgr = plugin.device_manager()
        self.config = devmgr.config
        handler = keystore.handler
        self.thread = thread = keystore.thread
        self.window = window

        def connect_and_doit():
            client = devmgr.client_by_id(device_id)
            if not client:
                raise RuntimeError("Device not connected")
            return client

        body = QWidget()
        body_layout = QVBoxLayout(body)
        grid = QGridLayout()
        grid.setColumnStretch(3, 1)

        # see <http://doc.qt.io/archives/qt-4.8/richtext-html-subset.html>
        title = QLabel('''<center>
<span style="font-size: x-large">Satochip Wallet</span>
<br><a href="https://satochip.io">satochip.io</a>''')
        title.setTextInteractionFlags(Qt.LinksAccessibleByMouse)

        grid.addWidget(title, 0, 0, 1, 2, Qt.AlignHCenter)
        y = 3

        rows = [
            ('fw_version', _("Firmware Version:")),
            ('sw_version', _("Electrum Support:")),
            ('is_seeded', _("Wallet seeded:")),
            ('needs_2FA', _("Requires 2FA:")),
            ('needs_SC', _("Secure Channel:")),
            ('card_label', _("Card label:")),
        ]
        for row_num, (member_name, label) in enumerate(rows):
            widget = QLabel('<tt>')
            widget.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)

            grid.addWidget(QLabel(label), y, 0, 1,1, Qt.AlignRight)
            grid.addWidget(widget, y, 1, 1, 1, Qt.AlignLeft)
            setattr(self, member_name, widget)
            y += 1

        body_layout.addLayout(grid)

        pin_btn = QPushButton('Change PIN')
        def _change_pin():
            thread.add(connect_and_doit, on_success=self.change_pin)
        pin_btn.clicked.connect(_change_pin)

        seed_btn = QPushButton('Reset seed')
        def _reset_seed():
            thread.add(connect_and_doit, on_success=self.reset_seed)
            thread.add(connect_and_doit, on_success=self.show_values)
        seed_btn.clicked.connect(_reset_seed)

        set_2FA_btn = QPushButton('Enable 2FA')
        def _set_2FA():
            thread.add(connect_and_doit, on_success=self.set_2FA)
            thread.add(connect_and_doit, on_success=self.show_values)
        set_2FA_btn.clicked.connect(_set_2FA)

        reset_2FA_btn = QPushButton('Disable 2FA')
        def _reset_2FA():
            thread.add(connect_and_doit, on_success=self.reset_2FA)
            thread.add(connect_and_doit, on_success=self.show_values)
        reset_2FA_btn.clicked.connect(_reset_2FA)

        change_2FA_server_btn = QPushButton('Select 2FA server')
        def _change_2FA_server():
            thread.add(connect_and_doit, on_success=self.change_2FA_server)
        change_2FA_server_btn.clicked.connect(_change_2FA_server)

        verify_card_btn = QPushButton('Verify card')
        def _verify_card():
            thread.add(connect_and_doit, on_success=self.verify_card)
        verify_card_btn.clicked.connect(_verify_card)

        change_card_label_btn = QPushButton('Change label')
        def _change_card_label():
            thread.add(connect_and_doit, on_success=self.change_card_label)
        change_card_label_btn.clicked.connect(_change_card_label)


        y += 3
        grid.addWidget(pin_btn, y, 0, 1, 2, Qt.AlignHCenter)
        y += 2
        grid.addWidget(seed_btn, y, 0, 1, 2, Qt.AlignHCenter)
        y += 2
        grid.addWidget(set_2FA_btn, y, 0, 1, 2, Qt.AlignHCenter)
        y += 2
        grid.addWidget(reset_2FA_btn, y, 0, 1, 2, Qt.AlignHCenter)
        y += 2
        grid.addWidget(change_2FA_server_btn, y, 0, 1, 2, Qt.AlignHCenter)
        y += 2
        grid.addWidget(verify_card_btn, y, 0, 1, 2, Qt.AlignHCenter)
        y += 2
        grid.addWidget(change_card_label_btn, y, 0, 1, 2, Qt.AlignHCenter)
        y += 2
        grid.addWidget(CloseButton(self), y, 0, 1, 2, Qt.AlignHCenter)

        dialog_vbox = QVBoxLayout(self)
        dialog_vbox.addWidget(body)

        # Fetch values and show them
        thread.add(connect_and_doit, on_success=self.show_values)


    def show_values(self, client):
        _logger.info("Show value!")
        is_ok= client.verify_PIN()
        if not is_ok:
            msg= f"action cancelled by user"
            self.window.show_error(msg)
            return

        sw_rel= 'v' + str(SATOCHIP_PROTOCOL_MAJOR_VERSION) + '.' + str(SATOCHIP_PROTOCOL_MINOR_VERSION)
        self.sw_version.setText('<tt>%s' % sw_rel)

        (response, sw1, sw2, d)=client.cc.card_get_status()
        if (sw1==0x90 and sw2==0x00):
            #fw_rel= 'v' + str(d["protocol_major_version"]) + '.' + str(d["protocol_minor_version"])
            fw_rel= 'v' + str(d["protocol_major_version"]) + '.' + str(d["protocol_minor_version"])  +'-'+ str(d["applet_major_version"]) +'.'+ str(d["applet_minor_version"])
            self.fw_version.setText('<tt>%s' % fw_rel)

            #is_seeded?
            if len(response) >=10:
                self.is_seeded.setText('<tt>%s' % "yes") if d["is_seeded"] else self.is_seeded.setText('<tt>%s' % "no")
            else: #for earlier versions
                try:
                    client.cc.card_bip32_get_authentikey()
                    self.is_seeded.setText('<tt>%s' % "yes")
                except Exception:
                    self.is_seeded.setText('<tt>%s' % "no")

            # needs2FA?
            if d["needs2FA"]:
                self.needs_2FA.setText('<tt>%s' % "yes")
            else:
                self.needs_2FA.setText('<tt>%s' % "no")

            # needs secure channel
            if d["needs_secure_channel"]:
                self.needs_SC.setText('<tt>%s' % "yes")
            else:
                self.needs_SC.setText('<tt>%s' % "no")

            # card label
            (response, sw1, sw2, label)= client.cc.card_get_label()
            if (label==""):
                label= "(none)"
            self.card_label.setText('<tt>%s' % label)

        else:
            fw_rel= "(unitialized)"
            self.fw_version.setText('<tt>%s' % fw_rel)
            self.needs_2FA.setText('<tt>%s' % "(unitialized)")
            self.is_seeded.setText('<tt>%s' % "no")
            self.needs_SC.setText('<tt>%s' % "(unknown)")
            self.card_label.setText('<tt>%s' % "(none)")


    def change_pin(self, client):
        _logger.info("In change_pin")
        msg_oldpin = _("Enter the current PIN for your Satochip:")
        msg_newpin = _("Enter a new PIN for your Satochip:")
        msg_confirm = _("Please confirm the new PIN for your Satochip:")
        msg_error= _("The PIN values do not match! Please type PIN again!")
        msg_cancel= _("PIN Change cancelled!")
        (is_pin, oldpin, newpin) = client.PIN_change_dialog(msg_oldpin, msg_newpin, msg_confirm, msg_error, msg_cancel)
        if (not is_pin):
            return

        oldpin= list(oldpin)
        newpin= list(newpin)
        try:
            (response, sw1, sw2)= client.cc.card_change_PIN(0, oldpin, newpin)
            if (sw1==0x90 and sw2==0x00):
                msg= _("PIN changed successfully!")
                self.window.show_message(msg)
            else:
                msg= _("Failed to change PIN!")
                self.window.show_error(msg)
        except WrongPinError as ex:
            msg= (f"Failed to change PIN. Wrong PIN! {ex.pin_left} tries remaining!")
            self.window.show_error(msg)
        except Exception as ex:
            self.window.show_error(str(ex))

    def reset_seed(self, client):
        _logger.info("In reset_seed")
        # is_ok= client.verify_PIN()
        # if not is_ok:
        #     msg= f"action cancelled by user"
        #     self.window.show_error(msg)
        #     return

        # pin
        msg = ''.join([
            _("WARNING!\n"),
            _("You are about to reset the seed of your Satochip. This process is irreversible!\n"),
            _("Please be sure that your wallet is empty and that you have a backup of the seed as a precaution.\n\n"),
            _("To proceed, enter the PIN for your Satochip:")
        ])
        password = self.reset_seed_dialog(msg)
        if (password is None):
            return
        pin = password.encode('utf8')
        pin= list(pin)

        # if 2FA is enabled, get challenge-response
        hmac=[]
        if (client.cc.needs_2FA is None):
            (response, sw1, sw2, d)=client.cc.card_get_status()
        if client.cc.needs_2FA:
            # challenge based on authentikey
            authentikeyx= bytearray(client.cc.parser.authentikey_coordx).hex()

            # format & encrypt msg
            import json
            msg= {'action':"reset_seed", 'authentikeyx':authentikeyx}
            msg=  json.dumps(msg)
            (id_2FA, msg_out)= client.cc.card_crypt_transaction_2FA(msg, True)
            d={}
            d['msg_encrypt']= msg_out
            d['id_2FA']= id_2FA

            #do challenge-response with 2FA device...
            self.window.show_message('2FA request sent! Approve or reject request on your second device.')
            server_2FA = self.config.get("satochip_2FA_server", default= SERVER_LIST[0])
            Satochip2FA.do_challenge_response(d, server_name= server_2FA)
            # decrypt and parse reply to extract challenge response
            try:
                reply_encrypt= d['reply_encrypt']
            except Exception as e:
                self.give_error("No response received from 2FA", True)
            reply_decrypt= client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
            _logger.info("challenge:response= "+ reply_decrypt)
            reply_decrypt= reply_decrypt.split(":")
            chalresponse=reply_decrypt[1]
            hmac= list(bytes.fromhex(chalresponse))

        # send request
        (response, sw1, sw2) = client.cc.card_reset_seed(pin, hmac)
        if (sw1==0x90 and sw2==0x00):
            msg= _("Seed reset successfully!\nYou should close this wallet and launch the wizard to generate a new wallet.")
            self.window.show_message(msg)
            #to do: close client?
        elif (sw1==0x9c and sw2==0x0b):
            msg= _(f"Failed to reset seed: request rejected by 2FA device (error code: {hex(256*sw1+sw2)})")
            self.window.show_message(msg)
            #to do: close client?
        else:
            msg= _(f"Failed to reset seed with error code: {hex(256*sw1+sw2)}")
            self.window.show_error(msg)

    def reset_seed_dialog(self, msg):
        _logger.info("In reset_seed_dialog")
        parent = self.top_level_window()
        d = WindowModalDialog(parent, _("Enter PIN"))
        pw = QLineEdit()
        pw.setEchoMode(2)
        pw.setMinimumWidth(200)

        vbox = QVBoxLayout()
        vbox.addWidget(WWLabel(msg))
        vbox.addWidget(pw)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        d.setLayout(vbox)

        passphrase = pw.text() if d.exec_() else None
        return passphrase

    def set_2FA(self, client):
        if not client.cc.needs_2FA:
            use_2FA=client.handler.yes_no_question(MSG_USE_2FA)
            if (use_2FA):
                # verify PIN
                is_ok= client.verify_PIN()
                if not is_ok:
                    msg= f"action cancelled by user"
                    self.window.show_error(msg)
                    return

                secret_2FA= urandom(20)
                secret_2FA_hex=secret_2FA.hex()
                # the secret must be shared with the second factor app (eg on a smartphone)
                try:
                    help_txt="Scan the QR-code with your Satochip-2FA app and make a backup of the following secret: "+ secret_2FA_hex
                    d = QRDialog(data=secret_2FA_hex, parent=None, title="Secret_2FA", show_text=False, help_text=help_txt, show_copy_text_btn=True, show_cancel_btn=True, config=self.config)
                    result=d.exec_() # result should be 0 or 1
                    if (result==1):
                        # further communications will require an id and an encryption key (for privacy).
                        # Both are derived from the secret_2FA using a one-way function inside the Satochip
                        amount_limit= 0 # i.e. always use
                        (response, sw1, sw2)=client.cc.card_set_2FA_key(secret_2FA, amount_limit)
                        if sw1!=0x90 or sw2!=0x00:
                            _logger.info(f"Unable to set 2FA with error code:= {hex(256*sw1+sw2)}")
                            self.window.show_error(f'Unable to setup 2FA with error code: {hex(256*sw1+sw2)}')
                        else:
                            self.window.show_message("2FA enabled successfully!")
                    else:
                        self.window.show_message("2FA cancelled by user!")
                        return
                except Exception as e:
                    _logger.info(f"SatochipPlugin: setup 2FA error: {e}")
                    self.window.show_error(f'Unable to setup 2FA with error code: {e}')
                    return

    def reset_2FA(self, client):
        if client.cc.needs_2FA:
            # verify pin
            is_ok= client.verify_PIN()
            if not is_ok:
                msg= f"action cancelled by user"
                self.window.show_error(msg)
                return

            # challenge based on ID_2FA
            # format & encrypt msg
            import json
            msg= {'action':"reset_2FA"}
            msg=  json.dumps(msg)
            (id_2FA, msg_out)= client.cc.card_crypt_transaction_2FA(msg, True)
            d={}
            d['msg_encrypt']= msg_out
            d['id_2FA']= id_2FA

            #do challenge-response with 2FA device...
            self.window.show_message('2FA request sent! Approve or reject request on your second device.')
            server_2FA = self.config.get("satochip_2FA_server", default= SERVER_LIST[0])
            Satochip2FA.do_challenge_response(d, server_name= server_2FA)
            # decrypt and parse reply to extract challenge response
            try:
                reply_encrypt= d['reply_encrypt']
            except Exception as e:
                self.give_error("No response received from 2FA!", True)
            reply_decrypt= client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
            _logger.info("challenge:response= "+ reply_decrypt)
            reply_decrypt= reply_decrypt.split(":")
            chalresponse=reply_decrypt[1]
            hmac= list(bytes.fromhex(chalresponse))

            # send request
            (response, sw1, sw2) = client.cc.card_reset_2FA_key(hmac)
            if (sw1==0x90 and sw2==0x00):
                msg= _("2FA reset successfully!")
                client.cc.needs_2FA= False
                self.window.show_message(msg)
            elif (sw1==0x9c and sw2==0x17):
                msg= _(f"Failed to reset 2FA: \nyou must reset the seed first (error code {hex(256*sw1+sw2)})")
                self.window.show_error(msg)
            else:
                msg= _(f"Failed to reset 2FA with error code: {hex(256*sw1+sw2)}")
                self.window.show_error(msg)
        else:
            msg= _(f"2FA is already disabled!")
            self.window.show_error(msg)

    def change_2FA_server(self, client):
        _logger.info("in change_2FA_server")
        help_txt="Select 2FA server in the list:"
        option_name= "satochip_2FA_server"
        options= SERVER_LIST #["server1", "server2", "server3"]
        title= "Select 2FA server"
        d = SelectOptionsDialog(option_name = option_name, options = options, parent=None, title=title, help_text=help_txt, config=self.config)
        result=d.exec_() # result should be 0 or 1

    def verify_card(self, client):
        # verify pin
        is_ok= client.verify_PIN()
        if not is_ok:
            return

        # verify authenticity
        is_authentic, txt_ca, txt_subca, txt_device, txt_error = self.card_verify_authenticity(client)

        # wrap data for better display
        tmp = ""
        for line in txt_ca.splitlines():
            tmp += textwrap.fill(line, 120, subsequent_indent="\t") + "\n"
        txt_ca = tmp
        tmp = ""
        for line in txt_subca.splitlines():
            tmp += textwrap.fill(line, 120, subsequent_indent="\t") + "\n"
        txt_subca = tmp
        tmp = ""
        for line in txt_device.splitlines():
            tmp += textwrap.fill(line, 120, subsequent_indent="\t") + "\n"
        txt_device = tmp

        if is_authentic:
            txt_result= 'Device authenticated successfully!'
        else:
            txt_result= ''.join(['Error: could not authenticate the issuer of this card! \n',
                                        'Reason: ', txt_error , '\n\n',
                                        'If you did not load the card yourself, be extremely careful! \n',
                                        'Contact support(at)satochip.io to report a suspicious device.'])
        d = DeviceCertificateDialog(
                parent=None,
                title= "Satochip certificate chain",
                is_authentic = is_authentic,
                txt_summary = txt_result,
                txt_ca = txt_ca,
                txt_subca = txt_subca,
                txt_device = txt_device,
        )
        result=d.exec_()


    def card_verify_authenticity(self, client): #todo: add this function in pysatochip

        cert_pem=txt_error=""
        try:
            cert_pem=client.cc.card_export_perso_certificate()
            _logger.info('Cert PEM: '+ str(cert_pem))
        except CardError as ex:
            txt_error= ''.join(["Unable to get device certificate: feature unsupported! \n",
                                "Authenticity validation is only available starting with Satochip v0.12 and higher"])
        except CardNotPresentError as ex:
            txt_error= "No card found! Please insert card."
        except UnexpectedSW12Error as ex:
            txt_error= "Exception during device certificate export: " + str(ex)

        if cert_pem=="(empty)":
            txt_error= "Device certificate is empty: the card has not been personalized!"

        if txt_error!="":
            return False, "(empty)", "(empty)", "(empty)", txt_error

        # check the certificate chain from root CA to device
        from pysatochip.certificate_validator import CertificateValidator
        validator= CertificateValidator()
        is_valid_chain, device_pubkey, txt_ca, txt_subca, txt_device, txt_error= validator.validate_certificate_chain(cert_pem, client.cc.card_type)
        if not is_valid_chain:
            return False, txt_ca, txt_subca, txt_device, txt_error

        # perform challenge-response with the card to ensure that the key is correctly loaded in the device
        is_valid_chalresp, txt_error = client.cc.card_challenge_response_pki(device_pubkey)

        return is_valid_chalresp, txt_ca, txt_subca, txt_device, txt_error

    def change_card_label(self, client):
        msg = ''.join([
            _("You can optionaly add a label to your Satochip.\n"),
            _("This label must be less than 64 chars long."),
        ])

        # verify pin
        is_ok= client.verify_PIN()
        if not is_ok:
            # msg= f"action cancelled by user"
            # self.window.show_error(msg)
            return

        # label dialog
        label = self.change_card_label_dialog(client, msg)
        if label is None:
            self.window.show_message(_("Operation aborted by user!"))
            return

        # set new label
        (response, sw1, sw2)= client.cc.card_set_label(label)
        if (sw1==0x90 and sw2==0x00):
            self.window.show_message(_("Card label changed successfully!"))
        elif (sw1==0x6D and sw2==0x00):
            self.window.show_error(_("Error: card does not support label!")) # starts with satochip v0.12
        else:
            self.window.show_error(f"Error while changing label: sw12={hex(sw1)} {hex(sw2)}")

    def change_card_label_dialog(self, client, msg):
        _logger.info("In change_card_label_dialog")
        while (True):
            parent = self.top_level_window()
            d = WindowModalDialog(parent, _("Enter Label"))
            pw = QLineEdit()
            pw.setEchoMode(0)
            pw.setMinimumWidth(200)

            vbox = QVBoxLayout()
            vbox.addWidget(WWLabel(msg))
            vbox.addWidget(pw)
            vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
            d.setLayout(vbox)

            label = pw.text() if d.exec_() else None
            if label is None or len(label.encode('utf-8'))<=64:
                return label
            else:
                self.window.show_error(_("Card label should not be longer than 64 chars!"))


class SelectOptionsDialog(WindowModalDialog):

    def __init__(
            self,
            *,
            option_name,
            options=None,
            parent=None,
            title="",
            help_text=None,
            config: SimpleConfig,
    ):
        WindowModalDialog.__init__(self, parent, title)
        self.config = config

        vbox = QVBoxLayout()
        if help_text:
            text_label = WWLabel()
            text_label.setText(help_text)
            vbox.addWidget(text_label)

        def set_option():
            _logger.info(f"New 2FA server: {options_combo.currentText()}")
            # save in config
            config.set_key(option_name, options_combo.currentText(), save=True)
            _logger.info("config changed!")

        default= config.get(option_name, default= SERVER_LIST[0])
        options_combo = QComboBox()
        options_combo.addItems(options)
        options_combo.setCurrentText(default)
        options_combo.currentIndexChanged.connect(set_option)
        vbox.addWidget(options_combo)

        hbox = QHBoxLayout()
        hbox.addStretch(1)

        b = QPushButton(_("Ok"))
        hbox.addWidget(b)
        b.clicked.connect(self.accept)
        b.setDefault(True)

        vbox.addLayout(hbox)
        self.setLayout(vbox)

        # note: the word-wrap on the text_label is causing layout sizing issues.
        #       see https://stackoverflow.com/a/25661985 and https://bugreports.qt.io/browse/QTBUG-37673
        #       workaround:
        self.setMinimumSize(self.sizeHint())

class DeviceCertificateDialog(WindowModalDialog):

    def __init__(
            self,
            *,
            parent=None,
            title="",
            is_authentic,
            txt_summary = "",
            txt_ca = "",
            txt_subca = "",
            txt_device = "",
    ):
        WindowModalDialog.__init__(self, parent, title)


        #super(QWidget, self).__init__(parent)
        self.layout = QVBoxLayout(self)

        # add summary text
        self.summary = QLabel(txt_summary)
        if is_authentic:
            self.summary.setStyleSheet('color: green')
        else:
            self.summary.setStyleSheet('color: red')
        self.summary.setWordWrap(True)
        self.layout.addWidget(self.summary)

        # Initialize tab screen
        self.tabs = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()
        self.tabs.resize(300,200)

        # Add tabs
        self.tabs.addTab(self.tab1,"RootCA")
        self.tabs.addTab(self.tab2,"SubCA")
        self.tabs.addTab(self.tab3,"Device")

        # Create first tab
        self.tab1.layout = QVBoxLayout(self)
        self.cert1 = QLabel(txt_ca)
        self.cert1.setWordWrap(True)
        self.tab1.layout.addWidget(self.cert1)
        self.tab1.setLayout(self.tab1.layout)

        # Create second tab
        self.tab2.layout = QVBoxLayout(self)
        self.cert2 = QLabel(txt_subca)
        self.cert2.setWordWrap(True)
        self.tab2.layout.addWidget(self.cert2)
        self.tab2.setLayout(self.tab2.layout)

        # Create third tab
        self.tab3.layout = QVBoxLayout(self)
        self.cert3 = QLabel(txt_device)
        self.cert3.setWordWrap(True)
        self.tab3.layout.addWidget(self.cert3)
        self.tab3.setLayout(self.tab3.layout)

        # Add tabs to widget
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)


##########################
#    Setup PIN  wizard   #
##########################

def clean_text(widget):
    text = widget.toPlainText().strip()
    return ' '.join(text.split())

class SatochipSetupLayout(QVBoxLayout):
    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(self, device):
        _logger.info("[SatochipSetupLayout] __init__()")
        QVBoxLayout.__init__(self)
        
        vbox = QVBoxLayout()

        # intro
        msg_setup = WWLabel(_("Please take a moment to set up your Satochip. This must be done only once."))
        vbox.addWidget(msg_setup)

        self.pw = PasswordLineEdit()
        self.pw.setMinimumWidth(32)
        #self.pw.setMaximumWidth(32)
        #self.pw.setValidator(QRegExpValidator(QRegExp('[1-9]{4,16}')))
        vbox.addWidget(WWLabel("Enter new PIN:"))
        vbox.addWidget(self.pw)
        self.addLayout(vbox)

        self.pw2 = PasswordLineEdit()
        self.pw2.setMinimumWidth(32)
        #self.pw2.setMaximumWidth(32)
        #self.pw2.setValidator(QRegExpValidator(QRegExp('[1-9]{4,16}')))
        vbox2 = QVBoxLayout()
        vbox2.addWidget(WWLabel("Confirm new PIN:"))
        vbox2.addWidget(self.pw2)
        self.addLayout(vbox2)

        # PIN validation
        if (self.pw.text()=="" or self.pw.text()==None):
            self.validChanged.emit(False)

        def set_enabled():
            is_valid= True
            if self.pw.text() != self.pw2.text():
                is_valid= False

            pw_bytes = self.pw.text().encode("utf-8")
            if len(pw_bytes)<4 or len(pw_bytes)>16:
                is_valid= False

            pw2_bytes = self.pw2.text().encode("utf-8")
            if len(pw2_bytes)<4 or len(pw2_bytes)>16:
                is_valid= False

            self.validChanged.emit(is_valid)

        self.pw2.textChanged.connect(set_enabled)
        self.pw.textChanged.connect(set_enabled)


    def get_settings(self):
        _logger.info("[SatochipSetupLayout] get_settings()")
        return self.pw.text()

class WCSatochipSetupParams(WalletWizardComponent):
    def __init__(self, parent, wizard):
        _logger.info("[WCSatochipSetupParams] __init__()")
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Satochip Setup'))
        self.plugins = wizard.plugins
        self._busy = True

    def on_ready(self):
        _logger.info("[WCSatochipSetupParams] on_ready()")
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        _name, _info = current_cosigner['hardware_device']
        self.settings_layout = SatochipSetupLayout(_info.device.id_)
        self.settings_layout.validChanged.connect(self.on_settings_valid_changed)
        self.layout().addLayout(self.settings_layout)
        self.layout().addStretch(1)

        self.valid = True # debug
        self.busy = False

    def on_settings_valid_changed(self, is_valid: bool):
        _logger.info(f"[WCSatochipSetupParams] on_settings_valid_changed() is_valid: {is_valid}")
        self.valid = is_valid
        
    def apply(self):
        _logger.info("[WCSatochipSetupParams] apply()")
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        current_cosigner['satochip_setup_settings'] = self.settings_layout.get_settings()


class WCSatochipSetup(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Satochip Setup'))
        _logger.info('[WCSatochipSetup] __init__()') # debugsatochip
        
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')

        self.layout().addWidget(WWLabel('Done'))

        self._busy = True

    def on_ready(self):
        _logger.info('[WCSatochipSetup] on_ready()') # debugsatochip
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        settings = current_cosigner['satochip_setup_settings']
        #method = current_cosigner['satochip_init']
        _name, _info = current_cosigner['hardware_device']
        device_id = _info.device.id_
        _logger.info(f'[WCSatochipSetup] on_ready() device_id: {device_id}') # debugsatochip


        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        client.handler = self.plugin.create_handler(self.wizard)

        def initialize_device_task(settings, device_id, client):
            try:
                #self.plugin._initialize_device(settings, method, device_id, handler)
                self.plugin._setup_device(settings, device_id, client)
                _logger.info('[WCSatochipSetup] initialize_device_task() Done initialize device')
                self.valid = True
                self.wizard.requestNext.emit()  # triggers Next GUI thread from event loop
            except Exception as e:
                self.valid = False
                self.error = repr(e)
                _logger.exception(repr(e))
            finally:
                self.busy = False

        t = threading.Thread(
            target=initialize_device_task,
            args=(settings, device_id, client),
            daemon=True)
        t.start()

    def apply(self):
        pass

##########################
#   Import seed wizard   #
##########################

class SatochipSeedLayout(QVBoxLayout):
    validChanged = pyqtSignal([bool], arguments=['valid'])

    def __init__(self, device):
        QVBoxLayout.__init__(self)
        
        label = QLabel(_("Enter a label to name your device:"))
        self.label_e = QLineEdit()
        hl = QHBoxLayout()
        hl.addWidget(label)
        hl.addWidget(self.label_e)
        hl.addStretch(1)
        self.addLayout(hl)

        self.text_e = QTextEdit()
        self.text_e.setMaximumHeight(60)
        msg = _("Enter your BIP39 mnemonic:")
        
        # TODO: validation?
        def set_enabled():
            item = ' '.join(str(clean_text(self.text_e)).split())
            (is_checksum_valid, is_wordlist_valid) = bip39_is_checksum_valid(item)
            self.validChanged.emit(is_checksum_valid and is_wordlist_valid)
        self.text_e.textChanged.connect(set_enabled)

        self.addWidget(QLabel(msg))
        self.addWidget(self.text_e)

        passphrase_msg = WWLabel(PASSPHRASE_HELP_SHORT)
        passphrase_warning = WWLabel(PASSPHRASE_NOT_PIN)
        passphrase_warning.setStyleSheet("color: red")
        self.addWidget(passphrase_msg)
        self.addWidget(passphrase_warning)
        #self.cb_phrase = QCheckBox(_('Enable passphrases'))
        #self.cb_phrase.setChecked(False)
        #self.addWidget(self.cb_phrase)

        self.passphrase_e = QLineEdit()
        self.passphrase_e.setMinimumWidth(100)
        passphrase_label = _("Enter your BIP39 passphrase (optional):")
        # TODO: validation?

        self.addWidget(QLabel(passphrase_label))
        self.addWidget(self.passphrase_e)

    def get_settings(self):
        item = ' '.join(str(clean_text(self.text_e)).split())
        return self.label_e.text(), item, self.passphrase_e.text()

class WCSatochipImportSeedParams(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Satochip Setup'))
        self.plugins = wizard.plugins
        self._busy = True

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        _name, _info = current_cosigner['hardware_device']
        self.settings_layout = SatochipSeedLayout(_info.device.id_)
        self.settings_layout.validChanged.connect(self.on_settings_valid_changed)
        self.layout().addLayout(self.settings_layout)
        self.layout().addStretch(1)

        self.valid = True # TODO #current_cosigner['satochip_init'] != TIM_PRIVKEY  # TODO: only privkey is validated
        self.busy = False

    def on_settings_valid_changed(self, is_valid: bool):
        self.valid = is_valid

    def apply(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        current_cosigner['satochip_seed_settings'] = self.settings_layout.get_settings()


class WCSatochipImportSeed(WalletWizardComponent):
    def __init__(self, parent, wizard):
        WalletWizardComponent.__init__(self, parent, wizard, title=_('Satochip Setup'))
        self.plugins = wizard.plugins
        self.plugin = self.plugins.get_plugin('satochip')

        self.layout().addWidget(WWLabel('Done'))

        self._busy = True

    def on_ready(self):
        current_cosigner = self.wizard.current_cosigner(self.wizard_data)
        settings = current_cosigner['satochip_seed_settings']
        #method = current_cosigner['satochip_init']
        _name, _info = current_cosigner['hardware_device']
        device_id = _info.device.id_
        client = self.plugins.device_manager.client_by_id(device_id, scan_now=False)
        client.handler = self.plugin.create_handler(self.wizard)

        def initialize_device_task(settings, device_id, handler):
            try:
                self.plugin._import_seed(settings, device_id, handler)
                _logger.info('[WCSatochipImportSeed] initialize_device_task() Done initialize device')
                self.valid = True
                self.wizard.requestNext.emit()  # triggers Next GUI thread from event loop
            except Exception as e:
                self.valid = False
                self.error = repr(e)
                _logger.exception(repr(e))
            finally:
                self.busy = False

        t = threading.Thread(
            target=initialize_device_task,
            args=(settings, device_id, client.handler),
            daemon=True)
        t.start()

    def apply(self):
        pass