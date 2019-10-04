from electrum.i18n import _
from electrum.logging import get_logger
from electrum.plugin import run_hook
from electrum.gui.qt.util import (EnterButton, Buttons, CloseButton, OkButton, CancelButton, WindowModalDialog, WWLabel)
from PyQt5.QtCore import Qt, pyqtSignal                                          
from PyQt5.QtWidgets import (QPushButton, QLabel, QVBoxLayout, QWidget, QGridLayout, QLineEdit, QCheckBox)
from functools import partial

#satochip
from .satochip import SatochipPlugin
from .CardConnector import CardConnector                                        
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase

_logger = get_logger(__name__)

class Plugin(SatochipPlugin, QtPluginBase):
    icon_unpaired = "satochip_unpaired.png"
    icon_paired = "satochip.png"
    #icon_unpaired = ":icons/satochip_unpaired.png"
    #icon_paired = ":icons/satochip.png"
    
    #def __init__(self, parent, config, name):
    #    BasePlugin.__init__(self, parent, config, name)
    
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
        device_id = self.choose_device(window, keystore)
        if device_id:
            SatochipSettingsDialog(window, self, keystore, device_id).exec_()
            
class Satochip_Handler(QtHandlerBase):

    def __init__(self, win):
        super(Satochip_Handler, self).__init__(win, 'Satochip')
        
    #TODO: something?    
    
class SatochipSettingsDialog(WindowModalDialog):
    '''This dialog doesn't require a device be paired with a wallet.
    
    We want users to be able to wipe a device even if they've forgotten
    their PIN.'''    
    
    def __init__(self, window, plugin, keystore, device_id):
        title = _("{} Settings").format(plugin.device)
        super(SatochipSettingsDialog, self).__init__(window, title)
        self.setMaximumWidth(540)

        devmgr = plugin.device_manager()
        config = devmgr.config
        handler = keystore.handler
        self.thread = thread = keystore.thread

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

        grid.addWidget(title , 0,0, 1,2, Qt.AlignHCenter)
        y = 3
        
        rows = [
            ('fw_version', _("Firmware Version")),
            ('sw_version', _("Electrum Support")),
            ('is_seeded', _("Wallet seeded")),
            ('needs_2FA', _("Requires 2FA ")),            
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

        seed_btn = QPushButton('reset seed')
        def _reset_seed():
            thread.add(connect_and_doit, on_success=self.reset_seed)
            thread.add(connect_and_doit, on_success=self.show_values)
        seed_btn.clicked.connect(_reset_seed)

        y += 3
        grid.addWidget(pin_btn, y, 0)
        grid.addWidget(seed_btn, y, 1)
        y += 5
        grid.addWidget(CloseButton(self), y, 1)

        dialog_vbox = QVBoxLayout(self)
        dialog_vbox.addWidget(body)

        # Fetch values and show them
        thread.add(connect_and_doit, on_success=self.show_values)


    def show_values(self, client):
        _logger.info("Show value!")
        v_supported= (CardConnector.SATOCHIP_PROTOCOL_MAJOR_VERSION<<8)+CardConnector.SATOCHIP_PROTOCOL_MINOR_VERSION
        sw_rel= hex(v_supported)
        self.sw_version.setText('<tt>%s' % sw_rel)
        
        (response, sw1, sw2, d)=client.cc.card_get_status()
        if (sw1==0x90 and sw2==0x00):
            v_applet= (d["protocol_major_version"]<<8)+d["protocol_minor_version"] 
            fw_rel= hex(v_applet)
            self.fw_version.setText('<tt>%s' % fw_rel)
            
            #is_seeded?
            try: 
                client.cc.card_bip32_get_authentikey()
                self.is_seeded.setText('<tt>%s' % "yes")
            except Exception:
                self.is_seeded.setText('<tt>%s' % "no")
            
            # needs2FA?
            if len(response)>=9 and response[8]==0X01: 
                self.needs_2FA.setText('<tt>%s' % "yes")
            elif len(response)>=9 and response[8]==0X00: 
                self.needs_2FA.setText('<tt>%s' % "no")
            else:
                self.needs_2FA.setText('<tt>%s' % "(unknown)")
            
        else:
            fw_rel= "(unitialized)"
            self.fw_version.setText('<tt>%s' % fw_rel)
            self.needs_2FA.setText('<tt>%s' % "(unitialized)")
            self.is_seeded.setText('<tt>%s' % "no")
            
        

    def change_pin(self, client):
        # old pin
        msg = _("Enter the current PIN for your Satochip:")
        (is_PIN, oldpin, oldpin)= client.PIN_dialog(msg)
        if (oldpin is None):
                return
                
        # new pin
        while (True):
            msg = _("Enter a new PIN for your Satochip:")
            (is_PIN, newpin, newpin)= client.PIN_dialog(msg)
            if (newpin is None):
                return
            msg = _("Please confirm the new PIN for your Satochip:")
            (is_PIN, pin_confirm, pin_confirm)= client.PIN_dialog(msg)
            if (pin_confirm is None):
                return
            if (newpin != pin_confirm):
                msg= _("The PIN values do not match! Please type PIN again!")
                client.handler.show_error(msg)
            else:
                break
        
        oldpin= list(oldpin)    
        newpin= list(newpin)  
        (response, sw1, sw2)= client.cc.card_change_PIN(0, oldpin, newpin)
        if (sw1==0x90 and sw2==0x00):
            msg= _("PIN changeg successfully!")
            client.handler.show_message(msg)
        else:
            msg= _("Failed to change PIN!")
            client.handler.show_error(msg)
    
    def reset_seed(self, client):
        
        # pin
        msg = ''.join([
            _("WARNING!\n"),
            _("You are about to reset the seed of your Satochip. This process is irreversible!\n"),
            _("Please be sure that your wallet is empty and that you have a backup of the seed as a precaution.\n\n"),
            _("To proceed, enter the PIN for your Satochip:")
        ])
        (password, reset_2FA)= self.reset_seed_dialog(msg)
        if (password is None):
            return
        pin = password.encode('utf8')
        pin= list(pin)
        
        # if 2FA is enabled, get challenge-response
        hmac=[]
        if (client.cc.needs_2FA==None):
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
            # _logger.info("encrypted message: "+msg_out)
            
            #do challenge-response with 2FA device...
            client.handler.show_message('2FA request sent! Approve or reject request on your second device.')
            run_hook('do_challenge_response', d)
            # decrypt and parse reply to extract challenge response
            try: 
                reply_encrypt= d['reply_encrypt']
            except Exception as e:
                self.give_error("No response received from 2FA.\nPlease ensure that the Satochip-2FA plugin is enabled in Tools>Optional Features", True)
            reply_decrypt= client.cc.card_crypt_transaction_2FA(reply_encrypt, False)
            _logger.info("challenge:response= "+ reply_decrypt)
            reply_decrypt= reply_decrypt.split(":")
            chalresponse=reply_decrypt[1]
            hmac= list(bytes.fromhex(chalresponse))
            
        # send request 
        (response, sw1, sw2) = client.cc.card_reset_seed(pin, hmac)
        if (sw1==0x90 and sw2==0x00):
            msg= _("Seed reset successfully!\nYou should close this wallet and launch the wizard to generate a new wallet.")
            client.handler.show_message(msg)
            #to do: close client?
        else:
            msg= _(f"Failed to reset seed with error code: {hex(sw1)}{hex(sw2)}")
            client.handler.show_error(msg)
            
        if reset_2FA and client.cc.needs_2FA:     
            # challenge based on ID_2FA
            # format & encrypt msg
            import json
            msg= {'action':"reset_2FA"}
            msg=  json.dumps(msg)
            (id_2FA, msg_out)= client.cc.card_crypt_transaction_2FA(msg, True)
            d={}
            d['msg_encrypt']= msg_out
            d['id_2FA']= id_2FA
            # _logger.info("encrypted message: "+msg_out)
            
            #do challenge-response with 2FA device...
            client.handler.show_message('2FA request sent! Approve or reject request on your second device.')
            run_hook('do_challenge_response', d)
            # decrypt and parse reply to extract challenge response
            try: 
                reply_encrypt= d['reply_encrypt']
            except Exception as e:
                self.give_error("No response received from 2FA.\nPlease ensure that the Satochip-2FA plugin is enabled in Tools>Optional Features", True)
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
                client.handler.show_message(msg)
            else:
                msg= _(f"Failed to reset 2FA with error code: {hex(sw1)}{hex(sw2)}")
                client.handler.show_error(msg)    
        
    def reset_seed_dialog(self, msg):
        parent = self.top_level_window()
        d = WindowModalDialog(parent, _("Enter PIN"))
        pw = QLineEdit()
        pw.setEchoMode(2)
        pw.setMinimumWidth(200)
        
        cb_reset_2FA = QCheckBox(_('Also reset 2FA'))
        
        vbox = QVBoxLayout()
        vbox.addWidget(WWLabel(msg))
        vbox.addWidget(pw)
        vbox.addWidget(cb_reset_2FA)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        d.setLayout(vbox)
        
        passphrase = pw.text() if d.exec_() else None
        reset_2FA= cb_reset_2FA.isChecked()
        return (passphrase, reset_2FA)
            
    