#from electrum.plugins import BasePlugin
#from electrum_gui.qt.util import EnterButton
from electrum.i18n import _
from functools import partial
from electrum_gui.qt.util import (EnterButton, Buttons, CloseButton, OkButton, WindowModalDialog)
from PyQt5.QtWidgets import (QVBoxLayout)

#satochip
from .satochip import SatochipPlugin
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase

class Plugin(SatochipPlugin, QtPluginBase):
    icon_unpaired = ":icons/satochip_unpaired.png"
    icon_paired = ":icons/satochip.png"
    
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
        
class Satochip_Handler(QtHandlerBase):

    def __init__(self, win):
        super(Satochip_Handler, self).__init__(win, 'Satochip')
        
    #TODO: something?    
    
    
    
    