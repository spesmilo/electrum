from electrum.util import print_error
from urlparse import urlparse, parse_qs
from PyQt4.QtGui import QPushButton, QMessageBox, QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit, QComboBox
from PyQt4.QtCore import Qt

from electrum.i18n import _
import re
import os
from electrum import Transaction
from electrum.bitcoin import MIN_RELAY_TX_FEE, is_valid
from electrum_gui.qt.qrcodewidget import QRCodeWidget
from electrum import bmp
from electrum_gui.qt import HelpButton, EnterButton
import json

try:
    import zbar
except ImportError:
    zbar = None

from electrum import BasePlugin
class Plugin(BasePlugin):

    def fullname(self): return 'QR scans'

    def description(self): return "QR Scans.\nInstall the zbar package to enable this plugin.\nOn linux, type: 'apt-get install python-zbar'"

    def __init__(self, gui, name):
        BasePlugin.__init__(self, gui, name)
        self._is_available = self._init()

    def _init(self):
        if not zbar:
            return False
        try:
            proc = zbar.Processor()
            proc.init(video_device=self.video_device())
        except zbar.UnsupportedError:
            return False
        except zbar.SystemError:
            # Cannot open video device
            pass
            #return False

        return True

    def init(self):
        self.win = self.gui.main_window

    def is_available(self):
        return self._is_available

    def is_enabled(self):
        return True

    def scan_qr_hook(self):
        proc = zbar.Processor()
        try:
            proc.init(video_device=self.video_device())
        except zbar.SystemError, e:
            QMessageBox.warning(self.win, _('Error'), _(e), _('OK'))
            return

        proc.visible = True

        while True:
            try:
                proc.process_one()
            except Exception:
                # User closed the preview window
                return {}

            for r in proc.results:
                if str(r.type) != 'QRCODE':
                    continue
                return r.data
        

    def video_device(self):
        device = self.config.get("video_device", "default")
        if device == 'default':
            device = ''
        return device

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), self.settings_dialog)
    
    def _find_system_cameras(self):
        device_root = "/sys/class/video4linux"
        devices = {} # Name -> device
        if os.path.exists(device_root):
            for device in os.listdir(device_root):
                name = open(os.path.join(device_root, device, 'name')).read()
                devices[name] = os.path.join("/dev",device)
        return devices

    def settings_dialog(self):
        system_cameras = self._find_system_cameras()

        d = QDialog()
        layout = QGridLayout(d)
        layout.addWidget(QLabel("Choose a video device:"),0,0)

        # Create a combo box with the available video devices:
        combo = QComboBox()

        # on change trigger for video device selection, makes the
        # manual device selection only appear when needed:
        def on_change(x):
            combo_text = str(combo.itemText(x))
            combo_data = combo.itemData(x)
            if combo_text == "Manually specify a device":
                custom_device_label.setVisible(True)
                self.video_device_edit.setVisible(True)
                if self.config.get("video_device") == "default":
                    self.video_device_edit.setText("")
                else:
                    self.video_device_edit.setText(self.config.get("video_device",''))
            else:
                custom_device_label.setVisible(False)
                self.video_device_edit.setVisible(False)
                self.video_device_edit.setText(combo_data.toString())

        # on save trigger for the video device selection window,
        # stores the chosen video device on close.
        def on_save():
            device = str(self.video_device_edit.text())
            self.config.set_key("video_device", device)
            d.accept()

        custom_device_label = QLabel("Video device: ")
        custom_device_label.setVisible(False)
        layout.addWidget(custom_device_label,1,0)
        self.video_device_edit = QLineEdit()
        self.video_device_edit.setVisible(False)
        layout.addWidget(self.video_device_edit, 1,1,2,2)
        combo.currentIndexChanged.connect(on_change)

        combo.addItem("Default","default")
        for camera, device in system_cameras.items():
            combo.addItem(camera, device)
        combo.addItem("Manually specify a device",self.config.get("video_device"))

        # Populate the previously chosen device:
        index = combo.findData(self.config.get("video_device"))
        combo.setCurrentIndex(index)

        layout.addWidget(combo,0,1)

        self.accept = QPushButton(_("Done"))
        self.accept.clicked.connect(on_save)
        layout.addWidget(self.accept,4,2)

        if d.exec_():
          return True
        else:
          return False
