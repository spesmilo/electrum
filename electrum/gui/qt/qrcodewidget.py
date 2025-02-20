from typing import Optional

import qrcode
import qrcode.exceptions

import PyQt6.QtGui as QtGui
from PyQt6.QtCore import QRect
from PyQt6.QtWidgets import QApplication, QVBoxLayout, QHBoxLayout, QPushButton, QWidget

from electrum.i18n import _
from electrum.simple_config import SimpleConfig
from electrum.gui.common_qt.util import draw_qr

from .util import WindowModalDialog, WWLabel, getSaveFileName


class QrCodeDataOverflow(qrcode.exceptions.DataOverflowError):
    pass


class QRCodeWidget(QWidget):

    MIN_BOXSIZE = 2  # min size in pixels of single black/white unit box of the qr code

    def __init__(self, data=None, *, manual_size: bool = False):
        QWidget.__init__(self)
        self.data = None
        self.qr = None
        self._framesize = None  # type: Optional[int]
        self._manual_size = manual_size
        self.setData(data)

    def setData(self, data):
        if data:
            qr = qrcode.QRCode(
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                border=1,
            )
            try:
                qr.add_data(data)
                qr_matrix = qr.get_matrix()  # test that data fits in QR code
            except (ValueError, qrcode.exceptions.DataOverflowError) as e:
                raise QrCodeDataOverflow() from e
            self.qr = qr
            self.data = data
            if not self._manual_size:
                k = len(qr_matrix)
                size = min(k * 5, 150 + k * self.MIN_BOXSIZE)
                self.setMinimumSize(size, size)
        else:
            self.qr = None
            self.data = None

        self.update()

    def paintEvent(self, e):
        if not self.data:
            return
        draw_qr(
            qr=self.qr,
            paint_device=self,
            is_enabled=self.isEnabled(),
            min_boxsize=self.MIN_BOXSIZE,
        )

    def grab(self) -> QtGui.QPixmap:
        """Overrides QWidget.grab to only include the QR code itself,
        excluding horizontal/vertical stretch.
        """
        fsize = self._framesize
        if fsize is None:
            fsize = -1
        rect = QRect(0, 0, fsize, fsize)
        return QWidget.grab(self, rect)


class QRDialog(WindowModalDialog):

    def __init__(
            self,
            *,
            data,
            parent=None,
            title="",
            show_text=False,
            help_text=None,
            show_copy_text_btn=False,
            config: SimpleConfig,
    ):
        WindowModalDialog.__init__(self, parent, title)
        self.config = config

        vbox = QVBoxLayout()

        qrw = QRCodeWidget(data, manual_size=False)
        vbox.addWidget(qrw, 1)

        help_text = data if show_text else help_text
        if help_text:
            text_label = WWLabel()
            text_label.setText(help_text)
            vbox.addWidget(text_label)
        hbox = QHBoxLayout()
        hbox.addStretch(1)

        def print_qr():
            filename = getSaveFileName(
                parent=self,
                title=_("Select where to save file"),
                filename="qrcode.png",
                config=self.config,
            )
            if not filename:
                return
            p = qrw.grab()
            p.save(filename, 'png')
            self.show_message(_("QR code saved to file") + " " + filename)

        def copy_image_to_clipboard():
            p = qrw.grab()
            QApplication.clipboard().setPixmap(p)
            self.show_message(_("QR code copied to clipboard"))

        def copy_text_to_clipboard():
            QApplication.clipboard().setText(data)
            self.show_message(_("Text copied to clipboard"))

        b = QPushButton(_("Copy Image"))
        hbox.addWidget(b)
        b.clicked.connect(copy_image_to_clipboard)

        if show_copy_text_btn:
            b = QPushButton(_("Copy Text"))
            hbox.addWidget(b)
            b.clicked.connect(copy_text_to_clipboard)

        b = QPushButton(_("Save"))
        hbox.addWidget(b)
        b.clicked.connect(print_qr)

        b = QPushButton(_("Close"))
        hbox.addWidget(b)
        b.clicked.connect(self.accept)
        b.setDefault(True)

        vbox.addLayout(hbox)
        self.setLayout(vbox)

        # note: the word-wrap on the text_label is causing layout sizing issues.
        #       see https://stackoverflow.com/a/25661985 and https://bugreports.qt.io/browse/QTBUG-37673
        #       workaround:
        self.setMinimumSize(self.sizeHint())
