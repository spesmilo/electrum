'''

Revealer
Do you have something to hide?
Secret backup plug-in for the electrum wallet.

Tiago Romagnani Silveira, 2017


'''

import os
import random
import traceback
from decimal import Decimal
from functools import partial
import sys

import qrcode
from PyQt5.QtPrintSupport import QPrinter
from PyQt5.QtCore import Qt, QRectF, QRect, QSizeF, QUrl, QPoint, QSize
from PyQt5.QtGui import (QPixmap, QImage, QBitmap, QPainter, QFontDatabase, QPen, QFont,
                         QColor, QDesktopServices, qRgba, QPainterPath)
from PyQt5.QtWidgets import (QGridLayout, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QLineEdit)

from electrum.plugin import hook
from electrum.i18n import _
from electrum.util import make_dir, InvalidPassword, UserCancelled
from electrum.gui.qt.util import (read_QIcon, EnterButton, WWLabel, icon_path,
                                  WindowModalDialog, Buttons, CloseButton, OkButton)
from electrum.gui.qt.qrtextedit import ScanQRTextEdit
from electrum.gui.qt.main_window import StatusBarButton

from .revealer import RevealerPlugin


class Plugin(RevealerPlugin):

    MAX_PLAINTEXT_LEN = 189  # chars

    def __init__(self, parent, config, name):
        RevealerPlugin.__init__(self, parent, config, name)
        self.base_dir = os.path.join(config.electrum_path(), 'revealer')

        if self.config.get('calibration_h') is None:
            self.config.set_key('calibration_h', 0)
        if self.config.get('calibration_v') is None:
            self.config.set_key('calibration_v', 0)

        self.calibration_h = self.config.get('calibration_h')
        self.calibration_v = self.config.get('calibration_v')

        self.f_size = QSize(1014*2, 642*2)
        self.abstand_h = 21
        self.abstand_v = 34
        self.calibration_noise = int('10' * 128)
        self.rawnoise = False
        make_dir(self.base_dir)

        self.extension = False

    @hook
    def create_status_bar(self, parent):
        b = StatusBarButton(read_QIcon('revealer.png'), "Revealer "+_("secret backup utility"),
                            partial(self.setup_dialog, parent))
        parent.addPermanentWidget(b)

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Printer Calibration'), partial(self.calibration_dialog, window))

    def password_dialog(self, msg=None, parent=None):
        from electrum.gui.qt.password_dialog import PasswordDialog
        parent = parent or self
        d = PasswordDialog(parent, msg)
        return d.run()

    def get_seed(self):
        password = None
        if self.wallet.has_keystore_encryption():
            password = self.password_dialog(parent=self.d.parent())
            if not password:
                raise UserCancelled()

        keystore = self.wallet.get_keystore()
        if not keystore or not keystore.has_seed():
            return
        self.extension = bool(keystore.get_passphrase(password))
        return keystore.get_seed(password)

    def setup_dialog(self, window):
        self.wallet = window.parent().wallet
        self.update_wallet_name(self.wallet)
        self.user_input = False

        self.d = WindowModalDialog(window, "Setup Dialog")
        self.d.setMinimumWidth(500)
        self.d.setMinimumHeight(210)
        self.d.setMaximumHeight(320)
        self.d.setContentsMargins(11,11,1,1)

        self.hbox = QHBoxLayout(self.d)
        vbox = QVBoxLayout()
        logo = QLabel()
        self.hbox.addWidget(logo)
        logo.setPixmap(QPixmap(icon_path('revealer.png')))
        logo.setAlignment(Qt.AlignLeft)
        self.hbox.addSpacing(16)
        vbox.addWidget(WWLabel("<b>"+_("Revealer Secret Backup Plugin")+"</b><br>"
                                    +_("To encrypt your backup, first we need to load some noise.")+"<br/>"))
        vbox.addSpacing(7)
        bcreate = QPushButton(_("Create a new Revealer"))
        bcreate.setMaximumWidth(181)
        bcreate.setDefault(True)
        vbox.addWidget(bcreate, Qt.AlignCenter)
        self.load_noise = ScanQRTextEdit()
        self.load_noise.setTabChangesFocus(True)
        self.load_noise.textChanged.connect(self.on_edit)
        self.load_noise.setMaximumHeight(33)
        self.hbox.addLayout(vbox)
        vbox.addWidget(WWLabel(_("or type an existing revealer code below and click 'next':")))
        vbox.addWidget(self.load_noise)
        vbox.addSpacing(3)
        self.next_button = QPushButton(_("Next"), self.d)
        self.next_button.setEnabled(False)
        vbox.addLayout(Buttons(self.next_button))
        self.next_button.clicked.connect(self.d.close)
        self.next_button.clicked.connect(partial(self.cypherseed_dialog, window))
        vbox.addWidget(
            QLabel("<b>" + _("Warning") + "</b>: " + _("Each revealer should be used only once.")
                   +"<br>"+_("more information at <a href=\"https://revealer.cc/faq\">https://revealer.cc/faq</a>")))

        def mk_digital():
            try:
                self.make_digital(self.d)
            except Exception:
                self.logger.exception('')
            else:
                self.cypherseed_dialog(window)

        bcreate.clicked.connect(mk_digital)
        return bool(self.d.exec_())

    def get_noise(self):
        text = self.load_noise.text()
        return ''.join(text.split()).lower()

    def on_edit(self):
        txt = self.get_noise()
        versioned_seed = self.get_versioned_seed_from_user_input(txt)
        if versioned_seed:
            self.versioned_seed = versioned_seed
        self.user_input = bool(versioned_seed)
        self.next_button.setEnabled(bool(versioned_seed))

    def make_digital(self, dialog):
        self.make_rawnoise(True)
        self.bdone(dialog)
        self.d.close()

    def get_path_to_revealer_file(self, ext: str= '') -> str:
        version = self.versioned_seed.version
        code_id = self.versioned_seed.checksum
        filename = self.filename_prefix + version + "_" + code_id + ext
        path = os.path.join(self.base_dir, filename)
        return os.path.normcase(os.path.abspath(path))

    def get_path_to_calibration_file(self):
        path = os.path.join(self.base_dir, 'calibration.pdf')
        return os.path.normcase(os.path.abspath(path))

    def bcrypt(self, dialog):
        self.rawnoise = False
        version = self.versioned_seed.version
        code_id = self.versioned_seed.checksum
        dialog.show_message(''.join([_("{} encrypted for Revealer {}_{} saved as PNG and PDF at: ").format(self.was, version, code_id),
                                     "<b>", self.get_path_to_revealer_file(), "</b>", "<br/>",
                                     "<br/>", "<b>", _("Always check your backups.")]),
                            rich_text=True)
        dialog.close()

    def ext_warning(self, dialog):
        dialog.show_message(''.join(["<b>",_("Warning"), ": </b>",
                                     _("your seed extension will <b>not</b> be included in the encrypted backup.")]),
                            rich_text=True)
        dialog.close()

    def bdone(self, dialog):
        version = self.versioned_seed.version
        code_id = self.versioned_seed.checksum
        dialog.show_message(''.join([_("Digital Revealer ({}_{}) saved as PNG and PDF at:").format(version, code_id),
                                     "<br/>","<b>", self.get_path_to_revealer_file(), '</b>']),
                            rich_text=True)


    def customtxt_limits(self):
        txt = self.text.text()
        self.max_chars.setVisible(False)
        self.char_count.setText(f"({len(txt)}/{self.MAX_PLAINTEXT_LEN})")
        if len(txt)>0:
            self.ctext.setEnabled(True)
        if len(txt) > self.MAX_PLAINTEXT_LEN:
            self.text.setPlainText(txt[:self.MAX_PLAINTEXT_LEN])
            self.max_chars.setVisible(True)

    def t(self):
        self.txt = self.text.text()
        self.seed_img(is_seed=False)

    def warn_old_revealer(self):
        if self.versioned_seed.version == '0':
            link = "https://revealer.cc/revealer-warning-and-upgrade/"
            self.d.show_warning(("<b>{warning}: </b>{ver0}<br>"
                                 "{url}<br>"
                                 "{risk}")
                                .format(warning=_("Warning"),
                                        ver0=_("Revealers starting with 0 are not secure due to a vulnerability."),
                                        url=_("More info at: {}").format(f'<a href="{link}">{link}</a>'),
                                        risk=_("Proceed at your own risk.")),
                                rich_text=True)

    def cypherseed_dialog(self, window):
        self.warn_old_revealer()

        d = WindowModalDialog(window, "Encryption Dialog")
        d.setMinimumWidth(500)
        d.setMinimumHeight(210)
        d.setMaximumHeight(450)
        d.setContentsMargins(11, 11, 1, 1)
        self.c_dialog = d

        hbox = QHBoxLayout(d)
        self.vbox = QVBoxLayout()
        logo = QLabel()
        hbox.addWidget(logo)
        logo.setPixmap(QPixmap(icon_path('revealer.png')))
        logo.setAlignment(Qt.AlignLeft)
        hbox.addSpacing(16)
        self.vbox.addWidget(WWLabel("<b>" + _("Revealer Secret Backup Plugin") + "</b><br>"
                               + _("Ready to encrypt for revealer {}")
                                    .format(self.versioned_seed.version+'_'+self.versioned_seed.checksum)))
        self.vbox.addSpacing(11)
        hbox.addLayout(self.vbox)
        grid = QGridLayout()
        self.vbox.addLayout(grid)

        cprint = QPushButton(_("Encrypt {}'s seed").format(self.wallet_name))
        cprint.setMaximumWidth(250)
        cprint.clicked.connect(partial(self.seed_img, True))
        self.vbox.addWidget(cprint)
        self.vbox.addSpacing(1)
        self.vbox.addWidget(WWLabel("<b>"+_("OR")+"</b> "+_("type a custom alphanumerical secret below:")))
        self.text = ScanQRTextEdit()
        self.text.setTabChangesFocus(True)
        self.text.setMaximumHeight(70)
        self.text.textChanged.connect(self.customtxt_limits)
        self.vbox.addWidget(self.text)
        self.char_count = WWLabel("")
        self.char_count.setAlignment(Qt.AlignRight)
        self.vbox.addWidget(self.char_count)
        self.max_chars = WWLabel("<font color='red'>"
                                 + _("This version supports a maximum of {} characters.").format(self.MAX_PLAINTEXT_LEN)
                                 +"</font>")
        self.vbox.addWidget(self.max_chars)
        self.max_chars.setVisible(False)
        self.ctext = QPushButton(_("Encrypt custom secret"))
        self.ctext.clicked.connect(self.t)
        self.vbox.addWidget(self.ctext)
        self.ctext.setEnabled(False)
        self.vbox.addSpacing(11)
        self.vbox.addLayout(Buttons(CloseButton(d)))
        return bool(d.exec_())

    def update_wallet_name(self, name):
        self.wallet_name = str(name)

    def seed_img(self, is_seed = True):

        if is_seed:
            try:
                cseed = self.get_seed()
            except UserCancelled:
                return
            except InvalidPassword as e:
                self.d.show_error(str(e))
                return
            if not cseed:
                self.d.show_message(_("This wallet has no seed"))
                return
            txt = cseed.upper()
        else:
            txt = self.txt.upper()

        img = QImage(self.SIZE[0], self.SIZE[1], QImage.Format_Mono)
        bitmap = QBitmap.fromImage(img, Qt.MonoOnly)
        bitmap.fill(Qt.white)
        painter = QPainter()
        painter.begin(bitmap)
        QFontDatabase.addApplicationFont(os.path.join(os.path.dirname(__file__), 'SourceSansPro-Bold.otf') )
        if len(txt) < 102 :
            fontsize = 15
            linespace = 15
            max_letters = 17
            max_lines = 6
            max_words = 3
        else:
            fontsize = 12
            linespace = 10
            max_letters = 21
            max_lines = 9
            max_words = int(max_letters/4)

        font = QFont('Source Sans Pro', fontsize, QFont.Bold)
        font.setLetterSpacing(QFont.PercentageSpacing, 100)
        font.setPixelSize(fontsize)
        painter.setFont(font)
        seed_array = txt.split(' ')

        for n in range(max_lines):
            nwords = max_words
            temp_seed = seed_array[:nwords]
            while len(' '.join(map(str, temp_seed))) > max_letters:
               nwords = nwords - 1
               temp_seed = seed_array[:nwords]
            painter.drawText(QRect(0, linespace*n , self.SIZE[0], self.SIZE[1]), Qt.AlignHCenter, ' '.join(map(str, temp_seed)))
            del seed_array[:nwords]

        painter.end()
        img = bitmap.toImage()
        if (self.rawnoise == False):
            self.make_rawnoise()

        self.make_cypherseed(img, self.rawnoise, False, is_seed)
        return img

    def make_rawnoise(self, create_revealer=False):
        if not self.user_input:
            self.versioned_seed = self.gen_random_versioned_seed()
        assert self.versioned_seed
        w, h = self.SIZE
        rawnoise = QImage(w, h, QImage.Format_Mono)

        noise_map = self.get_noise_map(self.versioned_seed)
        for (x,y), pixel in noise_map.items():
            rawnoise.setPixel(x, y, pixel)

        self.rawnoise = rawnoise
        if create_revealer:
            self.make_revealer()

    def make_calnoise(self):
        random.seed(self.calibration_noise)
        w, h = self.SIZE
        rawnoise = QImage(w, h, QImage.Format_Mono)
        for x in range(w):
            for y in range(h):
                rawnoise.setPixel(x,y,random.randint(0, 1))
        self.calnoise = self.pixelcode_2x2(rawnoise)

    def make_revealer(self):
        revealer = self.pixelcode_2x2(self.rawnoise)
        revealer.invertPixels()
        revealer = QBitmap.fromImage(revealer)
        revealer = revealer.scaled(self.f_size, Qt.KeepAspectRatio)
        revealer = self.overlay_marks(revealer)

        self.filename_prefix = 'revealer_'
        revealer.save(self.get_path_to_revealer_file('.png'))
        self.toPdf(QImage(revealer))
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.get_path_to_revealer_file('.pdf')))

    def make_cypherseed(self, img, rawnoise, calibration=False, is_seed = True):
        img = img.convertToFormat(QImage.Format_Mono)
        p = QPainter()
        p.begin(img)
        p.setCompositionMode(26) #xor
        p.drawImage(0, 0, rawnoise)
        p.end()
        cypherseed = self.pixelcode_2x2(img)
        cypherseed = QBitmap.fromImage(cypherseed)
        cypherseed = cypherseed.scaled(self.f_size, Qt.KeepAspectRatio)
        cypherseed = self.overlay_marks(cypherseed, True, calibration)

        if not is_seed:
            self.filename_prefix = 'custom_secret_'
            self.was = _('Custom secret')
        else:
            self.filename_prefix = self.wallet_name + '_seed_'
            self.was = self.wallet_name + ' ' + _('seed')
            if self.extension:
                self.ext_warning(self.c_dialog)


        if not calibration:
            self.toPdf(QImage(cypherseed))
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.get_path_to_revealer_file('.pdf')))
            cypherseed.save(self.get_path_to_revealer_file('.png'))
            self.bcrypt(self.c_dialog)
        return cypherseed

    def calibration(self):
        img = QImage(self.SIZE[0], self.SIZE[1], QImage.Format_Mono)
        bitmap = QBitmap.fromImage(img, Qt.MonoOnly)
        bitmap.fill(Qt.black)
        self.make_calnoise()
        img = self.overlay_marks(self.calnoise.scaledToHeight(self.f_size.height()), False, True)
        self.calibration_pdf(img)
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.get_path_to_calibration_file()))
        return img

    def toPdf(self, image):
        printer = QPrinter()
        printer.setPaperSize(QSizeF(210, 297), QPrinter.Millimeter)
        printer.setResolution(600)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(self.get_path_to_revealer_file('.pdf'))
        printer.setPageMargins(0,0,0,0,6)
        painter = QPainter()
        painter.begin(printer)

        delta_h = round(image.width()/self.abstand_v)
        delta_v = round(image.height()/self.abstand_h)

        size_h = 2028+((int(self.calibration_h)*2028/(2028-(delta_h*2)+int(self.calibration_h)))/2)
        size_v = 1284+((int(self.calibration_v)*1284/(1284-(delta_v*2)+int(self.calibration_v)))/2)

        image =  image.scaled(size_h, size_v)

        painter.drawImage(553,533, image)
        wpath = QPainterPath()
        wpath.addRoundedRect(QRectF(553,533, size_h, size_v), 19, 19)
        painter.setPen(QPen(Qt.black, 1))
        painter.drawPath(wpath)
        painter.end()

    def calibration_pdf(self, image):
        printer = QPrinter()
        printer.setPaperSize(QSizeF(210, 297), QPrinter.Millimeter)
        printer.setResolution(600)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(self.get_path_to_calibration_file())
        printer.setPageMargins(0,0,0,0,6)

        painter = QPainter()
        painter.begin(printer)
        painter.drawImage(553,533, image)
        font = QFont('Source Sans Pro', 10, QFont.Bold)
        painter.setFont(font)
        painter.drawText(254,277, _("Calibration sheet"))
        font = QFont('Source Sans Pro', 7, QFont.Bold)
        painter.setFont(font)
        painter.drawText(600,2077, _("Instructions:"))
        font = QFont('Source Sans Pro', 7, QFont.Normal)
        painter.setFont(font)
        painter.drawText(700, 2177, _("1. Place this paper on a flat and well iluminated surface."))
        painter.drawText(700, 2277, _("2. Align your Revealer borderlines to the dashed lines on the top and left."))
        painter.drawText(700, 2377, _("3. Press slightly the Revealer against the paper and read the numbers that best "
                                      "match on the opposite sides. "))
        painter.drawText(700, 2477, _("4. Type the numbers in the software"))
        painter.end()

    def pixelcode_2x2(self, img):
        result = QImage(img.width()*2, img.height()*2, QImage.Format_ARGB32 )
        white = qRgba(255,255,255,0)
        black = qRgba(0,0,0,255)

        for x in range(img.width()):
            for y in range(img.height()):
                c = img.pixel(QPoint(x,y))
                colors = QColor(c).getRgbF()
                if colors[0]:
                    result.setPixel(x*2+1,y*2+1, black)
                    result.setPixel(x*2,y*2+1, white)
                    result.setPixel(x*2+1,y*2, white)
                    result.setPixel(x*2, y*2, black)

                else:
                    result.setPixel(x*2+1,y*2+1, white)
                    result.setPixel(x*2,y*2+1, black)
                    result.setPixel(x*2+1,y*2, black)
                    result.setPixel(x*2, y*2, white)
        return result

    def overlay_marks(self, img, is_cseed=False, calibration_sheet=False):
        border_color = Qt.white
        base_img = QImage(self.f_size.width(),self.f_size.height(), QImage.Format_ARGB32)
        base_img.fill(border_color)
        img = QImage(img)

        painter = QPainter()
        painter.begin(base_img)

        total_distance_h = round(base_img.width() / self.abstand_v)
        dist_v = round(total_distance_h) / 2
        dist_h = round(total_distance_h) / 2

        img = img.scaledToWidth(base_img.width() - (2 * (total_distance_h)))
        painter.drawImage(total_distance_h,
                          total_distance_h,
                          img)

        #frame around image
        pen = QPen(Qt.black, 2)
        painter.setPen(pen)

        #horz
        painter.drawLine(0, total_distance_h, base_img.width(), total_distance_h)
        painter.drawLine(0, base_img.height()-(total_distance_h), base_img.width(), base_img.height()-(total_distance_h))
        #vert
        painter.drawLine(total_distance_h, 0,  total_distance_h, base_img.height())
        painter.drawLine(base_img.width()-(total_distance_h), 0,  base_img.width()-(total_distance_h), base_img.height())

        #border around img
        border_thick = 6
        Rpath = QPainterPath()
        Rpath.addRect(QRectF((total_distance_h)+(border_thick/2),
                             (total_distance_h)+(border_thick/2),
                             base_img.width()-((total_distance_h)*2)-((border_thick)-1),
                             (base_img.height()-((total_distance_h))*2)-((border_thick)-1)))
        pen = QPen(Qt.black, border_thick)
        pen.setJoinStyle (Qt.MiterJoin)

        painter.setPen(pen)
        painter.drawPath(Rpath)

        Bpath = QPainterPath()
        Bpath.addRect(QRectF((total_distance_h), (total_distance_h),
                             base_img.width()-((total_distance_h)*2), (base_img.height()-((total_distance_h))*2)))
        pen = QPen(Qt.black, 1)
        painter.setPen(pen)
        painter.drawPath(Bpath)

        pen = QPen(Qt.black, 1)
        painter.setPen(pen)
        painter.drawLine(0, base_img.height()/2, total_distance_h, base_img.height()/2)
        painter.drawLine(base_img.width()/2, 0, base_img.width()/2, total_distance_h)

        painter.drawLine(base_img.width()-total_distance_h, base_img.height()/2, base_img.width(), base_img.height()/2)
        painter.drawLine(base_img.width()/2, base_img.height(), base_img.width()/2, base_img.height() - total_distance_h)

        #print code
        f_size = 37
        QFontDatabase.addApplicationFont(os.path.join(os.path.dirname(__file__), 'DejaVuSansMono-Bold.ttf'))
        font = QFont("DejaVu Sans Mono", f_size-11, QFont.Bold)
        font.setPixelSize(35)
        painter.setFont(font)

        if not calibration_sheet:
            if is_cseed: #its a secret
                painter.setPen(QPen(Qt.black, 1, Qt.DashDotDotLine))
                painter.drawLine(0, dist_v, base_img.width(), dist_v)
                painter.drawLine(dist_h, 0,  dist_h, base_img.height())
                painter.drawLine(0, base_img.height()-dist_v, base_img.width(), base_img.height()-(dist_v))
                painter.drawLine(base_img.width()-(dist_h), 0,  base_img.width()-(dist_h), base_img.height())

                painter.drawImage(((total_distance_h))+11, ((total_distance_h))+11,
                                  QImage(icon_path('electrumb.png')).scaledToWidth(2.1*(total_distance_h), Qt.SmoothTransformation))

                painter.setPen(QPen(Qt.white, border_thick*8))
                painter.drawLine(base_img.width()-((total_distance_h))-(border_thick*8)/2-(border_thick/2)-2,
                                (base_img.height()-((total_distance_h)))-((border_thick*8)/2)-(border_thick/2)-2,
                                base_img.width()-((total_distance_h))-(border_thick*8)/2-(border_thick/2)-2 - 77,
                                (base_img.height()-((total_distance_h)))-((border_thick*8)/2)-(border_thick/2)-2)
                painter.setPen(QColor(0,0,0,255))
                painter.drawText(QRect(0, base_img.height()-107, base_img.width()-total_distance_h - border_thick - 11,
                                       base_img.height()-total_distance_h - border_thick), Qt.AlignRight,
                                 self.versioned_seed.version + '_'+self.versioned_seed.checksum)
                painter.end()

            else: # revealer

                painter.setPen(QPen(border_color, 17))
                painter.drawLine(0, dist_v, base_img.width(), dist_v)
                painter.drawLine(dist_h, 0,  dist_h, base_img.height())
                painter.drawLine(0, base_img.height()-dist_v, base_img.width(), base_img.height()-(dist_v))
                painter.drawLine(base_img.width()-(dist_h), 0,  base_img.width()-(dist_h), base_img.height())

                painter.setPen(QPen(Qt.black, 2))
                painter.drawLine(0, dist_v, base_img.width(), dist_v)
                painter.drawLine(dist_h, 0,  dist_h, base_img.height())
                painter.drawLine(0, base_img.height()-dist_v, base_img.width(), base_img.height()-(dist_v))
                painter.drawLine(base_img.width()-(dist_h), 0,  base_img.width()-(dist_h), base_img.height())
                logo = QImage(icon_path('revealer_c.png')).scaledToWidth(1.3*(total_distance_h))
                painter.drawImage((total_distance_h)+ (border_thick), ((total_distance_h))+ (border_thick), logo, Qt.SmoothTransformation)

                #frame around logo
                painter.setPen(QPen(Qt.black, border_thick))
                painter.drawLine(total_distance_h+border_thick, total_distance_h+logo.height()+3*(border_thick/2),
                                 total_distance_h+logo.width()+border_thick, total_distance_h+logo.height()+3*(border_thick/2))
                painter.drawLine(logo.width()+total_distance_h+3*(border_thick/2), total_distance_h+(border_thick),
                                 total_distance_h+logo.width()+3*(border_thick/2), total_distance_h+logo.height()+(border_thick))

                #frame around code/qr
                qr_size = 179

                painter.drawLine((base_img.width()-((total_distance_h))-(border_thick/2)-2)-qr_size,
                                (base_img.height()-((total_distance_h)))-((border_thick*8))-(border_thick/2)-2,
                                 (base_img.width()/2+(total_distance_h/2)-border_thick-(border_thick*8)/2)-qr_size,
                                (base_img.height()-((total_distance_h)))-((border_thick*8))-(border_thick/2)-2)

                painter.drawLine((base_img.width()/2+(total_distance_h/2)-border_thick-(border_thick*8)/2)-qr_size,
                                (base_img.height()-((total_distance_h)))-((border_thick*8))-(border_thick/2)-2,
                                 base_img.width()/2 + (total_distance_h/2)-border_thick-(border_thick*8)/2-qr_size,
                                 ((base_img.height()-((total_distance_h)))-(border_thick/2)-2))

                painter.setPen(QPen(Qt.white, border_thick * 8))
                painter.drawLine(
                    base_img.width() - ((total_distance_h)) - (border_thick * 8) / 2 - (border_thick / 2) - 2,
                    (base_img.height() - ((total_distance_h))) - ((border_thick * 8) / 2) - (border_thick / 2) - 2,
                    base_img.width() / 2 + (total_distance_h / 2) - border_thick - qr_size,
                    (base_img.height() - ((total_distance_h))) - ((border_thick * 8) / 2) - (border_thick / 2) - 2)

                painter.setPen(QColor(0,0,0,255))
                painter.drawText(QRect(((base_img.width()/2) +21)-qr_size, base_img.height()-107,
                                       base_img.width()-total_distance_h - border_thick -93,
                                       base_img.height()-total_distance_h - border_thick), Qt.AlignLeft, self.versioned_seed.get_ui_string_version_plus_seed())
                painter.drawText(QRect(0, base_img.height()-107, base_img.width()-total_distance_h - border_thick -3 -qr_size,
                                       base_img.height()-total_distance_h - border_thick), Qt.AlignRight, self.versioned_seed.checksum)

                # draw qr code
                qr_qt = self.paintQR(self.versioned_seed.get_ui_string_version_plus_seed()
                                     + self.versioned_seed.checksum)
                target = QRectF(base_img.width()-65-qr_size,
                                base_img.height()-65-qr_size,
                                qr_size, qr_size )
                painter.drawImage(target, qr_qt)
                painter.setPen(QPen(Qt.black, 4))
                painter.drawLine(base_img.width()-65-qr_size,
                                base_img.height()-65-qr_size,
                                 base_img.width() - 65 - qr_size,
                                (base_img.height() - ((total_distance_h))) - ((border_thick * 8)) - (border_thick / 2) - 4
                                 )
                painter.drawLine(base_img.width()-65-qr_size,
                                base_img.height()-65-qr_size,
                                 base_img.width() - 65,
                                base_img.height()-65-qr_size
                                 )
                painter.end()

        else: # calibration only
            painter.end()
            cal_img = QImage(self.f_size.width() + 100, self.f_size.height() + 100,
                              QImage.Format_ARGB32)
            cal_img.fill(Qt.white)

            cal_painter = QPainter()
            cal_painter.begin(cal_img)
            cal_painter.drawImage(0,0, base_img)

            #black lines in the middle of border top left only
            cal_painter.setPen(QPen(Qt.black, 1, Qt.DashDotDotLine))
            cal_painter.drawLine(0, dist_v, base_img.width(), dist_v)
            cal_painter.drawLine(dist_h, 0,  dist_h, base_img.height())

            pen = QPen(Qt.black, 2, Qt.DashDotDotLine)
            cal_painter.setPen(pen)
            n=15

            cal_painter.setFont(QFont("DejaVu Sans Mono", 21, QFont.Bold))
            for x in range(-n,n):
                #lines on bottom (vertical calibration)
                cal_painter.drawLine((((base_img.width())/(n*2)) *(x))+ (base_img.width()/2)-13,
                                 x+2+base_img.height()-(dist_v),
                                 (((base_img.width())/(n*2)) *(x))+ (base_img.width()/2)+13,
                                 x+2+base_img.height()-(dist_v))

                num_pos = 9
                if x > 9 : num_pos = 17
                if x < 0 : num_pos = 20
                if x < -9: num_pos = 27

                cal_painter.drawText((((base_img.width())/(n*2)) *(x))+ (base_img.width()/2)-num_pos,
                                 50+base_img.height()-(dist_v),
                                  str(x))

                #lines on the right (horizontal calibrations)

                cal_painter.drawLine(x+2+(base_img.width()-(dist_h)),
                                 ((base_img.height()/(2*n)) *(x))+ (base_img.height()/n)+(base_img.height()/2)-13,
                                 x+2+(base_img.width()-(dist_h)),
                                 ((base_img.height()/(2*n)) *(x))+ (base_img.height()/n)+(base_img.height()/2)+13)


                cal_painter.drawText(30+(base_img.width()-(dist_h)),
                                ((base_img.height()/(2*n)) *(x))+ (base_img.height()/2)+13, str(x))

            cal_painter.end()
            base_img = cal_img

        return base_img

    def paintQR(self, data):
        if not data:
            return
        qr = qrcode.QRCode()
        qr.add_data(data)
        matrix = qr.get_matrix()
        k = len(matrix)
        border_color = Qt.white
        base_img = QImage(k * 5, k * 5, QImage.Format_ARGB32)
        base_img.fill(border_color)
        qrpainter = QPainter()
        qrpainter.begin(base_img)
        boxsize = 5
        size = k * boxsize
        left = (base_img.width() - size)/2
        top = (base_img.height() - size)/2
        qrpainter.setBrush(Qt.black)
        qrpainter.setPen(Qt.black)

        for r in range(k):
            for c in range(k):
                if matrix[r][c]:
                    qrpainter.drawRect(left+c*boxsize, top+r*boxsize, boxsize - 1, boxsize - 1)
        qrpainter.end()
        return base_img

    def calibration_dialog(self, window):
        d = WindowModalDialog(window, _("Revealer - Printer calibration settings"))

        d.setMinimumSize(100, 200)

        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(''.join(["<br/>", _("If you have an old printer, or want optimal precision"),"<br/>",
                                       _("print the calibration pdf and follow the instructions "), "<br/>","<br/>",
                                    ])))
        self.calibration_h = self.config.get('calibration_h')
        self.calibration_v = self.config.get('calibration_v')
        cprint = QPushButton(_("Open calibration pdf"))
        cprint.clicked.connect(self.calibration)
        vbox.addWidget(cprint)

        vbox.addWidget(QLabel(_('Calibration values:')))
        grid = QGridLayout()
        vbox.addLayout(grid)
        grid.addWidget(QLabel(_('Right side')), 0, 0)
        horizontal = QLineEdit()
        horizontal.setText(str(self.calibration_h))
        grid.addWidget(horizontal, 0, 1)

        grid.addWidget(QLabel(_('Bottom')), 1, 0)
        vertical = QLineEdit()
        vertical.setText(str(self.calibration_v))
        grid.addWidget(vertical, 1, 1)

        vbox.addStretch()
        vbox.addSpacing(13)
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))

        if not d.exec_():
            return

        self.calibration_h = int(Decimal(horizontal.text()))
        self.config.set_key('calibration_h', self.calibration_h)
        self.calibration_v = int(Decimal(vertical.text()))
        self.config.set_key('calibration_v', self.calibration_v)


