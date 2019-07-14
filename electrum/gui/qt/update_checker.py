# Copyright (C) 2019 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
import base64
from distutils.version import StrictVersion

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel, QProgressBar,
                             QHBoxLayout, QPushButton)

from electrum import version
from electrum import constants
from electrum import ecc
from electrum.i18n import _
from electrum.util import make_aiohttp_session
from electrum.logging import Logger


class UpdateCheck(QWidget, Logger):
    url = "https://electrum.org/version"
    download_url = "https://electrum.org/#download"

    VERSION_ANNOUNCEMENT_SIGNING_KEYS = (
        "13xjmVAB1EATPP8RshTE8S8sNwwSUM9p1P",
    )

    def __init__(self, main_window, latest_version=None):
        self.main_window = main_window
        QWidget.__init__(self)
        self.setWindowTitle('Electrum - ' + _('Update Check'))
        self.content = QVBoxLayout()
        self.content.setContentsMargins(*[10]*4)

        self.heading_label = QLabel()
        self.content.addWidget(self.heading_label)

        self.detail_label = QLabel()
        self.detail_label.setTextInteractionFlags(Qt.LinksAccessibleByMouse)
        self.detail_label.setOpenExternalLinks(True)
        self.content.addWidget(self.detail_label)

        self.pb = QProgressBar()
        self.pb.setMaximum(0)
        self.pb.setMinimum(0)
        self.content.addWidget(self.pb)

        versions = QHBoxLayout()
        versions.addWidget(QLabel(_("Current version: {}".format(version.ELECTRUM_VERSION))))
        self.latest_version_label = QLabel(_("Latest version: {}".format(" ")))
        versions.addWidget(self.latest_version_label)
        self.content.addLayout(versions)

        self.update_view(latest_version)

        self.update_check_thread = UpdateCheckThread(self.main_window)
        self.update_check_thread.checked.connect(self.on_version_retrieved)
        self.update_check_thread.failed.connect(self.on_retrieval_failed)
        self.update_check_thread.start()

        close_button = QPushButton(_("Close"))
        close_button.clicked.connect(self.close)
        self.content.addWidget(close_button)
        self.setLayout(self.content)
        self.show()

    def on_version_retrieved(self, version):
        self.update_view(version)

    def on_retrieval_failed(self):
        self.heading_label.setText('<h2>' + _("Update check failed") + '</h2>')
        self.detail_label.setText(_("Sorry, but we were unable to check for updates. Please try again later."))
        self.pb.hide()

    @staticmethod
    def is_newer(latest_version):
        return latest_version > StrictVersion(version.ELECTRUM_VERSION)

    def update_view(self, latest_version=None):
        if latest_version:
            self.pb.hide()
            self.latest_version_label.setText(_("Latest version: {}".format(latest_version)))
            if self.is_newer(latest_version):
                self.heading_label.setText('<h2>' + _("There is a new update available") + '</h2>')
                url = "<a href='{u}'>{u}</a>".format(u=UpdateCheck.download_url)
                self.detail_label.setText(_("You can download the new version from {}.").format(url))
            else:
                self.heading_label.setText('<h2>' + _("Already up to date") + '</h2>')
                self.detail_label.setText(_("You are already on the latest version of Electrum."))
        else:
            self.heading_label.setText('<h2>' + _("Checking for updates...") + '</h2>')
            self.detail_label.setText(_("Please wait while Electrum checks for available updates."))


class UpdateCheckThread(QThread, Logger):
    checked = pyqtSignal(object)
    failed = pyqtSignal()

    def __init__(self, main_window):
        QThread.__init__(self)
        Logger.__init__(self)
        self.main_window = main_window

    async def get_update_info(self):
        async with make_aiohttp_session(proxy=self.main_window.network.proxy) as session:
            async with session.get(UpdateCheck.url) as result:
                signed_version_dict = await result.json(content_type=None)
                # example signed_version_dict:
                # {
                #     "version": "3.9.9",
                #     "signatures": {
                #         "1Lqm1HphuhxKZQEawzPse8gJtgjm9kUKT4": "IA+2QG3xPRn4HAIFdpu9eeaCYC7S5wS/sDxn54LJx6BdUTBpse3ibtfq8C43M7M1VfpGkD5tsdwl5C6IfpZD/gQ="
                #     }
                # }
                version_num = signed_version_dict['version']
                sigs = signed_version_dict['signatures']
                for address, sig in sigs.items():
                    if address not in UpdateCheck.VERSION_ANNOUNCEMENT_SIGNING_KEYS:
                        continue
                    sig = base64.b64decode(sig)
                    msg = version_num.encode('utf-8')
                    if ecc.verify_message_with_address(address=address, sig65=sig, message=msg,
                                                       net=constants.BitcoinMainnet):
                        self.logger.info(f"valid sig for version announcement '{version_num}' from address '{address}'")
                        break
                else:
                    raise Exception('no valid signature for version announcement')
                return StrictVersion(version_num.strip())

    def run(self):
        network = self.main_window.network
        if not network:
            self.failed.emit()
            return
        try:
            update_info = asyncio.run_coroutine_threadsafe(self.get_update_info(), network.asyncio_loop).result()
        except Exception as e:
            self.logger.info(f"got exception: '{repr(e)}'")
            self.failed.emit()
        else:
            self.checked.emit(update_info)
