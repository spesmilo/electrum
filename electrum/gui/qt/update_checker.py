# Copyright (C) 2019 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
import re
from typing import Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import QVBoxLayout, QLabel, QProgressBar, QHBoxLayout, QPushButton, QDialog

from electrum import version
from electrum import constants
from electrum.i18n import _
from electrum.util import make_aiohttp_session
from electrum.logging import Logger
from electrum.network import Network
from electrum._vendor.distutils.version import StrictVersion


class UpdateCheck(QDialog, Logger):
    url = "https://api.github.com/repos/hogusea/electrum/releases/latest"
    download_url = "https://github.com/hogusea/electrum/releases/latest"

    def __init__(self, *, latest_version=None):
        QDialog.__init__(self)
        self.setWindowTitle(f"{constants.APP_NAME_SHORT} - " + _('Update Check'))
        self.content = QVBoxLayout()
        self.content.setContentsMargins(*[10]*4)

        self.heading_label = QLabel()
        self.content.addWidget(self.heading_label)

        self.detail_label = QLabel()
        self.detail_label.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse)
        self.detail_label.setOpenExternalLinks(True)
        self.content.addWidget(self.detail_label)

        self.pb = QProgressBar()
        self.pb.setMaximum(0)
        self.pb.setMinimum(0)
        self.content.addWidget(self.pb)

        versions = QHBoxLayout()
        versions.addWidget(QLabel(_("Current version: {}").format(version.ELECTRUM_VERSION)))
        self.latest_version_label = QLabel(_("Latest version: {}").format(" "))
        versions.addWidget(self.latest_version_label)
        self.content.addLayout(versions)

        self.update_view(latest_version)

        self.update_check_thread = UpdateCheckThread()
        self.update_check_thread.checked.connect(self.on_version_retrieved)
        self.update_check_thread.failed.connect(self.on_retrieval_failed)
        self.update_check_thread.start()

        close_button = QPushButton(_("Close"))
        close_button.clicked.connect(self.close)
        self.content.addWidget(close_button)
        self.setLayout(self.content)
        self.show()

    @staticmethod
    def parse_strict_version(raw_version: str) -> StrictVersion:
        value = raw_version.strip()
        value_lower = value.lower()
        for prefix in ("refs/tags/", "mobick-v", "btcmobick-v", "v"):
            if value_lower.startswith(prefix):
                value = value[len(prefix):]
                value_lower = value.lower()

        match = re.search(r"\d+\.\d+(?:\.\d+)?", value)
        if not match:
            raise ValueError(f"could not parse release version from '{raw_version}'")
        return StrictVersion(match.group(0))

    @classmethod
    def is_newer(cls, latest_version):
        return latest_version > cls.parse_strict_version(version.ELECTRUM_VERSION)

    def on_version_retrieved(self, version):
        self.update_view(version)

    def on_retrieval_failed(self):
        self.heading_label.setText('<h2>' + _("Update check failed") + '</h2>')
        self.detail_label.setText(_("Sorry, but we were unable to check for updates. Please try again later."))
        self.pb.hide()

    def update_view(self, latest_version=None):
        if latest_version:
            self.pb.hide()
            self.latest_version_label.setText(_("Latest version: {}").format(latest_version))
            if self.is_newer(latest_version):
                self.heading_label.setText('<h2>' + _("There is a new update available") + '</h2>')
                url = "<a href='{u}'>{u}</a>".format(u=UpdateCheck.download_url)
                self.detail_label.setText(_("You can download the new version from {}.").format(url))
            else:
                self.heading_label.setText('<h2>' + _("Already up to date") + '</h2>')
                self.detail_label.setText(_("You are already on the latest version of BTCmobick."))
        else:
            self.heading_label.setText('<h2>' + _("Checking for updates...") + '</h2>')
            self.detail_label.setText(_("Please wait while BTCmobick checks for available updates."))


class UpdateCheckThread(QThread, Logger):
    checked = pyqtSignal(object)
    failed = pyqtSignal()

    def __init__(self):
        QThread.__init__(self)
        Logger.__init__(self)
        self.network = Network.get_instance()
        self._fut = None  # type: Optional[asyncio.Future]

    async def get_update_info(self):
        # note: Use long timeout here as it is not critical that we get a response fast,
        #       and it's bad not to get an update notification just because we did not wait enough.
        async with make_aiohttp_session(proxy=self.network.proxy, timeout=120) as session:
            async with session.get(UpdateCheck.url, headers={"Accept": "application/vnd.github+json"}) as result:
                result.raise_for_status()
                latest_release_dict = await result.json(content_type=None)
                release_tag = latest_release_dict.get("tag_name") or latest_release_dict.get("name")
                if not release_tag:
                    raise Exception("release payload did not include tag_name or name")

                release_url = latest_release_dict.get("html_url")
                if release_url:
                    UpdateCheck.download_url = release_url

                return UpdateCheck.parse_strict_version(release_tag)

    def run(self):
        if not self.network:
            self.failed.emit()
            return
        self._fut = asyncio.run_coroutine_threadsafe(self.get_update_info(), self.network.asyncio_loop)
        try:
            update_info = self._fut.result()
        except Exception as e:
            self.logger.info(f"got exception: '{repr(e)}'")
            self.failed.emit()
        else:
            self.checked.emit(update_info)

    def stop(self):
        if self._fut:
            self._fut.cancel()
        self.exit()
        self.wait()
