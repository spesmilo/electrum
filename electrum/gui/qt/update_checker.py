# Copyright (C) 2019 The Electrum developers
# Distributed under the MIT software license, see the accompanying
# file LICENCE or http://www.opensource.org/licenses/mit-license.php

import asyncio
import base64
from typing import Optional, Sequence, List
import json

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import QVBoxLayout, QLabel, QProgressBar, QHBoxLayout, QPushButton, QDialog

from electrum import version
from electrum import constants
from electrum.bitcoin import verify_usermessage_with_address
from electrum.i18n import _
from electrum.util import make_aiohttp_session
from electrum.crypto import sha256
from electrum.logging import Logger
from electrum.network import Network
from electrum._vendor.distutils.version import StrictVersion


class UpdateCheck(QDialog, Logger):
    url = "https://electrum.org/version"
    download_url = "https://electrum.org/#download"
    direct_download_url = "https://download.electrum.org"  # shown for prereleases

    VERSION_ANNOUNCEMENT_SIGNING_KEYS = (
        "13xjmVAB1EATPP8RshTE8S8sNwwSUM9p1P",  # ThomasV (since 3.3.4)
        "1Nxgk6NTooV4qZsX5fdqQwrLjYcsQZAfTg",  # ghost43 (since 4.1.2)
    )

    def __init__(self, *, latest_version=None, version_channel: int):
        QDialog.__init__(self)
        self.setWindowTitle('Electrum - ' + _('Update Check'))
        self.content = QVBoxLayout()
        self.content.setContentsMargins(*[10]*4)
        self.version_channel = version_channel

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

    def on_version_retrieved(self, versions: Sequence[StrictVersion]):
        latest_allowed_version = self.latest_allowed_version(versions, self.version_channel)
        self.update_view(latest_allowed_version)

    def on_retrieval_failed(self):
        self.heading_label.setText('<h2>' + _("Update check failed") + '</h2>')
        self.detail_label.setText(_("Sorry, but we were unable to check for updates. Please try again later."))
        self.pb.hide()

    @staticmethod
    def is_newer(latest_version: StrictVersion) -> bool:
        return latest_version > StrictVersion(version.ELECTRUM_VERSION)

    @staticmethod
    def is_version_allowed(v: StrictVersion, version_channel: int) -> bool:
        if v.prerelease:
            prerelease_type = v.prerelease[0]
            if prerelease_type == 'a':
                return version_channel >= 3
            elif prerelease_type == 'b':
                return version_channel >= 2
            raise NotImplementedError(f"Version type not supported: {version}")
        return True

    @staticmethod
    def latest_allowed_version(
        available_versions: Sequence[StrictVersion],
        version_channel: int,
    ) -> Optional[StrictVersion]:
        allowed_versions = [v for v in available_versions
                                if UpdateCheck.is_version_allowed(v, version_channel)]
        return max(allowed_versions, default=None)

    def update_view(self, latest_version=None):
        if latest_version:
            self.pb.hide()
            self.latest_version_label.setText(_("Latest version: {}").format(latest_version))
            if self.is_newer(latest_version):
                self.heading_label.setText('<h2>' + _("There is a new update available") + '</h2>')
                url = self.download_url if not latest_version.prerelease \
                        else f"{self.direct_download_url}/{latest_version}"
                url = "<a href='{u}'>{u}</a>".format(u=url)
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

    def __init__(self):
        QThread.__init__(self)
        Logger.__init__(self)
        self.network = Network.get_instance()
        self._fut = None  # type: Optional[asyncio.Future]

    async def get_update_info(self) -> List[StrictVersion]:
        # note: Use long timeout here as it is not critical that we get a response fast,
        #       and it's bad not to get an update notification just because we did not wait enough.
        signed_versions: List[StrictVersion] = []
        async with (make_aiohttp_session(proxy=self.network.proxy, timeout=120) as session):
            async with session.get(UpdateCheck.url) as result:
                signed_version_dict = await result.json(content_type=None)
                # example signed_version_dict:
                # signed_version_dict = {
                #     "version": "4.5.8",
                #     "signatures": {
                #         "1Crsz58e7mqPzzW1GUhWp8fhjtd3sBoTwc":
                #             "H1m9a9XoJippZgAsG2ZP/C8eHWQZiyl9tP1ISmk9QN7/XDveSH1GVlnB66Pr5CCzzrTjTc5X1fa/Sx0tBVaXzX4="
                #     },
                #     "extradata": {
                #         "android_versioncode_nullarch": 45405080,
                #         "version_alpha": "4.6.0a1",
                #         "version_beta": "4.5.9b1"
                #     },
                #     "extradata_hash_signatures": {
                #         "1Crsz58e7mqPzzW1GUhWp8fhjtd3sBoTwc":
                #             "ICcF3AHrpc80vkc6YJYF7/dxVwhI1OaT15mdlb8bnHdQLGx/olRW0jcZVeNzLxtln4goImGt6cSi6o3x89RFuXI="
                #     }
                # }
                version_num = signed_version_dict['version']
                version_sigs = signed_version_dict['signatures']
                self.validate_signatures(
                    msg=version_num,
                    signatures=version_sigs,
                )
                # stable version
                signed_versions.append(StrictVersion(version_num.strip()))

                extradata = signed_version_dict.get('extradata')
                if extradata:
                    extradata_sigs = signed_version_dict['extradata_hash_signatures']
                    signed_extradata_msg = sha256(
                        json.dumps(extradata, sort_keys=True, separators=(',', ':'))
                    ).hex()
                    self.validate_signatures(
                        msg=signed_extradata_msg,
                        signatures=extradata_sigs,
                    )
                    if alpha_version := extradata.get('version_alpha'):
                        signed_versions.append(StrictVersion(alpha_version.strip()))
                    if beta_version := extradata.get('version_beta'):
                        signed_versions.append(StrictVersion(beta_version.strip()))

        return signed_versions

    def validate_signatures(self, *, msg: str, signatures: dict):
        for address, sig in signatures.items():
            if address not in UpdateCheck.VERSION_ANNOUNCEMENT_SIGNING_KEYS:
                continue
            sig = base64.b64decode(sig, validate=True)
            if verify_usermessage_with_address(
                address=address,
                sig65=sig,
                message=msg.encode('utf-8'),
                net=constants.BitcoinMainnet
            ):
                self.logger.info(f"valid sig for version announcement '{msg=}' from '{address=}'")
                break
        else:
            raise Exception(f'no valid signature for version announcement {msg=} {signatures=}')

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
