#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Kivy GUI

import sys
import os
from typing import TYPE_CHECKING

from electrum import GuiImportError

KIVY_GUI_PATH = os.path.abspath(os.path.dirname(__file__))
os.environ['KIVY_DATA_DIR'] = os.path.join(KIVY_GUI_PATH, 'data')

try:
    sys.argv = ['']
    import kivy
except ImportError as e:
    # This error ideally shouldn't be raised with pre-built packages
    raise GuiImportError(
        "Error: Could not import kivy. Please install it using the "
        "instructions mentioned here `https://kivy.org/#download` .") from e

# minimum required version for kivy
kivy.require('1.8.0')

from electrum.logging import Logger
from electrum.gui import BaseElectrumGui

if TYPE_CHECKING:
    from electrum.simple_config import SimpleConfig
    from electrum.daemon import Daemon
    from electrum.plugin import Plugins


class ElectrumGui(BaseElectrumGui, Logger):

    def __init__(self, *, config: 'SimpleConfig', daemon: 'Daemon', plugins: 'Plugins'):
        BaseElectrumGui.__init__(self, config=config, daemon=daemon, plugins=plugins)
        Logger.__init__(self)
        self.logger.debug('ElectrumGUI: initialising')
        self.network = daemon.network

    def main(self):
        self.daemon.start_network()
        from .main_window import ElectrumWindow
        w = ElectrumWindow(
            config=self.config,
            network=self.network,
            plugins=self.plugins,
            gui_object=self,
        )
        w.run()

    def stop(self) -> None:
        from kivy.app import App
        from kivy.clock import Clock
        app = App.get_running_app()
        if not app:
            return
        Clock.schedule_once(lambda dt: app.stop())

    @classmethod
    def version_info(cls):
        ret = {
            "kivy.version": kivy.__version__,
        }
        if hasattr(kivy, "__path__"):
            ret["kivy.path"] = ", ".join(kivy.__path__ or [])
        return ret
