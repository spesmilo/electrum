#!/usr/bin/python

from electrum.plugin import BasePlugin

class Deniability(BasePlugin):
    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)