#!/usr/bin/env python3

from .. import set_verbosity
from electrum_ltc.network import filter_version
from . import util
import json
set_verbosity(False)

servers = filter_version(util.get_peers())
print(json.dumps(servers, sort_keys = True, indent = 4))
